"""Exercise the owned native image host against an isolated Go server child."""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import struct
import subprocess
import tempfile
import time
import zlib

CLIENT = Path(__file__).resolve().parents[1]
MAX_DDS = 16 * 1024 * 1024
MAX_PACKET = 2 * (MAX_DDS + 65536) + 256
TAGS = {0: b'LOGO\0\0\0\0', 31: b'FAPH\0\0\0\0', 61: b'CUPO\0\0\0\0'}


def synthetic_dds(seed):
    data = bytearray(128 + 8 * 8 * 4)
    data[:4] = b'DDS '
    struct.pack_into('<IIIIIII', data, 4, 124, 0x100f, 8, 8, 32, 0, 0)
    struct.pack_into('<IIIIIIII', data, 76, 32, 0x41, 0, 32,
                     0xff0000, 0xff00, 0xff, 0xff000000)
    struct.pack_into('<I', data, 108, 0x1000)
    for i in range(64):
        data[128 + 4*i:132 + 4*i] = bytes(((i+seed) & 255, (3*i+seed) & 255,
                                         (7*i+seed) & 255, 255))
    return bytes(data)


def sync_frame(identity, kind, image):
    descriptor = bytearray(32)
    struct.pack_into('<IH', descriptor, 0, 4, kind)
    descriptor[16:32] = bytes.fromhex(identity)
    return b'W2IMG001' + descriptor + struct.pack('<I', len(image)) + image


def check_packet(packet, expected, kind):
    """Decode bounded preview/main bodies independently of the server codec."""
    assert 288 <= len(packet) <= MAX_PACKET
    header = packet[:128]
    assert struct.unpack_from('<I', header, 4)[0] == 128
    assert header[16:24] == TAGS[kind]
    preview_size = struct.unpack_from('<I', header, 28)[0]
    assert 16 <= preview_size <= MAX_DDS + 65536
    second = 128 + preview_size
    assert second + 144 <= len(packet)
    canonical = bytearray(header)
    canonical[28:40] = bytes(12)
    assert bytes(canonical) == packet[second:second+128]
    height, width = struct.unpack_from('<II', expected, 12)
    assert struct.unpack_from('<II', header, 32) == (width, height)
    for body in (packet[128:second], packet[second+128:]):
        assert len(body) >= 16 and body[:4] == b'ZLIB'
        marker, compressed, size = struct.unpack_from('<III', body, 4)
        assert marker == 0x2050 and compressed == len(body)-16
        assert 128 <= size == len(expected) <= MAX_DDS
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(body[16:], size+1)
        assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
        assert decoded == expected


def asset_path(identity):
    assert re.fullmatch(r'[0-9a-f]{32}', identity)
    return '/ae70420fb2e24ec6a145023e0fa111f8/' + identity[:3] + '/' + identity[3:6] + '/' + identity + '.bin'



def wait_for_server_port(process, log, timeout=30, redactions=()):
    """Wait for the owned child, including slow first-launch scans on CI."""
    if timeout <= 0:
        raise ValueError('Startup timeout must be positive')
    deadline = time.monotonic() + timeout
    while True:
        text = log.read_text(encoding='utf-8', errors='replace')
        match = re.search(r'WWE 2K22 Go server:\s+http://127\.0\.0\.1:(\d+)', text)
        code = process.poll()
        if code is None and match and 0 < int(match[1]) <= 65535:
            return int(match[1])
        remaining = deadline - time.monotonic()
        if code is not None or remaining <= 0:
            for secret in redactions:
                if secret:
                    text = text.replace(secret, '[redacted]')
            text = re.sub(r'(?i)\b[0-9a-f]{64}\b', '[redacted]', text)
            diagnostic = text[-1600:].strip() or '(no output)'
            if code is not None:
                raise RuntimeError(f'Owned server child exited before startup (code {code}): {diagnostic}')
            raise TimeoutError(f'Owned server child did not announce its port within {timeout}s: {diagnostic}')
        time.sleep(min(.05, remaining))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True, type=Path, help='Go server executable to test')
    args = parser.parse_args()
    report = CLIENT / 'build/server-integration-tests/report.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text('{"passed": false}\n', encoding='utf-8')
    server = args.server.resolve(strict=True)
    built = CLIENT / 'build/native-image-tests'
    manifest = json.loads((built / 'manifest.json').read_text(encoding='utf-8-sig'))
    assert manifest['kind'] == 'owned-test-native-client'
    host_bytes = (built / 'owned-image-host.exe').read_bytes()
    host_sha = hashlib.sha256(host_bytes).hexdigest()
    dll = (built / 'dinput8.dll').read_bytes()
    dll_sha = hashlib.sha256(dll).hexdigest()
    assert host_sha == manifest['target_sha256']
    assert dll_sha == manifest['files']['dinput8.dll']['sha256']
    assert len(dll) == manifest['files']['dinput8.dll']['bytes']
    current = {item.relative_to(CLIENT).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
               for item in (CLIENT / 'src').rglob('*')
               if item.is_file() and item.suffix in ('.cpp', '.hpp', '.S', '.c', '.h', '.def')}
    assert manifest['source_sha256'] == current, 'Rebuild the owned native fixtures after source changes'
    env = {key: value for key, value in os.environ.items() if not key.startswith('WWE_')}
    hidden = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
    temp_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix='owned-native-go-', dir=temp_root) as directory:
        temp = Path(directory).resolve()
        assert temp.parent == temp_root and temp.name.startswith('owned-native-go-')
        native = temp / 'native'
        native.mkdir()
        host = native / 'owned-image-host.exe'
        host.write_bytes(host_bytes)
        (native / 'dinput8.dll').write_bytes(dll)
        keyfile = temp / 'access.key'
        key = secrets.token_hex(32)
        keyfile.write_text(key, encoding='ascii')
        log = temp / 'server.log'
        with log.open('wb') as output:
            process = subprocess.Popen(
                [str(server), '--bind-host', '127.0.0.1', '--http-host', '127.0.0.1',
                 '--advertise-host', '127.0.0.1', '--port', '0', '--custom-content',
                 '--state-file', str(temp / 'state.sqlite3'), '--access-key-file',
                 str(keyfile), '--log', '-'], cwd=temp, stdout=output, stderr=output,
                env=env, creationflags=hidden)
            try:
                port = wait_for_server_port(process, log, redactions=(key,))

                def call(path, data=None, session=None, marker=False):
                    raw = json.dumps(data).encode() if isinstance(data, dict) else data
                    headers = {'X-WWE-Lab-Key': key}
                    if session:
                        headers['X-Sessionid'] = session
                    if marker:
                        headers['X-WWE-Native-Images'] = '1'
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
                    try:
                        connection.request('GET' if raw is None else 'POST', path, raw, headers)
                        response = connection.getresponse()
                        body = response.read(MAX_PACKET+1)
                        assert len(body) <= MAX_PACKET
                        return response.status, body
                    finally:
                        connection.close()

                def obj(path, data=None, session=None, marker=False):
                    code, body = call(path, data, session, marker)
                    assert code == 200, (path, code)
                    return json.loads(body)

                def upload(account, paths):
                    subprocess.run([str(host), 'file', str(port), account['SessionID'],
                                    *map(str, paths)], cwd=native, env=env, check=True,
                                   capture_output=True, timeout=30, creationflags=hidden)

                settings = ('[Server]\nEnabled=1\nHost=127.0.0.1\nHttpPort=' + str(port) +
                            '\nHTTPS=0\nCustomContent=1\nPublicLobbies=0\nThreadCleanupGuard=0\nAccessKeyFile=' + str(keyfile) + '\n')
                (native / 'wwe2k22-private.ini').write_text(settings, encoding='utf-8')
                accounts = [obj('/api/Login', {'Login': secrets.token_hex(16)}) for _ in range(2)]
                assert accounts[0]['UserID'] != accounts[1]['UserID']
                expected, batches = {}, []
                for owner_index, account in enumerate(accounts):
                    paths = []
                    for kind in TAGS:
                        identity, image = secrets.token_hex(16), synthetic_dds(17+20*owner_index+kind)
                        expected[identity] = (image, kind, account['UserID'])
                        path = temp / (identity + '.bin')
                        path.write_bytes(sync_frame(identity, kind, image))
                        paths.append(path)
                    batches.append(paths)
                query = {'ContentIDs': list(expected)}
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    waiting = pool.submit(obj, '/api/ContentMetaGet', query, accounts[1]['SessionID'], True)
                    time.sleep(.05)
                    assert not waiting.done(), 'Missing dependency query did not wait'
                    for account, paths in zip(accounts, batches):
                        upload(account, paths)
                    assert len(waiting.result(timeout=10)['Results']) == 6
                old_fids = {}
                for account in accounts:
                    records = obj('/api/ContentMetaGet', query, account['SessionID'])['Results']
                    assert len(records) == 6
                    for record in records:
                        image, kind, owner = expected[record['ID']]
                        assert record['PID'] == owner
                        code, packet = call(asset_path(record['FileID']), session=account['SessionID'])
                        assert code == 200 and record['FileSize'] == len(packet)
                        check_packet(packet, image, kind)
                        old_fids[record['ID']] = record['FileID']
                identity = next(i for i, item in expected.items() if item[1:] == (31, accounts[0]['UserID']))
                updated_image = synthetic_dds(201)
                assert len(updated_image) == len(expected[identity][0])
                path = temp / 'updated-face.bin'
                path.write_bytes(sync_frame(identity, 31, updated_image))
                upload(accounts[0], [path, path])
                session = accounts[1]['SessionID']
                record = obj('/api/ContentMetaGet', {'ContentIDs': [identity]}, session)['Results'][0]
                assert record['FileID'] != old_fids[identity]
                shared = obj('/lab/images/sync', sync_frame(identity, 31, updated_image), session)
                assert shared['status'] == 'unchanged' and shared['FileID'] == record['FileID']
                assert call('/lab/images/sync', sync_frame(identity, 31, synthetic_dds(202)), session)[0] == 409
                records = obj('/api/ContentMetaGet', query, session)['Results']
                assert len(records) == 6
                for current in records:
                    assert current['FileID'] == (record['FileID'] if current['ID'] == identity else old_fids[current['ID']])
                code, packet = call(asset_path(record['FileID']), session=session)
                assert code == 200
                check_packet(packet, updated_image, 31)
                status = obj('/status')
                assert status['custom_content']['assets'] == 6
                results = dict(passed=True, native_to_go_exact_images=6, storage_kinds=list(TAGS),
                               both_accounts_preview_and_main_exact=True, metadata_wait_resolved=True,
                               same_size_edit_rotated=True, shared_duplicate_idempotent=True,
                               other_owner_409_isolated=True, assets=6, host_sha256=host_sha,
                               dll_sha256=dll_sha, server_sync_counts=status['native_image_sync'],
                               game_started=False, production_server_modified=False, user_data_used=False)
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    report.write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(results))


if __name__ == '__main__':
    main()
