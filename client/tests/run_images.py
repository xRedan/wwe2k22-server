"""Native image synchronization against owned loopback fixtures only."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_build', ROOT / 'build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--address-sanitizer', action='store_true',
                        help='Run the owned image suite with the toolchain AddressSanitizer runtime')
    args = parser.parse_args()
    args.compiler = args.compiler.resolve()
    child_env = None
    if args.address_sanitizer:
        runtime = args.compiler.with_name('libclang_rt.asan_dynamic-x86_64.dll')
        if not runtime.is_file():
            raise FileNotFoundError(runtime)
        child_env = os.environ.copy()
        child_env['PATH'] = str(args.compiler.parent) + os.pathsep + child_env.get('PATH', '')
        child_env['ASAN_OPTIONS'] = 'detect_leaks=0:halt_on_error=1'
    out = ROOT / 'build' / ('native-image-asan-tests' if args.address_sanitizer else 'native-image-tests')
    out.mkdir(parents=True, exist_ok=True)
    host = out / 'owned-image-host.exe'
    host_flags = (['-DWWE_OWNED_ASAN', '-fsanitize=address', '-shared-libasan',
                   '-fno-omit-frame-pointer', '-gline-tables-only']
                  if args.address_sanitizer else ['-static'])
    host_libraries = [] if args.address_sanitizer else ['-ldinput8']
    subprocess.run([str(args.compiler), '-std=c++17', '-O2', *host_flags, '-Wall',
                    '-Wextra', '-Werror', str(ROOT / 'tests/image_host.cpp'),
                    *host_libraries, '-ldxguid', '-lwinhttp', '-Wl,--no-insert-timestamp',
                    '-o', str(host)], check=True, env=child_env)
    build.build(out, args.compiler, build.sha(host), test_only=True,
                sanitizer='address' if args.address_sanitizer else None)
    captures = []
    markers = []
    lock = threading.Lock()
    arrived = threading.Event()
    release = threading.Event()
    redirected = []
    mode = ''

    class RedirectReceiver(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            redirected.append(True)
            self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()

    receiver = ThreadingHTTPServer(('127.0.0.1', 0), RedirectReceiver)
    threading.Thread(target=receiver.serve_forever, daemon=True).start()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == '/image-barrier':
                assert arrived.wait(5)
            if self.path == '/image-release':
                release.set()
            if mode == 'marker':
                markers.append((self.command, self.path, self.headers.get('X-WWE-Native-Images')))
            self.reply(200)

        def do_POST(self):
            if mode == 'marker':
                markers.append((self.command, self.path, self.headers.get('X-WWE-Native-Images')))
                self.reply(200)
                return
            assert self.path == '/lab/images/sync', self.path
            frame = self.rfile.read(int(self.headers['Content-Length']))
            assert frame[:8] == b'W2IMG001'
            assert len(frame) == 44 + struct.unpack_from('<I', frame, 40)[0]
            assert self.headers['Content-Type'] == 'application/octet-stream'
            assert self.headers.get_all('X-WWE-Lab-Key') == ['d' * 64]
            assert self.headers.get_all('X-Sessionid') in [['a' * 48], ['b' * 48]]
            assert self.headers.get('S') is None
            with lock:
                captures.append((frame, self.headers['X-Sessionid']))
                count = len(captures)
            arrived.set()
            if mode == 'inflight' and count == 1:
                assert release.wait(10)
            status = 200
            if mode == 'transient' and count == 1:
                status = 503
            if mode == 'auth' and count == 1:
                status = 401
            if mode == 'redirect':
                status = 307
            if mode == 'permanent':
                status = 409
            if mode == 'retry-cap':
                status = 503
            self.reply(status)

        def reply(self, status):
            self.send_response(status)
            if status == 307:
                self.send_header('Location', f'http://127.0.0.1:{receiver.server_port}/private')
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'{}')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    baseline = ('[Server]\nEnabled=1\nHost=127.0.0.1\n'
                f'HttpPort={server.server_port}\nHTTPS=0\n'
                'AccessKeyFile=fixture.key\nCustomContent=1\n'
                'PublicLobbies=0\nThreadCleanupGuard=0\n')
    (out / 'fixture.key').write_text('d' * 64, encoding='ascii')
    report = []
    try:
        for mode in ('malformed', 'bounds', 'queue', 'basic', 'stage', 'auth',
                     'rotation', 'transient', 'redirect', 'permanent', 'hook', 'hook-index',
                     'disabled', 'inflight', 'marker', 'coalesce',
                     'coalesce-budget', 'coalesce-typical', 'retry-cap',
                     'parallel', 'parallel-budget', 'burst', 'stop-race',
                     'coalesce-read-race', 'coalesce-write-race',
                     'coalesce-failed-race', 'coalesce-restore-race',
                     'capture-fuzz'):
            with lock:
                captures.clear()
            arrived.clear()
            release.clear()
            markers.clear()
            ini = baseline.replace('CustomContent=1', 'CustomContent=0') if mode == 'disabled' else baseline
            (out / 'wwe2k22-private.ini').write_text(ini, encoding='ascii')
            result = subprocess.run([str(host), mode, str(server.server_port)],
                                    cwd=out, capture_output=True, timeout=25,
                                    env=child_env)
            assert result.returncode == 0, (mode, result.returncode, result.stdout, result.stderr)
            with lock:
                records = list(captures)
            count = {'basic': 5, 'stage': 1, 'auth': 2, 'rotation': 2,
                     'transient': 2, 'redirect': 1, 'permanent': 3,
                     'hook': 1, 'hook-index': 3, 'inflight': 2, 'coalesce': 65,
                     'retry-cap': 16}.get(mode, 0)
            if mode.startswith('coalesce-') and 'race' in mode:
                count = 2
            assert len(records) == count, (mode, len(records), count)
            if mode == 'basic':
                assert [struct.unpack_from('<H', frame, 12)[0] for frame, _ in records] == [0, 31, 61, 0, 0]
                assert [frame[44 + 128] for frame, _ in records] == [0x51, 0x51, 0x51, 0x52, 0x51]
            if mode == 'hook-index':
                assert [frame[24] for frame, _ in records] == [10,11,12]
                assert [struct.unpack_from('<H',frame,12)[0] for frame, _ in records] == [0,31,61]
            if mode == 'stage':
                assert records[0][0][44 + 128] == 0x51
            if mode in ('auth', 'rotation', 'inflight'):
                assert [token for _, token in records] == ['a' * 48, 'b' * 48]
            if mode == 'marker':
                assert markers == [('POST', '/api/ContentMetaGet', '1'),
                                   ('GET', '/api/ContentMetaGet', None),
                                   ('POST', '/other', None)], markers
            if mode == 'coalesce':
                assert [frame[8 + 16] for frame, _ in records] == list(range(1, 66))
                assert [frame[44 + 128] for frame, _ in records] == [0x51, 0x52] + [0x51] * 63
            if mode == 'permanent':
                assert [token for _, token in records] == ['a' * 48, 'a' * 48, 'b' * 48]
            if mode.startswith('coalesce-') and 'race' in mode:
                expected_pixel = 0x52 if mode == 'coalesce-failed-race' else 0x51 if mode == 'coalesce-restore-race' else 0x53
                assert [frame[44 + 128] for frame, _ in records] == [0x51, expected_pixel], mode
            log = (out / 'wwe2k22-private.log').read_text()
            assert 'd' * 64 not in log and 'a' * 48 not in log and 'b' * 48 not in log
            assert not redirected
            entry = {'name': mode, 'passed': True}
            for line in result.stdout.splitlines():
                timing = json.loads(line)
                if 'duplicate_samples' in timing:
                    entry['timing'] = timing
                if 'fuzz_cases' in timing:
                    entry['fuzz'] = timing
            report.append(entry)
        result = {'passed': len(report), 'game_started': False,
                  'steam_started': False, 'cases': report}
        if args.address_sanitizer:
            result['sanitizer'] = 'AddressSanitizer'
            result['leak_sanitizer_enabled'] = False
        (out / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result))
    finally:
        server.shutdown()
        server.server_close()
        receiver.shutdown()
        receiver.server_close()


if __name__ == '__main__':
    main()
