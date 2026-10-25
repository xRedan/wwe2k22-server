"""Owned-process validation. Does not start or attach WWE, Steam or Sandboxie."""
import argparse, importlib.util, json, subprocess, threading, ssl, struct, time, shutil
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_build', ROOT / 'build.py')
buildmod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(buildmod)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compiler', required=True, type=Path)
    p.add_argument('--openssl', type=Path, default=Path(shutil.which('openssl') or 'openssl'))
    args = p.parse_args()
    out = ROOT / 'build/native-client-tests'
    out.mkdir(parents=True, exist_ok=True)
    host = out / 'owned-native-host.exe'
    subprocess.run([str(args.compiler), '-std=c++17', '-O2', '-static', '-Wall', '-Wextra', '-Werror', str(ROOT / 'tests/owned_host.cpp'), '-ldinput8', '-ldxguid', '-lwinhttp', '-Wl,--no-insert-timestamp', '-o', str(host)], check=True)
    buildmod.build(out, args.compiler, buildmod.sha(host), test_only=True)
    captures = []
    lock = threading.Lock()
    first = threading.Event()
    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):

        def log_message(self, *a):
            pass

        def do_GET(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def respond(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            with lock:
                captures.append((self.path, self.headers, body))
            if self.path == '/barrier':
                if not first.wait(5):
                    raise RuntimeError('First job did not arrive')
            if self.path == '/release':
                release.set()
            if body == b'{"block":true}':
                first.set()
                if not release.wait(10):
                    raise RuntimeError('Release did not arrive')
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', redirect_url)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            if self.path == '/lab/lobbies/list':
                obj = json.loads(body)
                code = int(obj['filters'][0]['value'])
                assert obj['result_count'] == 10
                assert obj['filters'][1:] == [
                    {'key': 'spec_dev', 'type': 'string', 'value': 'dev', 'comparison': 3},
                    {'key': 'spec_fps', 'type': 'numeric', 'value': 50, 'comparison': 1},
                    {'key': 'spec_fps', 'type': 'numeric', 'value': 70, 'comparison': -1}]
                assert self.headers['Accept'] == 'application/vnd.wwe2k22.lobby-ids'
                assert self.headers['S'] == '111'
                payload = b'W2L1' + struct.pack('<IQQ', 2, 109212290963898369, 109212290963898370)
                mime = 'application/vnd.wwe2k22.lobby-ids'
                if code == 102: payload = b'W2L1' + bytes(4)
                if code == 103: payload = b'BAD!' + payload[4:]
                if code == 104: payload = b'W2L1' + struct.pack('<IQ', 1, 1)
                if code == 105: payload = b'W2L1' + struct.pack('<IQQ', 2, 109212290963898369, 109212290963898369)
                if code == 106: payload = b'W2L1' + struct.pack('<I', 11) + bytes(88)
                if code == 107: payload = payload[:-1]
                if code == 110: payload += bytes(500)
                if code == 111: mime = 'application/json'
                if code == 112: time.sleep(0.4)
                status = 401 if code == 108 else 302 if code == 109 else 200
                self.send_response(status)
                if code == 109: self.send_header('Location', redirect_url)
                self.send_header('Content-Length', str(len(payload)))
                self.send_header('Content-Type', mime)
                self.end_headers()
                self.wfile.write(payload)
                return
            publication_case = json.loads(body).get('publication_case') if body and self.path.startswith('/lab/lobbies/') else None
            status = 200
            if publication_case == 'pending':
                first.set()
                if not release.wait(10):
                    raise RuntimeError('Pending publication was not released')
                status = 503
            elif publication_case == 'once':
                with lock:
                    attempts = sum(path == self.path and content == body for path, _, content in captures)
                status = 503 if attempts == 1 else 200
            elif publication_case == 'cap':
                status = 503
            elif publication_case == 'permanent':
                status = 400
            elif publication_case == 'redirect':
                self.send_response(307)
                self.send_header('Location', redirect_url)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            self.send_response(status)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'{}')
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    redirected = []

    class Receiver(BaseHTTPRequestHandler):

        def log_message(self, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            self.do_GET()

        def do_GET(self):
            redirected.append(True)
            self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()
    receiver = ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
    threading.Thread(target=receiver.serve_forever, daemon=True).start()
    redirect_url = f'http://127.0.0.1:{receiver.server_port}/must-not-receive-credentials'
    report = []
    baseline = '[Server]\nEnabled=1\nHost=127.0.0.1\nHttpPort=' + str(server.server_port) + '\nHTTPS=0\nAccessKeyFile=fixture.key\nCustomContent=1\nPublicLobbies=1\nThreadCleanupGuard=1\n'
    key = 'd' * 64
    (out / 'fixture.key').write_text(key, encoding='ascii')

    def case(name, mode='http', settings=None, code=0, url=None):
        first.clear()
        release.clear()
        (out / 'wwe2k22-private.ini').write_text(settings or baseline, encoding='ascii')
        with lock:
            captures.clear()
        result = subprocess.run([str(host), url or f'http://127.0.0.1:{server.server_port}/', mode], cwd=out, capture_output=True, timeout=25)
        if result.returncode != code:
            raise AssertionError(f'{name}: exit {result.returncode}; stdout={result.stdout!r}; stderr={result.stderr!r}')
        log = (out / 'wwe2k22-private.log').read_text() if (out / 'wwe2k22-private.log').exists() else ''
        assert key not in log
        with lock:
            record = list(captures)
        if code == 0:
            for _, headers, _ in record:
                assert headers.get_all('X-WWE-Lab-Key') == [key]
        report.append({'name': name, 'passed': True})
        return record
    try:
        case('native-bootstrap-redirect-and-authentication')
        case('closing-one-handle-tree-keeps-independent-requests-working', 'children')
        case('handle-reuse-generation-and-tracking-capacity', 'generation')
        case('concurrent-handles-remain-independent', 'concurrent')
        record = case('reused-asset-clears-only-client-owned-stale-session', 'retry')
        tokens = [h.get_all('X-Sessionid') for path, h, _ in record if path.endswith('.bin')]
        assert tokens == [['a' * 48], None, ['b' * 48]], tokens
        record = case('asset-inline-session-does-not-duplicate-injected-header', 'asset-inline')
        assert [h.get_all('X-Sessionid') for path, h, _ in record if path.endswith('.bin')] == [['b' * 48]]
        record = case('unreadable-session-commit-state-is-not-accepted', 'commit')
        assert [h.get('S') for path, h, _ in record if path.startswith('/lab/lobbies/')] == ['111']
        case('automatic-redirect-cannot-forward-private-authentication', 'redirect')
        assert not redirected
        case('startup-failure-stops-idle-worker-and-staged-hooks', 'startup-fail', code=20)
        case('failed-activation-stays-inert-and-keeps-live-trampolines', 'activation-fail', code=20)
        case('unrelated-destination-is-not-redirected-or-contacted', 'unrelated')
        record = case('cdn-gateway-preserves-eleven-arguments-and-learns-host', 'cdn')
        asset = [h for path, h, _ in record if path.endswith('.bin')]
        assert len(asset) == 2 and asset[0].get('X-Sessionid') == 'a' * 48 and (asset[1].get('X-Sessionid') is None)
        assert next((h for path, h, _ in record if path == '/not-asset')).get('X-Sessionid') is None
        report.append({'name': 'cdn-session-forwarding-path-scope-and-ambiguous-header-reset', 'passed': True})
        record = case('steam-owner-abi-publication-joinable-and-private-transitions', 'steam')
        actions = [p.rsplit('/', 1)[-1] for p, _, _ in record if p.startswith('/lab/lobbies/')]
        assert actions == ['publish', 'withdraw', 'publish', 'withdraw', 'publish', 'withdraw'], actions
        for path, headers, body in record:
            if path.startswith('/lab/lobbies/'):
                assert headers['S'] == '111'
                obj = json.loads(body)
                if path.endswith('/publish'):
                    assert obj['visibility'] == 'public' and obj['member_count'] == 1 and (obj['member_limit'] == 2)
        record = case('replacement-steam-context-reuses-safe-existing-hooks', 'steam-rebind')
        assert [p.rsplit('/', 1)[-1] for p, _, _ in record if p.startswith('/lab/lobbies/')] == ['publish', 'withdraw'] * 4
        record = case('unknown-steam-interface-withdraws-instead-of-calling-stale-object', 'steam-unexpected')
        assert [p.rsplit('/', 1)[-1] for p, _, _ in record if p.startswith('/lab/lobbies/')] == ['publish', 'withdraw'] * 3
        case('cdn-gateway-preserves-floating-registers-and-return', 'cdn-floats')
        record = case('bounded-strings-invalid-pointers-and-explicit-header-length', 'edges')
        asset = [h for path, h, _ in record if path.endswith('.bin')]
        assert [h.get('X-Sessionid') for h in asset] == ['c' * 48, 'c' * 48, None]
        record = case('bounded-worker-queue-and-session-rotation-drop-stale-jobs', 'queue')
        jobs = [(h.get('S'), json.loads(b)) for path, h, b in record if path.startswith('/lab/lobbies/')]
        assert jobs == [('111', {'block': True}), ('222', {'after': True})]
        for mode, count in [('once', 2), ('permanent', 1), ('cap', 3), ('redirect', 1)]:
            record = case('publication-' + mode + '-bounded-retry-policy', 'publication-' + mode)
            jobs = [item for item in record if item[0].startswith('/lab/lobbies/')]
            assert len(jobs) == count, (mode, len(jobs))
        for mode in ('pending', 'rotate'):
            record = case('publication-' + mode + '-cancels-obsolete-retry', 'publication-' + mode)
            jobs = [(path.rsplit('/', 1)[-1], headers.get('S'), json.loads(body))
                    for path, headers, body in record if path.startswith('/lab/lobbies/')]
            expected = [('publish', '111', {'publication_case': 'pending'}),
                        ('publish' if mode == 'rotate' else 'withdraw',
                         '222' if mode == 'rotate' else '111', {'newer': True})]
            assert jobs == expected, (mode, jobs)
        assert not redirected
        for code, label in [(101,'real-ids-and-native-candidate-layout'), (102,'empty-list'),
                (103,'unknown-protocol'), (104,'invalid-steam-id'), (105,'duplicate-id'),
                (106,'result-count-over-limit'), (107,'truncated-response'), (108,'expired-session'),
                (109,'redirect-refused'), (110,'oversized-response'), (111,'wrong-content-type'),
                (112,'rotated-session'), (113,'missing-session'), (114,'excess-filters'),
                (115,'unreadable-filter-pointer'), (116,'other-task-remains-native'),
                (117,'inactive-hook-remains-native')]:
            record = case('native-lobby-search-' + label, 'query-' + str(code))
            queries = [r for r in record if r[0] == '/lab/lobbies/list']
            assert len(queries) == (0 if code >= 113 else 1), (code, len(queries))
        assert not redirected
        case('cleanup-guard-skips-only-absent-system-and-context', 'guard')
        crash = out / 'wwe2k22-native-crash.log'
        crash.unlink(missing_ok=True)
        case('exception-observer-records-and-preserves-native-exception-handling', 'exception')
        events = [json.loads(line) for line in crash.read_text().splitlines()]
        assert len(events) == 16
        assert events[-1]['event'] == 'native-exception' and events[-1]['code'] == 3221225501
        for name, old, new in [('zero-port', 'HttpPort=' + str(server.server_port), 'HttpPort=0'), ('invalid-ip', 'Host=127.0.0.1', 'Host=999.1.2.3'), ('url-host', 'Host=127.0.0.1', 'Host=http://127.0.0.1'), ('missing-key', 'AccessKeyFile=fixture.key', 'AccessKeyFile=absent.key'), ('invalid-bool', 'HTTPS=0', 'HTTPS=2')]:
            case(name + '-rejected', settings=baseline.replace(old, new), code=20)
        case('drive-relative-key-path-is-rejected', settings=baseline.replace('fixture.key', out.drive + 'fixture.key'), code=20)
        for label, path in [('unc-key', r'\\127.0.0.1\share\fixture.key'),
                            ('device-key', r'\\.\pipe\wwe-test'), ('directory-key', '.')]:
            case(label + '-rejected', settings=baseline.replace('fixture.key', path), code=20)
        openssl = args.openssl
        if not openssl.is_file():
            raise RuntimeError('OpenSSL is required for the local TLS negative test')
        cert = out / 'fixture-cert.pem'
        private = out / 'fixture-private.pem'
        subprocess.run([str(openssl), 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(private), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'], check=True, capture_output=True)
        tls = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, private)
        tls.socket = context.wrap_socket(tls.socket, server_side=True)
        threading.Thread(target=tls.serve_forever, daemon=True).start()
        try:
            case('https-default-rejects-untrusted-certificate', 'tls-default', settings=baseline.replace('HTTPS=0', 'HTTPS=1').replace('HttpPort=' + str(server.server_port), 'HttpPort=' + str(tls.server_port)), url=f'https://127.0.0.1:{tls.server_port}/')
            case('https-rejects-untrusted-certificate-and-clears-insecure-flags', 'tls', settings=baseline.replace('HTTPS=0', 'HTTPS=1').replace('HttpPort=' + str(server.server_port), 'HttpPort=' + str(tls.server_port)), url=f'https://127.0.0.1:{tls.server_port}/')
        finally:
            tls.shutdown()
            tls.server_close()
            private.unlink()
            cert.unlink()
        original = host.read_bytes()
        try:
            host.write_bytes(original + b'fixture-tampered')
            case('wrong-executable-digest-rejected', code=20)
        finally:
            host.write_bytes(original)
        case('explicit-disable-passes-through-without-redirect', settings=baseline.replace('Enabled=1', 'Enabled=0'), code=22)
        (out / 'report.json').write_text(json.dumps({'game_started': False, 'steam_started': False, 'cases': report}, indent=2) + '\n')
        print(json.dumps({'passed': len(report), 'game_started': False, 'report': str(out / 'report.json')}))
    finally:
        server.shutdown()
        server.server_close()
        receiver.shutdown()
        receiver.server_close()
if __name__ == '__main__':
    main()
