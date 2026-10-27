"""CI smoke check of an owned Linux container; no real game or user data."""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True, timeout=60).strip()


def main(image):
    name = 'wwe2k22-check-' + uuid.uuid4().hex
    volume = name + '-state'
    try:
        docker('volume', 'create', volume)
        docker('run', '--detach', '--name', name, '--read-only', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges:true', '--pids-limit', '128',
               '--memory', '512m', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=272m',
               '--mount', 'type=volume,src=' + volume + ',dst=/data',
               '--publish', '127.0.0.1::8787/tcp', '--publish', '127.0.0.1::8788/udp',
               '--env', 'WWE_BIND_HOST=0.0.0.0', '--env', 'WWE_ADVERTISE_HOST=127.0.0.1',
               '--env', 'WWE_ALLOWED_NETWORKS=127.0.0.0/8,172.16.0.0/12,10.0.0.0/8,192.168.0.0/16',
               '--env', 'WWE_ACCESS_KEY_FILE=/data/access.key',
               '--env', 'WWE_GENERATE_ACCESS_KEY=true', image)
        inspected = json.loads(docker('inspect', name))[0]
        assert inspected['Config']['User'] == '10001:10001'
        assert inspected['HostConfig']['ReadonlyRootfs']
        assert inspected['NetworkSettings']['Ports']['8788/udp']
        port = inspected['NetworkSettings']['Ports']['8787/tcp'][0]['HostPort']
        url = 'http://127.0.0.1:' + port
        # This operator-only command does not start listeners or open databases.
        key = docker('exec', name, '/wwe2k22-server', '--print-access-key')
        assert len(key) == 64 and all(c in '0123456789abcdef' for c in key)

        def get(path, authenticate=True):
            headers = {'X-WWE-Lab-Key': key} if authenticate else {}
            with urllib.request.urlopen(urllib.request.Request(url + path, headers=headers), timeout=3) as response:
                return json.load(response)

        for attempt in range(40):
            try:
                health = get('/health')
                break
            except (OSError, urllib.error.URLError):
                if attempt == 39:
                    raise
                time.sleep(0.25)
        assert health['implementation'] == 'go' and health['matchmaking']
        assert health['access_key_required'] and health['udp_port'] == 8788
        status = get('/status')
        assert status['durable_metadata'] and status['capabilities']['native_image_sync']
        try:
            get('/health', False)
            raise AssertionError('unauthenticated request accepted')
        except urllib.error.HTTPError as error:
            assert error.code == 401
        docker('restart', name)
        # Docker may allocate a different host port for an ephemeral mapping.
        # Probe the current mapping rather than retaining the pre-restart URL.
        inspected = json.loads(docker('inspect', name))[0]
        port = inspected['NetworkSettings']['Ports']['8787/tcp'][0]['HostPort']
        url = 'http://127.0.0.1:' + port
        assert docker('exec', name, '/wwe2k22-server', '--print-access-key') == key
        for attempt in range(40):
            try:
                get('/health')
                break
            except (OSError, urllib.error.URLError):
                if attempt == 39:
                    raise
                time.sleep(0.25)
        print('Container smoke passed: non-root, read-only, TCP/UDP mappings, authentication, persistent key/state, restart.')
    finally:
        # Only the randomly named resources created by this invocation are removed.
        subprocess.run(['docker', 'rm', '--force', name], check=False, capture_output=True, timeout=60)
        subprocess.run(['docker', 'volume', 'rm', volume], check=False, capture_output=True, timeout=60)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: container_smoke.py IMAGE')
    main(sys.argv[1])
