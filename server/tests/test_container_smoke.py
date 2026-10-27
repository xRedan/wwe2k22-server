"""Regression checks for the Docker probe; no daemon or real credentials."""
import contextlib
import io
import json
import unittest
import urllib.error
from unittest import mock

import container_smoke


class ContainerSmokeTests(unittest.TestCase):
    def simulate(self, change_port, change_key=False):
        state = {'restarted': False, 'ports_checked_after_restart': False}
        key = '12' * 32

        def docker(*args):
            if args[0] == 'inspect':
                if state['restarted']:
                    state['ports_checked_after_restart'] = True
                port = '32002' if change_port and state['restarted'] else '32001'
                return json.dumps([{
                    'Config': {'User': '10001:10001'},
                    'HostConfig': {'ReadonlyRootfs': True},
                    'NetworkSettings': {'Ports': {
                        '8787/tcp': [{'HostIp': '127.0.0.1', 'HostPort': port}],
                        '8788/udp': [{'HostIp': '127.0.0.1', 'HostPort': '32003'}],
                    }},
                }])
            if args[0] == 'exec':
                return '34' * 32 if change_key and state['restarted'] else key
            if args[0] == 'restart':
                state['restarted'] = True
                return args[1]
            if args[0] in ('run', 'volume'):
                return 'owned-fixture'
            raise AssertionError('Unexpected Docker operation')

        def urlopen(request, timeout):
            port = '32002' if change_port and state['restarted'] else '32001'
            if not request.full_url.startswith('http://127.0.0.1:' + port + '/'):
                raise urllib.error.URLError('stale published port')
            if request.get_header('X-wwe-lab-key') != key:
                raise urllib.error.HTTPError(request.full_url, 401, 'key required', {}, None)
            payload = {'durable_metadata': True, 'capabilities': {'native_image_sync': True}} if request.full_url.endswith('/status') else {
                'implementation': 'go', 'matchmaking': True, 'access_key_required': True, 'udp_port': 8788,
            }
            return io.BytesIO(json.dumps(payload).encode())

        with mock.patch.object(container_smoke, 'docker', side_effect=docker), \
             mock.patch.object(container_smoke.urllib.request, 'urlopen', side_effect=urlopen), \
             mock.patch.object(container_smoke.time, 'sleep'), \
             mock.patch.object(container_smoke.subprocess, 'run') as cleanup, \
             contextlib.redirect_stdout(io.StringIO()):
            try:
                container_smoke.main('owned-fixture:local')
            finally:
                self.assertEqual(cleanup.call_count, 2)
        return state

    def test_new_ephemeral_port_after_restart(self):
        self.assertTrue(self.simulate(True)['ports_checked_after_restart'])

    def test_unchanged_port_after_restart(self):
        self.simulate(False)

    def test_changed_key_still_fails(self):
        with self.assertRaises(AssertionError):
            self.simulate(True, change_key=True)


if __name__ == '__main__':
    unittest.main()
