"""Exercise bounded startup waits without spawning a server or sleeping."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import run_server_integration as integration


class ServerStartupTests(unittest.TestCase):
    def run_wait(self, text='', exit_code=None, announce_after=None, timeout=10, redactions=()):
        with tempfile.TemporaryDirectory(prefix='owned-startup-unit-') as directory:
            log = Path(directory)/'server.log'
            log.write_text(text, encoding='utf-8')
            clock = [0.0]
            def sleep(seconds):
                clock[0] += seconds
                if announce_after is not None and clock[0] >= announce_after:
                    log.write_text('WWE 2K22 Go server: http://127.0.0.1:17001\n', encoding='utf-8')
            child = SimpleNamespace(poll=lambda: exit_code)
            with patch.object(integration.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(integration.time, 'sleep', side_effect=sleep):
                return integration.wait_for_server_port(child, log, timeout, redactions)

    def test_slow_start_after_the_previous_six_second_limit(self):
        self.assertEqual(self.run_wait(announce_after=7), 17001)

    def test_already_announced(self):
        self.assertEqual(self.run_wait(text='WWE 2K22 Go server: http://127.0.0.1:8787\n'), 8787)

    def test_exit_reports_diagnostics_and_redacts_keys(self):
        key = 'a'*64
        with self.assertRaises(RuntimeError) as result:
            self.run_wait(text='startup failed '+key+' sample-secret', exit_code=7, redactions=('sample-secret',))
        message = str(result.exception)
        self.assertIn('code 7', message)
        self.assertIn('startup failed', message)
        self.assertNotIn(key, message)
        self.assertNotIn('sample-secret', message)

    def test_timeout_is_bounded_and_has_diagnostics(self):
        with self.assertRaises(TimeoutError) as result:
            self.run_wait(text='startup pending', timeout=.12)
        self.assertIn('startup pending', str(result.exception))

    def test_invalid_port_is_not_readiness(self):
        with self.assertRaises(TimeoutError):
            self.run_wait(text='WWE 2K22 Go server: http://127.0.0.1:0\n', timeout=.12)


if __name__ == '__main__':
    unittest.main()
