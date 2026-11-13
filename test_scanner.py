import contextlib
import errno
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import scanner


class ScannerTests(unittest.TestCase):
    def test_port_ranges_and_validation(self):
        self.assertEqual(scanner.parse_ports('443,22,80-82,22'), [22, 80, 81, 82, 443])
        for invalid in ('0', '65536', '90-80', '22,', 'a', '1-2-3'):
            with self.subTest(invalid=invalid), self.assertRaises(scanner.argparse.ArgumentTypeError):
                scanner.parse_ports(invalid)

    def test_live_loopback_open_and_closed(self):
        with socket.socket() as listener, socket.socket() as reserved:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            reserved.bind(('127.0.0.1', 0))
            open_port = listener.getsockname()[1]
            closed_port = reserved.getsockname()[1]
            report = scanner.scan('127.0.0.1', [open_port, closed_port], timeout=5)
        states = {row['port']: row['state'] for row in report['ports']}
        self.assertEqual(states[open_port], 'open')
        self.assertEqual(states[closed_port], 'closed')

    def test_timeout_and_failures_are_not_closed(self):
        for error, expected in [(TimeoutError(), 'filtered'),
                                (OSError(errno.ENETUNREACH, 'network'), 'unreachable'),
                                (PermissionError(errno.EACCES, 'denied'), 'error')]:
            with self.subTest(expected=expected), patch('scanner.socket.socket') as connection:
                connection.return_value.__enter__.return_value.connect.side_effect = error
                result = scanner.probe(socket.AF_INET, ('127.0.0.1', 0), 80, 1)
                self.assertEqual(result['state'], expected)

    def test_invalid_limits_before_network(self):
        for timeout, workers in [(0, 1), (float('nan'), 1), (float('inf'), 1), (1, 0), (1, 257)]:
            with self.subTest(timeout=timeout, workers=workers), self.assertRaises(ValueError):
                scanner.scan('localhost', [80], timeout, workers)

    def test_ipv6_endpoint(self):
        with patch('scanner.socket.socket') as connection:
            result = scanner.probe(socket.AF_INET6, ('::1', 0, 0, 0), 443, 1)
            connection.return_value.__enter__.return_value.connect.assert_called_once_with(('::1', 443, 0, 0))
            self.assertEqual(result['state'], 'open')

    def test_json_export_and_refuse_overwrite(self):
        report = {'target': 'localhost', 'ports': [{'port': 80, 'state': 'closed'}]}
        with tempfile.TemporaryDirectory() as directory, patch('scanner.scan', return_value=report):
            path = Path(directory) / 'scan.json'
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(scanner.main(['localhost', '--json', '--open-only', '-o', str(path)]), 0)
            self.assertEqual(json.loads(output.getvalue()), report)
            self.assertEqual(json.loads(path.read_text()), report)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                scanner.main(['localhost', '-o', str(path)])
            self.assertEqual(json.loads(path.read_text()), report)

    def test_no_cloud_call_without_ai_and_fallback(self):
        report = {'target': 'localhost', 'ports': []}
        with patch('scanner.scan', return_value=report), patch('scanner.ai_summary', side_effect=RuntimeError()) as ai:
            with contextlib.redirect_stdout(io.StringIO()):
                scanner.main(['localhost', '--json'])
            ai.assert_not_called()
            with patch.dict('os.environ', {'GEMINI_API_KEY': 'test'}), contextlib.redirect_stdout(io.StringIO()) as output:
                scanner.main(['localhost', '--json', '--ai'])
            self.assertIn('ai_error', json.loads(output.getvalue()))

    def test_module_command_without_site_packages(self):
        result = subprocess.run([sys.executable, '-S', '-m', 'sentinel', 'scan', '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--ports', result.stdout)


if __name__ == '__main__':
    unittest.main()
