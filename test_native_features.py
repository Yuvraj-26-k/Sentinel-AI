import contextlib
import io
import json
import socket
import threading
import unittest
from unittest.mock import MagicMock, patch

import scanner


class NativeFeaturesTests(unittest.TestCase):
    def test_timeout_retry_then_success(self):
        replies = [{'port': 80, 'state': 'filtered'}, {'port': 80, 'state': 'open'}]
        with patch('scanner.resolve_target', return_value=(socket.AF_INET, ('127.0.0.1', 0))), patch('scanner.probe', side_effect=replies) as probe:
            report = scanner.scan('localhost', [80], retries=1)
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(report['ports'][0]['attempts'], 2)
        self.assertEqual(report['counts'], {'open': 1})

    def test_closed_is_not_retried_and_inspection_never_changes_state(self):
        replies = [{'port': 22, 'state': 'open'}, {'port': 80, 'state': 'closed'}]
        with patch('scanner.resolve_target', return_value=(socket.AF_INET, ('127.0.0.1', 0))), patch('scanner.probe', side_effect=replies) as probe, patch('scanner.inspect_service', return_value={'inspection_note': 'timeout'}):
            report = scanner.scan('localhost', [22, 80], workers=1, services=True)
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(report['counts'], {'open': 1, 'closed': 1})
        self.assertEqual(report['ports'][0]['service_evidence']['inspection_note'], 'timeout')

    def test_os_clues_are_evidence_bound(self):
        self.assertEqual(scanner.os_clues([{'port': 22}])['status'], 'unknown')
        result = scanner.os_clues([{'port': 22, 'service_evidence': {'banner': 'SSH-2.0-OpenSSH Ubuntu'}}])
        self.assertEqual(result['status'], 'unverified clues')
        self.assertEqual(result['clues'][0]['possible_family'], 'Linux')
        self.assertEqual(result['clues'][0]['confidence'], 'low')

    def test_http_probe_collects_headers_without_following_redirects(self):
        with patch('scanner.socket.socket') as factory:
            stream = factory.return_value.__enter__.return_value
            stream.recv.return_value = b'HTTP/1.0 302 Found\r\nServer: Example\r\nLocation: http://elsewhere\r\n\r\n'
            evidence = scanner.inspect_service(socket.AF_INET, ('127.0.0.1', 0), 80, 'localhost', 1)
            stream.connect.assert_called_once_with(('127.0.0.1', 80))
            self.assertTrue(stream.sendall.call_args.args[0].startswith(b'HEAD / HTTP/1.0'))
            self.assertEqual(evidence['protocol_observed'], 'http')
            self.assertEqual(evidence['server_header'], 'Example')
            stream.recv.assert_called_once_with(4096)

    def test_tls_evidence_does_not_claim_certificate_trust(self):
        with patch('scanner.socket.socket'), patch('scanner.ssl.SSLContext') as context:
            tls = context.return_value.wrap_socket.return_value
            tls.version.return_value = 'TLSv1.3'
            tls.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
            tls.recv.return_value = b'HTTP/1.1 200 OK\r\nServer: Example\r\n\r\n'
            result = scanner.inspect_service(socket.AF_INET, ('127.0.0.1', 0), 443, 'localhost', 1)
            self.assertEqual(result['tls']['version'], 'TLSv1.3')
            self.assertEqual(result['tls']['certificate_validation'], 'not performed')
            tls.close.assert_called_once()

    def test_live_ssh_banner_from_local_listener(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            listener.settimeout(5)
            port = listener.getsockname()[1]
            def serve():
                connection, _ = listener.accept()
                with connection:
                    connection.sendall(b'SSH-2.0-Example Ubuntu\r\n')
            server = threading.Thread(target=serve, daemon=True)
            server.start()
            evidence = scanner.inspect_service(socket.AF_INET, ('127.0.0.1', 0), port, 'localhost', 2)
            server.join(timeout=5)
            self.assertEqual(evidence['protocol_observed'], 'ssh')
            self.assertIn('Ubuntu', evidence['banner'])

    def test_ai_payload_is_bounded_and_text_separated_from_instructions(self):
        report = {'target': 'localhost', 'counts': {'open': 201, 'closed': 50000},
                  'ports': [{'port': p, 'state': 'open'} for p in range(1, 202)] + [{'port': 300, 'state': 'closed'}]}
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({'candidates': [{'content': {'parts': [{'text': 'Review port 22.'}]}}]}).encode()
        with patch.dict('os.environ', {'GEMINI_API_KEY': 'fake-test-key'}), patch('scanner.urllib.request.urlopen', return_value=response) as request:
            self.assertEqual(scanner.ai_summary(report), 'Review port 22.')
        payload = json.loads(request.call_args.args[0].data)
        self.assertIn('untrusted data', payload['systemInstruction']['parts'][0]['text'])
        data = json.loads(payload['contents'][0]['parts'][0]['text'])
        self.assertEqual(len(data['open_ports']), 200)
        self.assertEqual(data['omitted_open_ports'], 1)
        self.assertEqual(data['counts']['closed'], 50000)
        self.assertNotIn('fake-test-key', request.call_args.args[0].full_url)

    def test_empty_ai_response_fails_to_local_fallback(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"candidates":[{"content":{"parts":[{"text":""}]}}]}'
        with patch.dict('os.environ', {'GEMINI_API_KEY': 'fake'}), patch('scanner.urllib.request.urlopen', return_value=response):
            with self.assertRaisesRegex(ValueError, 'no summary'):
                scanner.ai_summary({'ports': []})

    def test_no_nmap_backend_option_and_invalid_retries(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            scanner.main(['localhost', '--engine', 'nmap'])
        for retries in (-1, 4):
            with self.assertRaises(ValueError):
                scanner.scan('localhost', [80], retries=retries)

    def test_terminal_control_bytes_removed(self):
        self.assertNotIn('\x1b', scanner.display_text('SSH-2.0-Example\x1b[2J'))


if __name__ == '__main__':
    unittest.main()
