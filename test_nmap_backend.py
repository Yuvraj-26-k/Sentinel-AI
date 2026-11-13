import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import nmap_backend as backend
import scanner

XML = '''<nmaprun version="7.95"><scaninfo type="syn" protocol="tcp" services="22,80"/>
<host><status state="up" reason="syn-ack"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><extraports state="closed" count="998"><extrareasons reason="resets" count="998"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="9.0" method="probed"><cpe>cpe:/a:test</cpe></service>
<script id="ssh-hostkey" output="keys"><table key="test"><elem key="bits">256</elem></table></script></port>
<port protocol="udp" portid="53"><state state="open|filtered" reason="no-response"/></port></ports>
<os><osmatch name="Linux" accuracy="96"><osclass osfamily="Linux" accuracy="96"/></osmatch></os>
<hostscript><script id="example" output="host result"/></hostscript>
<trace><hop ttl="1" ipaddr="127.0.0.1" rtt="0.1"/></trace></host>
<host><status state="down"/><address addr="::1" addrtype="ipv6"/></host>
<runstats><finished exit="success"/><hosts up="1" down="1" total="2"/></runstats></nmaprun>'''


class NmapTests(unittest.TestCase):
    def test_xml_keeps_estimates_states_nested_scripts_and_grouped_ports(self):
        report = backend.parse_report(XML)
        self.assertEqual(len(report['hosts']), 2)
        host = report['hosts'][0]
        self.assertEqual(host['os_matches'][0]['accuracy'], '96')
        self.assertEqual(host['ports'][0]['service']['version'], '9.0')
        self.assertEqual(host['ports'][1]['state'], 'open|filtered')
        self.assertEqual(host['extra_ports'][0]['attributes']['count'], '998')
        self.assertEqual(host['ports'][0]['scripts'][0]['children'][0]['children'][0]['text'], '256')
        self.assertEqual(host['host_scripts'][0]['attributes']['output'], 'host result')
        self.assertEqual(host['trace'][0]['ttl'], '1')
        self.assertEqual(report['raw_xml'], XML)

    def test_command_is_argument_list_and_report_parses(self):
        completed = subprocess.CompletedProcess([], 0, XML, 'warning')
        with patch('nmap_backend.subprocess.run', return_value=completed) as run:
            report = backend.run_scan('nmap', ['-O', '-sV', '127.0.0.1'])
        self.assertEqual(run.call_args.args[0], ['nmap', '-O', '-sV', '127.0.0.1', '-oX', '-'])
        self.assertFalse(run.call_args.kwargs['shell'])
        self.assertEqual(report['warnings'], 'warning')

    def test_native_passes_all_flags_and_exit_status(self):
        with patch('nmap_backend.find_nmap', return_value='nmap'), patch('nmap_backend.subprocess.call', return_value=3) as call:
            self.assertEqual(backend.main(['--native', '--', '-A', '-oN', 'report.txt', '127.0.0.1']), 3)
            self.assertEqual(call.call_args.args[0], ['nmap', '-A', '-oN', 'report.txt', '127.0.0.1'])
            self.assertFalse(call.call_args.kwargs['shell'])

    def test_nmap_failure_and_invalid_xml(self):
        with patch('nmap_backend.subprocess.run', return_value=subprocess.CompletedProcess([], 1, '', 'requires root')):
            with self.assertRaisesRegex(ValueError, 'requires root'):
                backend.run_scan('nmap', ['-O', '127.0.0.1'])
        for xml in ('bad XML', '<other/>'):
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                backend.parse_report(xml)

    def test_no_output_conflicts_or_silent_native_option_loss(self):
        for option in ('-oX', '-oAfoo', '--resume', '--append-output'):
            with self.subTest(option=option), self.assertRaises(ValueError):
                backend.run_scan('nmap', [option])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            backend.main(['--native', '--json', '--', '127.0.0.1'])

    def test_structured_flags_extra_args_and_json_output(self):
        report = backend.parse_report(XML)
        report['warnings'] = ''
        with tempfile.TemporaryDirectory() as folder, patch('nmap_backend.find_nmap', return_value='nmap'), patch('nmap_backend.run_scan', return_value=report) as run:
            path = Path(folder) / 'report.json'
            with contextlib.redirect_stdout(io.StringIO()) as output:
                backend.main(['127.0.0.1', '-O', '-sV', '-sU', '-p', '53', '--json', '-o', str(path), '--', '--version-light'])
            self.assertEqual(json.loads(output.getvalue()), report)
            self.assertEqual(json.loads(path.read_text()), report)
            self.assertEqual(run.call_args.args[1], ['-O', '-sV', '-sU', '-p', '53', '--version-light', '127.0.0.1'])
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                backend.main(['127.0.0.1', '-o', str(path)])

    def test_missing_nmap_actionable_message(self):
        with patch('nmap_backend.shutil.which', return_value=None), self.assertRaisesRegex(ValueError, 'Install it'):
            backend.find_nmap()

    def test_dependency_free_entry_and_engine_dispatch(self):
        result = subprocess.run([sys.executable, '-S', '-m', 'sentinel', 'nmap', '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--os', result.stdout)
        with patch('nmap_backend.main', return_value=0) as main:
            self.assertEqual(scanner.main(['--engine', 'nmap', '127.0.0.1', '-O']), 0)
            main.assert_called_once_with(['127.0.0.1', '-O'])
        with patch('nmap_backend.main', return_value=0) as main:
            self.assertEqual(scanner.main(['--engine=nmap', '127.0.0.1', '-O']), 0)
            main.assert_called_once_with(['127.0.0.1', '-O'])


if __name__ == '__main__':
    unittest.main()
