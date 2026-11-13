"""Nmap-backed scanning with structured reports and lossless native mode."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET


def xml_node(element):
    """Keep nested NSE results and future XML fields without flattening them."""
    return {'tag': element.tag, 'attributes': dict(element.attrib),
            'text': element.text or '', 'children': [xml_node(child) for child in element]}


def parse_report(xml):
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as error:
        raise ValueError('Nmap returned invalid XML') from error
    if root.tag != 'nmaprun':
        raise ValueError('Expected an Nmap XML report')
    report = {'engine': 'nmap', 'version': root.get('version'), 'hosts': [],
              'scan_info': [dict(item.attrib) for item in root.findall('scaninfo')],
              'run_stats': xml_node(root.find('runstats')) if root.find('runstats') is not None else None,
              'raw_xml': xml}
    for host in root.findall('host'):
        status = host.find('status')
        item = {'status': dict(status.attrib) if status is not None else {},
                'addresses': [dict(a.attrib) for a in host.findall('address')],
                'hostnames': [dict(a.attrib) for a in host.findall('hostnames/hostname')],
                'ports': [], 'os_matches': [],
                'extra_ports': [xml_node(a) for a in host.findall('ports/extraports')],
                'host_scripts': [xml_node(a) for a in host.findall('hostscript/script')],
                'trace': [dict(a.attrib) for a in host.findall('trace/hop')]}
        for port in host.findall('ports/port'):
            state, service = port.find('state'), port.find('service')
            item['ports'].append({
                'port': int(port.get('portid')), 'protocol': port.get('protocol'),
                'state': state.get('state', 'unknown') if state is not None else 'unknown',
                'reason': state.get('reason', '') if state is not None else '',
                'service': dict(service.attrib) if service is not None else {},
                'cpe': [a.text for a in port.findall('service/cpe')],
                'scripts': [xml_node(a) for a in port.findall('script')]})
        for match in host.findall('os/osmatch'):
            item['os_matches'].append({**dict(match.attrib),
                                      'classes': [xml_node(a) for a in match.findall('osclass')]})
        # Older Nmap versions also place osclass directly beneath os.
        item['os_classes'] = [xml_node(a) for a in host.findall('os/osclass')]
        report['hosts'].append(item)
    return report


def find_nmap(executable=None):
    candidate = executable or os.environ.get('NMAP_PATH') or 'nmap'
    found = shutil.which(candidate)
    if not found:
        raise ValueError('Nmap is not installed or not on PATH. Install it from https://nmap.org/download.html '
                         '(Windows: include Npcap), or set NMAP_PATH to the executable.')
    return found


def run_scan(executable, arguments):
    # Output is owned by Sentinel; native mode supports every output option.
    if any(arg.startswith(('-oX', '-oA', '-oN', '-oG', '-oS')) or arg in {'--resume', '--append-output'}
           for arg in arguments):
        raise ValueError('Use --native for Nmap output/resume options; structured mode owns XML output.')
    result = subprocess.run([executable, *arguments, '-oX', '-'], capture_output=True,
                            text=True, encoding='utf-8', errors='replace', shell=False)
    if result.returncode:
        raise ValueError(f'Nmap exited with code {result.returncode}: {result.stderr.strip()}')
    report = parse_report(result.stdout)
    report['warnings'] = result.stderr.strip()
    return report


def render(report, open_only=False):
    print(f"Sentinel / Nmap {report['version']}")
    for host in report['hosts']:
        names = ', '.join(a.get('addr', '') for a in host['addresses'])
        print(f"\nHost: {names} ({host['status'].get('state', 'unknown')})")
        for match in host['os_matches']:
            print(f"OS estimate: {match.get('name')} | Nmap accuracy: {match.get('accuracy', '?')}%")
        if not host['os_matches']:
            print('OS: no fingerprint match reported (use -O to request detection).')
        print('PORT         STATE            SERVICE / VERSION')
        for port in host['ports']:
            if open_only and port['state'] != 'open':
                continue
            service = port['service']
            label = ' '.join(service.get(k, '') for k in ('name', 'product', 'version', 'extrainfo')).strip()
            print(f"{str(port['port']) + '/' + port['protocol']:<12} {port['state']:<16} {label}")
            for script in port['scripts']:
                print(f"  NSE {script['attributes'].get('id')}: {script['attributes'].get('output', '')}")
        for extra in host['extra_ports']:
            attrs = extra['attributes']
            print(f"Grouped ports: {attrs.get('count')} {attrs.get('state')} (see JSON for reasons)")
        for script in host['host_scripts']:
            print(f"NSE {script['attributes'].get('id')}: {script['attributes'].get('output', '')}")
        for hop in host['trace']:
            print(f"Hop {hop.get('ttl')}: {hop.get('ipaddr', '*')} {hop.get('rtt', '?')} ms")
    if not report['hosts']:
        print('No hosts reported. Check discovery settings, routing, and permissions.')
    print('\nOS matches are estimates; service fingerprints and script output need verification.')
    if report['warnings']:
        print('Nmap warnings: ' + report['warnings'])
    if 'ai_explanation' in report:
        print('\nAI explanation (unverified):\n' + report['ai_explanation'])
    if 'ai_error' in report:
        print(report['ai_error'])


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    extra = []
    if '--' in argv:
        boundary = argv.index('--')
        argv, extra = argv[:boundary], argv[boundary+1:]
    parser = argparse.ArgumentParser(description='Nmap-powered Sentinel. Only scan authorized systems.',
                                     epilog='Pass additional Nmap arguments after --. Use --native -- ARGS for the full native interface.')
    parser.add_argument('targets', nargs='*', help='IP, hostname, CIDR or Nmap target range')
    parser.add_argument('--nmap-path', help='path to installed Nmap executable')
    parser.add_argument('--native', action='store_true', help='run all Nmap arguments directly; no JSON/AI processing')
    parser.add_argument('-p', '--ports', help='Nmap port expression, including T: and U: prefixes')
    parser.add_argument('-O', '--os', action='store_true', help='OS fingerprinting; may require privileges')
    parser.add_argument('-sV', '--service-version', action='store_true', help='probe service products and versions')
    parser.add_argument('-sS', '--syn', action='store_true', help='TCP SYN scan; requires raw-packet privileges')
    parser.add_argument('-sT', '--connect', action='store_true', help='TCP connect scan')
    parser.add_argument('-sU', '--udp', action='store_true', help='UDP scan; may be slow and require privileges')
    parser.add_argument('-sn', '--discover', action='store_true', help='host discovery without port scan')
    parser.add_argument('-Pn', '--skip-discovery', action='store_true', help='treat targets as online')
    parser.add_argument('-6', '--ipv6', action='store_true')
    parser.add_argument('--traceroute', action='store_true')
    parser.add_argument('--script', help='explicit NSE script names or categories; no scripts run by default')
    parser.add_argument('--top-ports', type=int)
    parser.add_argument('--timing', type=int, choices=range(6), help='Nmap timing template 0-5')
    parser.add_argument('--open-only', action='store_true', help='hide non-open table rows; keep full JSON')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('-o', '--output', help='create a JSON report without overwriting')
    parser.add_argument('--ai', action='store_true', help='send scan report to Gemini for an explanation')
    args = parser.parse_args(argv)
    if args.native:
        structured = (args.ports or args.os or args.service_version or args.syn or args.connect or args.udp or
                      args.discover or args.skip_discovery or args.ipv6 or args.traceroute or args.script or
                      args.top_ports is not None or args.timing is not None or args.open_only or args.json or args.output or args.ai)
        if structured:
            parser.error('--native accepts Nmap options after --; remove structured report options')
    elif not args.targets and not extra:
        parser.error('supply at least one target or Nmap arguments after --')
    if args.syn and args.connect:
        parser.error('choose -sS or -sT, not both')
    if args.top_ports is not None and not 1 <= args.top_ports <= 65535:
        parser.error('--top-ports must be 1-65535')
    if args.ai and not os.environ.get('GEMINI_API_KEY'):
        parser.error('--ai requires GEMINI_API_KEY')
    try:
        executable = find_nmap(args.nmap_path)
        if args.native:
            return subprocess.call([executable, *extra, *args.targets], shell=False)
        options = []
        for enabled, flag in ((args.os, '-O'), (args.service_version, '-sV'), (args.syn, '-sS'),
                              (args.connect, '-sT'), (args.udp, '-sU'), (args.discover, '-sn'),
                              (args.skip_discovery, '-Pn'), (args.ipv6, '-6'), (args.traceroute, '--traceroute')):
            if enabled:
                options.append(flag)
        for value, flag in ((args.ports, '-p'), (args.script, '--script'), (args.top_ports, '--top-ports')):
            if value is not None:
                options.extend([flag, str(value)])
        if args.timing is not None:
            options.append(f'-T{args.timing}')
        report = run_scan(executable, [*options, *extra, *args.targets])
        if args.ai:
            from scanner import ai_summary
            try:
                # Raw XML duplicates the structured data and can be very large.
                report['ai_explanation'] = ai_summary({k: v for k, v in report.items() if k != 'raw_xml'})
            except Exception:
                report['ai_error'] = 'AI explanation unavailable; Nmap results are intact.'
        encoded = json.dumps(report, indent=2)
        if args.output:
            with Path(args.output).expanduser().open('x', encoding='utf-8') as output:
                output.write(encoded + '\n')
        if args.json:
            print(encoded)
        else:
            render(report, args.open_only)
        return 0
    except (OSError, ValueError) as error:
        parser.exit(1, f'sentinel nmap: {error}\n')
    except KeyboardInterrupt:
        parser.exit(130, 'Nmap scan interrupted.\n')


if __name__ == '__main__':
    raise SystemExit(main())
