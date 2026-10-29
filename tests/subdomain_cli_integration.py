#!/usr/bin/env python3
"""Real CLI, c-ares and libcurl against loopback fixtures that never forward."""
import csv
import io
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


BINARY = str(Path(sys.argv.pop(1)).resolve())


def question(packet):
    position = 12
    labels = []
    while True:
        length = packet[position]
        position += 1
        if not length:
            break
        if length > 63:
            raise ValueError('fixture accepts uncompressed DNS questions only')
        labels.append(packet[position:position + length].decode('ascii'))
        position += length
    rtype, rclass = struct.unpack('!HH', packet[position:position + 4])
    if rclass != 1:
        raise ValueError('unexpected DNS class')
    return '.'.join(labels).lower(), rtype, position + 4


class LocalDNS:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.settimeout(0.05)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.held = threading.Event()
        self.requests = []
        self.errors = []
        self.wildcard = False
        self.worker = threading.Thread(target=self.serve, daemon=True)
        self.worker.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                name, rtype, end = question(packet)
                self.requests.append((name, rtype))
                if name == 'hold.example.test':
                    self.held.set()
                    continue
                rcode, address = 0, None
                if name == 'example.com' and rtype == 1:
                    address = '192.0.2.1'
                elif name.endswith('.invalid'):
                    rcode = 3
                elif self.wildcard and name.endswith('.example.test'):
                    if rtype == 1:
                        address = f'192.0.2.{40 + len(self.requests) % 6}'
                elif name.startswith('dnxwc-'):
                    rcode = 3
                elif name in ('dual.example.test', 'good.example.test'):
                    address = '192.0.2.20' if rtype == 1 else '2001:db8::20' if rtype == 28 else None
                elif name == 'v6.example.test':
                    address = '2001:db8::21' if rtype == 28 else None
                elif name == 'fail.example.test':
                    rcode = 2
                else:
                    rcode = 3
                record = b''
                if address is not None:
                    data = ipaddress.ip_address(address).packed
                    record = b'\xc0\x0c' + struct.pack('!HHIH', rtype, 1, 60, len(data)) + data
                header = packet[:2] + struct.pack('!HHHHH', 0x8180 | rcode, 1, bool(record), 0, 0)
                self.socket.sendto(header + packet[12:end] + record, peer)
            except Exception as error:
                self.errors.append(repr(error))

    def close(self):
        self.stop.set()
        self.worker.join(timeout=2)
        self.socket.close()


class BlockedProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.requests = []
        super().__init__(('127.0.0.1', 0), RejectRequest)
        self.worker = threading.Thread(target=self.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        self.worker.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.worker.join(timeout=2)


class RejectRequest(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        first = self.rfile.readline(8192)
        self.server.requests.append(first.decode('ascii', errors='replace').strip())
        self.wfile.write(b'HTTP/1.1 502 Fixture blocks upstream\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')


class SubdomainCLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='dark-nexus-subdomain-cli-')
        self.root = Path(self.temporary.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        if os.geteuid() == 0:
            account = pwd.getpwnam('nobody')
            os.chown(self.root, account.pw_uid, account.pw_gid)
            os.chown(self.home, account.pw_uid, account.pw_gid)
        self.dns = LocalDNS()
        self.proxy = BlockedProxy()
        self.environment = dict(os.environ, HOME=str(self.home), NO_COLOR='1', TERM='dumb')
        if os.geteuid() == 0:
            self.environment.update(SUDO_UID=str(account.pw_uid), SUDO_GID=str(account.pw_gid))
        proxy = f'http://127.0.0.1:{self.proxy.server_address[1]}'
        for name in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY'):
            self.environment[name] = proxy
        for name in ('no_proxy', 'NO_PROXY', 'VT_API_KEY', 'ST_API_KEY', 'SHODAN_API_KEY',
                     'CENSYS_API_ID', 'CENSYS_API_SECRET'):
            self.environment.pop(name, None)
        (self.root / 'resolvers.txt').write_text(f'127.0.0.1:{self.dns.port}\n')

    def tearDown(self):
        self.proxy.close()
        self.dns.close()
        self.temporary.cleanup()

    def command(self, words, fmt='json', output='-'):
        path = self.root / 'wordlist.txt'
        path.write_text('\n'.join(words) + '\n')
        return [BINARY, '--subdomain', 'example.test', '--wordlist', str(path), '--no-enrich',
                '--no-permutations', '--no-deep-passive', '--quiet', '--output', output, '--format', fmt]

    def assert_local_activity(self, start):
        self.assertFalse(self.dns.errors)
        self.assertIn(('example.com', 1), self.dns.requests)
        self.assertTrue(any(name.endswith('.invalid') for name, _ in self.dns.requests))
        requests = self.proxy.requests[start:]
        self.assertTrue(requests, 'crt.sh must reach the blocking loopback proxy')
        self.assertTrue(all(request == 'CONNECT crt.sh:443 HTTP/1.1' for request in requests), requests)
        self.assertTrue(all(name == 'example.com' or name.endswith('.invalid') or name.endswith('.example.test')
                            for name, _ in self.dns.requests), self.dns.requests)

    def run_case(self, words, fmt='json', code=0, output='-'):
        start = len(self.proxy.requests)
        result = subprocess.run(self.command(words, fmt, output), cwd=self.root, env=self.environment,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, code, (words, fmt, result.stdout[-5000:], result.stderr))
        self.assertNotIn('\x1b', result.stdout)
        self.assert_local_activity(start)
        return result

    def test_dual_stack_and_ipv6_only_results_in_all_formats(self):
        for fmt in ('json', 'csv', 'txt'):
            with self.subTest(format=fmt):
                result = self.run_case(('dual', 'v6', 'absent'), fmt)
                if fmt == 'json':
                    report = json.loads(result.stdout)
                    self.assertEqual(report['status'], 'complete')
                    self.assertTrue(report['warnings'])
                    entries = {row['sub']: row for row in report['subdomains']}
                    self.assertEqual(set(entries), {'dual.example.test', 'v6.example.test'})
                    self.assertEqual(entries['dual.example.test']['ips'], ['192.0.2.20'])
                    self.assertEqual(entries['dual.example.test']['ipv6'], ['2001:db8::20'])
                    self.assertEqual(entries['v6.example.test']['ips'], [])
                    self.assertEqual(entries['v6.example.test']['ipv6'], ['2001:db8::21'])
                elif fmt == 'csv':
                    rows = list(csv.DictReader(io.StringIO(result.stdout)))
                    self.assertEqual({row['identifier'] for row in rows if row['record_type'] == 'subdomain'},
                                     {'dual.example.test', 'v6.example.test'})
                    v6 = next(row for row in rows if row['identifier'] == 'v6.example.test')
                    self.assertEqual(json.loads(v6['details'])['ipv6'], ['2001:db8::21'])
                else:
                    self.assertIn('Status: complete', result.stdout)
                    self.assertIn('2001:db8::21', result.stdout)
                    self.assertNotIn('absent.example.test', result.stdout)

    def test_nxdomain_is_successful_empty_result_in_all_formats(self):
        for fmt in ('json', 'csv', 'txt'):
            with self.subTest(format=fmt):
                result = self.run_case(('absent',), fmt)
                if fmt == 'json':
                    report = json.loads(result.stdout)
                    self.assertEqual(report['status'], 'complete')
                    self.assertEqual(report['errors'], [])
                    self.assertEqual(report['subdomains'], [])
                elif fmt == 'csv':
                    rows = list(csv.DictReader(io.StringIO(result.stdout)))
                    self.assertFalse(any(row['record_type'] == 'subdomain' for row in rows))
                    self.assertEqual(json.loads(rows[0]['details'])['status'], 'complete')
                else:
                    self.assertIn('Status: complete', result.stdout)

    def test_terminal_accents_respect_color_controls_and_keep_reports_clean(self):
        for color in ('always', 'never', 'auto'):
            with self.subTest(color=color):
                start = len(self.proxy.requests)
                destination = self.root / f'colors-{color}.json'
                command = self.command(('dual', 'v6'), output=str(destination))
                command.remove('--quiet')
                command += ['--color', color]
                result = subprocess.run(command, cwd=self.root, env=self.environment,
                                        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                self.assert_local_activity(start)
                if color == 'always':
                    self.assertIn('\x1b[32m192.0.2.20', result.stdout)
                    self.assertRegex(result.stdout, r'\x1b\[32mIPv6: +2001:db8::20')
                else:
                    self.assertNotIn('\x1b', result.stdout)
                report = json.loads(destination.read_text())
                self.assertEqual({row['sub'] for row in report['subdomains']},
                                 {'dual.example.test', 'v6.example.test'})
                self.assertNotIn('\\u001b', destination.read_text())
        command = self.command(('dual', 'v6')) + ['--color', 'always']
        command.remove('--quiet')
        result = subprocess.run(command, cwd=self.root, env=self.environment,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('\x1b', result.stdout)
        self.assertEqual(len(json.loads(result.stdout)['subdomains']), 2)
        self.assertIn('\x1b[32m', result.stderr)

    def test_deep_mode_does_not_turn_rotating_wildcard_into_wordlist_findings(self):
        self.dns.wildcard = True
        start = len(self.proxy.requests)
        command = self.command(('www', 'mail', 'host123')) + ['--mode', 'deep']
        result = subprocess.run(command, cwd=self.root, env=self.environment,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assert_local_activity(start)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'complete')
        self.assertEqual(report['subdomains'], [])
        self.assertEqual(report['subdomain_candidates'], [])
        self.assertTrue(any('wildcard' in warning.lower() for warning in report['warnings']))
        candidate_names = {'www.example.test', 'mail.example.test', 'host123.example.test'}
        self.assertFalse(any(name in candidate_names for name, _ in self.dns.requests))
        probes = [(name, rtype) for name, rtype in self.dns.requests if name.startswith('dnxwc-')]
        self.assertGreaterEqual(len({name for name, _ in probes}), 2)
        module = json.loads((self.root / 'example.test_subdomains.json').read_text())
        self.assertEqual(module, [])
        checkpoint = json.loads((self.root / 'example.test_subdomains_checkpoint.json').read_text())
        self.assertEqual(checkpoint['count'], 0)
        self.assertEqual(checkpoint['resolved_count'], 0)
        self.assertEqual(checkpoint['candidate_count'], 0)

    def test_bruteforce_respects_explicit_wordlist_instead_of_discovered_list(self):
        start = len(self.proxy.requests)
        command = self.command(('dual', 'v6', 'absent')) + ['--bruteforce']
        result = subprocess.run(command, cwd=self.root, env=self.environment,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assert_local_activity(start)
        queried = {name for name, _ in self.dns.requests
                   if name.endswith('.example.test') and not name.startswith('dnxwc-')}
        self.assertEqual(queried, {'dual.example.test', 'v6.example.test', 'absent.example.test'})
        report = json.loads(result.stdout)
        self.assertEqual({row['sub'] for row in report['subdomains']},
                         {'dual.example.test', 'v6.example.test'})

    def test_passive_only_never_runs_builtin_or_installed_wordlists(self):
        start = len(self.proxy.requests)
        command = [BINARY, '--subdomain', 'example.test', '--mode', 'deep', '--passive-only',
                   '--no-enrich', '--no-deep-passive', '--quiet', '--output', '-', '--format', 'json']
        result = subprocess.run(command, cwd=self.root, env=self.environment,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assert_local_activity(start)
        queried = [name for name, _ in self.dns.requests
                   if name.endswith('.example.test') and not name.startswith('dnxwc-')]
        self.assertEqual(queried, [])
        report = json.loads(result.stdout)
        self.assertEqual(report['subdomains'], [])
        self.assertEqual(report['subdomain_candidates'], [])

    def test_default_deep_uses_compact_builtin_instead_of_installed_wordlist(self):
        self.dns.wildcard = True
        start = len(self.proxy.requests)
        report_path = self.root / 'default-deep.json'
        command = [BINARY, '--subdomain', 'example.test', '--mode', 'deep', '--no-enrich',
                   '--no-deep-passive', '--no-permutations', '--output', str(report_path), '--format', 'json']
        result = subprocess.run(command, cwd=self.root, env=self.environment,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, (result.stdout[-5000:], result.stderr))
        self.assert_local_activity(start)
        match = re.search(r'\bbuiltin \((\d+) words\)', result.stdout)
        self.assertIsNotNone(match, result.stdout)
        self.assertGreater(int(match.group(1)), 0)
        self.assertLessEqual(int(match.group(1)), 512)
        self.assertNotIn('streaming:', result.stdout)
        self.assertNotIn('best-dns-wordlist.txt', result.stdout)
        queried = [name for name, _ in self.dns.requests
                   if name.endswith('.example.test') and not name.startswith('dnxwc-')]
        self.assertEqual(queried, [])
        report = json.loads(report_path.read_text())
        self.assertEqual(report['subdomains'], [])
        self.assertEqual(report['subdomain_candidates'], [])

    def test_servfail_is_exported_as_failure_in_all_formats(self):
        for fmt in ('json', 'csv', 'txt'):
            with self.subTest(format=fmt):
                result = self.run_case(('fail',), fmt, code=1)
                self.assertIn('DNS', result.stderr)
                if fmt == 'json':
                    report = json.loads(result.stdout)
                    self.assertEqual(report['status'], 'failed')
                    self.assertEqual(report['subdomains'], [])
                    self.assertTrue(report['errors'])
                elif fmt == 'csv':
                    rows = list(csv.DictReader(io.StringIO(result.stdout)))
                    self.assertTrue(any(row['record_type'] == 'error' for row in rows))
                    self.assertEqual(json.loads(rows[0]['details'])['status'], 'failed')
                else:
                    self.assertIn('Status: failed', result.stdout)
                    self.assertIn('Error:', result.stdout)

    def test_partial_dns_results_survive_real_cli_errors(self):
        report = json.loads(self.run_case(('good', 'fail'), code=1).stdout)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual([row['sub'] for row in report['subdomains']], ['good.example.test'])
        module = json.loads((self.root / 'example.test_subdomains.json').read_text())
        self.assertEqual([row['subdomain'] for row in module], ['good.example.test'])

    def test_report_file_and_module_exports_are_usable(self):
        result = self.run_case(('dual', 'v6'), output=str(self.root / 'report.json'))
        self.assertEqual(result.stdout, '')
        report = json.loads((self.root / 'report.json').read_text())
        self.assertEqual(len(report['subdomains']), 2)
        module = json.loads((self.root / 'example.test_subdomains.json').read_text())
        checkpoint = json.loads((self.root / 'example.test_subdomains_checkpoint.json').read_text())
        self.assertEqual(len(module), checkpoint['count'])
        self.assertEqual(checkpoint['count'], 2)
        self.assertTrue(all(row['ipv6'] for row in module))

    def test_signals_cancel_active_dns_and_preserve_json(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig):
                self.dns.held.clear()
                start = len(self.proxy.requests)
                process = subprocess.Popen(self.command(('good', 'hold')), cwd=self.root,
                                           env=self.environment, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    self.assertTrue(self.dns.held.wait(5), 'CLI never reached the local waiting DNS fixture')
                    time.sleep(0.08)
                    started = time.monotonic()
                    process.send_signal(sig)
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 130, (stdout, stderr))
                    self.assertLess(time.monotonic() - started, 3)
                    self.assertNotIn('\x1b', stdout)
                    report = json.loads(stdout)
                    self.assertEqual(report['status'], 'cancelled')
                    self.assertTrue(any(row['sub'] == 'good.example.test' for row in report['subdomains']), report)
                    self.assert_local_activity(start)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()


if __name__ == '__main__':
    unittest.main()
