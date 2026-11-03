#!/usr/bin/env python3
"""Reproducible DNS degradation benchmark; all traffic terminates on loopback.

The long delayed case intentionally exceeds the old 30-second queue deadline.
Run explicitly, not as part of the short CTest suite. JSON records individual
runs (no percentile claims from a single measurement).
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from benchmark_process import run_measured


def fixtures(binary):
    spec = importlib.util.spec_from_file_location(
        'subdomain_cli_fixture', Path(__file__).with_name('subdomain_cli_integration.py'))
    module = importlib.util.module_from_spec(spec)
    old_arguments = sys.argv
    old_bytecode = sys.dont_write_bytecode
    try:
        sys.argv = [str(spec.origin), str(binary)]
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.argv = old_arguments
        sys.dont_write_bytecode = old_bytecode
    return module


CASES = {
    'healthy': dict(count=10000, concurrency=256, timeout=500, delay_ms=0),
    'delayed': dict(count=10000, concurrency=16, timeout=500, delay_ms=80),
    'loss': dict(count=1000, concurrency=64, timeout=100, delay_ms=10, loss_every=7),
    'outage': dict(count=10000, concurrency=16, timeout=100, delay_ms=0, outage=True),
}


def run_case(binary, fixture, name, options, legacy):
    dns = fixture.LocalDNS(delay_ms=options['delay_ms'],
                           loss_every=options.get('loss_every', 0), outage=options.get('outage', False),
                           positive_index=options['count'] - 1)
    proxy = fixture.BlockedProxy()
    try:
        with tempfile.TemporaryDirectory(prefix='dark-nexus-degradation-') as temporary:
            root = Path(temporary)
            (root / 'home').mkdir()
            words = root / 'words.txt'
            words.write_text(''.join(f'bench{i}\n' for i in range(options['count'])))
            (root / 'resolvers.txt').write_text(f'127.0.0.1:{dns.port}\n')
            environment = dict(os.environ, HOME=str(root / 'home'), NO_COLOR='1', TERM='dumb')
            for key in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY'):
                environment[key] = f'http://127.0.0.1:{proxy.server_address[1]}'
            for key in ('no_proxy', 'NO_PROXY', 'VT_API_KEY', 'ST_API_KEY', 'SHODAN_API_KEY',
                        'CENSYS_API_ID', 'CENSYS_API_SECRET'):
                environment.pop(key, None)
            command = [str(binary), '--subdomain', 'example.test', '--wordlist', str(words),
                       '--no-enrich', '--no-permutations', '--no-deep-passive', '--quiet',
                       '--dns-concurrency', str(options['concurrency']), '--dns-timeout', str(options['timeout']),
                       '--dns-retries', '1', '--output', '-', '--format', 'json']
            process = run_measured(command, cwd=root, env=environment, timeout=240)
            elapsed = process.elapsed_seconds
            report = json.loads(process.stdout)
            assert process.memory_samples > 0 and process.peak_rss_kib > 0
            assert process.returncode in (0, 1), (process.returncode, process.stderr)
            assert not dns.errors, dns.errors
            assert proxy.requests and all(line == 'CONNECT crt.sh:443 HTTP/1.1' for line in proxy.requests), proxy.requests
            assert all(host == 'example.com' or host.endswith('.invalid') or host.endswith('.example.test')
                       for host, _ in dns.requests)
            assert json.loads((root / 'example.test_subdomains.json').read_text()) == report
            checkpoint = json.loads((root / 'example.test_subdomains_checkpoint.json').read_text())
            assert checkpoint.pop('checkpoint')['final']
            assert checkpoint == report
            queried = {key: count for key, count in dns.query_counts.items() if key[0].startswith('bench')}
            stats = report.get('subdomain_dns', {})
            if not legacy:
                assert stats['unattempted_queries'] == 0, stats
                assert stats['deadline_queries'] == 0, stats
                if name == 'outage':
                    assert process.returncode == 1 and stats['stopped_early'], report
                    assert stats['candidate_checks'] < options['count'], stats
                else:
                    assert process.returncode == 0 and report['status'] == 'complete', report
                    assert stats['candidate_checks'] == options['count'], stats
                    assert len(queried) == options['count'] * 2, (name, len(queried))
                    assert len(report['subdomains']) == 1, report['subdomains']
                    tail = report['subdomains'][0]
                    assert tail['sub'] == f"bench{options['count'] - 1}.example.test"
                    assert tail['ips'] == ['192.0.2.20'] and tail['ipv6'] == ['2001:db8::20']
                    assert all(queried[(f'bench{i}.example.test', 1)] == 1 for i in range(options['count']))
            return dict(case=name, options=options, elapsed_seconds=elapsed, peak_rss_kib=process.peak_rss_kib,
                        memory_samples=process.memory_samples, wait4_peak_rss_kib=process.wait4_peak_rss_kib,
                        status=report['status'], resolved=len(report['subdomains']), query_packets=sum(queried.values()),
                        unique_family_queries=len(queried), expected_family_queries=options['count'] * 2,
                        dns=stats, errors=report['errors'])
    finally:
        dns.close()
        proxy.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--cases', nargs='+', choices=CASES, default=list(CASES))
    parser.add_argument('--legacy', action='store_true', help='record baseline incompleteness without new-policy assertions')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error('fixture assertions require Python without -O/PYTHONOPTIMIZE')
    if os.geteuid() == 0:
        parser.error('run as an unprivileged user; no root is needed for loopback fixtures')
    binary = args.binary.resolve(strict=True)
    fixture = fixtures(binary)
    output = dict(binary=str(binary), sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  legacy=args.legacy, runs=[])
    for name in args.cases:
        result = run_case(binary, fixture, name, CASES[name], args.legacy)
        output['runs'].append(result)
        args.output.write_text(json.dumps(output, indent=2) + '\n')
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
