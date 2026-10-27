#!/usr/bin/env python3
"""DNS/WHOIS process regression checks with local, bounded fake helpers only."""
import csv
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def check(condition, detail):
    if not condition:
        raise AssertionError(detail)


HELPER = r'''
import ipaddress, json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
mode = os.environ['DNX_FIXTURE_MODE']
kind = Path(sys.argv[0]).name
entry = json.dumps({'helper': kind, 'args': args}) + '\n'
fd = os.open(os.environ['DNX_FIXTURE_CALLS'], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
os.write(fd, entry.encode())
os.close(fd)
if mode in ('hang', 'cancel'):
    time.sleep(5)
    sys.exit(0)
if kind == 'whois':
    incoming = sys.stdin.read()
    if mode == 'capture-overflow':
        print('Domain Name: example.test')
        print('Long-Key: ' + 'x' * (1024 * 1024) + ' uncaptured-tail-marker')
        sys.exit(0)
    if mode in ('stderr-denied', 'stderr-limit', 'stderr-warning'):
        print({'stderr-denied': 'Error: access denied',
               'stderr-limit': 'WHOIS LIMIT EXCEEDED - try again later',
               'stderr-warning': 'Warning: fixture registry redirected the query'}[mode],
              file=sys.stderr)
    if mode == 'long-line':
        print('Long-Key: ' + 'x' * 20000 + ' tail-marker-preserved')
        sys.exit(0)
    if mode in ('limit', 'denied', 'partial-refusal'):
        if mode == 'partial-refusal': print('Domain Name: example.test')
        print('WHOIS LIMIT EXCEEDED - try again later' if mode == 'limit' else 'Error: access denied')
        sys.exit(0)
    if mode in ('no-match', 'not-found', 'no-entries'):
        print({'no-match': 'No match for EXAMPLE.TEST', 'not-found': 'NOT FOUND', 'no-entries': '%ERROR:101: no entries found'}[mode])
        sys.exit(0)
    if mode == 'empty': sys.exit(0)
    if mode == 'failed':
        print('fixture helper failure', file=sys.stderr)
        sys.exit(9)
    if mode == 'partial':
        print('Domain Name: example.test')
        print('Fixture-Key: partial data')
        print('fixture incomplete response', file=sys.stderr)
        sys.exit(7)
    if mode == 'unsafe':
        print('\x1b[31mOdd-Key\x1b[0m: café Москва')
        print('Repeated: one')
        print('Repeated: two')
        print('Unusual-Field: retained')
        sys.exit(0)
    print('% fixture registry comment')
    print('Domain Name: example.test')
    print('Registrar: Local Fixture')
    print('Unusual-Field: retained')
    print('Repeated: one')
    print('Repeated: two')
    if incoming: print('LEAKED_STDIN:' + incoming)
    sys.exit(0)

allowed = {'A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA', 'SRV', 'DS', 'DNSKEY', 'AXFR', 'PTR'}
rrtype = next((a.upper() for a in args if a.upper() in allowed), '')
if '-x' in args: rrtype = 'PTR'
names = [a for a in args if not a.startswith(('+', '-', '@')) and a.upper() not in allowed]
name = names[0] if names else 'example.test'
if '-x' in args: name = args[args.index('-x') + 1]

def answer(records=(), status='NOERROR', truncated=False):
    print(';; ->>HEADER<<- opcode: QUERY, status: ' + status + ', id: 1234')
    print(';; flags: qr rd ra' + (' tc' if truncated else '') + '; QUERY: 1, ANSWER: ' + str(len(records)) + ', AUTHORITY: 0, ADDITIONAL: 0')
    print(';; ANSWER SECTION:')
    for record in records: print(record)

def rr(rtype, data, owner=None):
    return (owner or name).rstrip('.') + '. 60 IN ' + rtype + ' ' + data

if mode == 'failed':
    print('fixture helper failure', file=sys.stderr)
    sys.exit(9)
if mode == 'servfail': answer(status='SERVFAIL'); sys.exit(0)
if mode == 'nxdomain': answer(status='NXDOMAIN'); sys.exit(0)
if mode == 'nxdomain-data':
    answer([rr('A', '192.0.2.10')] if rrtype == 'A' else [], status='NXDOMAIN')
    sys.exit(0)
if mode == 'nxdomain-cname':
    answer([rr('CNAME', 'absent.example.test.')], status='NXDOMAIN')
    sys.exit(0)
if mode == 'unrelated' and rrtype in ('A', 'TXT'):
    answer([rr('A', '192.0.2.199', 'foreign.test')] if rrtype == 'A' else [rr('TXT', '"v=spf1 include:foreign-spf.test -all"', 'foreign.test')])
    sys.exit(0)
if mode == 'cname-chain' and rrtype == 'A':
    answer([rr('CNAME', 'alias.example.test.'), rr('A', '192.0.2.10', 'alias.example.test')])
    sys.exit(0)
if mode == 'empty': answer(); sys.exit(0)
if mode == 'invalid': print('not a DNS response'); sys.exit(0)
if mode == 'a-failure' and rrtype == 'A':
    print('fixture A lookup failed', file=sys.stderr)
    sys.exit(4)
if mode == 'cname-only':
    answer([rr('CNAME', 'alias.example.test.')])
    sys.exit(0)
if rrtype == 'PTR':
    answer([rr('PTR', 'reverse.example.test.', ipaddress.ip_address(name).reverse_pointer)])
    sys.exit(0)
if rrtype == 'AXFR':
    soa = rr('SOA', 'ns1.example.test. admin.example.test. 1 3600 600 86400 60', 'example.test')
    if mode == 'axfr-refused': answer(status='REFUSED')
    elif mode == 'axfr-diagnostic': print(';; communications error to 192.0.2.53#53: timed out')
    elif mode == 'axfr-truncated': answer([soa, rr('A', '192.0.2.10'), soa], truncated=True)
    elif mode == 'axfr-one-soa': answer([soa, rr('A', '192.0.2.10')])
    elif mode == 'axfr-mismatch': answer([soa, rr('A', '192.0.2.10'), rr('SOA', 'ns1.example.test. admin.example.test. 1 3600 600 86400 60', 'other.test')])
    else: answer([soa, rr('A', '192.0.2.77', 'transfer.example.test'), soa])
    sys.exit(0)
records = []
if rrtype == 'A':
    records = [rr('A', '192.0.2.' + str(n)) for n in range(1, 21)] if mode == 'many-ptr' else [rr('A', '192.0.2.10')]
elif rrtype == 'AAAA': records = [rr('AAAA', '2001:db8::10')]
elif rrtype == 'MX': records = [rr('MX', '10 mail.example.test.')]
elif rrtype == 'TXT':
    if name.startswith('_dmarc.'): records = [rr('TXT', '"v=DMARC1; p=reject"')]
    elif name != 'example.test': records = [rr('TXT', '"v=spf1 -all"')]
    elif mode == 'many-spf': records = [rr('TXT', '"v=spf1 ' + ' '.join('include:spf' + str(n) + '.example.test' for n in range(20)) + ' -all"')]
    elif mode == 'unsafe-spf': records = [rr('TXT', '"v=spf1 include:@evil.test include:+evil.test include:-option redirect=@evil.test include:good.example.test -all"')]
    else: records = [rr('TXT', '"v=spf1 -all"')]
elif rrtype == 'NS':
    if mode == 'many-ns': records = [rr('NS', 'ns' + str(n) + '.example.test.') for n in range(20)]
    elif mode.startswith('axfr-'): records = [rr('NS', 'ns1.example.test.')]
elif rrtype == 'SOA': records = [rr('SOA', 'ns1.example.test. admin.example.test. 1 3600 600 86400 60')]
elif rrtype == 'CAA': records = [rr('CAA', '0 issue "ca.example.test"')]
elif rrtype == 'DS': records = [rr('DS', '12345 13 2 ABCDEF')]
elif rrtype == 'DNSKEY': records = [rr('DNSKEY', '257 3 13 AQIDBA==')]
answer(records)
'''


def main():
    check(len(sys.argv) == 2, 'usage: dns_whois_integration.py /path/to/dark_nexus')
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    checks = 0
    with tempfile.TemporaryDirectory(prefix='dark-nexus-dns-whois-') as temporary:
        root = Path(temporary)
        tools = root / 'tools'
        tools.mkdir()
        home = root / 'home'
        home.mkdir()
        for name in ('dig', 'whois'):
            helper = tools / name
            helper.write_text('#!' + sys.executable + '\n' + HELPER)
            helper.chmod(0o755)
        env = dict(os.environ, PATH=str(tools), HOME=str(home), TERM='dumb', NO_COLOR='1')
        serial = 0

        def command(module, mode='normal', extra=(), timeout=200, target='example.test'):
            nonlocal serial
            serial += 1
            calls_path = root / ('calls-' + str(serial))
            current_env = dict(env, DNX_FIXTURE_MODE=mode, DNX_FIXTURE_CALLS=str(calls_path))
            argv = [binary, '--' + module, target, '--timeout', str(timeout), *extra]
            return argv, current_env, calls_path

        def calls(path):
            return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

        def run(module, mode='normal', extra=(), code=0, timeout=200, input_text=None, target='example.test'):
            nonlocal checks
            argv, current_env, calls_path = command(module, mode, extra, timeout, target)
            started = time.monotonic()
            result = subprocess.run(argv, cwd=root, env=current_env, input=input_text,
                                    capture_output=True, text=True, timeout=8)
            elapsed = time.monotonic() - started
            check(result.returncode == code, (argv, mode, result.returncode, result.stdout, result.stderr))
            check(elapsed < 5, ('helper deadline not bounded', mode, elapsed))
            check(not list(root.glob('*.log')), 'implicit log created')
            checks += 1
            return result, calls(calls_path)

        def report(module, mode='normal', code=0, extra=(), timeout=200):
            result, invoked = run(module, mode, ('-q', '--output', '-', '--format', 'json', *extra), code, timeout)
            check('\x1b' not in result.stdout, 'ANSI escaped into JSON stream')
            data = json.loads(result.stdout)
            check(data['target'] == 'example.test', data)
            check(data.get('status') in ('complete', 'partial', 'failed', 'cancelled'), data)
            check(isinstance(data.get('errors'), list) and all(isinstance(x, str) for x in data['errors']), data)
            check(isinstance(data.get('warnings'), list) and all(isinstance(x, str) for x in data['warnings']), data)
            check(isinstance(data.get('dns_records'), list) and isinstance(data.get('whois_records'), list), data)
            if code == 0:
                check(data['status'] == 'complete' and not data['errors'], data)
            else:
                check(data['status'] in ('partial', 'failed') and data['errors'], data)
                check(result.stderr.strip(), 'quiet mode hid a module failure')
            return data, invoked

        dns, invoked = report('dns')
        check(any(' MX ' in record and 'mail.example.test.' in record for record in dns['dns_records']), dns)
        check(any(' A ' in record and '192.0.2.10' in record for record in dns['dns_records']), dns)
        check(any(' AAAA ' in record and '2001:db8::10' in record for record in dns['dns_records']), dns)
        check(any(' PTR ' in record for record in dns['dns_records']), dns)
        check(any('-x' in item['args'] for item in invoked), invoked)
        check(all(item['helper'] == 'dig' and '-r' in item['args'] for item in invoked), invoked)
        for mode in ('empty', 'nxdomain'):
            data, _ = report('dns', mode)
            check(not data['dns_records'], data)
        for mode in ('failed', 'servfail', 'invalid', 'hang', 'nxdomain-data'):
            data, _ = report('dns', mode, code=1, timeout=100)
            check(data['status'] == 'failed' and not data['dns_records'], data)
        failed_text, _ = run('dns', 'servfail', code=1)
        check('spoofing' not in failed_text.stdout.lower(), failed_text.stdout)
        data, _ = report('dns', 'a-failure', code=1)
        check(data['status'] == 'partial' and any(' MX ' in x for x in data['dns_records']), data)
        data, invoked = report('dns', 'unrelated', code=1)
        check(not any('foreign.test' in x or '192.0.2.199' in x for x in data['dns_records']), data)
        check(not any('foreign-spf.test' in item['args'] or '192.0.2.199' in item['args'] for item in invoked), invoked)
        data, _ = report('dns', 'cname-chain')
        check(any('alias.example.test.' in record and ' A ' in record for record in data['dns_records']), data)
        data, _ = report('dns', 'nxdomain-cname')
        check(not any(' A ' in record or ' AAAA ' in record for record in data['dns_records']), data)
        for address in ('192.0.2.10', '2001:db8::10'):
            result, invoked = run('dns', extra=('-q', '-o', '-'), target=address)
            data = json.loads(result.stdout)
            check(data['status'] == 'complete' and data['target'] == address, data)
            check(any(' PTR ' in record for record in data['dns_records']), data)
            check(len(invoked) == 1 and '-x' in invoked[0]['args'] and address in invoked[0]['args'], invoked)
        data, _ = report('dns', 'cname-only')
        check(not any(' A ' in x or ' AAAA ' in x for x in data['dns_records']), data)
        data, invoked = report('dns', 'unsafe-spf')
        check(not any(any('@evil.test' in arg or '+evil.test' in arg or '-option' == arg for arg in item['args']) for item in invoked), invoked)
        check(any('good.example.test' in item['args'] for item in invoked), invoked)
        for mode, selector in [('many-spf', lambda x: any(arg.startswith('spf') for arg in x['args'])),
                               ('many-ns', lambda x: any(arg.startswith('@') for arg in x['args'])),
                               ('many-ptr', lambda x: '-x' in x['args'])]:
            _, invoked = report('dns', mode)
            count = sum(selector(item) for item in invoked)
            check(0 < count <= 8, (mode, count, invoked))
        for mode in ('axfr-refused', 'axfr-diagnostic', 'axfr-truncated', 'axfr-one-soa', 'axfr-mismatch'):
            result, _ = run('dns', mode)
            check('ZONE TRANSFER SUCCEEDED' not in result.stdout.upper(), (mode, result.stdout))
            check('transfer.example.test' not in result.stdout, (mode, result.stdout))
            data, _ = report('dns', mode)
            check(data['warnings'], (mode, data))
            check(not any('transfer.example.test' in record for record in data['dns_records']), data)
        result, _ = run('dns', 'axfr-valid')
        check('transfer completed' in result.stdout, result.stdout)
        data, _ = report('dns', 'axfr-valid')
        check(any('transfer.example.test' in record for record in data['dns_records']), data)

        whois, invoked = report('whois')
        check(any('Unusual-Field: retained' in line for line in whois['whois_records']), whois)
        check(sum(line.startswith('Repeated:') for line in whois['whois_records']) == 2, whois)
        check(len(invoked) == 1 and invoked[0]['helper'] == 'whois', invoked)
        data, _ = report('whois', 'partial', code=1)
        check(data['status'] == 'partial' and 'Fixture-Key: partial data' in data['whois_records'], data)
        for mode in ('empty', 'failed', 'hang', 'limit', 'denied'):
            data, _ = report('whois', mode, code=1, timeout=100)
            check(data['status'] == 'failed', data)
        data, _ = report('whois', 'partial-refusal', code=1)
        check(data['status'] == 'partial' and any('Domain Name:' in record for record in data['whois_records']), data)
        for mode in ('stderr-denied', 'stderr-limit'):
            data, _ = report('whois', mode, code=1)
            check(data['status'] == 'partial' and 'Domain Name: example.test' in data['whois_records'], data)
            check(any('server refused the query' in error for error in data['errors']), data)
            check(not any('access denied' in record or 'LIMIT EXCEEDED' in record
                          for record in data['whois_records']), data)
        data, _ = report('whois', 'stderr-warning')
        check('Domain Name: example.test' in data['whois_records'], data)
        check(not any('fixture registry redirected' in record for record in data['whois_records']), data)
        data, _ = report('whois', 'capture-overflow', code=1, timeout=2000)
        check(data['status'] == 'partial' and 'Domain Name: example.test' in data['whois_records'], data['status'])
        check(any('capture limit' in error for error in data['errors']), data['errors'])
        check(sum(len(record) for record in data['whois_records']) <= 1024 * 1024,
              'WHOIS capture exceeded its limit')
        check(not any('uncaptured-tail-marker' in record for record in data['whois_records']),
              'WHOIS capture retained output beyond its limit')
        for mode in ('no-match', 'not-found', 'no-entries'):
            data, _ = report('whois', mode)
            check(data['whois_records'], data)
        data, _ = report('whois', 'long-line')
        check(any(record.endswith('tail-marker-preserved') and len(record) > 20000 for record in data['whois_records']), data)
        data, _ = report('whois', 'unsafe')
        check(any('café Москва' in record for record in data['whois_records']), data)
        check(all('\x1b' not in record for record in data['whois_records']), data)
        for fmt in ('csv', 'txt'):
            unsafe, _ = run('whois', 'unsafe', extra=('-q', '-o', '-', '--format', fmt))
            check('\x1b' not in unsafe.stdout and 'café Москва' in unsafe.stdout, unsafe.stdout)
        result, _ = run('whois', 'unsafe')
        check('\x1b' not in result.stdout and 'café Москва' in result.stdout, result)
        result, _ = run('whois', input_text='UPSTREAM_INPUT')
        check('LEAKED_STDIN' not in result.stdout, result.stdout)

        for module in ('dns', 'whois'):
            report(module, extra=('--color', 'always'))
            for fmt in ('csv', 'txt'):
                result, _ = run(module, extra=('-q', '-o', '-', '--format', fmt))
                check('\x1b' not in result.stdout, result.stdout)
                if fmt == 'csv':
                    rows = list(csv.DictReader(io.StringIO(result.stdout)))
                    check(any(row['record_type'] == module for row in rows), rows)
                else:
                    check('Target: example.test' in result.stdout, result.stdout)
                    check('mail.example.test' in result.stdout if module == 'dns' else 'Unusual-Field: retained' in result.stdout, result.stdout)
            path = root / (module + '-report.json')
            result, _ = run(module, extra=('-q', '--output', str(path)))
            check(not result.stdout and json.loads(path.read_text())['status'] == 'complete', result)
            for invalid_timeout in ('0', '60001', '-1', 'invalid'):
                run(module, extra=('--timeout', invalid_timeout), code=2)

        for module in ('dns', 'whois'):
            result, invoked = run(module, code=2, target='2001:db8:::1')
            check(not invoked, 'invalid IPv6 reached a helper')
            check(result.stderr.strip(), result)

        # Cancel while a local helper is running. Exported JSON must survive both
        # SIGINT and SIGTERM, and no long-running helper should delay shutdown.
        for module in ('dns', 'whois'):
            for sig in (signal.SIGINT, signal.SIGTERM):
                argv, current_env, calls_path = command(module, 'cancel', ('-q', '-o', '-'), 1000)
                process = subprocess.Popen(argv, cwd=root, env=current_env,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 3
                    while not calls_path.exists() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.01)
                    check(calls_path.exists(), ('helper never started', argv, process.poll()))
                    started = time.monotonic()
                    process.send_signal(sig)
                    stdout, stderr = process.communicate(timeout=3)
                    check(time.monotonic() - started < 2, 'cancellation did not stop helpers promptly')
                    check(process.returncode == 130, (module, sig, process.returncode, stdout, stderr))
                    data = json.loads(stdout)
                    check(data['status'] == 'cancelled', data)
                    check('\x1b' not in stdout, stdout)
                    checks += 1
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
    print(f'{checks} DNS/WHOIS process checks passed (local fake helpers, no network)')


if __name__ == '__main__':
    main()
