#!/usr/bin/env python3
"""CLI process checks with fake dig/whois; no external network access."""
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
checks = 0
with tempfile.TemporaryDirectory(prefix='dark-nexus-cli-') as temporary:
    root = Path(temporary)
    tools = root / 'tools'
    tools.mkdir()
    calls = root / 'calls'
    (tools / 'dig').write_text('''#!/usr/bin/env python3
import os, sys
with open(os.environ['DARK_NEXUS_TEST_CALLS'], 'a') as f:
    f.write(' '.join(sys.argv[1:]) + '\\n')
types = ('A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA', 'SRV', 'DS', 'DNSKEY', 'AXFR', 'PTR')
kind = next((arg.upper() for arg in sys.argv[1:] if arg.upper() in types), '')
question = next((arg for arg in sys.argv[1:] if not arg.startswith(('+', '-', '@')) and arg.upper() not in types), 'example.test')
print(';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234')
print(';; flags: qr rd ra; QUERY: 1, ANSWER: ' + ('1' if kind in ('MX', 'TXT') else '0') + ', AUTHORITY: 0, ADDITIONAL: 0')
print(';; ANSWER SECTION:')
if kind == 'MX': print(question.rstrip('.') + '. 60 IN MX 10 mail.example.test.')
if kind == 'TXT': print(question.rstrip('.') + '. 60 IN TXT "v=spf1 -all"')
''')
    (tools / 'whois').write_text('''#!/usr/bin/env python3
import os, sys
with open(os.environ['DARK_NEXUS_TEST_CALLS'], 'a') as f:
    f.write('whois ' + ' '.join(sys.argv[1:]) + '\\n')
incoming = sys.stdin.read()
if incoming: print('LEAKED_STDIN:' + incoming)
print('Domain Name: example.test')
''')
    for path in tools.iterdir():
        path.chmod(0o755)
    environment = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                       DARK_NEXUS_TEST_CALLS=str(calls), TERM='dumb', NO_COLOR='1')

    def run(*args, code=0):
        global checks
        process = subprocess.run([binary, *args], cwd=root, env=environment,
                                 stdin=subprocess.DEVNULL, capture_output=True,
                                 text=True, timeout=20)
        assert process.returncode == code, (args, process.returncode, process.stderr)
        checks += 1
        return process

    help_result = run()
    assert 'Usage:' in help_result.stdout and '\x1b' not in help_result.stdout
    assert not list(root.glob('*.log'))
    run('--version')
    assert 'osint' not in run('--list-modules').stdout.lower()
    assert 'osint' not in help_result.stdout.lower()
    for module in ['portscan', 'subdomain', 'traceroute', 'dns', 'whois',
                   'netscan', 'site', 'ip-intel', 'os-detect', 'recon']:
        run('--help', module)
        run('--' + module, '--help')
    for arguments in [('--unknown', 'example.test'), ('--dns',),
                      ('--dns', 'example.test', '--ports', '80'),
                      ('--portscan', '127.0.0.1', '-T9'),
                      ('--portscan', '127.0.0.1', '--ports', '90-80'),
                      ('--portscan', '127.0.0.1', '--ipv4', '--ipv6'),
                      ('--dns', 'example.test', '--format', 'json'),
                      ('--subdomain', 'example.test', '--wordlist', '/no/such/wordlist'),
                      ('--subdomain', 'example.test', '--passive-only', '--wordlist', 'hosts.txt'),
                      ('--subdomain', 'example.test', '--wordlist', 'hosts.txt', '--passive-only'),
                      ('--subdomain', 'example.test', '--passive-only', '--bruteforce'),
                      ('--subdomain', 'example.test', '--bruteforce', '--passive-only'),
                      ('--dns', 'example.test', '--bruteforce'),
                      ('--dns', 'example.test', '--passive-only'),
                      ('--osint', 'username'), ('--help', 'osint'),
                      ('--subdomain', 'example.test', '--js', '--no-http'),
                      ('--subdomain', 'example.test', '--no-enrich', '--tech'),
                      ('--subdomain', 'example.test', '--no-cname', '--service-hints'),
                      ('--subdomain', 'example.test', '--permutations', '--passive-only')]:
        run(*arguments, code=2)
    fifo = root / 'wordlist-fifo'
    os.mkfifo(fifo)
    run('--subdomain', 'example.test', '--wordlist', str(fifo), code=2)
    run('--subdomain', 'example.test', '--wordlist', str(root), code=2)
    assert not calls.exists(), 'informational/invalid commands invoked a network helper'
    result = run('--dns', 'example.test', '--output', '-')
    report = json.loads(result.stdout)
    assert report['target'] == 'example.test'
    assert any(' MX ' in record for record in report['dns_records'])
    assert '\x1b' not in result.stdout
    assert all('example.test' in line for line in calls.read_text().splitlines())
    assert 'example.test' in result.stderr
    result = run('--dns', 'example.test', '--quiet', '--output', '-')
    json.loads(result.stdout)
    assert result.stderr == ''
    result = run('--dns', 'example.test', '-q', '-o', '-', '--format', 'csv')
    rows = list(csv.DictReader(io.StringIO(result.stdout)))
    assert rows[0]['record_type'] == 'metadata' and any(r['record_type'] == 'dns' for r in rows)
    result = run('--dns', 'example.test', '-q', '-o', '-', '--format', 'txt')
    assert 'Target: example.test' in result.stdout
    path = root / 'folder with spaces' / 'report.JSON'
    run('--dns', 'example.test', '-q', '-o', str(path))
    json.loads(path.read_text())
    override = root / 'report.txt'
    run('--dns', 'example.test', '-q', '--json', str(override))
    json.loads(override.read_text())
    result = run('--whois', 'example.test')
    assert 'Domain Name' in result.stdout
    assert 'whois example.test' in calls.read_text()
    fed = subprocess.run([binary, '--whois', 'example.test'], cwd=root, env=environment,
                         input='UPSTREAM_INPUT', capture_output=True, text=True, timeout=20)
    assert fed.returncode == 0 and 'LEAKED_STDIN' not in fed.stdout
    checks += 1
    missing_env = dict(environment, PATH=str(root / 'missing-tools'))
    missing = subprocess.run([binary, '--whois', 'example.test', '--quiet'],
                             cwd=root, env=missing_env, capture_output=True, text=True, timeout=20)
    assert missing.returncode == 1 and missing.stdout == '' and 'required helper' in missing.stderr
    checks += 1
    colored = run('--dns', 'example.test', '-q', '-o', '-', '--color', 'always')
    json.loads(colored.stdout)
    assert '\x1b' not in colored.stdout
    run('--dns', 'example.test', '-q', '-o', str(root), code=1)
    if Path('/dev/full').exists():
        run('--dns', 'example.test', '-q', '-o', '/dev/full', '--format', 'json', code=1)
    log = root / 'scan.log'
    run('--whois', 'example.test', '-q', '--log-file', str(log))
    assert log.exists()
    for line in log.read_text().splitlines():
        json.loads(line)
print(f'{checks} process checks passed (fake network helpers)')
