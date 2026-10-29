#!/usr/bin/env python3
"""Read-only doctor process checks; helpers are inert local fixtures, never run."""
import os
from pathlib import Path
import json
import subprocess
import sys
import tempfile

CORE = ('dig', 'whois', 'host', 'ping', 'curl', 'openssl', 'getent')
EXPECTED_IDS = {'core.' + name for name in CORE} | {'wordlist', 'raw'}


def require(condition, detail):
    # Keep checks active when Python is run with -O, including in Release CI.
    if not condition:
        raise AssertionError(detail)


def main():
    require(len(sys.argv) == 2, 'usage: doctor_integration.py /absolute/path/to/dark_nexus')
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    checks = 0
    with tempfile.TemporaryDirectory(prefix='dark-nexus-doctor-') as temporary:
        root = Path(temporary)
        home = root / 'home'
        home.mkdir()
        tools = root / 'tools'
        tools.mkdir()
        missing = root / 'missing-tools'
        missing.mkdir()
        marker = root / 'helper-was-executed'
        # An absolute interpreter and shell builtins ensure the marker would be
        # written even when PATH contains only fixtures, if doctor ran a helper.
        stub = '#!/bin/sh\nprintf invoked >> "$DARK_NEXUS_TEST_MARKER"\nexit 99\n'

        def executable(directory, name):
            result = directory / name
            result.write_text(stub)
            result.chmod(0o755)
            return result

        for name in CORE + ('locate',):
            executable(tools, name)
        environment = dict(os.environ, PATH=str(tools), HOME=str(home), TERM='dumb',
                           NO_COLOR='1', DARK_NEXUS_TEST_MARKER=str(marker))
        # Avoid inherited test-specific dictionary overrides; standard runtime
        # dictionary locations are intentionally not assumed absent on the host.
        environment.pop('DARK_NEXUS_WORDLIST', None)

        def snapshot():
            return {str(path.relative_to(root)): ('link', os.readlink(path))
                    if path.is_symlink() else ('dir',) if path.is_dir()
                    else ('file', path.read_bytes(), path.stat().st_mode)
                    for path in root.rglob('*')}

        def run(*arguments, code=0, env=None, cwd=None):
            nonlocal checks
            before = snapshot()
            result = subprocess.run([binary, *arguments], cwd=cwd or root,
                                    env=environment if env is None else env,
                                    stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, timeout=10)
            require(result.returncode == code,
                    (arguments, result.returncode, result.stdout, result.stderr))
            require(not marker.exists(), 'doctor executed a helper: ' + str(arguments))
            require(snapshot() == before, 'doctor wrote a file or log: ' + str(arguments))
            checks += 1
            return result

        def report(*arguments, code=0, env=None, cwd=None):
            result = run(*arguments, code=code, env=env, cwd=cwd)
            require('\x1b' not in result.stdout, 'JSON contains terminal escapes')
            require(result.stderr == '', 'doctor JSON emitted extra diagnostics')
            data = json.loads(result.stdout)
            require(isinstance(data, dict), data)
            require(data.get('schema_version') == 1, data)
            require(data.get('version') == '2.0.0', data)
            require(data.get('status') in ('ok', 'warn', 'fail'), data)
            records = data.get('checks')
            require(isinstance(records, list), data)
            by_id = {item['id']: item for item in records}
            require(set(by_id) == EXPECTED_IDS and len(records) == len(EXPECTED_IDS), data)
            for record in records:
                require(record.get('status') in ('ok', 'warn', 'fail'), record)
                require(isinstance(record.get('detail'), str) and record['detail'], record)
                require(isinstance(record.get('remedy'), str), record)
                require(isinstance(record.get('workflows'), list), record)
                require(all(isinstance(item, str) and item for item in record['workflows']), record)
            require((data['status'] == 'fail') == (code == 1), data)
            return data, by_id

        json_args = ('doctor', '--output', '-', '--format', 'json')
        baseline, records = report(*json_args)
        for name in CORE:
            require(records['core.' + name]['status'] == 'ok', records)
        for arguments in [('--doctor', '--json', '-'), ('doctor', '--output', '-'),
                          ('doctor', '--json', '-', '--color', 'always'),
                          ('--doctor', '--output', '-', '--no-color', '--no-log')]:
            same, _ = report(*arguments)
            require(same == baseline, 'equivalent doctor commands changed diagnostics')
        for _ in range(2):
            same, _ = report(*json_args)
            require(same == baseline, 'repeated doctor diagnostics are unstable')

        for arguments in [('doctor',), ('--doctor',)]:
            plain = run(*arguments)
            require('\x1b' not in plain.stdout and plain.stderr == '', plain)
            require('2.0.0' in plain.stdout and all(name in plain.stdout for name in CORE), plain)
        pipe_env = dict(environment, TERM='xterm-256color')
        pipe_env.pop('NO_COLOR')
        piped = run('doctor', env=pipe_env)
        require('\x1b' not in piped.stdout and piped.stderr == '', piped)
        for arguments in [('--help', 'doctor'), ('doctor', '--help'), ('--doctor', '--help')]:
            help_result = run(*arguments)
            require('doctor' in help_result.stdout.lower(), help_result)
            require('\x1b' not in help_result.stdout, help_result)

        # Empty PATH and empty PATH components mean the working directory.
        for search_path in ['', ':', str(missing) + ':', ':' + str(missing)]:
            _, found = report(*json_args, env=dict(environment, PATH=search_path), cwd=tools)
            require(all(found['core.' + name]['status'] == 'ok' for name in CORE), found)
        _, found = report(*json_args, env=dict(environment, PATH='tools'), cwd=root)
        require(all(found['core.' + name]['status'] == 'ok' for name in CORE), found)

        absent_env = dict(environment, PATH=str(missing))
        _, absent = report(*json_args, env=absent_env, code=1)
        for name in CORE:
            record = absent['core.' + name]
            require(record['status'] == 'fail', record)
            require(record['remedy'] and record['workflows'], record)
        missing_plain = run('doctor', env=absent_env, code=1)
        require(all(name in missing_plain.stdout for name in CORE), missing_plain)
        run('--help', 'doctor', env=absent_env)

        # A directory, a non-executable file and a dangling link are not usable
        # executable commands, while an executable regular-file symlink is.
        unusual = root / 'unusual'
        unusual.mkdir()
        for name in CORE:
            executable(unusual, name)
        (unusual / 'dig').unlink()
        (unusual / 'dig').mkdir()
        (unusual / 'whois').chmod(0o644)
        (unusual / 'host').unlink()
        (unusual / 'host').symlink_to(unusual / 'nonexistent-host')
        (unusual / 'ping').unlink()
        (unusual / 'ping').symlink_to(tools / 'ping')
        _, found = report(*json_args, env=dict(environment, PATH=str(unusual)), code=1)
        for name in ('dig', 'whois', 'host'):
            require(found['core.' + name]['status'] == 'fail', found)
        for name in ('ping', 'curl', 'openssl', 'getent'):
            require(found['core.' + name]['status'] == 'ok', found)
        # The resolver must continue after an unusable earlier PATH candidate.
        _, found = report(*json_args, env=dict(environment,
                          PATH=str(unusual) + os.pathsep + str(tools)))
        require(all(found['core.' + name]['status'] == 'ok' for name in CORE), found)

        # Unset PATH uses the platform execvp default search path, never optional
        # fallback directories for core commands. Do not execute those commands.
        default_env = dict(environment)
        default_env.pop('PATH')
        expected = {name: any((Path(directory) / name).is_file()
                              and os.access(Path(directory) / name, os.X_OK)
                              for directory in os.defpath.split(os.pathsep)) for name in CORE}
        _, found = report(*json_args, env=default_env, code=0 if all(expected.values()) else 1)
        for name, present in expected.items():
            require((found['core.' + name]['status'] == 'ok') == present, found)

        invalid = [
            ('doctor', 'example.test'), ('--doctor', '127.0.0.1'),
            ('doctor', '--portscan', '127.0.0.1'), ('--dns', 'example.test', '--doctor'),
            ('doctor', '--ports', '80'), ('doctor', '--threads', '4'),
            ('doctor', '--timeout', '1'), ('doctor', '--wordlist', str(tools / 'dig')),
            ('doctor', '--ipv4'), ('doctor', '--quiet'), ('doctor', '-q'),
            ('doctor', '--version'), ('--list-modules', '--doctor'),
            ('doctor', '--log-file', str(root / 'unwanted.log')),
            ('doctor', '--output', str(root / 'unwanted.json')),
            ('doctor', '--json', str(root / 'unwanted.json')),
            ('doctor', '--output', '-', '--format', 'csv'),
            ('doctor', '--output', '-', '--format', 'txt'),
            ('doctor', '--format', 'json'), ('doctor', '--unknown'),
        ]
        for arguments in invalid:
            result = run(*arguments, code=2)
            require(result.stderr.strip(), 'invalid doctor arguments lack an explanation')
    print(f'{checks} doctor process checks passed (read-only local fixtures)')


if __name__ == '__main__':
    main()
