#!/usr/bin/env python3
"""Installer regressions: fake package managers/CMake, no sudo or network."""
import os
import errno
import fcntl
import pty
import re
import select
import struct
import termios
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time
import unittest

INSTALLER = Path(__file__).resolve().parents[1] / 'install.sh'


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='dnx installer test ')
        self.root = Path(self.temporary.name)
        self.log = self.root / 'run.log'

    def tearDown(self):
        self.temporary.cleanup()

    def shell(self, body, code=0, timeout=10):
        script = f'source {shlex.quote(str(INSTALLER))}\nDNX_LOG={shlex.quote(str(self.log))}\n' + body
        result = subprocess.run(['bash', '-c', script], text=True, capture_output=True, timeout=timeout)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def fixture(self):
        source = self.root / 'source'
        (source / 'src').mkdir(parents=True)
        (source / 'include').mkdir()
        (source / 'CMakeLists.txt').write_text('project(fixture)\n')
        (source / 'best-dns-wordlist.txt').write_text('www\nmail\n')
        # An unrelated nested checkout must not be copied or deleted.
        (source / 'dark-nexus').mkdir()
        (source / 'dark-nexus' / 'keep').write_text('untouched')
        tools = self.root / 'tools'
        tools.mkdir()
        fake_cmake = tools / 'cmake'
        fake_cmake.write_text('''#!/usr/bin/env python3
import os, sys, time, subprocess
from pathlib import Path
if os.environ.get('DNX_TEST_SLOW'):
    marker = Path(os.environ['DNX_TEST_SLOW'])
    subprocess.Popen(['bash', '-c', 'sleep 2; touch \"$1\"', 'test', str(marker) + '.orphan'])
    marker.write_text('running')
    time.sleep(30)
if '--build' in sys.argv:
    if os.environ.get('DNX_TEST_BUILD_FAIL'): sys.exit(9)
    build = Path(sys.argv[sys.argv.index('--build') + 1])
    if os.environ.get('DNX_TEST_PROGRESS'):
        for i in range(1, 5):
            print(f'[{i}/4] Building object {i}', flush=True)
            time.sleep(0.12)
    target = build / 'dark_nexus'
    target.write_text('#!/usr/bin/env bash\\nif [[ "${DNX_TEST_VERSION_FAIL:-}" == 1 ]]; then exit 8; fi\\nprintf "dark-nexus 2.0.0\\\\n"\\n')
    target.chmod(0o755)
else:
    build = Path(sys.argv[sys.argv.index('-B') + 1])
    build.mkdir(parents=True)
    assert not (build.parent / 'dark-nexus').exists()
print('fixture CMake: visible output')
''')
        fake_cmake.chmod(0o755)
        env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'])
        return source, env

    def install(self, *, piped=False, changes=None, code=0):
        source, env = self.fixture()
        env.update(changes or {})
        prefix = self.root / 'install'
        (prefix / 'bin').mkdir(parents=True)
        old = prefix / 'bin' / 'dark-nexus'
        old.write_text('old executable')
        args = ['--skip-deps', '--skip-helpers', '--prefix', str(prefix), '--source', str(source)]
        command = ['bash', '-s', '--', *args] if piped else ['bash', str(INSTALLER), *args]
        result = subprocess.run(command, input=INSTALLER.read_text() if piped else '',
                                env=env, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        self.assertEqual((source / 'dark-nexus' / 'keep').read_text(), 'untouched')
        # Clean up just the log created by this test invocation.
        for line in result.stdout.splitlines():
            if line.startswith('Log: /tmp/dark-nexus-install.'):
                Path(line[5:]).unlink(missing_ok=True)
        return result, prefix

    def test_source_has_no_side_effects(self):
        result = subprocess.run(['bash', '-c', 'source "$1"', 'test', str(INSTALLER)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '', ''))

    def test_help_no_privileges_or_dependencies(self):
        result = subprocess.run(['bash', str(INSTALLER), '--help'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('--skip-helpers', result.stdout)

    def test_invalid_arguments(self):
        for args in [['--unknown'], ['--prefix'], ['--source'], ['--prefix', '/'], ['--prefix', 'relative']]:
            with self.subTest(args=args):
                result = subprocess.run(['bash', str(INSTALLER), *args], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_distribution_detection(self):
        for name, like, expected in [('cachyos', '', 'arch'), ('custom', 'arch', 'arch'),
                                     ('ubuntu', 'debian', 'debian'), ('kali', '', 'debian'),
                                     ('rocky', 'rhel', 'fedora'), ('opensuse-tumbleweed', '', 'suse')]:
            result = self.shell(f'dnx_family {shlex.quote(name)} {shlex.quote(like)}')
            self.assertEqual(result.stdout.strip(), expected)
        self.shell('dnx_family unsupported', code=1)

    def test_already_installed_packages_do_not_contact_repositories(self):
        result = self.shell('''DNX_FAMILY=arch
dnx_installed() { return 0; }
dnx_run() { exit 99; }
dnx_packages Core cmake git curl''')
        self.assertIn('already installed', result.stdout)

    def test_arch_only_missing_packages_no_upgrade_or_refresh(self):
        result = self.shell('''DNX_FAMILY=arch
dnx_installed() { [[ "$1" == present ]]; }
dnx_pacman_busy() { return 1; }
dnx_run() { printf '%s\\n' "$*"; }
dnx_packages Core present whois''')
        self.assertIn('pacman -S --needed --noconfirm whois', result.stdout)
        self.assertNotIn('-Syu', result.stdout)
        self.assertNotIn('-Sy ', result.stdout)
        self.assertNotIn('noconfirm present', result.stdout)

    def test_arch_failure_has_recovery_advice(self):
        result = self.shell('''DNX_FAMILY=arch
dnx_installed() { return 1; }
dnx_pacman_busy() { return 1; }
dnx_run() { return 7; }
dnx_packages Core whois''', code=1)
        self.assertIn('sudo pacman -Syu yourself', result.stderr)

    def test_arch_lock_is_not_deleted(self):
        result = self.shell('''DNX_FAMILY=arch
dnx_installed() { return 1; }
dnx_pacman_busy() { return 0; }
dnx_run() { exit 99; }
dnx_packages Core whois''', code=1)
        self.assertIn('Do not delete its lock', result.stderr)

    def test_apt_refresh_failure_prevents_install(self):
        result = self.shell('''DNX_FAMILY=debian
dnx_installed() { return 1; }
dnx_run() { printf '%s\\n' "$*"; return 42; }
dnx_packages Core cmake''', code=42)
        self.assertIn('Acquire::https::Timeout=30', result.stdout)
        self.assertNotIn('install -y', result.stdout)

    def test_apt_bounded_locks_and_network(self):
        result = self.shell('''DNX_FAMILY=debian
dnx_installed() { return 1; }
dnx_run() { printf '%s\\n' "$*"; }
dnx_packages Core cmake''')
        self.assertIn('DPkg::Lock::Timeout=60', result.stdout)
        self.assertIn('Acquire::Retries=1', result.stdout)
        self.assertIn('install -y cmake', result.stdout)

    def test_rpm_and_suse_install_failures_propagate(self):
        for family in ['fedora', 'suse']:
            self.shell(f'''DNX_FAMILY={family}
dnx_installed() {{ return 1; }}
dnx_run() {{ return 23; }}
dnx_packages Core cmake''', code=23)

    def test_run_streams_output_and_keeps_exit_status(self):
        result = self.shell("dnx_run fixture 5 bash -c 'echo live-output; exit 17'", code=17)
        self.assertIn('live-output', result.stdout)
        self.assertIn('live-output', self.log.read_text())

    def test_run_does_not_inherit_stdin(self):
        result = self.shell("dnx_run fixture 5 bash -c 'if read -r value; then exit 99; fi; echo no-input'")
        self.assertIn('no-input', result.stdout)

    def test_timeout_terminates_child_process_group(self):
        marker = self.root / 'orphan'
        command = f'(sleep 2; touch {shlex.quote(str(marker))}) & wait'
        start = time.monotonic()
        result = self.shell('dnx_run stalled 1 bash -c ' + shlex.quote(command), code=124)
        self.assertLess(time.monotonic() - start, 5)
        self.assertIn('exceeded 1s', result.stderr)
        time.sleep(1.2)
        self.assertFalse(marker.exists(), 'timeout left an orphan download/process')

    def test_log_write_failure_is_not_success(self):
        self.shell(f'DNX_LOG={shlex.quote(str(self.root))}\ndnx_run fixture 5 true', code=1)

    def test_invalid_job_override(self):
        for value in ['0', '-1', 'abc', '999999', '129']:
            self.shell(f'DARK_NEXUS_JOBS={shlex.quote(value)}\ndnx_jobs', code=1)
        result = self.shell('DARK_NEXUS_JOBS=1\ndnx_jobs')
        self.assertEqual(result.stdout.strip(), '1')

    def test_successful_local_install_and_private_work_cleanup(self):
        result, prefix = self.install()
        self.assertIn('Installation complete', result.stdout)
        self.assertIn('fixture CMake: visible output', result.stdout)
        self.assertIn('dark-nexus 2.0.0', (prefix / 'bin' / 'dark-nexus').read_text())
        self.assertEqual((prefix / 'share/wordlists/dark-nexus/best-dns-wordlist.txt').read_text(), 'www\nmail\n')
        self.assertEqual(list((prefix / 'bin').glob('.dark-nexus.*')), [])

    def test_one_command_piped_script_entrypoint(self):
        result, _ = self.install(piped=True)
        self.assertIn('Installation complete', result.stdout)

    def test_build_failure_keeps_previous_executable(self):
        result, prefix = self.install(changes={'DNX_TEST_BUILD_FAIL': '1'}, code=9)
        self.assertEqual((prefix / 'bin/dark-nexus').read_text(), 'old executable')
        self.assertNotIn('Installation complete', result.stdout)

    def test_bad_new_executable_keeps_previous_installation(self):
        result, prefix = self.install(changes={'DNX_TEST_VERSION_FAIL': '1'}, code=8)
        self.assertEqual((prefix / 'bin/dark-nexus').read_text(), 'old executable')
        self.assertFalse((prefix / 'share').exists())

    def test_helper_failure_is_optional(self):
        result = self.shell(f'''DNX_SKIP_HELPERS=0
DNX_SKIP_DEPS=1
DNX_PREFIX={shlex.quote(str(self.root / 'optional'))}
dnx_run() {{ return 19; }}
dnx_helpers''')
        self.assertIn('already installed', result.stderr)

    def test_termination_stops_child_processes_and_preserves_old_binary(self):
        source, env = self.fixture()
        prefix = self.root / 'interrupted'
        (prefix / 'bin').mkdir(parents=True)
        old = prefix / 'bin/dark-nexus'
        old.write_text('old executable')
        marker = self.root / 'active'
        env['DNX_TEST_SLOW'] = str(marker)
        process = subprocess.Popen(['bash', str(INSTALLER), '--skip-deps', '--skip-helpers',
                                    '--prefix', str(prefix), '--source', str(source)],
                                   env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(marker.exists(), 'fixture did not start')
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 143, stdout + stderr)
            self.assertEqual(old.read_text(), 'old executable')
            time.sleep(2.1)
            self.assertFalse(Path(str(marker) + '.orphan').exists())
            for line in stdout.splitlines():
                if line.startswith('Log: /tmp/dark-nexus-install.'):
                    Path(line[5:]).unlink(missing_ok=True)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_existing_unrelated_helper_is_preserved(self):
        target = self.root / 'bin' / 'sherlock'
        target.parent.mkdir()
        target.write_text('user-tool')
        self.shell(f'''DNX_PREFIX={shlex.quote(str(self.root))}
DNX_HELPERS={shlex.quote(str(self.root / 'helpers'))}
dnx_link_helper /other/bin/sherlock sherlock''')
        self.assertEqual(target.read_text(), 'user-tool')

    def terminal_install(self, *, changes=None, args=None, code=0, columns=80, cancel=False):
        source, env = self.fixture()
        env.pop('NO_COLOR', None)
        env.update(TERM='xterm-256color', LANG='C.UTF-8', DNX_TEST_PROGRESS='1')
        env.update(changes or {})
        prefix = self.root / 'terminal-install'
        (prefix / 'bin').mkdir(parents=True)
        (prefix / 'bin/dark-nexus').write_text('old executable')
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, columns, 0, 0))
        marker = self.root / 'terminal-active'
        if cancel:
            env['DNX_TEST_SLOW'] = str(marker)
        process = subprocess.Popen(['bash', str(INSTALLER), '--skip-deps', '--skip-helpers',
                                    '--prefix', str(prefix), '--source', str(source), *(args or [])],
                                   stdin=subprocess.DEVNULL, stdout=slave, stderr=slave, env=env)
        os.close(slave)
        output = bytearray()
        deadline = time.monotonic() + 15
        cancelled = False
        try:
            while time.monotonic() < deadline:
                if cancel and marker.exists() and not cancelled:
                    process.send_signal(signal.SIGTERM)
                    cancelled = True
                ready, _, _ = select.select([master], [], [], 0.05)
                if ready:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO: raise
                        break
                    if not chunk: break
                    output.extend(chunk)
                elif process.poll() is not None:
                    break
            process.wait(timeout=2)
            text = output.decode(errors='replace')
            self.assertEqual(process.returncode, code, text)
            log = next((line[5:].strip() for line in text.splitlines()
                        if line.startswith('Log: /tmp/dark-nexus-install.')), None)
            full_log = Path(log).read_text() if log else ''
            if log: Path(log).unlink(missing_ok=True)
            return text, full_log, prefix
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            os.close(master)

    def test_terminal_panel_has_real_counts_and_completes(self):
        output, log, prefix = self.terminal_install()
        self.assertIn('4/6 Compile', output)
        self.assertIn('4/4 tasks', output)
        self.assertIn('6/6 Complete', output)
        self.assertIn('\x1b[?25l', output)
        self.assertIn('\x1b[?25h', output)
        self.assertIn('\x1b[36m', output)
        self.assertIn('[1/4] Building object 1', log)
        self.assertIn('[4/4] Building object 4', log)
        self.assertIn('2.0.0', (prefix / 'bin/dark-nexus').read_text())

    def test_terminal_panel_no_color(self):
        output, _, _ = self.terminal_install(changes={'NO_COLOR': ''})
        self.assertNotIn('\x1b[36m', output)
        self.assertIn('6/6 Complete', output)
        self.assertIn('\x1b[?25h', output)

    def test_terminal_plain_option(self):
        output, _, _ = self.terminal_install(args=['--no-progress'])
        self.assertNotIn('\x1b', output)
        self.assertIn('fixture CMake: visible output', output)

    def test_dumb_terminal_keeps_plain_logs(self):
        output, _, _ = self.terminal_install(changes={'TERM': 'dumb'})
        self.assertNotIn('\x1b', output)
        self.assertIn('Installation complete', output)

    def test_narrow_terminal_panel(self):
        output, _, _ = self.terminal_install(columns=36)
        self.assertIn('Installation complete', output)
        for frame in re.findall(r'\x1b\[2K(?:\x1b\[36m)?([^\r\n\x1b]+)', output):
            self.assertLessEqual(len(frame), 35, repr(frame))

    def test_terminal_failure_shows_diagnostics_and_restores_cursor(self):
        output, _, prefix = self.terminal_install(changes={'DNX_TEST_BUILD_FAIL': '1'}, code=9)
        self.assertIn('Recent output:', output)
        self.assertIn('failed (exit 9)', output)
        self.assertIn('\x1b[?25h', output)
        self.assertNotIn('6/6 Complete', output)
        self.assertEqual((prefix / 'bin/dark-nexus').read_text(), 'old executable')

    def test_terminal_cancel_restores_cursor(self):
        output, _, prefix = self.terminal_install(cancel=True, code=143)
        self.assertIn('\x1b[?25h', output)
        self.assertNotIn('6/6 Complete', output)
        self.assertEqual((prefix / 'bin/dark-nexus').read_text(), 'old executable')

    def test_progress_does_not_advance_with_elapsed_time(self):
        output = self.shell('''DNX_COLUMNS=80 DNX_PHASE=3 DNX_PHASES=6
DNX_TASK_DONE=0 DNX_TASK_TOTAL=0 DNX_STAGE_TITLE=Configure DNX_OPERATION=Waiting
DNX_UI_COLOR='' DNX_UI_RESET='' DNX_UI_UNICODE=0 DNX_STAGE_SECONDS=$SECONDS
dnx_ui_draw 0
DNX_STAGE_SECONDS=$((SECONDS - 120))
dnx_ui_draw 99''').stdout
        bars = re.findall(r'\[([=\-]+)\]', output)
        self.assertEqual(len(bars), 2)
        self.assertEqual(bars[0], bars[1])

    def test_terminal_batches_logs_and_preserves_partial_lines(self):
        command = "printf partial; sleep 0.2; printf '%s\\n' '-result'; for ((i=1;i<=1000;i++)); do echo \"compiler line $i\"; done"
        result = self.shell('''DNX_UI=1 DNX_UI_COLOR='' DNX_UI_RESET='' DNX_UI_UNICODE=0
DNX_PHASE=4 DNX_PHASES=6 DNX_STAGE_TITLE=Compile DNX_STAGE_SECONDS=$SECONDS
dnx_run fixture 5 bash -c ''' + shlex.quote(command))
        log = self.log.read_text()
        self.assertIn('partial-result', log)
        self.assertIn('compiler line 1000', log)
        self.assertLess(len(result.stdout), len(log), 'terminal should summarize a burst instead of redrawing each log line')


if __name__ == '__main__':
    unittest.main()
