"""Measure Linux child timing and sampled memory after exec."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace


def run_measured(command, *, timeout, cwd=None, env=None):
    """Capture bounded execution and sample the child's VmHWM every 2 ms.

    Temporary files avoid pipe deadlocks while wait4 owns child reaping.
    VmHWM belongs to the executable's current memory map. wait4 ru_maxrss can
    include the Python runner's inherited pre-exec RSS; retain it separately.
    """
    if timeout <= 0 or not hasattr(os, 'wait4'):
        raise ValueError('a positive timeout and Linux wait4 support are required')
    with tempfile.TemporaryFile(mode='w+b') as stdout, tempfile.TemporaryFile(mode='w+b') as stderr:
        began = time.perf_counter()
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr)
        peak_rss = 0
        samples = 0
        try:
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                try:
                    lines = Path(f'/proc/{process.pid}/status').read_text().splitlines()
                    for line in lines:
                        if line.startswith('VmHWM:'):
                            peak_rss = max(peak_rss, int(line.split()[1]))
                            samples += 1
                            break
                except (FileNotFoundError, ProcessLookupError):
                    pass
                if time.perf_counter() - began >= timeout:
                    raise subprocess.TimeoutExpired(command, timeout)
                time.sleep(0.002)
            elapsed = time.perf_counter() - began
            stdout.seek(0)
            stderr.seek(0)
            return SimpleNamespace(returncode=process.returncode,
                                   stdout=stdout.read().decode('utf-8'),
                                   stderr=stderr.read().decode('utf-8'),
                                   elapsed_seconds=elapsed, peak_rss_kib=peak_rss,
                                   memory_samples=samples, wait4_peak_rss_kib=int(usage.ru_maxrss))
        finally:
            if process.returncode is None:
                process.kill()
                process.wait()
