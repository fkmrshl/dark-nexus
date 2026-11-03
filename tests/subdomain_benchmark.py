#!/usr/bin/env python3
"""Repeated local DNS/JS benchmarks with raw measurements and build provenance."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys

sys.dont_write_bytecode = True
import dns_degradation_benchmark as dns
import subdomain_js_benchmark as js


def summary(rows):
    times = [row['elapsed_seconds'] for row in rows]
    memory = [row['peak_rss_kib'] for row in rows]
    return {'samples': len(rows), 'median_seconds': statistics.median(times),
            'min_seconds': min(times), 'max_seconds': max(times),
            'median_peak_rss_kib': statistics.median(memory), 'max_peak_rss_kib': max(memory)}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def release_build(binary):
    cache = binary.parent / 'CMakeCache.txt'
    values = {}
    for line in cache.read_text().splitlines():
        if '=' in line and ':' in line.split('=', 1)[0]:
            key, value = line.split('=', 1)
            values[key.split(':', 1)[0]] = value
    if values.get('CMAKE_BUILD_TYPE') != 'Release':
        raise ValueError('benchmark binaries must come from CMAKE_BUILD_TYPE=Release builds')
    flags = ' '.join(values.get(key, '') for key in ('CMAKE_CXX_FLAGS', 'CMAKE_CXX_FLAGS_RELEASE',
                                                   'CMAKE_EXE_LINKER_FLAGS', 'CMAKE_EXE_LINKER_FLAGS_RELEASE'))
    if 'sanitize' in flags:
        raise ValueError('sanitizer builds must not be used for performance claims')
    return {'cmake_type': values['CMAKE_BUILD_TYPE'], 'generator': values.get('CMAKE_GENERATOR'),
            'cxx_flags': values.get('CMAKE_CXX_FLAGS', ''),
            'release_flags': values.get('CMAKE_CXX_FLAGS_RELEASE', ''),
            'linker_flags': values.get('CMAKE_EXE_LINKER_FLAGS', ''),
            'release_linker_flags': values.get('CMAKE_EXE_LINKER_FLAGS_RELEASE', '')}


def host_info(cpu_label=None):
    memory = next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                  if line.startswith('MemTotal:'))
    return {'system': platform.system(), 'kernel': platform.release(), 'architecture': platform.machine(),
            'cpu': cpu_label, 'cpu_source': 'owner-provided public label' if cpu_label else 'withheld',
            'logical_cpus': os.cpu_count(), 'memory_kib': int(memory),
            'python': platform.python_version(),
            'compiler': subprocess.check_output(['c++', '--version'], text=True).splitlines()[0],
            'libraries': {name: subprocess.check_output(['pkg-config', '--modversion', name], text=True).strip()
                          for name in ('libcurl', 'openssl', 'liburing')},
            'c_ares': '1.28.1 (CMake pinned source)'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--js-binary', type=Path, required=True)
    parser.add_argument('--current-revision', required=True)
    parser.add_argument('--baseline-revision', required=True)
    parser.add_argument('--cpu-label', help='optional owner-provided public CPU label; model omitted by default')
    parser.add_argument('--quick-repetitions', type=int, default=5)
    parser.add_argument('--stress-repetitions', type=int, default=3)
    parser.add_argument('--js-repetitions', type=int, default=5)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error('fixture assertions require Python without -O/PYTHONOPTIMIZE')
    if os.geteuid() == 0:
        parser.error('use an ordinary user; all fixtures use unprivileged loopback ports')
    if min(args.quick_repetitions, args.stress_repetitions, args.js_repetitions) < 1:
        parser.error('repetition counts must be positive')
    binaries = {'current': args.binary.resolve(strict=True), 'baseline': args.baseline.resolve(strict=True)}
    js_binary = args.js_binary.resolve(strict=True)
    here = Path(__file__).parent
    harness_files = ['benchmark_process.py', 'dns_degradation_benchmark.py', 'subdomain_benchmark.py',
                     'subdomain_cli_integration.py', 'subdomain_js_benchmark.py', 'subdomain_js_benchmark.cpp']
    data = {'schema': 'dark-nexus-local-benchmark/1', 'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'host': host_info(args.cpu_label), 'build': {'cmake_type': 'Release', 'app_optimization': '-O2',
                                        'js_optimization': '-O2', 'cxx_standard': 17, 'sanitizers': False},
            'products': {key: {'revision': getattr(args, key + '_revision'), 'binary_sha256': digest(binary),
                               'build': release_build(binary)}
                         for key, binary in binaries.items()},
            'js_binary_sha256': digest(js_binary),
            'harness_sha256': {file: digest(here / file) for file in harness_files},
            'protocol': {'dns': 'real CLI, A+AAAA, no enrichment/permutations/deep-passive, automatic exports included',
                         'dns_warmups': 'one discarded healthy/loss run per binary; stress cases have no discarded runs',
                         'order': 'paired current/baseline; order reverses on alternating repetitions',
                         'js': 'current-source stage only, real HTTP fixture, 32 pages/50 scripts/20ms reply delay',
                         'js_warmups': 1,
                         'rss': 'Child /proc/PID/status VmHWM sampled every 2ms, KiB; may miss the final interval',
                         'wait4_rss': 'OS lifetime peak also recorded; may include inherited Python RSS before exec',
                         'timing': 'process launch to exit; verification and fixture setup/teardown excluded',
                         'statistics': 'median and min/max; no percentile estimate from small samples'},
            'dns': [], 'js': []}
    fixture = dns.fixtures(binaries['current'])
    data['harness_sha256']['CMakeLists.txt'] = digest(here.parent / 'CMakeLists.txt')
    release_build(js_binary)
    comparable = ('cmake_type', 'cxx_flags', 'release_flags', 'linker_flags', 'release_linker_flags')
    if any(data['products']['current']['build'][key] != data['products']['baseline']['build'][key]
           for key in comparable):
        raise ValueError('current and baseline builds must use matching optimization/linker flags')
    js.write_output(args.output, data)
    for case in ('healthy', 'loss', 'delayed', 'outage'):
        repetitions = args.quick_repetitions if case in ('healthy', 'loss') else args.stress_repetitions
        warmups = 1 if case in ('healthy', 'loss') else 0
        rows = {version: [] for version in binaries}
        entry = {'case': case, 'options': dns.CASES[case], 'warmups_per_binary': warmups,
                 'runs': rows, 'summary': {}}
        data['dns'].append(entry)
        for _ in range(warmups):
            for version, binary in binaries.items():
                dns.run_case(binary, fixture, case, dns.CASES[case], version == 'baseline')
        for repetition in range(repetitions):
            order = ('current', 'baseline') if repetition % 2 == 0 else ('baseline', 'current')
            for version in order:
                row = dns.run_case(binaries[version], fixture, case, dns.CASES[case], version == 'baseline')
                row['repetition'] = repetition + 1
                rows[version].append(row)
                entry['summary'][version] = summary(rows[version])
                if case != 'outage' and all(run['status'] == 'complete' for run in rows[version]):
                    entry['summary'][version]['completed_candidates_per_second'] = (
                        dns.CASES[case]['count'] / entry['summary'][version]['median_seconds'])
                js.write_output(args.output, data)
                print(json.dumps({'stage': 'dns', 'case': case, 'version': version,
                                  'repetition': repetition + 1, 'seconds': row['elapsed_seconds'],
                                  'status': row['status'], 'resolved': row['resolved']}), flush=True)
    for mode, workers in (('uncached', 1), ('uncached', 4), ('cached', 4)):
        js.run_case(js_binary, mode, workers)
        entry = {'mode': mode, 'workers': workers, 'warmups': 1, 'delay_ms': 20, 'runs': []}
        data['js'].append(entry)
        for repetition in range(args.js_repetitions):
            row = js.run_case(js_binary, mode, workers)
            row['repetition'] = repetition + 1
            entry['runs'].append(row)
            entry['summary'] = summary(entry['runs'])
            js.write_output(args.output, data)
            print(json.dumps({'stage': 'js', 'mode': mode, 'workers': workers,
                              'repetition': repetition + 1, 'seconds': row['elapsed_seconds']}), flush=True)
    data['completed_at_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    js.write_output(args.output, data)


if __name__ == '__main__':
    main()
