#!/usr/bin/env python3
"""Measure current JS discovery configurations against a loopback-only fixture."""
import argparse
import collections
import http.server
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import tempfile
import threading
import time
from benchmark_process import run_measured

PAGES = 32
SCRIPTS = 50
HTML = ('<html><body>' + ''.join(
    "<script src='/script/%d.js'></script>" % i for i in range(SCRIPTS)
) + '</body></html>').encode()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, delay_ms):
        super().__init__(('127.0.0.1', 0), Handler)
        self.delay = delay_ms / 1000
        self.lock = threading.Lock()
        self.requests = collections.Counter()
        self.active = 0
        self.max_active = 0
        self.invalid = 0


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        page = re.fullmatch(r'/page/(0|[1-9][0-9]?)', self.path)
        script = re.fullmatch(r'/script/(0|[1-9][0-9]?)\.js', self.path)
        valid_page = page and int(page.group(1)) < PAGES
        valid_script = script and int(script.group(1)) < SCRIPTS
        # Absolute request targets, proxy requests and paths outside the fixture are rejected.
        if not (valid_page or valid_script):
            with self.server.lock:
                self.server.invalid += 1
            self.send_error(404)
            return
        with self.server.lock:
            self.server.requests[self.path] += 1
            self.server.active += 1
            self.server.max_active = max(self.server.max_active, self.server.active)
        try:
            time.sleep(self.server.delay)
        finally:
            with self.server.lock:
                self.server.active -= 1
        # Count concurrent service delays. The response can reach a client
        # before this handler returns, so handler lifetime is not a worker cap.
        body = HTML if valid_page else ('const host = "asset%s.localhost";' % script.group(1)).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html' if valid_page else 'application/javascript')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_case(binary, mode, workers, delay_ms=20):
    """Run and validate one configuration; elapsed time covers the complete process."""
    if mode not in ('cached', 'uncached') or not 1 <= workers <= 8 or delay_ms < 0:
        raise ValueError('invalid benchmark configuration')
    server = Server(delay_ms)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # A minimal environment avoids proxy settings and inherited credentials.
        env = {'PATH': os.defpath, 'NO_PROXY': '*', 'no_proxy': '*', 'LC_ALL': 'C'}
        process = run_measured([str(Path(binary).resolve()), str(server.server_port), mode, str(workers)],
                               timeout=45, env=env)
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, 'JS benchmark', process.stdout, process.stderr)
        elapsed = process.elapsed_seconds
        result = json.loads(process.stdout)
        if process.memory_samples == 0 or process.peak_rss_kib <= 0:
            raise ValueError('no child memory samples were collected')
        with server.lock:
            counts = dict(server.requests)
            max_active = server.max_active
            invalid = server.invalid
        expected_names = {'asset%d.localhost' % i for i in range(SCRIPTS)}
        if set(result['candidates']) != expected_names or len(result['candidates']) != SCRIPTS:
            raise ValueError('unexpected candidate names')
        expected = {'/script/%d.js' % i: 1 for i in range(SCRIPTS)}
        if mode == 'uncached':
            expected.update({'/page/%d' % i: 1 for i in range(PAGES)})
        if counts != expected or invalid or max_active > workers:
            raise ValueError('unexpected request counts, paths or concurrency')
        progress = result['progress']
        if (progress['pages_attempted'] != PAGES or progress['pages_processed'] != PAGES or
                progress['cached_pages'] != (PAGES if mode == 'cached' else 0) or
                progress['scripts_total'] != SCRIPTS or progress['scripts_completed'] != SCRIPTS or
                progress['candidates'] != SCRIPTS or progress['budget_exhausted'] or result['errors']):
            raise ValueError('unexpected discovery progress or errors')
        return {'elapsed_seconds': elapsed, 'peak_rss_kib': process.peak_rss_kib, 'result': result,
                'memory_samples': process.memory_samples, 'wait4_peak_rss_kib': process.wait4_peak_rss_kib,
                'server': {'pages': sum(v for k, v in counts.items() if k.startswith('/page/')),
                           'scripts': sum(v for k, v in counts.items() if k.startswith('/script/')),
                           'request_counts': counts, 'peak_delayed_requests': max_active}}
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def write_output(path, data):
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent, delete=False) as output:
            temporary = output.name
            json.dump(data, output, indent=2)
            output.write('\n')
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('--repetitions', type=int, default=5)
    parser.add_argument('--warmups', type=int, default=1)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if args.repetitions < 1 or args.warmups < 0:
        parser.error('repetitions must be positive and warmups nonnegative')
    data = {'description': 'Current configuration comparison on a local fixture',
            'delay_ms': 20, 'repetitions': args.repetitions, 'warmups': args.warmups, 'cases': []}
    for mode, workers in [('uncached', 1), ('uncached', 4), ('cached', 4)]:
        for _ in range(args.warmups):
            run_case(args.binary, mode, workers)
        case = {'mode': mode, 'workers': workers, 'runs': []}
        data['cases'].append(case)
        for _ in range(args.repetitions):
            case['runs'].append(run_case(args.binary, mode, workers))
            times = [run['elapsed_seconds'] for run in case['runs']]
            case['elapsed_seconds'] = {'median': statistics.median(times), 'min': min(times), 'max': max(times)}
            write_output(args.output, data)


if __name__ == '__main__':
    main()
