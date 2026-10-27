#!/usr/bin/env python3
"""Exercise bounded subdomain HTTP transport against loopback HTTP/TLS fixtures."""
import http.server
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    calls = []

    def log_message(self, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_GET(self):
        self.calls.append(self.path)
        try:
            self.send_response(302 if self.path == '/redirect' else 200)
            if self.path == '/redirect':
                self.send_header('Location', '/destination')
                self.send_header('Content-Length', '0')
            elif self.path == '/headers':
                self.send_header('X-Large', 'x' * 70000)
                self.send_header('Content-Length', '0')
            elif self.path == '/body':
                self.send_header('Content-Length', str(2 * 1024 * 1024))
            elif self.path in ('/hang', '/partial'):
                self.send_header('Content-Length', '10000')
            elif self.path == '/stream':
                self.send_header('Connection', 'close')
            else:
                self.send_header('Content-Length', '5')
            self.end_headers()
            self.wfile.flush()
            if self.path in ('/hang', '/partial'):
                if self.path == '/partial':
                    self.wfile.write(b'partial')
                    self.wfile.flush()
                time.sleep(3)
            elif self.path in ('/body', '/stream'):
                for _ in range(2048):
                    self.wfile.write(b'x' * 1024)
                self.wfile.flush()
            elif self.path not in ('/redirect', '/headers'):
                self.wfile.write(b'hello')
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: subdomain_http_tests.py /path/to/subdomain_http_fixture')
    fixture = str(Path(sys.argv[1]).resolve(strict=True))
    env = dict(os.environ, NO_PROXY='*', no_proxy='*')
    server = Server(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = 'http://127.0.0.1:' + str(server.server_port)
    checks = 0

    def run(mode, path=None, url=None):
        nonlocal checks
        args = [fixture, mode]
        if path is not None or url is not None:
            args.append(url if url is not None else origin + path)
        result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=8)
        assert result.returncode == 0, (mode, result.stderr)
        assert not result.stderr, (mode, result.stderr)
        checks += 1
        return json.loads(result.stdout)

    try:
        good = run('get', '/')
        assert good['success'] and good['http_code'] == 200 and good['body_size'] == 5, good
        for mode, path, cap in [('get', '/body', 1024 * 1024), ('get', '/stream', 1024 * 1024),
                                ('target', '/stream', 50000), ('get', '/headers', 1024 * 1024)]:
            result = run(mode, path)
            assert result['truncated'] and not result['success'] and result['http_code'] == 0, result
            assert result['body_size'] <= cap and result['header_size'] <= 64 * 1024, result
        timeout = run('timeout', '/partial')
        assert timeout['timed_out'] and timeout['http_code'] == 0 and not timeout['success'], timeout
        assert timeout['elapsed_ms'] < 1800, timeout
        cancelled = run('cancel', '/hang')
        assert cancelled['cancelled'] and not cancelled['success'] and cancelled['http_code'] == 0, cancelled
        assert cancelled['elapsed_ms'] < 2000, cancelled
        before = len(Handler.calls)
        early = run('pre-cancel', '/')
        assert early['cancelled'] and len(Handler.calls) == before, early
        redirected = run('get', '/redirect')
        assert redirected['http_code'] == 302 and not redirected['success'], redirected
        assert '/destination' not in Handler.calls, Handler.calls
        title = run('title')['title']
        assert 'café' in title and '\ufffd' in title and '\x1b' not in title, title
        assert run('warnings')['count'] == 64
        openssl = shutil.which('openssl')
        assert openssl, 'openssl executable required for the TLS verification fixture'
        with tempfile.TemporaryDirectory(prefix='dark-nexus-http-tls-') as temporary:
            root = Path(temporary)
            key, cert = root / 'key.pem', root / 'cert.pem'
            subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost'],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
            tls = Server(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            tls.socket = context.wrap_socket(tls.socket, server_side=True)
            threading.Thread(target=tls.serve_forever, daemon=True).start()
            try:
                for mode in ('get', 'target'):
                    result = run(mode, url='https://127.0.0.1:' + str(tls.server_port) + '/')
                    assert not result['success'] and result['http_code'] == 0 and result['transport_code'] != 0, result
            finally:
                tls.shutdown()
                tls.server_close()
    finally:
        server.shutdown()
        server.server_close()
    print(f'{checks} subdomain HTTP process checks passed (loopback only)')


if __name__ == '__main__':
    main()
