#!/usr/bin/env python3
"""Exercise bounded subdomain HTTP transport against loopback HTTP/TLS fixtures."""
import http.server
import gzip
import json
import os
from pathlib import Path
import shutil
import socket
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
    hosts = []

    def log_message(self, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_GET(self):
        self.calls.append(self.path)
        self.hosts.append(self.headers.get("Host"))
        try:
            if self.path in ('/interim', '/interim-only'):
                self.wfile.write(b'HTTP/1.1 103 Early Hints\r\nServer: interim\r\n\r\n')
                self.wfile.flush()
                if self.path == '/interim-only':
                    self.close_connection = True
                    return
            if self.path == '/header-stall':
                self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Header: unfinished')
                self.wfile.flush()
                time.sleep(3)
                return
            payload = gzip.compress(b'x' * 60000) if self.path == '/gzip' else None
            oversized = self.path == '/target-large' or getattr(self.server, 'oversized_root', False)
            upgrade = self.path == '/upgrade' or getattr(self.server, 'upgrade_root', False)
            self.send_response(101 if upgrade else 302 if self.path == '/redirect' else 404 if self.path == '/missing' else 200)
            if self.path == '/redirect':
                self.send_header('Location', '/destination')
                self.send_header('Content-Length', '0')
            elif self.path == '/headers':
                self.send_header('X-Large', 'x' * 70000)
                self.send_header('Content-Length', '0')
            elif self.path == '/body':
                self.send_header('Content-Length', str(2 * 1024 * 1024))
            elif oversized:
                self.send_header('Content-Length', '60000')
            elif self.path == '/exact-target':
                self.send_header('Content-Length', '50000')
            elif payload is not None:
                self.send_header('Content-Encoding', 'gzip')
                self.send_header('Content-Length', str(len(payload)))
            elif self.path in ('/hang', '/partial'):
                self.send_header('Content-Length', '10000')
            elif self.path == '/stream':
                self.send_header('Connection', 'close')
            elif self.path == '/trailers':
                self.send_header('Transfer-Encoding', 'chunked')
            elif upgrade:
                self.send_header('Connection', 'upgrade')
                self.send_header('Upgrade', 'websocket')
            else:
                self.send_header('Content-Length', '5')
            self.end_headers()
            self.wfile.flush()
            if upgrade:
                self.close_connection = True
            elif self.path == '/trailers':
                self.wfile.write(b'5\r\nhello\r\n0\r\nX-Powered-By: PHP\r\n\r\n')
                self.wfile.flush()
            elif self.path in ('/hang', '/partial'):
                if self.path == '/partial':
                    self.wfile.write(b'partial')
                    self.wfile.flush()
                time.sleep(3)
            elif self.path in ('/body', '/stream'):
                for _ in range(2048):
                    self.wfile.write(b'x' * 1024)
                self.wfile.flush()
            elif oversized or self.path == '/exact-target':
                self.wfile.write(b'x' * (60000 if oversized else 50000))
                self.wfile.flush()
            elif payload is not None:
                self.wfile.write(payload)
                self.wfile.flush()
            elif self.path not in ('/redirect', '/headers'):
                self.wfile.write(b'hello')
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_HEAD(self):
        self.calls.append('HEAD ' + self.path)
        self.send_response(200)
        self.send_header('Content-Length', '60000')
        self.end_headers()

    def do_CONNECT(self):
        # A local proxy stub that acknowledges CONNECT but never contacts an upstream.
        self.calls.append('CONNECT ' + self.path)
        self.send_response(200, 'Connection established')
        self.send_header('X-Proxy-Only', 'fixture')
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: subdomain_http_tests.py /path/to/subdomain_http_fixture')
    fixture = str(Path(sys.argv[1]).resolve(strict=True))
    env = dict(os.environ, NO_PROXY='*', no_proxy='*')
    env.pop('DNX_FIXTURE_CA', None)
    server = Server(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = 'http://127.0.0.1:' + str(server.server_port)
    checks = 0

    def run(mode, path=None, url=None, extra_env=None, addresses=()):
        nonlocal checks
        args = [fixture, mode]
        if path is not None or url is not None:
            args.append(url if url is not None else origin + path)
        args.extend(addresses)
        result = subprocess.run(args, env=dict(env, **(extra_env or {})), capture_output=True, text=True, timeout=8)
        assert result.returncode == 0, (mode, result.stderr)
        assert not result.stderr, (mode, result.stderr)
        checks += 1
        return json.loads(result.stdout)

    try:
        good = run('get', '/')
        assert good['success'] and good['http_code'] == 200 and good['body_size'] == 5, good
        assert good['headers_complete'] and good['body_complete'], good
        assert good['effective_url'] == origin + '/', good
        for mode, path, cap in [('get', '/body', 1024 * 1024), ('get', '/stream', 1024 * 1024),
                                ('target', '/stream', 50000), ('get', '/headers', 1024 * 1024)]:
            result = run(mode, path)
            assert result['truncated'] and not result['success'] and result['http_code'] == 200, result
            assert not result['body_complete'], result
            assert result['body_size'] <= cap and result['header_size'] <= 64 * 1024, result
            if path == '/headers':
                assert not result['headers_complete'], result
        for path in ('/target-large', '/gzip'):
            result = run('target', path)
            assert result['http_code'] == 200 and result['truncated'] and not result['success'], result
            assert result['body_size'] == 50000 and result['headers_complete'] and not result['body_complete'], result
        exact = run('target', '/exact-target')
        assert exact['success'] and exact['body_size'] == 50000 and not exact['truncated'], exact
        missing = run('target', '/missing')
        assert missing['http_code'] == 404 and missing['body_complete'] and not missing['success'], missing
        timeout = run('timeout', '/partial')
        assert timeout['timed_out'] and timeout['http_code'] == 200 and not timeout['success'], timeout
        assert timeout['headers_complete'] and not timeout['body_complete'], timeout
        assert timeout['elapsed_ms'] < 1800, timeout
        deadline = run('deadline', '/hang')
        assert deadline['timed_out'] and not deadline['body_complete'] and not deadline['global_cancelled'], deadline
        assert deadline['elapsed_ms'] < 1000, deadline
        before = len(Handler.calls)
        expired = run('pre-deadline', '/')
        assert expired['timed_out'] and not expired['global_cancelled'] and len(Handler.calls) == before, expired
        stalled = run('timeout', '/header-stall')
        assert stalled['http_code'] == 200 and stalled['timed_out'] and not stalled['headers_complete'], stalled
        cancelled = run('cancel', '/hang')
        assert cancelled['cancelled'] and not cancelled['success'] and cancelled['http_code'] == 200, cancelled
        assert not cancelled['body_complete'], cancelled
        assert cancelled['elapsed_ms'] < 2000, cancelled
        before = len(Handler.calls)
        early = run('pre-cancel', '/')
        assert early['cancelled'] and len(Handler.calls) == before, early
        redirected = run('get', '/redirect')
        assert redirected['http_code'] == 302 and not redirected['success'], redirected
        assert '/destination' not in Handler.calls, Handler.calls
        interim = run('get', '/interim')
        assert interim['http_code'] == 200 and interim['success'] and interim['headers_complete'], interim
        assert 'Server: interim' not in interim['headers'], interim
        trailers = run('get', '/trailers')
        assert trailers['success'] and trailers['body_size'] == 5, trailers
        assert 'X-Powered-By' not in trailers['headers'], trailers
        upgrade = run('get', '/upgrade')
        assert upgrade['http_code'] == 101 and upgrade['headers_complete'] and not upgrade['success'], upgrade
        interim_only = run('get', '/interim-only')
        assert interim_only['http_code'] == 0 and not interim_only['success'] and not interim_only['headers_complete'], interim_only
        proxy_only = run('get', url='https://127.0.0.1:1/', extra_env={
            'NO_PROXY': '', 'no_proxy': '', 'https_proxy': origin, 'HTTPS_PROXY': origin})
        assert proxy_only['http_code'] == 0 and not proxy_only['headers_complete'], proxy_only
        assert proxy_only['headers'] == '', proxy_only
        for mode in ('probe', 'head-probe'):
            fallback = run(mode, url='127.0.0.1:' + str(server.server_port))
            assert fallback['http_code'] == 200 and fallback['body_complete'], fallback
            assert len(fallback['attempts']) == 2 and fallback['attempts'][0]['http_code'] == 0, fallback
            assert fallback['attempts'][0]['requested_url'].startswith('https://'), fallback
            assert fallback['attempts'][1]['requested_url'].startswith('http://'), fallback
            assert fallback['method'] == ('HEAD' if mode == 'head-probe' else 'GET'), fallback
        name = 'bound.example.test:' + str(server.server_port)
        proxy_env = {'NO_PROXY': '', 'no_proxy': '', 'http_proxy': origin, 'https_proxy': origin,
                     'HTTP_PROXY': origin, 'HTTPS_PROXY': origin, 'ALL_PROXY': origin, 'all_proxy': origin}
        before = len(Handler.calls)
        pinned = run('pinned-probe', url=name, extra_env=proxy_env, addresses=['127.0.0.2', '127.0.0.1'])
        assert pinned['success'] and pinned['dns_pinned'] and pinned['primary_ip'] == '127.0.0.1', pinned
        assert all(a['dns_pinned'] for a in pinned['attempts']), pinned
        assert Handler.hosts[-1] == name and len(Handler.calls) == before + 1, Handler.calls
        before = len(Handler.calls)
        invalid = run('pinned-probe', url=name, addresses=['127.0.0.1', 'bad'])
        assert not invalid['dns_pinned'] and not invalid['success'] and len(Handler.calls) == before, invalid
        literal = run('pinned-probe', url='127.0.0.1:' + str(server.server_port), addresses=['127.0.0.2'])
        assert not literal['dns_pinned'] and not literal['success'] and len(Handler.calls) == before, literal
        assert all(not attempt['dns_pinned'] for attempt in literal['attempts']), literal
        too_many = run('pinned-probe', url=name, addresses=['127.0.0.1'] * 257)
        assert not too_many['dns_pinned'] and len(Handler.calls) == before, too_many
        unbound = run('probe', url=name, extra_env=proxy_env)
        assert not unbound['dns_pinned'] and any(call.startswith('CONNECT ') for call in Handler.calls[before:]), unbound
        assert good['primary_ip'] == '127.0.0.1' and not good['dns_pinned'], good
        try:
            class Server6(Server):
                address_family = socket.AF_INET6
            ipv6 = Server6(('::1', 0), Handler)
        except OSError:
            ipv6 = None
        if ipv6:
            threading.Thread(target=ipv6.serve_forever, daemon=True).start()
            try:
                bound6 = run('pinned-probe', url='bound.example.test:' + str(ipv6.server_port), addresses=['::1'])
                assert bound6['success'] and bound6['primary_ip'] == '::1' and bound6['dns_pinned'], bound6
            finally:
                ipv6.shutdown()
                ipv6.server_close()
        title = run('title')['title']
        assert 'café' in title and '\ufffd' in title and '\x1b' not in title, title
        assert run('warnings')['count'] == 64
        openssl = shutil.which('openssl')
        assert openssl, 'openssl executable required for the TLS verification fixture'
        with tempfile.TemporaryDirectory(prefix='dark-nexus-http-tls-') as temporary:
            root = Path(temporary)
            key, cert = root / 'key.pem', root / 'cert.pem'
            subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=DNS:localhost,DNS:bound.example.test,IP:127.0.0.1'],
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
                named = run('pinned-probe', url='bound.example.test:' + str(tls.server_port),
                            addresses=['127.0.0.1'], extra_env={'DNX_FIXTURE_CA': str(cert)})
                assert named['success'] and named['dns_pinned'] and named['primary_ip'] == '127.0.0.1', named
                assert Handler.hosts[-1] == 'bound.example.test:' + str(tls.server_port), Handler.hosts
                wrong = run('pinned-probe', url='wrong.example.test:' + str(tls.server_port),
                            addresses=['127.0.0.1'], extra_env={'DNX_FIXTURE_CA': str(cert)})
                assert not wrong['success'] and wrong['attempts'][0]['transport_code'] != 0, wrong
                tls.oversized_root = True
                trusted = run('probe', url='127.0.0.1:' + str(tls.server_port), extra_env={'DNX_FIXTURE_CA': str(cert)})
                assert trusted['http_code'] == 200 and trusted['truncated'] and not trusted['body_complete'], trusted
                assert trusted['headers_complete'] and trusted['body_size'] == 50000, trusted
                assert len(trusted['attempts']) == 1 and trusted['requested_url'].startswith('https://'), trusted
                tls.oversized_root = False
                tls.upgrade_root = True
                upgraded = run('probe', url='127.0.0.1:' + str(tls.server_port), extra_env={'DNX_FIXTURE_CA': str(cert)})
                assert upgraded['http_code'] == 101 and len(upgraded['attempts']) == 1, upgraded
            finally:
                tls.shutdown()
                tls.server_close()
    finally:
        server.shutdown()
        server.server_close()
    print(f'{checks} subdomain HTTP process checks passed (loopback only)')


if __name__ == '__main__':
    main()
