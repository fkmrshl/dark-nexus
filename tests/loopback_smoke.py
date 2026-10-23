#!/usr/bin/env python3
"""Optional real-socket smoke test; only 127.0.0.1, no external targets.
Run manually: python3 tests/loopback_smoke.py ./build/dark_nexus
"""
import json
from pathlib import Path
import socket
import subprocess
import sys
import threading

binary = str(Path(sys.argv[1]).resolve())
listener = socket.socket()
listener.bind(('127.0.0.1', 0))
listener.listen(16)
listener.settimeout(0.2)
closed = socket.socket()
closed.bind(('127.0.0.1', 0))  # Reserve a TCP port, deliberately without listen().
open_port, closed_port = listener.getsockname()[1], closed.getsockname()[1]
stop = threading.Event()

def serve():
    while not stop.is_set():
        try:
            connection, _ = listener.accept()
            connection.sendall(b'local fixture\r\n')
            connection.close()
        except socket.timeout:
            continue
        except OSError:
            break

worker = threading.Thread(target=serve)
worker.start()
try:
    result = subprocess.run([
        binary, '--portscan', '127.0.0.1', '--ports', f'{open_port},{closed_port}',
        '--connect', '--threads', '1', '--timeout', '200', '--banner-timeout', '100',
        '--retries', '0', '--no-http', '--no-tls', '--quiet', '--output', '-'],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    ports = {record['port'] for record in report['ports']}
    assert open_port in ports and closed_port not in ports, (ports, open_port, closed_port)
    assert report['target'] == '127.0.0.1' and report['resolved_ip'] == '127.0.0.1'
    assert result.stderr == '' and '\x1b' not in result.stdout
    print('loopback: open/closed TCP ports, worker overrides and clean JSON stdout passed')
finally:
    stop.set()
    listener.close()
    closed.close()
    worker.join()
