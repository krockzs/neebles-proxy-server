#!/usr/bin/env python3
"""Integration QA for the Tailscale-bound NEEBLES Proxy Server health endpoint.

This test is intentionally read-only and never enables forwarding or Exit Node.
"""
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from urllib.request import urlopen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--port', type=int, default=18877)
    args = parser.parse_args()
    state = json.loads(subprocess.check_output(['/usr/bin/tailscale', 'status', '--json'], timeout=8))
    if state.get('CurrentTailnet', {}).get('Name') != 'olate.pablo@gmail.com':
        print('SKIP: active tailnet is not Stark')
        return 77
    if state.get('BackendState') != 'Running':
        print('SKIP: Tailscale not running')
        return 77
    ips = state.get('Self', {}).get('TailscaleIPs', [])
    ip = next((v for v in ips if ':' not in v and v.startswith('100.')), None)
    if not ip:
        print('SKIP: no Tailscale IPv4 address')
        return 77
    command = [args.binary, '--policy', args.policy, '--port', str(args.port)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        url = f'http://{ip}:{args.port}/health'
        payload = None
        for _ in range(40):
            if process.poll() is not None:
                out, err = process.communicate(timeout=2)
                raise RuntimeError(f'listener exited: {process.returncode}, {err.decode(errors="replace")}')
            try:
                with urlopen(url, timeout=0.4) as response:
                    if response.status != 200:
                        raise RuntimeError(f'unexpected HTTP status {response.status}')
                    payload = json.loads(response.read())
                    break
            except (OSError, TimeoutError):
                time.sleep(0.15)
        if payload is None:
            raise RuntimeError('health endpoint unreachable within deadline')
        assert payload['health'] == 'reachable', payload
        assert payload['tailscale_ipv4'] == ip, payload
        assert payload['exit_ready'] is False, payload
        assert payload['authorization_enforced'] is False, payload
        print(json.dumps({'integration': 'passed', 'ip': ip, 'port': args.port,
                          'http_status': 200, 'exit_ready': payload['exit_ready'],
                          'authorization_enforced': payload['authorization_enforced']}, indent=2))
        return 0
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=3)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
