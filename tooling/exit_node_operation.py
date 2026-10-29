#!/usr/bin/env python3
"""Privileged exit-node transition backend. Never a standalone Boss authority.

Boss must grant this operation, own lifecycle and supply a Secrets-brokered,
read-only API credential FD. Local policy files never authorize activation.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

from live_policy_gate import fetch_policy, read_token
from verify_exit_policy import validate

HOST = 'server-20fms4udus'
TAILNET = 'olate.pablo@gmail.com'
SERVER = '100.71.3.52'
CLIENT = '100.90.51.25'
TAILSCALE = '/usr/bin/tailscale'


class TransitionError(RuntimeError):
    pass


def execute(args, timeout=12):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise TransitionError('tailscale_operation_failed')
    return result.stdout


def status(run=execute):
    try:
        data = json.loads(run([TAILSCALE, 'status', '--json']))
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        raise TransitionError('tailscale_status_unavailable') from exc
    if not isinstance(data, dict):
        raise TransitionError('invalid_tailscale_status')
    return data


def assert_identity(state, hostname=socket.gethostname):
    if hostname() != HOST:
        raise TransitionError('wrong_host')
    if state.get('BackendState') != 'Running':
        raise TransitionError('tailscale_not_running')
    if state.get('CurrentTailnet', {}).get('Name') != TAILNET:
        raise TransitionError('wrong_tailnet')
    if SERVER not in state.get('Self', {}).get('TailscaleIPs', []):
        raise TransitionError('wrong_server_ip')


def assert_forwarding(read_text=lambda p: Path(p).read_text()):
    # Backend does not silently modify OS-wide sysctls; Boss must own setup.
    if read_text('/proc/sys/net/ipv4/ip_forward').strip() != '1':
        raise TransitionError('ipv4_forwarding_not_prepared')


def activate(fd, *, run=execute, get_state=None, hostname=socket.gethostname,
             policy_reader=fetch_policy, token_reader=read_token,
             forward_reader=lambda p: Path(p).read_text()):
    if os.geteuid() != 0:
        raise TransitionError('root_authority_required')
    get_state = get_state or (lambda: status(run))
    state = get_state()
    assert_identity(state, hostname)
    assert_forwarding(forward_reader)
    token = token_reader(fd)
    errors = validate(policy_reader(token), CLIENT)
    if errors:
        raise TransitionError('live_policy_does_not_exclusively_authorize_client')
    # Authorization is checked immediately before mutation; no tokens logged.
    run([TAILSCALE, 'set', '--advertise-exit-node=true'])
    post = get_state()
    # This confirms advertisement only, NOT admin approval or client egress.
    if not bool(post.get('Self', {}).get('ExitNodeOption', False)):
        try:
            run([TAILSCALE, 'set', '--advertise-exit-node=false'])
        except Exception:
            raise TransitionError('advertisement_not_confirmed_rollback_failed')
        raise TransitionError('advertisement_not_confirmed_rolled_back')
    return {'advertisement_confirmed': True, 'admin_approval_verified': False,
            'client_egress_verified': False, 'server': SERVER, 'client': CLIENT}


def deactivate(*, run=execute, get_state=None, hostname=socket.gethostname):
    if os.geteuid() != 0:
        raise TransitionError('root_authority_required')
    state = (get_state or (lambda: status(run)))()
    assert_identity(state, hostname)
    run([TAILSCALE, 'set', '--advertise-exit-node=false'])
    post = (get_state or (lambda: status(run)))()
    if bool(post.get('Self', {}).get('ExitNodeOption', False)):
        raise TransitionError('advertisement_still_enabled')
    return {'advertisement_confirmed_off': True}



def observe_exit_node(*, get_state=status, hostname=socket.gethostname):
    """Read-only local observation; never claims policy approval or client egress."""
    state = get_state()
    assert_identity(state, hostname)
    own = state.get('Self', {})
    return {
        'server': SERVER,
        'client': CLIENT,
        'tailnet': TAILNET,
        'advertised': bool(own.get('ExitNodeOption', False)),
        'admin_approval_verified': False,
        'client_egress_verified': False,
        'policy_verified_live': False,
        'ready': False,
        'observation': 'local_tailscale_only',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    op = parser.add_mutually_exclusive_group(required=True)
    op.add_argument('--activate', action='store_true')
    op.add_argument('--deactivate', action='store_true')
    op.add_argument('--status', action='store_true')
    parser.add_argument('--credential-fd', type=int)
    args = parser.parse_args()
    try:
        if args.status:
            result = observe_exit_node()
        elif args.activate:
            if args.credential_fd is None or args.credential_fd < 3:
                raise TransitionError('secrets_credential_fd_required')
            result = activate(args.credential_fd)
        else:
            result = deactivate()
        print(json.dumps({'ok': True, **result}, sort_keys=True))
        return 0
    except (TransitionError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        # Structured failure without leaking tokens or raw process output.
        code = str(exc) if isinstance(exc, TransitionError) else 'operation_unavailable'
        print(json.dumps({'ok': False, 'error': code}, sort_keys=True))
        return 7


if __name__ == '__main__':
    sys.exit(main())
