#!/usr/bin/env python3
"""Verify the active Tailscale grants policy using a read-only control-plane API.

This is a gate, not an activation command. Tokens are read from an inherited FD;
no token is accepted via command-line, environment variable or project file.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

from verify_exit_policy import validate

TAILNET = 'olate.pablo@gmail.com'
CLIENT = '100.90.51.25'


def fetch_policy(token, tailnet=TAILNET, opener=urllib.request.urlopen):
    url = 'https://api.tailscale.com/api/v2/tailnet/' + urllib.parse.quote(tailnet, safe='') + '/acl'
    req = urllib.request.Request(url, headers={
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/json',
        'User-Agent': 'NEEBLES-Proxy-Server/policy-gate',
    }, method='GET')
    with opener(req, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError('unexpected_http_status')
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise RuntimeError('policy_too_large')
        policy = json.loads(raw)
        if not isinstance(policy, dict):
            raise ValueError('policy_not_object')
        return policy


def read_token(fd):
    if fd < 3:
        raise ValueError('credential_fd_must_be_inherited')
    raw = os.read(fd, 8193)
    if len(raw) > 8192:
        raise ValueError('credential_too_large')
    token = raw.decode('utf-8').strip()
    if not token or '\n' in token or '\r' in token:
        raise ValueError('invalid_credential')
    return token


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--credential-fd', type=int, required=True,
                     help='Inherited read-only descriptor containing one temporary API bearer token')
    args = cli.parse_args()
    try:
        token = read_token(args.credential_fd)
        policy = fetch_policy(token)
        errors = validate(policy, CLIENT)
        result = {'verified_live_policy': not errors, 'tailnet': TAILNET,
                  'client': CLIENT, 'errors': errors,
                  'verification': 'tailscale_api_live_read_only',
                  'activation_performed': False}
        print(json.dumps(result, sort_keys=True))
        return 0 if not errors else 7
    except (OSError, ValueError, RuntimeError, urllib.error.URLError, json.JSONDecodeError):
        print(json.dumps({'verified_live_policy': False,
                          'activation_performed': False,
                          'errors': ['live_policy_unavailable_or_invalid']}, sort_keys=True))
        return 8


if __name__ == '__main__':
    sys.exit(main())
