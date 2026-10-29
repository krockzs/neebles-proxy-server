#!/usr/bin/env python3
"""Fail-closed verification of a Tailscale policy snapshot for one exit-node client.

This validates policy *content*, not its deployment or the status of the control plane.
"""
import argparse
import ipaddress
import json
from pathlib import Path

INTERNET = 'autogroup:internet'


def validate(policy, client):
    errors = []
    try:
        ip = ipaddress.IPv4Address(client)
        if not str(ip).startswith('100.'):
            errors.append('client_is_not_a_tailscale_ipv4')
    except ipaddress.AddressValueError:
        errors.append('invalid_client_ipv4')
    if not isinstance(policy, dict):
        return ['policy_not_object']
    grants = policy.get('grants', [])
    acls = policy.get('acls', [])
    if not isinstance(grants, list) or not isinstance(acls, list):
        return ['invalid_grants_or_acls']
    exact = False
    for i, grant in enumerate(grants):
        if not isinstance(grant, dict):
            errors.append(f'grant_{i}_invalid'); continue
        dst, src = grant.get('dst', []), grant.get('src', [])
        if not isinstance(dst, list) or not isinstance(src, list):
            errors.append(f'grant_{i}_selectors_invalid'); continue
        if INTERNET not in dst:
            continue
        if src == [client] and dst == [INTERNET] and grant.get('ip') == ['*']:
            if set(grant) - {'src','dst','ip'}:
                errors.append(f'grant_{i}_unsupported_conditions')
            else:
                exact = True
        else:
            errors.append(f'grant_{i}_internet_access_not_exclusive')
    for i, acl in enumerate(acls):
        if not isinstance(acl, dict):
            errors.append(f'acl_{i}_invalid'); continue
        dst = acl.get('dst', [])
        if not isinstance(dst, list):
            errors.append(f'acl_{i}_destinations_invalid'); continue
        if any(isinstance(x,str) and (x == '*:*' or x.startswith(INTERNET + ':')) for x in dst):
            errors.append(f'acl_{i}_internet_access_not_exclusive')
    if not exact:
        errors.append('exact_client_internet_grant_missing')
    return errors


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--policy', required=True, type=Path)
    cli.add_argument('--client', default='100.90.51.25')
    args = cli.parse_args()
    try:
        data = json.loads(args.policy.read_text())
    except (ValueError, OSError) as exc:
        print(json.dumps({'ok':False,'errors':['cannot_read_json'],'detail':str(exc)}))
        return 2
    errors = validate(data, args.client)
    print(json.dumps({'ok':not errors,'client':args.client,'errors':errors,
        'scope':'offline_policy_snapshot_only', 'applied_to_tailnet':False}, sort_keys=True))
    return 0 if not errors else 3

if __name__ == '__main__':
    raise SystemExit(main())
