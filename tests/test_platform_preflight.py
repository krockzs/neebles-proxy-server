#!/usr/bin/env python3
"""F22 regression: preflight has a documented read-only status shape."""
import json, subprocess, sys
p=subprocess.run([sys.argv[1], "--preflight"], capture_output=True, text=True, timeout=8)
assert p.returncode in (0,7), (p.returncode,p.stderr)
x=json.loads(p.stdout)
assert x["operation"]=="preflight" and x["read_only"] is True
assert x["live_acl_verified"] is False
assert x["client_egress_verified"] is False
assert x["ready_for_activation"] is False
assert isinstance(x["identity_verified"],bool)
assert isinstance(x["ipv4_forwarding"],bool)
print("PASS native read-only preflight, explicit fail-closed gates")
