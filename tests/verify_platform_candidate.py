#!/usr/bin/env python3
"""Non-mutating checks for the native privileged-operation candidate."""

import json
import os
import pathlib
import subprocess
import sys

binary = pathlib.Path(sys.argv[1])
policy = pathlib.Path(sys.argv[2])

assert binary.is_file()
assert binary.read_bytes()[:4] == b"\x7fELF"

obj = json.loads(policy.read_text())
assert set(obj) == {"schema", "module", "operations"}
assert obj["schema"] == "1"
assert obj["module"] == "neebles-proxy-server"

operations = obj["operations"]
assert set(operations) == {"deactivate"}

entry = operations["deactivate"]
assert entry == {
    "executable": (
        "/usr/lib/neebles/module-operations/"
        "neebles-proxy-server-platform"
    ),
    "argv": ["--deactivate"],
}

# Never run the privileged operation as root in this test.
if os.geteuid() == 0:
    print("SKIP: root execution prohibited for negative test")
    sys.exit(77)

result = subprocess.run(
    [str(binary), "--deactivate"],
    capture_output=True,
    text=True,
    timeout=10,
    check=False,
)

assert result.returncode == 3, (
    result.returncode,
    result.stdout,
    result.stderr,
)
assert "Root authority required" in result.stderr
assert not result.stdout.strip()

print("PASS: non-root execution denied")
print("PASS: fixed executable and arguments")
print("PASS: no activate operation authorized")
