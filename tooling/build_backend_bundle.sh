#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# The runtime is regenerated exclusively from the tested source, not patched in place.
BACKEND=(verify_exit_policy.py live_policy_gate.py exit_node_operation.py)
for f in "${BACKEND[@]}"; do test -s "tooling/$f"; done
TMP="$(mktemp -d "$ROOT/runtime/.backend-stage.XXXXXXXX")"
trap 'rm -rf -- "$TMP"' EXIT
for f in "${BACKEND[@]}"; do cp -- "tooling/$f" "$TMP/$f"; done
PYTHONDONTWRITEBYTECODE=1 python3 -B - "$TMP" <<'PY'
import ast, pathlib, sys
p = pathlib.Path(sys.argv[1])
for name in ('verify_exit_policy.py', 'live_policy_gate.py', 'exit_node_operation.py'):
    ast.parse((p/name).read_text(), filename=name)
PY
# Refuse to replace runtime if any test fails.
for test in test_verify_exit_policy.py test_live_policy_gate.py test_exit_node_operation.py test_readonly_status.py; do
    PYTHONDONTWRITEBYTECODE=1 python3 -B "tooling/$test"
done
# Atomic directory exchange on the same filesystem, with restoration on failure.
OLD="$ROOT/runtime/.backend-previous.$$"
if [[ -e runtime/backend ]]; then mv -- runtime/backend "$OLD"; fi
if ! mv -- "$TMP" runtime/backend; then
    if [[ -d "$OLD" ]]; then mv -- "$OLD" runtime/backend; fi
    exit 1
fi
trap - EXIT
rm -rf -- "$OLD"
for f in "${BACKEND[@]}"; do cmp -- "tooling/$f" "runtime/backend/$f"; done
sha256sum runtime/backend/*.py
printf '%s\n' 'PASS: runtime backend equals tested source'
