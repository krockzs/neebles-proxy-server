#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
BUILD_DIR="${TMPDIR:-/tmp}/neebles-proxy-server-024-build"
cmake -S . -B "$BUILD_DIR" -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build "$BUILD_DIR" --parallel "$(nproc)"
ctest --test-dir "$BUILD_DIR" --output-on-failure
for name in neebles-proxy-server neebles-proxy-server-inspect neebles-proxy-server-policy neebles-proxy-server-controller neebles-proxy-server-health neebles-proxy-server-platform; do
    [[ -x "$BUILD_DIR/$name" ]] || { echo "Missing binary: $name" >&2; exit 1; }
    install -D -m 0755 "$BUILD_DIR/$name" "runtime/$name"
    file "runtime/$name"
    if ldd "runtime/$name" | grep -q 'not found'; then
        echo "Unresolved runtime dependency: $name" >&2
        exit 1
    fi
done
sha256sum runtime/neebles-proxy-server runtime/neebles-proxy-server-inspect runtime/neebles-proxy-server-policy runtime/neebles-proxy-server-controller runtime/neebles-proxy-server-health runtime/neebles-proxy-server-platform
printf '%s\n' 'PASS: complete runtime candidate bundle; not certified as Boss-installable.'

# Preserve the Python authorization backend in the distributable runtime.
bash "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/build_backend_bundle.sh"
