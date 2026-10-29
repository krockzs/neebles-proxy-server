#!/usr/bin/env python3
# NEEBLES_PROXY_104_IPC_GATE: unprivileged local socket and persistence regression.
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "runtime/neebles-proxy-server-health"
FIXTURE = ROOT / "contracts/allowlist.example.json"
STATUS = ROOT / "tests/tailscale.health.fixture.json"
TAILNET = "olate.pablo@gmail.com"

class BridgeTest(unittest.TestCase):
    def setUp(self):
        self.temp_home = tempfile.TemporaryDirectory(prefix="neebles-104-home-")
        session_base = Path(os.environ.get("XDG_RUNTIME_DIR", "/run/user/" + str(os.getuid())))
        if not session_base.is_dir() or not os.access(session_base, os.W_OK):
            self.skipTest("No writable user runtime directory for isolated Unix socket")
        self.temp_runtime = tempfile.TemporaryDirectory(prefix="proxy104-", dir=session_base)
        self.runtime = Path(self.temp_runtime.name)
        self.sock = self.runtime / "neebles/proxy-server.sock"
        self.env = dict(os.environ, HOME=self.temp_home.name, XDG_RUNTIME_DIR=str(self.runtime))
        self.process = None
        self.start_process()

    def start_process(self):
        self.process = subprocess.Popen([str(BINARY), "--ipc-only", "--policy", str(FIXTURE),
            "--status-fixture", str(STATUS)], env=self.env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        # Socket paths may exist after process exit; require a live listener.
        ready = False
        for _ in range(100):
            if self.process.poll() is not None:
                out, err = self.process.communicate(timeout=2)
                self.fail(f"Health exited rc={self.process.returncode}, stdout={out!r}, stderr={err!r}")
            if self.sock.exists():
                try:
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                        probe.settimeout(.2)
                        probe.connect(str(self.sock))
                        ready = True
                        break
                except (ConnectionRefusedError, FileNotFoundError, OSError):
                    pass
            time.sleep(.03)
        self.assertTrue(ready, "Local IPC did not become connectable")

    def stop_process(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try: self.process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.communicate(timeout=3)
        self.process = None

    def tearDown(self):
        self.stop_process()
        self.temp_runtime.cleanup()
        self.temp_home.cleanup()

    def query(self, request):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(str(self.sock))
            raw = request if isinstance(request, bytes) else json.dumps(request).encode() + b"\n"
            connection.sendall(raw)
            result = b""
            while b"\n" not in result:
                data = connection.recv(8192)
                if not data: break
                result += data
                self.assertLessEqual(len(result), 8192)
        return json.loads(result)

    def test_policy_roundtrip_restart_and_permissions(self):
        self.assertEqual(stat.S_IMODE(self.sock.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.sock.parent.stat().st_mode), 0o700)
        current = self.query({"op": "policy.get"})
        self.assertTrue(current["ok"], current)
        self.assertFalse(current["authorization_enforced"])
        new = {"schema_version": 1, "tailnet": TAILNET,
               "allowed_clients": ["100.90.51.25", "100.68.101.32"]}
        response = self.query({"op": "policy.set", "policy": new})
        self.assertTrue(response["ok"], response)
        path = Path(self.temp_home.name) / ".config/neebles/proxy-server/allowlist.json"
        self.assertEqual(json.loads(path.read_text()), new)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.stop_process()
        self.start_process()
        result = self.query({"op": "policy.get"})
        self.assertEqual(result["policy"], new)

    def test_denies_invalid_policy_and_malformed_input(self):
        baseline = self.query({"op": "policy.get"})["policy"]
        bad = dict(baseline, allowed_clients=["100.90.51.25", "100.90.51.25"])
        self.assertFalse(self.query({"op": "policy.set", "policy": bad})["ok"])
        bad = dict(baseline, tailnet="unauthorized.example")
        self.assertFalse(self.query({"op": "policy.set", "policy": bad})["ok"])
        self.assertEqual(self.query({"op": "policy.get"})["policy"], baseline)
        self.assertFalse(self.query(b"not-json\n")["ok"])
        self.assertFalse(self.query({"op": "unknown"})["ok"])

    def test_status_is_advisory_only(self):
        value = self.query({"op": "status"})
        self.assertTrue(value["ok"], value)
        self.assertTrue(value["advisory_only"])
        self.assertFalse(self.query({"op": "policy.get"})["authorization_enforced"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
