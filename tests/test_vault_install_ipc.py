#!/usr/bin/env python3
"""Tests for the real Proxy Server IPC client with a mock Secrets peer."""

import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import unittest

MODULE = "neebles-proxy-server"
REQUEST = {"op": "vault.ensure", "module": MODULE}
MAX_FRAME = 16 * 1024 * 1024


def recv_exact(sock, length):
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            raise EOFError("incomplete IPC frame")
        result.extend(chunk)
    return bytes(result)


class BrokerCase(unittest.TestCase):
    binary = None

    def exchange(self, response, *, raw=False, expected_request=True):
        with tempfile.TemporaryDirectory(prefix="neebles-f17-") as tmp:
            runtime = Path(tmp)
            directory = runtime / "neebles-secrets"
            directory.mkdir(mode=0o700)
            address = directory / "secrets.sock"

            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.settimeout(7)
            listener.bind(str(address))
            listener.listen(1)

            recorded = []
            failures = []

            def server():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(7)
                        header = recv_exact(connection, 4)
                        size = struct.unpack(">I", header)[0]
                        if not 0 < size <= MAX_FRAME:
                            raise ValueError("invalid request length")
                        message = json.loads(
                            recv_exact(connection, size).decode("utf-8")
                        )
                        recorded.append(message)

                        if raw:
                            connection.sendall(response)
                        else:
                            body = json.dumps(
                                response, separators=(",", ":")
                            ).encode("utf-8")
                            connection.sendall(
                                struct.pack(">I", len(body)) + body
                            )
                except Exception as exc:
                    failures.append(repr(exc))

            thread = threading.Thread(target=server)
            thread.start()

            try:
                env = os.environ.copy()
                env["XDG_RUNTIME_DIR"] = str(runtime)
                env["QT_QPA_PLATFORM"] = "offscreen"
                proc = subprocess.run(
                    [str(self.binary), "--intent", "install-vault"],
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=12,
                )
            finally:
                thread.join(timeout=8)
                listener.close()

            self.assertFalse(thread.is_alive(), "mock server hung")
            self.assertFalse(failures, failures)

            if expected_request:
                self.assertEqual(recorded, [REQUEST])

            return proc

    def test_invalid_boss_module_identity_rejected(self):
        with tempfile.TemporaryDirectory(prefix="neebles-f21-identity-") as temp:
            env = os.environ.copy()
            env["XDG_RUNTIME_DIR"] = temp
            env["NEEBLES_MODULE"] = "neebles-connect"
            env["QT_QPA_PLATFORM"] = "offscreen"
            result = subprocess.run(
                [str(self.binary), "--intent", "install-vault"],
                env=env, capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("PROXY_VAULT_INSTALL_FAILED", result.stderr)

    def test_success(self):
        result = self.exchange({
            "ok": True,
            "data": {"module": MODULE, "exists": True},
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PROXY_VAULT_READY", result.stdout)

    def test_existing_vault_is_success(self):
        # Idempotency: Secrets reports the vault already exists.
        result = self.exchange({
            "ok": True,
            "data": {
                "module": MODULE,
                "exists": True,
                "created": False,
            },
        })
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_locked_secrets_rejected(self):
        result = self.exchange({
            "ok": False,
            "error": "locked",
        })
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PROXY_VAULT_INSTALL_FAILED", result.stderr)

    def test_foreign_module_rejected(self):
        result = self.exchange({
            "ok": True,
            "data": {
                "module": "neebles-connect",
                "exists": True,
            },
        })
        self.assertNotEqual(result.returncode, 0)

    def test_missing_vault_confirmation_rejected(self):
        result = self.exchange({
            "ok": True,
            "data": {"module": MODULE, "exists": False},
        })
        self.assertNotEqual(result.returncode, 0)

    def test_missing_data_rejected(self):
        result = self.exchange({"ok": True})
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_json_rejected(self):
        body = b"not-json"
        result = self.exchange(
            struct.pack(">I", len(body)) + body,
            raw=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_zero_length_frame_rejected(self):
        result = self.exchange(
            struct.pack(">I", 0),
            raw=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_oversized_frame_rejected(self):
        result = self.exchange(
            struct.pack(">I", MAX_FRAME + 1),
            raw=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_truncated_frame_rejected(self):
        result = self.exchange(
            struct.pack(">I", 100) + b"{}",
            raw=True,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        parser.error("binary does not exist")

    BrokerCase.binary = binary
    unittest.main(argv=["test_vault_install_ipc"], verbosity=2)
