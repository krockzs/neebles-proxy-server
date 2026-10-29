#!/usr/bin/env python3
"""Integration contract with Boss 2.0.11 provider; no network mutation."""

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import Mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
BOSS = pathlib.Path.home() / "NEEBLES/neebles-boss"
PROVIDER = BOSS / "client/platform-operations/platform_provider.py"

spec = importlib.util.spec_from_file_location("boss_platform_provider", PROVIDER)
provider = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provider)

MODULE = "neebles-proxy-server"
ACTION = "deactivate"


class PlatformContract(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads(
            (ROOT / "contracts/platform-operations.candidate.json").read_text()
        )
        self.lifecycle = json.loads(
            (ROOT / "tooling/custom-v2-candidate/lifecycle.platform.DRAFT.json").read_text()
        )
        self.operation = self.lifecycle["transitions"]["disable"]["operations"][
            "deactivate-exit-node"
        ]
        self.request = {
            "schema": "1",
            "module": MODULE,
            "operation": ACTION,
        }
        self.executor = Mock(
            return_value=subprocess.CompletedProcess(args=[], returncode=0)
        )

    def test_version_and_lifecycle(self):
        manifest = json.loads((ROOT / "manifest.json").read_text())
        self.assertEqual(manifest["version"], "1.0.0")
        self.assertEqual(self.operation["artillery"], "boss.platform_operation")
        self.assertEqual(self.operation["objective"], "execute")
        self.assertEqual(
            self.operation["munition"],
            {"operation": ACTION, "require_privilege": "true"},
        )

    def test_only_deactivate_granted(self):
        self.assertEqual(self.policy["schema"], "1")
        self.assertEqual(self.policy["module"], MODULE)
        self.assertEqual(set(self.policy["operations"]), {ACTION})
        self.assertEqual(
            self.policy["operations"][ACTION],
            {
                "executable": (
                    "/usr/lib/neebles/module-operations/"
                    "neebles-proxy-server-platform"
                ),
                "argv": ["--deactivate"],
            },
        )

    def call_provider(self, request, peer_uid=0, expected_uid=0):
        # The executor is mocked: no Tailscale process can be started.
        # The executable opener supplies the previously compiled candidate.
        binary = ROOT / "runtime/neebles-proxy-server-platform"
        def open_candidate(_):
            return os.open(binary, os.O_RDONLY)

        return provider.handle(
            request,
            peer_uid,
            expected_uid,
            policy_loader=lambda module: (
                self.policy["operations"]
                if module == self.policy["module"]
                else (_ for _ in ()).throw(ValueError("unknown module"))
            ),
            executor=self.executor,
            executable_opener=open_candidate,
        )

    def test_authorized_contract_uses_fixed_argv(self):
        result = self.call_provider(self.request)
        self.assertTrue(result["ok"], result)
        self.executor.assert_called_once()
        argv = self.executor.call_args.args[0]
        self.assertEqual(argv[1:], ["--deactivate"])
        self.assertTrue(argv[0].startswith("/proc/self/fd/"))

    def test_wrong_uid_is_denied(self):
        result = self.call_provider(self.request, peer_uid=1000)
        self.assertFalse(result["ok"])
        self.executor.assert_not_called()

    def test_ungranted_activate_is_denied(self):
        req = dict(self.request, operation="activate")
        result = self.call_provider(req)
        self.assertFalse(result["ok"])
        self.executor.assert_not_called()

    def test_ungranted_module_is_denied(self):
        req = dict(self.request, module="another-module")
        result = self.call_provider(req)
        self.assertFalse(result["ok"])
        self.executor.assert_not_called()

    def test_request_supplied_arguments_are_rejected(self):
        req = dict(self.request, argv=["--activate"])
        result = self.call_provider(req)
        self.assertFalse(result["ok"])
        self.executor.assert_not_called()

    def test_native_elf_signature(self):
        binary = ROOT / "runtime/neebles-proxy-server-platform"
        with binary.open("rb") as stream:
            self.assertEqual(stream.read(4), b"\x7fELF")


if __name__ == "__main__":
    unittest.main(verbosity=2)
