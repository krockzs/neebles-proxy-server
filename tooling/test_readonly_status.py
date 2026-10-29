#!/usr/bin/env python3
"""Read-only status tests; no Tailscale changes or privileged calls."""
import unittest
from unittest.mock import patch
import exit_node_operation as op

class TestStatus(unittest.TestCase):
    def state(self, advertised):
        return {'BackendState': 'Running',
                'CurrentTailnet': {'Name': op.TAILNET},
                'Self': {'TailscaleIPs': [op.SERVER], 'ExitNodeOption': advertised}}

    def test_advertised_is_not_ready(self):
        result = op.observe_exit_node(get_state=lambda: self.state(True), hostname=lambda: op.HOST)
        self.assertTrue(result['advertised'])
        self.assertFalse(result['ready'])
        self.assertFalse(result['admin_approval_verified'])
        self.assertFalse(result['client_egress_verified'])

    def test_not_advertised(self):
        result = op.observe_exit_node(get_state=lambda: self.state(False), hostname=lambda: op.HOST)
        self.assertFalse(result['advertised'])

    def test_wrong_host_fails(self):
        with self.assertRaises(op.TransitionError):
            op.observe_exit_node(get_state=lambda: self.state(True), hostname=lambda: 'other-host')

    def test_never_mutates_network(self):
        with patch.object(op, 'execute', side_effect=AssertionError('mutation')):
            op.observe_exit_node(get_state=lambda: self.state(True), hostname=lambda: op.HOST)

if __name__ == '__main__':
    unittest.main(verbosity=2)
