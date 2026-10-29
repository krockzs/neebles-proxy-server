#!/usr/bin/env python3
import io
import unittest
from live_policy_gate import fetch_policy, TAILNET, CLIENT

GOOD = {'grants': [{'src': [CLIENT], 'dst': ['autogroup:internet'], 'ip': ['*']}]}

class Response(io.BytesIO):
    status = 200
    def __enter__(self): return self
    def __exit__(self, *args): self.close()

class TestLiveGate(unittest.TestCase):
    def test_endpoint_and_bearer(self):
        def opener(req, timeout):
            self.assertEqual(timeout, 10)
            self.assertEqual(req.get_method(), 'GET')
            self.assertIn('/tailnet/olate.pablo%40gmail.com/acl', req.full_url)
            self.assertEqual(req.get_header('Authorization'), 'Bearer temporary')
            return Response(__import__('json').dumps(GOOD).encode())
        self.assertEqual(fetch_policy('temporary', TAILNET, opener), GOOD)
    def test_reject_non_object(self):
        with self.assertRaises(ValueError):
            fetch_policy('temporary', opener=lambda *a, **kw: Response(b'[]'))
    def test_reject_oversized(self):
        with self.assertRaises(RuntimeError):
            fetch_policy('temporary', opener=lambda *a, **kw: Response(b' ' * (2*1024*1024+1)))
    def test_no_activate_commands(self):
        from pathlib import Path
        source = Path(__file__).with_name('live_policy_gate.py').read_text()
        self.assertNotIn('advertise-exit-node=true',source)
        self.assertNotIn('subprocess.run',source)

if __name__ == '__main__': unittest.main(verbosity=2)
