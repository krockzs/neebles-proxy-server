#!/usr/bin/env python3
import unittest
from verify_exit_policy import validate
C='100.90.51.25'
EXACT={'grants':[{'src':[C],'dst':['autogroup:internet'],'ip':['*']}]}
class TestPolicy(unittest.TestCase):
    def test_exact(self): self.assertEqual(validate(EXACT,C),[])
    def test_broad_source(self): self.assertTrue(validate({'grants':[{'src':['*'],'dst':['autogroup:internet'],'ip':['*']}]},C))
    def test_additional_broad_grant(self): self.assertTrue(validate({'grants':EXACT['grants']+[{'src':['autogroup:member'],'dst':['autogroup:internet'],'ip':['*']}]},C))
    def test_legacy_acl(self): self.assertTrue(validate({'grants':EXACT['grants'],'acls':[{'action':'accept','src':['*'],'dst':['*:*']}]},C))
    def test_missing(self): self.assertTrue(validate({'grants':[]},C))
    def test_mismatched_client(self): self.assertTrue(validate(EXACT,'100.90.51.26'))
    def test_wrong_net(self): self.assertTrue(validate(EXACT,'192.168.1.50'))
    def test_invalid_grant(self): self.assertTrue(validate({'grants':[False]},C))
    def test_more_destinations(self): self.assertTrue(validate({'grants':[{'src':[C],'dst':['autogroup:internet','*'],'ip':['*']}]},C))
if __name__=='__main__': unittest.main(verbosity=2)
