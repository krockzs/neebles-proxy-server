import unittest
from unittest.mock import patch
import exit_node_operation as m


class TestTransitions(unittest.TestCase):
    def state(self, advertised=False):
        return {'BackendState':'Running','CurrentTailnet':{'Name':m.TAILNET},
                'Self':{'TailscaleIPs':[m.SERVER], 'ExitNodeOption': advertised}}

    def params(self, **overrides):
        kw = dict(run=lambda args: '', hostname=lambda: m.HOST,
                  token_reader=lambda fd: 'redacted',
                  policy_reader=lambda token: {'grants':[{'src':[m.CLIENT],
                      'dst':['autogroup:internet'],'ip':['*']}]},
                  forward_reader=lambda p: '1')
        kw.update(overrides)
        return kw

    @patch.object(m.os, 'geteuid', return_value=0)
    def test_activation_calls_real_tailscale_only_after_live_gate(self, _):
        commands=[]
        states=iter([self.state(),self.state(True)])
        kw=self.params(run=lambda args: commands.append(args),get_state=lambda: next(states))
        result=m.activate(3,**kw)
        self.assertTrue(result['advertisement_confirmed'])
        self.assertEqual(commands,[[m.TAILSCALE,'set','--advertise-exit-node=true']])

    @patch.object(m.os, 'geteuid', return_value=0)
    def test_rejects_broad_grant_without_mutation(self, _):
        commands=[]
        kw=self.params(run=lambda a: commands.append(a),get_state=lambda:self.state(),
                       policy_reader=lambda t:{'grants':[{'src':['*'],'dst':['autogroup:internet'],'ip':['*']}]})
        with self.assertRaisesRegex(m.TransitionError,'live_policy'):
            m.activate(3,**kw)
        self.assertEqual(commands,[])

    @patch.object(m.os, 'geteuid', return_value=0)
    def test_rejects_wrong_host(self, _):
        with self.assertRaisesRegex(m.TransitionError,'wrong_host'):
            m.activate(3,**self.params(get_state=lambda:self.state(),hostname=lambda:'thomyorke-pc'))

    @patch.object(m.os, 'geteuid', return_value=0)
    def test_rejects_disabled_forwarding(self, _):
        with self.assertRaisesRegex(m.TransitionError,'ipv4_forwarding'):
            m.activate(3,**self.params(get_state=lambda:self.state(),forward_reader=lambda p:'0'))

    @patch.object(m.os, 'geteuid', return_value=0)
    def test_rollback_when_advertisement_not_confirmed(self, _):
        commands=[]
        kw=self.params(run=lambda a: commands.append(a),get_state=lambda:self.state())
        with self.assertRaisesRegex(m.TransitionError,'rolled_back'):
            m.activate(3,**kw)
        self.assertEqual(len(commands),2)
        self.assertEqual(commands[1][-1],'--advertise-exit-node=false')

    @patch.object(m.os, 'geteuid', return_value=0)
    def test_deactivation(self, _):
        commands=[]
        states=iter([self.state(True),self.state(False)])
        r=m.deactivate(run=lambda a:commands.append(a),get_state=lambda:next(states),hostname=lambda:m.HOST)
        self.assertTrue(r['advertisement_confirmed_off'])
        self.assertEqual(commands[0][-1],'--advertise-exit-node=false')

    @patch.object(m.os, 'geteuid', return_value=1000)
    def test_nonroot_fails(self, _):
        with self.assertRaisesRegex(m.TransitionError,'root_authority'):
            m.activate(3,**self.params())


if __name__=='__main__':
    unittest.main(verbosity=2)
