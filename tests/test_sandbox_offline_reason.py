"""Managed application diagnostics follow the same native permission revision."""
import json
import os
import tempfile
import unittest

from test_sandbox_profile_leases import Driver
from test_sandbox_selection_recovery import Events


@unittest.skipUnless(os.environ.get('HIDDIFY_SANDBOX_DRIVER'), 'explicit Linux host integration driver required')
class OfflineReason(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='hiddify-offline-reason-')
        self.addCleanup(temp.cleanup)
        self.driver = Driver(temp.name)
        self.addCleanup(self.driver.close)
        self.events = Events(self.driver)
        self.driver.send('launch', command=['/usr/bin/sleep', '90'])
        initial = self.events.wait(lambda e: e.get('kind') == 'sandbox' and e['state'] == 0)
        self.assertFalse(initial.get('message'), 'an ordinary offline launch has no error')

    def assert_reason(self, profile, words):
        mark = self.events.mark()
        started = self.driver.send('start', profile=json.dumps(profile))
        self.assertEqual(self.events.reply(started, mark)['error'], '<nil>')
        # Start first revokes, then publishes the accepted profile as a new revision.
        first = self.events.wait(lambda e: e.get('kind') == 'sandbox' and e['state'] == 0, mark)
        next_state = self.events.wait(lambda e: e.get('kind') == 'sandbox' and e['state'] in (0, 1)
                                      and e['revision'] > first['revision'], mark)
        self.assertEqual(next_state['state'], 0, 'this profile cannot grant a worker')
        message = next_state.get('message', '').lower()
        self.assertTrue(any(word in message for word in words), 'offline event must explain this policy decision')
        self.assertNotIn('synthetic-private', message)

        mark = self.events.mark()
        stopped = self.driver.send('stop')
        self.assertEqual(self.events.reply(stopped, mark)['error'], '<nil>')
        cleared = self.events.wait(lambda e: e.get('kind') == 'sandbox' and e['state'] == 0
                                   and e['revision'] > next_state['revision'], mark)
        self.assertFalse(cleared.get('message'), 'a later disconnect must not report an older profile rejection')

    def test_direct_has_a_reason_and_disconnect_clears_it(self):
        self.assert_reason({'outbounds': [{'type': 'direct', 'tag': 'synthetic-private-direct'}],
                            'route': {'final': 'synthetic-private-direct'}}, ['direct'])

    def test_unguarded_external_controller_does_not_grant_socks(self):
        self.assert_reason({
            'experimental': {'clash_api': {'external_controller': '127.0.0.1:0'}},
            'outbounds': [{'type': 'socks', 'tag': 'synthetic-private-proxy', 'server': '127.0.0.1',
                           'server_port': 1080, 'version': '5', 'username': 'synthetic-private-user',
                           'password': 'synthetic-private-password'}],
            'route': {'final': 'synthetic-private-proxy'},
        }, ['clash', 'vless', 'reality', 'socks', 'controller'])

    def test_mutable_external_selection_explains_offline(self):
        self.assert_reason({
            'experimental': {'clash_api': {'external_controller': '127.0.0.1:0'}},
            'outbounds': [
                {'type': 'direct', 'tag': 'synthetic-private-direct'},
                {'type': 'socks', 'tag': 'synthetic-private-proxy', 'server': '127.0.0.1', 'server_port': 1080},
                {'type': 'selector', 'tag': 'select', 'outbounds': ['synthetic-private-proxy', 'synthetic-private-direct']},
            ],
            'route': {'final': 'select'},
        }, ['clash', 'single', 'one', 'controller', 'multiple', 'ambiguous'])
