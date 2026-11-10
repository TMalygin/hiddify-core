"""Review regressions: a rejected selection must not discard the accepted config.

Run against the explicitly supplied native fixture. The imported fixture and
original lease tests stay frozen; this observer retains every event it reads.
"""
import json
import os
import queue
import subprocess
import tempfile
import time
import unittest

from test_sandbox_profile_leases import Driver, PROBE, Proxy, profile


IDENTIFIED_PROBE = PROBE.replace(
    'tcp = udp = None',
    'import secrets\ninstance = secrets.token_hex(16)\ntcp = udp = None',
).replace("result['env'] =", "result['instance'] = instance\n    result['env'] =")


class Events:
    def __init__(self, driver):
        self.driver = driver
        self.items = []

    def mark(self):
        while True:
            try:
                self.items.append(self.driver.events.get_nowait())
            except queue.Empty:
                return len(self.items)

    def wait(self, predicate, since=0, timeout=8):
        until = time.monotonic() + timeout
        index = since
        while True:
            while index < len(self.items):
                event = self.items[index]
                index += 1
                if predicate(event):
                    return event
                if event.get('kind') in ('stream_end', 'driver_exit'):
                    raise AssertionError(f'unexpected session termination: {event}')
            remaining = until - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f'event deadline; last events={self.items[-6:]}')
            try:
                self.items.append(self.driver.events.get(timeout=remaining))
            except queue.Empty:
                raise AssertionError(f'event deadline; last events={self.items[-6:]}') from None

    def reply(self, request, since):
        return self.wait(lambda event: event.get('kind') == 'reply' and event.get('id') == request, since)

    def probe(self, online, since, after=-1):
        return self.wait(lambda event: event.get('kind') == 'probe'
                         and event['seq'] > after
                         and event['tcp'] == online and event['udp'] == online, since)


@unittest.skipUnless(os.environ.get('HIDDIFY_SANDBOX_DRIVER'), 'explicit Linux host integration driver required')
class SelectionRecovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hiddify-selection-recovery-')
        self.addCleanup(self.temp.cleanup)
        self.a, self.b = Proxy(), Proxy()
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)
        self.routes = self.host_routes()
        self.driver = Driver(self.temp.name)
        self.addCleanup(self.driver.close)
        self.events = Events(self.driver)
        self.driver.send('launch', command=['/usr/bin/python3', '-c', IDENTIFIED_PROBE])
        self.first = self.events.probe(False, 0)
        self.identity = (self.first['pid'], self.first['netns'], self.first['instance'])
        a, b = json.loads(profile(self.a))['outbounds'][0], json.loads(profile(self.b))['outbounds'][0]
        a['tag'], b['tag'] = 'a', 'b'
        self.content = json.dumps({'outbounds': [a, b, {'type': 'direct', 'tag': 'direct'}, {
            'type': 'selector', 'tag': 'select', 'outbounds': ['a', 'b', 'direct'], 'default': 'a',
        }], 'route': {'final': 'select'}})
        mark = self.events.mark()
        request = self.driver.send('start', profile=self.content)
        self.assertEqual(self.events.reply(request, mark)['error'], '<nil>')
        self.online = self.events.probe(True, mark, self.first['seq'])
        self.same_application(self.online)

    @staticmethod
    def host_routes():
        return [subprocess.check_output(['ip', '-j', family, 'route', 'show', 'table', 'main'])
                for family in ('-4', '-6')]

    def tearDown(self):
        self.assertEqual(self.routes, self.host_routes(), 'host routes changed')

    def same_application(self, event):
        self.assertEqual((event['pid'], event['netns'], event['instance']), self.identity,
                         'selection recovery replaced the isolated application')

    @staticmethod
    def child_traffic(proxy):
        # The ordinary core shares this fixture and may run URL health checks.
        # Identify our application by its synthetic target and payload, never
        # by whether the entire shared fixture log is empty.
        return [event for event in proxy.events
                if (event[1], event[2]) == ('198.51.100.44', 443)
                or event[3].startswith(b'profile-flow-')]

    def rejected_then_valid(self, group, outbound, middle_direct=False):
        mark = self.events.mark()
        rejected = self.driver.send('select', group=group, outbound=outbound)
        self.assertNotEqual(self.events.reply(rejected, mark)['error'], '<nil>')
        offline = self.events.probe(False, mark, self.online['seq'])
        self.same_application(offline)
        self.assertEqual(self.child_traffic(self.b), [])

        if middle_direct:
            mark = self.events.mark()
            selected = self.driver.send('select', group='select', outbound='direct')
            self.assertEqual(self.events.reply(selected, mark)['error'], '<nil>')
            for _ in range(3):
                offline = self.events.wait(lambda event: event.get('kind') == 'probe'
                                           and event['seq'] > offline['seq'], mark)
                self.same_application(offline)
                self.assertFalse(offline['tcp'] or offline['udp'], 'DIRECT granted app network')
            self.assertEqual(self.child_traffic(self.b), [])

        mark = self.events.mark()
        selected = self.driver.send('select', group='select', outbound='b')
        self.assertEqual(self.events.reply(selected, mark)['error'], '<nil>')
        recovered = self.events.probe(True, mark, offline['seq'])
        self.same_application(recovered)
        self.assertTrue(self.child_traffic(self.b), 'correct selection did not reach proxy B')
        old_count = len(self.child_traffic(self.a))
        later = self.events.probe(True, self.events.mark(), recovered['seq'] + 2)
        self.same_application(later)
        self.assertEqual(len(self.child_traffic(self.a)), old_count, 'old proxy carried new app traffic')

    def test_valid_selection_recovers_after_unknown_outbound(self):
        self.rejected_then_valid('select', 'missing-outbound')

    def test_valid_selection_recovers_after_unknown_group(self):
        self.rejected_then_valid('missing-group', 'b')

    def test_recovery_does_not_grant_direct(self):
        self.rejected_then_valid('select', 'missing-outbound', middle_direct=True)

    def test_failed_profile_reload_cannot_be_undone_by_selection(self):
        mark = self.events.mark()
        failed = self.driver.send('reload', profile='{"outbounds": [')
        self.assertNotEqual(self.events.reply(failed, mark)['error'], '<nil>')
        offline = self.events.probe(False, mark, self.online['seq'])
        mark = self.events.mark()
        selected = self.driver.send('select', group='select', outbound='b')
        self.assertEqual(self.events.reply(selected, mark)['error'], '<nil>')
        # A valid selection in the ordinary old core must not restore permission
        # to a profile whose replacement failed. Require consecutive offline
        # probes, rather than accepting one transient offline sample.
        for _ in range(4):
            offline = self.events.wait(lambda event: event.get('kind') == 'probe'
                                       and event['seq'] > offline['seq'], mark)
            self.same_application(offline)
            self.assertFalse(offline['tcp'] or offline['udp'], 'failed reload restored old permission')
        self.assertEqual(self.child_traffic(self.b), [])
        mark = self.events.mark()
        restarted = self.driver.send('restart', profile=self.content)
        self.assertEqual(self.events.reply(restarted, mark)['error'], '<nil>')
        self.same_application(self.events.probe(True, mark, offline['seq']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
