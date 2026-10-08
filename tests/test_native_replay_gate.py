"""Regression checks for the development-only replay acceptance gate."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC=importlib.util.spec_from_file_location('native_gate',Path(__file__).with_name('native_radius_container.py'))
GATE=importlib.util.module_from_spec(SPEC)
with mock.patch('subprocess.check_output',return_value='192.0.2.7'):
    SPEC.loader.exec_module(GATE)


class ReplayGateTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name)
        self.expected={'session_id':'fixture-unique','replay_id':'a'*64,'received_at':1791460000,
                       'source_ip':'192.0.2.7','client_id':'office','location_id':'nyc',
                       'status':'Start','packet_id':'1','request_authenticator':'0x'+'b'*32}
        (root/'replay-expectations.json').write_text(json.dumps({'records':[self.expected],'files':[]}))
        self.patches=[mock.patch.object(GATE,'ROOT',root),mock.patch.object(GATE,'REPLAY_POLLS',1,create=True),
                      mock.patch.object(GATE,'start_radius'),mock.patch.object(GATE.time,'sleep'),
                      mock.patch.object(GATE.sys,'argv',['native','replay'])]
        for patch in self.patches:patch.start();self.addCleanup(patch.stop)

    def test_replay_fails_if_database_is_down(self):
        with mock.patch.object(GATE,'intake_rows',side_effect=RuntimeError('database unavailable'),create=True):
            with self.assertRaisesRegex(RuntimeError,'database unavailable'):GATE.main()

    def test_replay_fails_if_expected_intake_rows_are_missing(self):
        with mock.patch.object(GATE,'intake_rows',return_value=[],create=True),mock.patch.object(GATE,'pending_replay_ids',return_value=set(),create=True):
            with self.assertRaisesRegex(AssertionError,'replay'):GATE.main()

    def test_replay_fails_if_original_metadata_changes(self):
        changed={**self.expected,'received_at':1791460999}
        with mock.patch.object(GATE,'intake_rows',return_value=[changed],create=True),mock.patch.object(GATE,'pending_replay_ids',return_value=set(),create=True):
            with self.assertRaisesRegex(AssertionError,'replay'):GATE.main()

    def test_replay_fails_if_matching_pending_work_remains(self):
        with mock.patch.object(GATE,'intake_rows',return_value=[self.expected],create=True),mock.patch.object(GATE,'pending_replay_ids',return_value={'a'*64},create=True):
            with self.assertRaisesRegex(AssertionError,'replay'):GATE.main()

    def test_replay_succeeds_only_with_original_context_and_drained_work(self):
        with mock.patch.object(GATE,'intake_rows',return_value=[self.expected]),mock.patch.object(GATE,'pending_replay_ids',return_value=set()):
            GATE.main()

    def test_acked_packet_gate_requires_persisted_rows(self):
        with mock.patch.object(GATE,'intake_rows',return_value=[]):
            with self.assertRaisesRegex(AssertionError,'missing ACKed packet'):
                GATE.assert_packets_delivered([self.expected])

    def duplicate_fixture(self,observations,counts):
        records=[dict(self.expected,replay_id=char*64,status=status,packet_id=str(i))
                 for i,(char,status) in enumerate(zip('abc',['Start','Interim-Update','Stop']))]
        original=[dict(record,processed=True,observation_id=observation)
                  for record,observation in zip(records,observations)]
        duplicates=[row.copy() for row in original for _ in range(2)]
        (GATE.ROOT/'replay-expectations.json').write_text(json.dumps({'records':records,'files':['retained.detail']}))
        (GATE.ROOT/'retained.detail').write_text('synthetic retained test record\n')
        with mock.patch.object(GATE,'run'),mock.patch.object(GATE,'write'),\
             mock.patch.object(GATE,'pending_replay_ids',return_value=set()),\
             mock.patch.object(GATE,'intake_rows',side_effect=[original,original,original,duplicates,duplicates]),\
             mock.patch.object(GATE,'postgres_json',return_value=counts):
            GATE.replay_test(duplicate=True)

    def test_duplicate_gate_rejects_distinct_status_reports_collapsing(self):
        with self.assertRaisesRegex(AssertionError,'distinct status reports'):
            self.duplicate_fixture(['collapsed-observation']*3,{'observations':1,'outbox':1})

    def test_duplicate_gate_requires_each_expected_observation_and_outbox(self):
        for counts in [{'observations':2,'outbox':3},{'observations':3,'outbox':2}]:
            with self.subTest(counts=counts),self.assertRaisesRegex(AssertionError,'immutable event/outbox'):
                self.duplicate_fixture(['start','interim','stop'],counts)

    def test_duplicate_gate_accepts_three_reports_with_deduplicated_copies(self):
        self.duplicate_fixture(['start','interim','stop'],{'observations':3,'outbox':3})


if __name__=='__main__':unittest.main()
