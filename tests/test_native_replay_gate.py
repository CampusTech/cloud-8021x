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


if __name__=='__main__':unittest.main()
