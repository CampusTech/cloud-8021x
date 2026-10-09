"""Traffic is a counter increase, not the sum of completed-session snapshots."""
from pathlib import Path
import sys
import json
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import radius_usage


def event(second, session='one', kind='Acct-Update', upload=0, download=0,
          duration=None, **fields):
    return dict(timestamp=second, event=kind, session_id=session,
                src_ip='203.0.113.1', nas_ip='10.0.0.2', calling_station='aa:bb:cc:dd:ee:ff',
                input_bytes=upload, output_bytes=download,
                session_time=second if duration is None else duration, **fields)


class UsageTests(unittest.TestCase):
    def test_window_uses_baseline_and_includes_ongoing_sessions(self):
        events = [event(10,upload=1000,download=2000),
                  event(20,upload=1200,download=2400),
                  event(25,session='two',kind='Acct-Start'),
                  event(30,session='two',upload=100,download=150),
                  event(40,kind='Acct-Stop',upload=1300,download=2600)]
        report = radius_usage.window_usage(events, start=15, end=35)
        self.assertEqual(report['upload_bytes'], 300)
        self.assertEqual(report['download_bytes'], 550)
        self.assertEqual(report['intervals'], 2)

    def test_deduplicates_across_servers_and_ignores_reordered_updates(self):
        a=event(20,upload=200,download=400,duration=20,host='radius-primary')
        b=dict(a,host='radius-secondary',timestamp=21)
        report=radius_usage.window_usage([event(0,kind='Acct-Start'),a,b,
            event(22,upload=100,download=200,duration=10),
            event(30,kind='Acct-Stop',upload=300,download=500,duration=30)],0,40)
        self.assertEqual((report['upload_bytes'],report['download_bytes']), (300,500))

    def test_first_mid_session_snapshot_is_baseline_not_new_traffic(self):
        report=radius_usage.window_usage([event(20,upload=5000,download=6000),
                                         event(30,upload=5100,download=6200)],0,40)
        self.assertEqual((report['upload_bytes'],report['download_bytes']), (100,200))
        self.assertEqual(report['baselines_missing'],1)

    def test_equal_session_ids_from_different_clients_are_independent(self):
        a=event(0,kind='Acct-Start');b=dict(a,calling_station='11:22:33:44:55:66')
        report=radius_usage.window_usage([a,b,event(20,upload=200),
                dict(event(20,upload=300),calling_station='11:22:33:44:55:66')],0,40)
        self.assertEqual(report['upload_bytes'],500)

    def test_upgrading_legacy_counter_precision_rebaselines_without_a_false_spike(self):
        report=radius_usage.window_usage([event(10,upload=100),
            event(20,upload=(1<<32)+200,counter_bits=64),
            event(30,upload=(1<<32)+300,counter_bits=64)],0,40)
        self.assertEqual(report['upload_bytes'],100)
        self.assertEqual(report['counter_format_changes'],1)

    def test_64_bit_counter_increase_and_interval_average_rates(self):
        a=event(10,upload=(1<<32)-100,download=(2<<32)-100)
        b=event(20,upload=(1<<32)+100,download=(2<<32)+200)
        report=radius_usage.window_usage([a,b],0,30)
        interval=report['records'][0]
        self.assertEqual((interval['upload_delta_bytes'],interval['download_delta_bytes']),(200,300))
        self.assertEqual(interval['interval_seconds'],10)
        self.assertEqual(interval['upload_bps'],160)
        self.assertEqual(interval['download_bps'],240)

    def test_counter_reset_never_counts_full_new_snapshot_as_traffic(self):
        report=radius_usage.window_usage([event(10,upload=1000,download=2000),
            event(20,upload=50,download=100),event(30,upload=75,download=150)],0,40)
        self.assertEqual((report['upload_bytes'],report['download_bytes']),(25,50))
        self.assertEqual(report['counter_resets'],1)

    def test_missing_session_context_is_not_grouped_into_one_fake_session(self):
        broken=dict(event(10,upload=100),session_id='')
        report=radius_usage.window_usage([broken,dict(broken,timestamp=20,input_bytes=200)],0,40)
        self.assertEqual(report['upload_bytes'],0)
        self.assertEqual(report['invalid_records'],2)

    def test_verified_identity_only_and_stable_usage_ids(self):
        begin=event(0,kind='Acct-Start',identity_verified=True,device_id='fleet:4',device_name='Known Mac',device_owner='owner@example.test',site_name='NYC',ssid='Campus')
        end=event(20,upload=200,identity_verified=False,device_name='forged',device_owner='forged@example.test',site_name='NYC',ssid='Campus')
        report=radius_usage.window_usage([begin,end],0,40)
        r=report['records'][0]
        self.assertTrue(r['identity_verified'])
        self.assertEqual(r['device_name'],'Known Mac')
        self.assertEqual(r['device_owner'],'owner@example.test')
        again=radius_usage.window_usage([dict(begin,host='secondary'),dict(end,host='secondary')],0,40)
        self.assertEqual(r['usage_id'],again['records'][0]['usage_id'])

    def test_collector_checkpoint_survives_overlapping_batches_and_restart(self):
        tracker = radius_usage.UsageTracker()
        first = tracker.process([event(0, kind='Acct-Start'), event(10, upload=100)], 0, 40)
        restored = radius_usage.UsageTracker(state=tracker.export_state())
        second = restored.process([event(10, upload=100),
            event(20, kind='Acct-Stop', upload=150)], 0, 40)
        third = restored.process([event(20, kind='Acct-Stop', upload=150)], 0, 40)
        self.assertEqual((first['upload_bytes'], second['upload_bytes'], third['upload_bytes']),
                         (100, 50, 0))

    def test_iso_timestamps_and_half_open_boundary_credit_whole_interval(self):
        events = [dict(event(0, kind='Acct-Start'), timestamp='2026-10-07T00:00:00Z'),
                  dict(event(10, upload=100), timestamp='2026-10-07T00:00:10+00:00'),
                  dict(event(20, upload=150), timestamp='2026-10-07T00:00:20Z')]
        report = radius_usage.window_usage(events, '2026-10-07T00:00:10Z', '2026-10-07T00:00:20Z')
        self.assertEqual(report['upload_bytes'], 100)
        self.assertEqual(report['records'][0]['interval_seconds'], 10)

    def test_mac_formats_deduplicate_and_sources_are_separate(self):
        begin = event(0, kind='Acct-Start')
        update = event(10, upload=100)
        retry = dict(update, calling_station='AABB.CCDD.EEFF', timestamp=11)
        other = dict(update, src_ip='203.0.113.2')
        report = radius_usage.window_usage([begin, update, retry, other], 0, 20)
        self.assertEqual(report['upload_bytes'], 100)
        self.assertEqual(report['baselines_missing'], 1)

    def test_same_second_highwater_has_no_invented_rate(self):
        report = radius_usage.window_usage([event(0, kind='Acct-Start'),
            event(10, upload=100), event(11, upload=120, duration=10),
            event(12, upload=110, duration=10), event(20, upload=150)], 0, 30)
        self.assertEqual(report['upload_bytes'], 150)
        same_second = report['records'][1]
        self.assertEqual(same_second['upload_delta_bytes'], 20)
        self.assertEqual(same_second['interval_seconds'], 0)
        self.assertIsNone(same_second['upload_bps'])

    def test_stop_is_terminal_and_late_start_cannot_reset_baseline(self):
        report = radius_usage.window_usage([event(0, kind='Acct-Start'),
            event(10, upload=100), event(11, kind='Acct-Start'),
            event(20, kind='Acct-Stop', upload=150), event(30, upload=999)], 0, 40)
        self.assertEqual(report['upload_bytes'], 150)

    def test_duplicate_stop_marks_terminal_even_when_counters_unchanged(self):
        report = radius_usage.window_usage([event(0, kind='Acct-Start'),
            event(10, upload=100), event(11, kind='Acct-Stop', upload=100, duration=10),
            event(20, upload=200)], 0, 30)
        self.assertEqual(report['upload_bytes'], 100)

    def test_counters_retain_full_64_bit_integer_precision(self):
        initial = (1 << 63) + 1
        report = radius_usage.window_usage([event(10, upload=initial),
            event(20, upload=str(initial + 123))], 0, 30)
        self.assertEqual(report['upload_bytes'], 123)

    def test_invalid_counters_timestamps_and_window_are_rejected(self):
        bad = [dict(event(10), input_bytes='-1'), dict(event(10), input_bytes=1.5),
               dict(event(10), timestamp='2026-10-07T00:00:00'),
               dict(event(10), timestamp=float('nan')), dict(event(10), session_time=True)]
        report = radius_usage.window_usage(bad, 0, 30)
        self.assertEqual(report['invalid_records'], 5)
        with self.assertRaises(ValueError):
            radius_usage.window_usage([], 30, 0)

    def test_unverified_only_identity_is_never_exposed(self):
        report = radius_usage.window_usage([event(0, kind='Acct-Start'),
            event(10, upload=100, identity_verified='true', device_id='forged',
                  device_owner='forged', device_name='forged')], 0, 20)
        record = report['records'][0]
        self.assertFalse(record['identity_verified'])
        self.assertNotIn('device_owner', record)
        self.assertNotIn('device_id', record)

    def test_checkpoint_is_json_and_deduplicates_both_servers_after_restart(self):
        tracker = radius_usage.UsageTracker()
        first = tracker.process([event(0, kind='Acct-Start', host='radius-primary'),
            event(10, upload=100, download=200, host='radius-primary'),
            event(11, upload=100, download=200, duration=10, host='radius-secondary')], 0, 20)
        checkpoint = json.loads(json.dumps(tracker.export_state()))
        self.assertEqual(checkpoint['version'], 1)
        restored = radius_usage.UsageTracker(checkpoint)
        second = restored.process([event(5, upload=50, download=100),
            event(10, upload=100, download=200),
            event(20, kind='Acct-Stop', upload=150, download=300, host='radius-secondary'),
            event(21, kind='Acct-Stop', upload=150, download=300, duration=20, host='radius-primary')], 0, 30)
        self.assertEqual(first['upload_bytes'] + second['upload_bytes'], 150)
        self.assertEqual(first['download_bytes'] + second['download_bytes'], 300)
        terminal = radius_usage.UsageTracker(json.loads(json.dumps(restored.export_state())))
        self.assertEqual(terminal.process([event(30, upload=999)], 0, 40)['upload_bytes'], 0)
        self.assertTrue(terminal.export_state()['sessions'][0]['stopped'])

    def test_checkpoint_exports_independent_metadata_and_prunes_only_stale_sessions(self):
        tracker = radius_usage.UsageTracker()
        tracker.process([event(0, kind='Acct-Start'), event(10, upload=100),
            event(30, session='new', kind='Acct-Start')], 0, 40)
        state = tracker.export_state()
        state['sessions'][0]['upload'] = 999
        self.assertNotEqual(tracker.export_state()['sessions'][0]['upload'], 999)
        self.assertEqual(tracker.prune_before(20), 1)
        self.assertEqual(tracker.prune_before(30), 0)
        replay = tracker.process([event(40, upload=200)], 30, 50)
        self.assertEqual(replay['upload_bytes'], 0)
        self.assertEqual(replay['baselines_missing'], 1)
        self.assertEqual(tracker.export_state()['sessions'][0]['last_seen'], 30)

    def test_malformed_checkpoint_is_rejected_instead_of_silently_reset(self):
        tracker = radius_usage.UsageTracker()
        tracker.process([event(0, kind='Acct-Start')], 0, 10)
        valid = tracker.export_state()
        invalid = [{}, {'version': 2, 'sessions': []}, {'version': True, 'sessions': []},
                   {'version': 1, 'sessions': [{}]}]
        bad_counter = json.loads(json.dumps(valid))
        bad_counter['sessions'][0]['upload'] = -1
        invalid.append(bad_counter)
        bad_terminal = json.loads(json.dumps(valid))
        bad_terminal['sessions'][0]['stopped'] = 'false'
        invalid.append(bad_terminal)
        bad_receipt = json.loads(json.dumps(valid))
        bad_receipt['sessions'][0]['last_seen'] = float('nan')
        invalid.append(bad_receipt)
        for state in invalid:
            with self.subTest(state=state), self.assertRaises(ValueError):
                radius_usage.UsageTracker(state)

    def test_marked_64bit_start_counts_first_full_counter_snapshot(self):
        report = radius_usage.window_usage([event(0, kind='Acct-Start', counter_bits=64),
            event(10, upload=(1 << 32) + 100, counter_bits=64)], 0, 20)
        self.assertEqual(report['upload_bytes'], (1 << 32) + 100)
        self.assertEqual(report['counter_format_changes'], 0)
        self.assertEqual(report['records'][0]['counter_bits'], 64)
        self.assertEqual(report['records'][0]['counter_quality'], 'full_64bit')

    def test_unmarked_legacy_intervals_are_flagged_as_partial_precision(self):
        report = radius_usage.window_usage([event(0, kind='Acct-Start'), event(10, upload=100)], 0, 20)
        self.assertEqual(report['records'][0]['counter_bits'], 0)
        self.assertEqual(report['records'][0]['counter_quality'], 'legacy_32bit')

    def test_format_upgrade_survives_restart_and_ignores_legacy_other_server(self):
        tracker = radius_usage.UsageTracker()
        tracker.process([event(10, upload=100)], 0, 20)
        old_state = tracker.export_state()
        for session in old_state['sessions']:
            del session['counter_bits']
            del session['format_marked']
        restored = radius_usage.UsageTracker(old_state)
        upgraded = restored.process([event(20, upload=(1 << 32) + 200, counter_bits=64)], 0, 30)
        self.assertEqual(upgraded['upload_bytes'], 0)
        self.assertEqual(upgraded['counter_format_changes'], 1)
        after = radius_usage.UsageTracker(json.loads(json.dumps(restored.export_state())))
        report = after.process([event(25, upload=250, host='radius-secondary'),
            event(30, upload=(1 << 32) + 300, counter_bits=64)], 0, 40)
        self.assertEqual(report['upload_bytes'], 100)
        self.assertEqual(report['counter_resets'], 0)
        self.assertEqual(report['counter_format_changes'], 0)

    def test_invalid_counter_precision_markers_fail_closed(self):
        bad = [event(10, counter_bits='64'), event(10, counter_bits=True),
               event(10, counter_bits=128), event(10, counter_bits=32, upload=1 << 32)]
        report = radius_usage.window_usage(bad, 0, 20)
        self.assertEqual(report['invalid_records'], 4)
        tracker = radius_usage.UsageTracker()
        tracker.process([event(0, kind='Acct-Start')], 0, 20)
        state = tracker.export_state()
        state['sessions'][0]['counter_bits'] = 128
        with self.assertRaises(ValueError):
            radius_usage.UsageTracker(state)


if __name__ == '__main__':
    unittest.main()
