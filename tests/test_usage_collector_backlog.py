"""Backlogs retain committed progress and the original baseline credit boundary."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import radius_usage_collector as collector_module


FLOOR = 1791374400
LARGE = 9007199254740993
CREDENTIALS = {'api_key': 'api', 'app_key': 'app'}


def event(offset, value, kind='Acct-Update'):
    return {'attributes': {'timestamp': collector_module.iso(FLOOR + offset),
                          'host': 'radius-primary', 'attributes': {
        'event': kind, 'src_ip': '203.0.113.1', 'nas_ip': '10.0.0.2',
        'calling_station': 'aa:bb:cc:dd:ee:ff', 'session_id': 'backlog',
        'session_time': offset + 129600, 'input_bytes': value, 'output_bytes': value * 2,
        'counter_bits': 64}}}


class SearchFixture:
    """A paginated transport that honors time bounds, including endpoint ties."""
    def __init__(self, events):
        self.events = events
        self.searches = []
        self.posted = []
        self.before_search = None
        self.intake_error = None

    def __call__(self, url, headers, payload):
        if 'events/search' not in url:
            if self.intake_error:
                raise self.intake_error
            self.posted.extend(payload)
            return {}
        start = collector_module.radius_usage.timestamp(payload['filter']['from'])
        end = collector_module.radius_usage.timestamp(payload['filter']['to'])
        if 'cursor' not in payload['page']:
            if self.before_search:
                self.before_search(start, end)
            self.searches.append((start, end))
        selected = [item for item in self.events if start <= collector_module.radius_usage.timestamp(
                    item['attributes']['timestamp']) <= end]
        cursor = int(payload['page'].get('cursor', 0))
        page = selected[cursor:cursor + payload['page']['limit']]
        next_cursor = cursor + len(page)
        meta = {'page': {'after': str(next_cursor)}} if next_cursor < len(selected) else {}
        return {'data': page, 'meta': meta}


class BacklogTests(unittest.TestCase):
    def setUp(self):
        # Exercise actual pagination/overflow with small deterministic fixtures.
        for name, value in (('MAX_EVENTS', 4), ('PAGE_SIZE', 2)):
            patcher = patch.object(collector_module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def baseline_events(self):
        return [event(-129600, 0, 'Acct-Start')] + [
            event(offset, LARGE + index * 10) for index, offset in enumerate(
                [-120000, -100000, -80000, -60000, -40000, -20000, -1, 0, 3600, 7200])]

    def test_initial_baseline_over_limit_makes_progress_without_crediting_history(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            http = SearchFixture(self.baseline_events())
            collector = collector_module.Collector(CREDENTIALS, state, http=http)
            collector.run_once(FLOOR, FLOOR + 8000)
            self.assertEqual(sum(item['input_bytes'] for item in http.posted), 30)
            self.assertEqual(sum(item['output_bytes'] for item in http.posted), 60)
            saved = json.loads(state.read_text())
            self.assertEqual(saved['credit_start'], FLOOR)
            self.assertEqual(saved['through'], FLOOR + 8000)
            self.assertEqual(saved['version'], 1)
            self.assertEqual(saved['pending'], [])
            self.assertEqual(saved['tracker']['sessions'][0]['upload'], LARGE + 90)

    def test_interrupted_baseline_resumes_exact_floor_counters_and_no_history_credit(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            http = SearchFixture(self.baseline_events())
            def interrupt_after_commit(start, end):
                if state.exists() and json.loads(state.read_text())['through'] < FLOOR:
                    raise KeyboardInterrupt()
            http.before_search = interrupt_after_commit
            collector = collector_module.Collector(CREDENTIALS, state, http=http,
                                                   heartbeat=True, collector_id='radius-primary')
            with self.assertRaises(KeyboardInterrupt):
                collector.run_once(FLOOR, FLOOR + 8000)
            saved = json.loads(state.read_text())
            self.assertEqual(saved['version'], 2)
            self.assertEqual(saved['phase'], 'baseline')
            self.assertEqual(saved['credit_start'], FLOOR)
            self.assertLess(saved['through'], FLOOR)
            self.assertFalse(saved['uncertain'])
            self.assertFalse(saved['seeded'])
            self.assertEqual(saved['pending'], [])
            self.assertEqual(http.posted, [])
            self.assertGreater(saved['tracker']['sessions'][0]['upload'], 2 ** 53)
            through = saved['through']
            restarted = SearchFixture(self.baseline_events())
            collector_module.Collector(CREDENTIALS, state, http=restarted).run_once(FLOOR + 600, FLOOR + 8000)
            self.assertEqual(restarted.searches[0][0], through - 900)
            self.assertEqual(sum(item['input_bytes'] for item in restarted.posted), 30)
            self.assertEqual(json.loads(state.read_text())['credit_start'], FLOOR)
            self.assertEqual(json.loads(state.read_text())['version'], 1)

    def test_outage_backlog_restarts_after_chunk_without_duplicate_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            initial = SearchFixture([event(0, 0, 'Acct-Start'), event(10, 10)])
            collector_module.Collector(CREDENTIALS, state, http=initial).run_once(FLOOR, FLOOR + 20)
            events = [event(offset, 10 + index * 10) for index, offset in enumerate(
                [10, 4000, 8000, 12000, 16000, 20000, 24000, 28000, 32000])]
            http = SearchFixture(events)
            def interrupt_after_commit(start, end):
                if json.loads(state.read_text())['through'] > FLOOR + 20:
                    raise KeyboardInterrupt()
            http.before_search = interrupt_after_commit
            with self.assertRaises(KeyboardInterrupt):
                collector_module.Collector(CREDENTIALS, state, http=http).run_once(FLOOR + 30000, FLOOR + 33000)
            through = json.loads(state.read_text())['through']
            self.assertGreater(through, FLOOR + 20)
            restarted = SearchFixture(events)
            collector_module.Collector(CREDENTIALS, state, http=restarted).run_once(FLOOR + 32000, FLOOR + 33000)
            posted = initial.posted + http.posted + restarted.posted
            self.assertEqual(sum(item['input_bytes'] for item in posted), 90)
            self.assertEqual(len({item['usage_id'] for item in posted}), len(posted))
            self.assertEqual(restarted.searches[0][0], through - 900)

    def test_dense_timestamp_fails_closed_retaining_prior_baseline_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            events = self.baseline_events()[:4] + [event(0, LARGE + 50)] * 5
            http = SearchFixture(events)
            with self.assertRaisesRegex(ValueError, 'event limit'):
                collector_module.Collector(CREDENTIALS, state, http=http).run_once(FLOOR, FLOOR + 8000)
            self.assertTrue(state.exists())
            saved = json.loads(state.read_text())
            self.assertLessEqual(saved['through'], FLOOR)
            self.assertEqual(saved['credit_start'], FLOOR)
            self.assertEqual(http.posted, [])
            before = json.loads(state.read_text())
            with self.assertRaises(ValueError):
                collector_module.Collector(CREDENTIALS, state, http=SearchFixture(events)).run_once(FLOOR, FLOOR + 8000)
            after = json.loads(state.read_text())
            self.assertGreaterEqual(after['through'], before['through'])
            self.assertLessEqual(after['through'], FLOOR)
            self.assertEqual(after['credit_start'], FLOOR)
            self.assertEqual(after['tracker'], before['tracker'])
            self.assertEqual(after['pending'], [])

    def test_chunk_delivery_rejection_is_retryable_but_ambiguity_blocks_restart(self):
        for error, uncertain in ((HTTPError('https://test', 403, 'denied', {}, None), False),
                                 (URLError('response lost'), True)):
            with self.subTest(uncertain=uncertain), tempfile.TemporaryDirectory() as directory:
                state = Path(directory) / 'state'
                http = SearchFixture(self.baseline_events())
                http.intake_error = error
                with self.assertRaises(RuntimeError):
                    collector_module.Collector(CREDENTIALS, state, http=http).run_once(FLOOR, FLOOR + 8000)
                saved = json.loads(state.read_text())
                self.assertEqual(saved['uncertain'], uncertain)
                self.assertTrue(saved['pending'])
                restarted = SearchFixture(self.baseline_events())
                collector = collector_module.Collector(CREDENTIALS, state, http=restarted)
                if uncertain:
                    with self.assertRaisesRegex(RuntimeError, 'reconciliation'):
                        collector.run_once(FLOOR + 600, FLOOR + 8000)
                    self.assertEqual(restarted.searches, [])
                    self.assertEqual(restarted.posted, [])
                    self.assertEqual(state.read_bytes(), json.dumps(saved, separators=(',', ':')).encode())
                else:
                    collector.run_once(FLOOR + 600, FLOOR + 8000)
                    self.assertEqual(sum(item['input_bytes'] for item in restarted.posted), 30)
                    self.assertEqual(json.loads(state.read_text())['pending'], [])

    def test_large_quiet_gap_has_bounded_contiguous_searches_with_one_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            http = SearchFixture([event(0, 0, 'Acct-Start'), event(10, 10)])
            collector_module.Collector(CREDENTIALS, state, http=http).run_once(FLOOR, FLOOR + 20)
            http = SearchFixture([event(10, 10), event(200000, 20), event(250000, 30)])
            collector_module.Collector(CREDENTIALS, state, http=http).run_once(FLOOR + 259000, FLOOR + 260000)
            self.assertGreater(len(http.searches), 1)
            self.assertEqual(http.searches[0][0], FLOOR + 20 - 900)
            self.assertEqual(http.searches[-1][1], FLOOR + 260000)
            self.assertTrue(all(end - start <= 172800 for start, end in http.searches))
            self.assertTrue(all(first[1] == second[0] for first, second in zip(http.searches, http.searches[1:])))
            self.assertEqual(sum(item['input_bytes'] for item in http.posted), 20)

    def test_v2_baseline_rejects_invalid_phase_delivery_and_credit_boundaries(self):
        saved = {'version': 2, 'phase': 'baseline', 'tracker': {'version': 1, 'sessions': []},
                 'through': FLOOR - 100, 'credit_start': FLOOR, 'pending': [],
                 'uncertain': False, 'seeded': False, 'preview_id': None}
        invalid = [{'phase': 'credit'}, {'phase': None}, {'pending': [{}]},
                   {'uncertain': True}, {'seeded': True}, {'through': None},
                   {'credit_start': None}, {'through': FLOOR}, {'through': FLOOR + 1},
                   {'credit_start': float('nan')}, {'credit_start': True}, {'unexpected': 1}]
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            for change in invalid:
                with self.subTest(change=change):
                    state.write_text(json.dumps(saved | change))
                    before = state.read_bytes()
                    with self.assertRaises(ValueError):
                        collector_module.Collector(CREDENTIALS, state, http=SearchFixture([]))
                    self.assertEqual(state.read_bytes(), before)
            state.write_text(json.dumps(saved))
            collector = collector_module.Collector(CREDENTIALS, state, http=SearchFixture([]))
            self.assertEqual(collector.credit_start, FLOOR)
            self.assertEqual(collector.checkpoint, FLOOR - 100)
            with self.assertRaisesRegex(ValueError, 'initialized'):
                collector.seed_once([], FLOOR, FLOOR + 10)

    def test_baseline_reaching_exact_floor_returns_to_v1_without_traffic(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            http = SearchFixture([event(-100, LARGE), event(0, LARGE + 10)])
            def interrupt_at_floor(start, end):
                if state.exists() and json.loads(state.read_text())['through'] == FLOOR:
                    raise KeyboardInterrupt()
            http.before_search = interrupt_at_floor
            with patch.object(collector_module, 'MAX_SEARCH_SECONDS', 3600):
                with self.assertRaises(KeyboardInterrupt):
                    collector_module.Collector(CREDENTIALS, state, http=http).run_once(FLOOR, FLOOR + 10)
            saved = json.loads(state.read_text())
            self.assertEqual(saved['version'], 1)
            self.assertNotIn('phase', saved)
            self.assertEqual(saved['credit_start'], FLOOR)
            self.assertEqual(saved['through'], FLOOR)
            self.assertEqual(http.posted, [])
            restarted = SearchFixture([event(-100, LARGE), event(0, LARGE + 10)])
            collector_module.Collector(CREDENTIALS, state, http=restarted).run_once(FLOOR + 5, FLOOR + 10)
            self.assertEqual(sum(item['input_bytes'] for item in restarted.posted), 10)


if __name__ == '__main__':
    unittest.main()
