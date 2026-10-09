"""Development-only deployed Python checkpoint contract; no live HTTP."""
import json
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_usage_collector_backlog import (  # noqa: E402
    BacklogTests, CREDENTIALS, FLOOR, SearchFixture, collector_module,
)

mode, name = sys.argv[1:]
state = Path(name)
http = SearchFixture(BacklogTests().baseline_events())
with patch.object(collector_module, 'MAX_EVENTS', 4), patch.object(collector_module, 'PAGE_SIZE', 2):
    if mode == 'interrupt':
        def interrupt_after_commit(start, end):
            if state.exists() and json.loads(state.read_text())['through'] < FLOOR:
                raise KeyboardInterrupt()
        http.before_search = interrupt_after_commit
        try:
            collector_module.Collector(CREDENTIALS, state, http=http, heartbeat=True,
                                       collector_id='radius-primary').run_once(FLOOR, FLOOR + 8000)
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError('fixture did not interrupt')
        saved = json.loads(state.read_text())
        assert saved['version'] == 2 and saved['phase'] == 'baseline'
        assert saved['through'] < saved['credit_start'] == FLOOR
        assert saved['pending'] == [] and http.posted == []
    elif mode == 'resume':
        before = json.loads(state.read_text())
        assert before['version'] == 2 and before['credit_start'] == FLOOR
        collector_module.Collector(CREDENTIALS, state, http=http).run_once(FLOOR + 600, FLOOR + 8000)
        saved = json.loads(state.read_text())
        assert http.searches[0][0] == before['through'] - 900
        assert sum(item['input_bytes'] for item in http.posted) == 30
        assert sum(item['output_bytes'] for item in http.posted) == 60
        assert saved['credit_start'] == FLOOR and saved['version'] == 1
        assert 'phase' not in saved
    else:
        raise AssertionError('unknown fixture action')
