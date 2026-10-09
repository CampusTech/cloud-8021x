"""Checkpoint cumulative accounting once, downstream of both RADIUS servers.

The collector creates observed interval logs, never estimates missing traffic.
One state file must be shared by every invocation. An ambiguous intake result
requires an operator to reconcile the pending batch; it is never retried blindly.
The collector does not configure or restart RADIUS or the APs.
Checkpoints retain the initial credit_start so late indexing cannot backfill
traffic before the requested initial window. Legacy version-1 checkpoints have
no recoverable origin; their first resumed 15-minute overlap becomes this floor.
Interrupted baseline-only searches use a typed version-2 checkpoint until the
original credit floor is reached; ordinary checkpoints retain version 1.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import logging
import math
import os
import re
from pathlib import Path
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

import radius_usage


LOG = logging.getLogger("radius_usage_collector")
MAX_EVENTS = 100000
MAX_RESPONSE = 32 * 1024 * 1024
PAGE_SIZE = 1000
MAX_SEARCH_SECONDS = 48 * 3600
MIN_SEARCH_SECONDS = 1
HOSTS = {"radius-primary", "radius-secondary"}
SEARCH_QUERY = ("service:radius-acct (host:radius-primary OR host:radius-secondary) "
                "(@event:Acct-Start OR @event:Acct-Update OR @event:Acct-Stop)")


def iso(value):
    return datetime.fromtimestamp(radius_usage.timestamp(value), timezone.utc).isoformat().replace("+00:00", "Z")


class NoRedirect(HTTPRedirectHandler):
    """Never forward either Datadog credential to a redirect destination."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SearchEventLimit(ValueError):
    """Only a complete search that exceeds the bound can be safely subdivided."""


def request_json(url, headers, payload):
    raw = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode()
    request = Request(url, data=raw, headers={**headers, "Content-Type": "application/json"}, method="POST")
    with build_opener(NoRedirect).open(request, timeout=45) as response:
        if "events/search" not in url and response.status != 202:
            raise RuntimeError("Unexpected intake status; delivery needs reconciliation")
        body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise ValueError("Datadog response exceeds the configured size limit")
        return json.loads(body) if body else {}


def configured_hosts(hosts=None):
    values = tuple(HOSTS if hosts is None else hosts)
    label = r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
    if (not values or len(values) > 16
            or any(not isinstance(host, str) or len(host) > 253
                   or not re.fullmatch(label + r'(?:\.' + label + r')*', host) for host in values)
            or len(set(values)) != len(values)):
        raise ValueError('Source hosts must be unique valid DNS hostnames')
    return frozenset(values)


def flatten(event, hosts=None):
    """Use Datadog's authoritative, timezone-aware receipt time, not legacy JSON time."""
    if not isinstance(event, dict) or not isinstance(event.get("attributes"), dict):
        raise ValueError("Malformed accounting search result")
    outer = event["attributes"]
    attrs = outer.get("attributes")
    if not isinstance(attrs, dict):
        raise ValueError("Missing accounting search attributes")
    value = dict(attrs)
    value["timestamp"] = iso(outer.get("timestamp"))
    host = outer.get("host") or attrs.get("host")
    tags = outer.get("tags", [])
    if not host and isinstance(tags, list):
        host = next((tag[5:] for tag in tags if isinstance(tag, str) and tag.startswith("host:")), None)
    if host not in (HOSTS if hosts is None else hosts):
        raise ValueError("Accounting record is not attributed to a configured RADIUS host")
    value["host"] = host
    return value


class Collector:
    VERSION = 1

    def __init__(self, credentials, state_path, http=None, dry_run=False,
                 site="us5.datadoghq.com", preview_id=None, heartbeat=False, collector_id=None, hosts=None):
        if site not in {"datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com",
                        "datadoghq.eu", "ap1.datadoghq.com", "ap2.datadoghq.com", "ddog-gov.com"}:
            raise ValueError("Unsupported Datadog site")
        if not isinstance(credentials, dict) or not all(isinstance(credentials.get(k), str) and credentials[k]
                                                      for k in ("api_key", "app_key")):
            raise ValueError("Credentials file needs two nonempty Datadog credentials")
        self.credentials = credentials
        self.state_path = Path(state_path)
        self.http = http or request_json
        self.dry_run = dry_run
        self.site = site
        self.preview_id = preview_id
        self.hosts = configured_hosts(hosts)
        host_query = ' OR '.join('host:"' + host + '"' for host in sorted(self.hosts))
        self.search_query = ('service:radius-acct (' + host_query + ') '
                             '(@event:Acct-Start OR @event:Acct-Update OR @event:Acct-Stop)')
        if heartbeat and (not isinstance(collector_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", collector_id)):
            raise ValueError("Heartbeat requires a stable collector ID")
        self.heartbeat = heartbeat
        self.collector_id = collector_id
        self.headers = {"DD-API-KEY": credentials["api_key"], "DD-APPLICATION-KEY": credentials["app_key"]}
        self._reload()

    def _reload(self):
        self.tracker = radius_usage.UsageTracker()
        self.checkpoint = None
        self.credit_start = None
        self.pending = []
        self.uncertain = False
        self.seeded = False
        self.baseline = False
        if not self.state_path.exists():
            return
        if self.state_path.is_symlink():
            raise ValueError("Checkpoint must not be a symlink")
        saved = json.loads(self.state_path.read_text(encoding="utf-8"))
        if (not isinstance(saved, dict) or type(saved.get("version")) is not int
                or saved["version"] not in {self.VERSION, 2}):
            raise ValueError("Unsupported or malformed collector checkpoint")
        required = {"version", "tracker", "through", "pending", "uncertain", "seeded", "preview_id"}
        self.baseline = saved["version"] == 2
        valid_fields = (required | {"credit_start", "phase"},) if self.baseline else (
            required, required | {"credit_start"})
        if set(saved) not in valid_fields:
            raise ValueError("Malformed collector checkpoint fields")
        if self.baseline and (saved["phase"] != "baseline" or saved["pending"] != []
                              or saved["uncertain"] is not False or saved["seeded"] is not False):
            raise ValueError("Malformed collector baseline phase")
        if type(saved["uncertain"]) is not bool or type(saved["seeded"]) is not bool:
            raise ValueError("Malformed collector checkpoint delivery state")
        if not isinstance(saved["pending"], list) or len(saved["pending"]) > MAX_EVENTS:
            raise ValueError("Malformed collector pending batch")
        for record in saved["pending"]:
            if (not isinstance(record, dict) or record.get("event") != "Acct-Usage"
                    or record.get("service") != "radius-usage"
                    or not isinstance(record.get("usage_id"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", record["usage_id"])
                    or record.get("hostname") not in self.hosts):
                raise ValueError("Malformed pending usage record")
            radius_usage.timestamp(record.get("timestamp"))
            if (radius_usage.integer(record.get("input_bytes")) != radius_usage.integer(record.get("upload_delta_bytes"))
                    or radius_usage.integer(record.get("output_bytes")) != radius_usage.integer(record.get("download_delta_bytes"))
                    or record.get("counter_quality") not in {"full_64bit", "legacy_32bit", "legacy32_unknown"}
                    or record.get("preview_id") != self.preview_id):
                raise ValueError("Malformed pending usage interval")
        if saved["preview_id"] != self.preview_id:
            raise ValueError("Checkpoint belongs to a different preview")
        self.tracker = radius_usage.UsageTracker(saved["tracker"])
        self.checkpoint = radius_usage.timestamp(saved["through"]) if saved["through"] is not None else None
        if "credit_start" in saved:
            self.credit_start = radius_usage.timestamp(saved["credit_start"]) if saved["credit_start"] is not None else None
            if self.baseline:
                if (self.credit_start is None or self.checkpoint is None
                        or self.credit_start <= self.checkpoint):
                    raise ValueError("Malformed collector baseline credit boundary")
            elif ((self.credit_start is None) != (self.checkpoint is None)
                    or (self.credit_start is not None and self.credit_start > self.checkpoint)):
                raise ValueError("Malformed collector initial credit boundary")
        elif self.checkpoint is not None:
            # The original window cannot be reconstructed from an old checkpoint.
            # Retain its first recovery overlap, then persist that fixed floor.
            self.credit_start = self.checkpoint - 900
        self.pending = saved["pending"]
        self.uncertain = saved["uncertain"]
        self.seeded = saved["seeded"]
        if self.pending and self.checkpoint is None:
            raise ValueError("Malformed pending checkpoint without receipt highwater")
        if self.uncertain and not self.pending:
            raise ValueError("Malformed uncertain checkpoint without pending delivery")

    @contextmanager
    def _lock(self):
        # A dry run must not leave a checkpoint or lock artifact behind.
        if self.dry_run:
            self._reload()
            yield
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise RuntimeError("Another usage collector holds this checkpoint") from error
            self._reload()
            yield
        finally:
            os.close(fd)

    def _save(self):
        if self.dry_run:
            return
        saved = {"version": self.VERSION, "tracker": self.tracker.export_state(),
                 "through": self.checkpoint, "pending": self.pending,
                 "uncertain": self.uncertain, "seeded": self.seeded, "preview_id": self.preview_id,
                 "credit_start": self.credit_start}
        if self.baseline:
            saved.update(version=2, phase="baseline")
        if self.state_path.is_symlink():
            raise ValueError("Checkpoint must not be a symlink")
        fd, name = tempfile.mkstemp(prefix=".usage-checkpoint-", dir=self.state_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as target:
                os.fchmod(target.fileno(), 0o600)
                json.dump(saved, target, separators=(",", ":"), allow_nan=False)
                target.flush()
                os.fsync(target.fileno())
            os.replace(name, self.state_path)
            directory_fd = os.open(self.state_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def _request(self, url, payload, intake=False):
        # Logs intake requires only the ingestion credential.
        headers = {"DD-API-KEY": self.credentials["api_key"]} if intake else self.headers
        for attempt in range(3):
            try:
                if intake:
                    # Mark before the network call: a crash between acceptance
                    # and checkpoint clearing is as ambiguous as a timeout.
                    self.uncertain = True
                    self._save()
                return self.http(url, headers, payload)
            except HTTPError as error:
                if intake and 400 <= error.code < 500:
                    self.uncertain = False
                    self._save()
                if error.code == 429 and attempt < 2:
                    delay = error.headers.get("Retry-After", "1") if error.headers else "1"
                    try:
                        delay = float(delay)
                    except (ValueError, TypeError):
                        raise RuntimeError("Datadog rate limit; retry delay cannot be honored") from None
                    if delay < 0 or delay > 60:
                        raise RuntimeError("Datadog rate limit; retry later") from None
                    time.sleep(delay)
                    continue
                # 4xx, including exhausted 429, is a definite rejection. 5xx,
                # redirects and transport failures may conceal accepted intake.
                if intake and not 400 <= error.code < 500:
                    self.uncertain = True
                    self._save()
                raise RuntimeError(f"Datadog rejected request (HTTP {error.code})") from None
            except Exception:
                if intake:
                    self.uncertain = True
                    self._save()
                # Do not expose request headers, credential-bearing exception URLs,
                # or server response bodies via the operational log.
                raise RuntimeError("Datadog request failed; intake delivery may need reconciliation" if intake
                                   else "Datadog search failed; checkpoint unchanged") from None

    def _search(self, start, end):
        payload = {"filter": {"query": self.search_query, "from": iso(start), "to": iso(end)},
                   "sort": "timestamp", "page": {"limit": PAGE_SIZE}}
        events, cursors = [], set()
        for _ in range(MAX_EVENTS // PAGE_SIZE + 1):
            response = self._request("https://api." + self.site + "/api/v2/logs/events/search", payload)
            if not isinstance(response, dict) or not isinstance(response.get("data"), list):
                raise ValueError("Malformed accounting search page; checkpoint unchanged")
            meta = response.get("meta", {})
            if not isinstance(meta, dict) or meta.get("warnings") or meta.get("status") not in {None, "done"}:
                raise ValueError("Incomplete accounting search; checkpoint unchanged")
            page = response["data"]
            if len(page) > PAGE_SIZE:
                raise ValueError("Accounting page exceeds page limit; checkpoint unchanged")
            if len(events) + len(page) > MAX_EVENTS:
                raise SearchEventLimit("Accounting search exceeds event limit; checkpoint unchanged")
            events.extend(flatten(event, self.hosts) for event in page)
            page_meta = meta.get("page", {})
            if not isinstance(page_meta, dict):
                raise ValueError("Malformed accounting pagination; checkpoint unchanged")
            cursor = page_meta.get("after")
            if not cursor:
                return events
            if not isinstance(cursor, str) or cursor in cursors:
                raise ValueError("Accounting cursor repeated; checkpoint unchanged")
            cursors.add(cursor)
            # Copy payload so test/transport histories retain the prior request.
            payload = {**payload, "page": {"limit": PAGE_SIZE, "cursor": cursor}}
        raise SearchEventLimit("Accounting pagination exceeds event limit; checkpoint unchanged")

    def _deliver(self):
        if self.uncertain:
            raise RuntimeError("Pending intake delivery is uncertain; operator reconciliation required before retry")
        while self.pending:
            batch = []
            size = 2
            for record in self.pending[:100]:
                encoded = json.dumps(record, separators=(",", ":"), allow_nan=False).encode()
                if len(encoded) > 1024 * 1024:
                    raise ValueError("Pending usage record exceeds intake size limit")
                if size + len(encoded) + 1 > 4 * 1024 * 1024:
                    break
                batch.append(record)
                size += len(encoded) + 1
            self._request("https://http-intake.logs." + self.site + "/api/v2/logs", batch, intake=True)
            self.pending = self.pending[len(batch):]
            self.uncertain = False
            self._save()

    def _process(self, events, start, end, seeded=False, baseline=False):
        events = [dict(item) for item in events]
        if baseline:
            events = [item for item in events if radius_usage.timestamp(item["timestamp"]) < end]
        for item in events:
            if not item.get("ssid"):
                called = item.get("called_station", "")
                match = re.match(r"^(?:(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[0-9a-f]{12}|(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}):(.+)$",
                                 called, re.IGNORECASE) if isinstance(called, str) else None
                if match:
                    item["ssid"] = match.group(1)
        # Baseline-only chunks contain receipts strictly before the original
        # floor. A valid empty credit window lets the tracker learn counters
        # without assigning historical increases to the requested window.
        report = self.tracker.process(events, start, start + 1 if baseline else end)
        records = []
        for record in report["records"]:
            quality = record.get("counter_quality", "legacy_32bit")
            value = {**record, "timestamp": iso(record["timestamp"]), "service": "radius-usage",
                     "hostname": record.get("host"), "input_bytes": record["upload_delta_bytes"],
                     "output_bytes": record["download_delta_bytes"], "counter_quality": quality,
                     "measurement": "observed_interval", "ddsource": "radius",
                     "source_session_time": record["session_time"], "session_time": record["interval_seconds"]}
            site_name = value.get("site_name")
            value["site_name"] = site_name.strip() if isinstance(site_name, str) and site_name.strip() else "Unknown site"
            owner = value.get("device_owner")
            value["device_owner"] = owner if isinstance(owner, str) and owner.strip() else "N/A"
            if value["hostname"] not in self.hosts:
                raise ValueError("Usage interval has no configured source hostname")
            value.pop("host", None)
            if self.preview_id:
                value["preview_id"] = self.preview_id
            records.append(value)
        self.pending = records
        if self.credit_start is None:
            self.credit_start = radius_usage.timestamp(start)
        # Adaptive splitting may put the first recovery chunk wholly inside
        # the overlap. Replaying it must not move committed progress backward.
        self.checkpoint = max(self.checkpoint, end) if self.checkpoint is not None else end
        self.baseline = baseline and self.checkpoint < self.credit_start
        self.seeded = self.seeded or seeded
        self.tracker.prune_before(self.checkpoint - 7 * 86400)
        self._save()  # Durable highwater and outbox precede the first intake call.
        if not self.dry_run:
            self._deliver()
        result = {key: value for key, value in report.items() if key != "records"} | {
            "source_records": len(events), "dry_run": self.dry_run,
            "through": iso(end), "data_available": bool(events),
            "source_completeness": "observed_only"}
        if self.heartbeat and not self.dry_run and not baseline:
            heartbeat = {"service": "radius-usage-collector", "event": "Collection-Heartbeat",
                         "timestamp": iso(time.time()), "ddsource": "radius",
                         "hostname": self.collector_id, "collector_id": self.collector_id,
                         "through": result["through"], "source_records": len(events),
                         "intervals": len(records), "source_completeness": "observed_only"}
            if self.preview_id:
                heartbeat["preview_id"] = self.preview_id
            # Health logs never enter the traffic outbox. Failure cannot poison
            # its delivery state; a restart rechecks sources before announcing health.
            try:
                self.http("https://http-intake.logs." + self.site + "/api/v2/logs",
                          {"DD-API-KEY": self.credentials["api_key"]}, [heartbeat])
            except Exception:
                raise RuntimeError("Collector heartbeat intake failed; checkpoint preserved") from None
        return result

    def run_once(self, start, end):
        start, end = radius_usage.timestamp(start), radius_usage.timestamp(end)
        if start >= end:
            raise ValueError("Start must precede end")
        with self._lock():
            if self.uncertain:
                raise RuntimeError("Pending intake delivery is uncertain; operator reconciliation required before retry")
            if self.checkpoint is not None and end < self.checkpoint:
                raise ValueError("End precedes collector checkpoint")
            if self.pending and not self.dry_run:
                self._deliver()
            search_start = self.checkpoint - 900 if self.checkpoint is not None else start - 36 * 3600
            # The initial window excludes older traffic used only as a baseline.
            # After checkpointing, credit every unseen increase in the search
            # overlap: downtime and delayed indexing must not consume traffic
            # silently. Persistent session counters suppress reports already seen.
            if self.credit_start is None:
                self.credit_start = start
            chunk_start = search_start
            result = None
            while chunk_start < end:
                chunk_end = min(end, chunk_start + MAX_SEARCH_SECONDS)
                while True:
                    try:
                        events = self._search(chunk_start, chunk_end)
                        break
                    except SearchEventLimit:
                        # Nothing from a truncated search has been processed.
                        # Split time only; a dense minimum-size window fails
                        # closed, retaining every earlier committed chunk.
                        if chunk_end - chunk_start <= MIN_SEARCH_SECONDS:
                            raise
                        chunk_end = chunk_start + max(MIN_SEARCH_SECONDS,
                                                       (chunk_end - chunk_start) / 2)
                credit_start = max(chunk_start, self.credit_start)
                result = self._process(events, credit_start, chunk_end,
                                       baseline=chunk_end <= self.credit_start)
                # The recovery overlap applies once, never between chunks.
                chunk_start = chunk_end
            return result

    def seed_once(self, events, start, end):
        """Bootstrap cached flat source records once; never silently reseed state."""
        start, end = radius_usage.timestamp(start), radius_usage.timestamp(end)
        if start >= end:
            raise ValueError("Start must precede end")
        if len(events) > MAX_EVENTS:
            raise ValueError("Seed exceeds event limit")
        with self._lock():
            if self.seeded or self.checkpoint is not None or self.pending or self.uncertain:
                raise ValueError("Collector checkpoint already initialized; seed refused")
            for item in events:
                if not isinstance(item, dict) or item.get("host") not in self.hosts:
                    raise ValueError("Seed must contain flat records with configured RADIUS host")
            return self._process(events, start, end, seeded=True)

    seed = seed_once


@contextmanager
def runner_lock(state_path, dry_run=False):
    """Keep one CLI collector active, including between follow-mode polls."""
    if dry_run:
        yield
        return
    path = Path(state_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path.with_name(path.name + ".runner.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another CLI usage collector is active") from error
        yield
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", required=True, help="private JSON containing api_key and app_key")
    parser.add_argument("--state", required=True, help="private durable collector checkpoint")
    parser.add_argument("--start", help="inclusive timezone-aware timestamp; default ten minutes ago")
    parser.add_argument("--end", help="exclusive timezone-aware timestamp; default now")
    parser.add_argument("--site", default="us5.datadoghq.com")
    parser.add_argument("--preview-id")
    parser.add_argument("--heartbeat", action="store_true", help="emit success health logs, including quiet passes")
    parser.add_argument("--collector-id", help="stable unique identity for collector health")
    parser.add_argument("--hosts", nargs='+', help="canonical Datadog accounting source hostnames")
    parser.add_argument("--seed-file", help="flat cached JSONL records, bootstrapped once")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--interval", type=float, default=120)
    parser.add_argument("--duration", type=float, help="maximum follow lifetime in seconds")
    args = parser.parse_args(argv)
    if not math.isfinite(args.interval) or args.interval <= 0 or (args.duration is not None and
            (not math.isfinite(args.duration) or args.duration <= 0)):
        parser.error("Interval and duration must be positive")
    if args.seed_file and (not args.start or not args.end):
        parser.error("Cached seed requires explicit start and end")
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(levelname)s %(message)s")
    try:
        credentials = json.loads(Path(args.credentials).read_text(encoding="utf-8"))
        collector = Collector(credentials, args.state, dry_run=args.dry_run, site=args.site, preview_id=args.preview_id,
                              heartbeat=args.heartbeat, collector_id=args.collector_id, hosts=args.hosts)
        with runner_lock(args.state, args.dry_run):
            started = time.monotonic()
            end = radius_usage.timestamp(args.end) if args.end else time.time()
            start = radius_usage.timestamp(args.start) if args.start else end - 600
            if args.seed_file:
                with open(args.seed_file, encoding="utf-8") as source:
                    events = []
                    for line in source:
                        if line.strip():
                            events.append(json.loads(line))
                            if len(events) > MAX_EVENTS:
                                raise ValueError("Seed exceeds event limit")
                report = collector.seed_once(events, start, end)
            else:
                report = collector.run_once(start, end)
            LOG.info("Usage collection: %s", json.dumps(report, separators=(",", ":")))
            while args.follow:
                if args.duration is not None and time.monotonic() - started >= args.duration:
                    break
                delay = args.interval
                if args.duration is not None:
                    delay = min(delay, max(0, args.duration - (time.monotonic() - started)))
                time.sleep(delay)
                if args.duration is not None and time.monotonic() - started >= args.duration:
                    break
                start, end = end, time.time()
                report = collector.run_once(start, end)
                LOG.info("Usage collection: %s", json.dumps(report, separators=(",", ":")))
    except (ValueError, OSError, RuntimeError) as error:
        # All network errors have already been sanitized by _request.
        LOG.error("%s", str(error))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
