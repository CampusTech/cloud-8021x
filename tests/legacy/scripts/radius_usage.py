"""Compute observed traffic increments from cumulative RADIUS accounting reports.

A report is credited wholly at its receipt timestamp in [start, end). Rates are
averages over the reported session-time interval, not instantaneous throughput.
Include earlier reports to establish baselines. A first mid-session snapshot is
never treated as new traffic. Missing data and counter resets cause undercounts,
not invented traffic. Source/NAS/client/session must uniquely identify a session.

CLI: python3 scripts/radius_usage.py --start 2026-10-07T00:00:00Z \
    --end 2026-10-08T00:00:00Z accounting.jsonl
Input is flat JSONL (stdin by default); timestamps accept epoch seconds or ISO
8601 with a timezone. --format jsonl emits only credited interval records. The
report format also contains totals and diagnostic counts. No network calls or
persistent state are involved in the CLI. A WAN source change creates a new
baseline and a conservative gap until office/source normalization is available.
The UsageTracker API supports a versioned JSON checkpoint across batches.
Overlapping offline replay output must be deduplicated downstream by usage_id.
"""
import argparse
from datetime import datetime
import hashlib
import json
import math
import re
import sys


ACCOUNTING_EVENTS = {"Acct-Start", "Acct-Update", "Acct-Stop"}
IDENTITY_FIELDS = ("device_id", "device_name", "device_owner", "device_model",
                   "serial", "certificate_fingerprint")
DISPLAY_FIELDS = ("site_name", "ssid", "ap_name", "host", "vlan_id", "vlan_name",
                  "nas_port", "called_station")


def timestamp(value):
    """Parse epoch seconds or timezone-aware ISO 8601 without local-time guesses."""
    if isinstance(value, bool):
        raise ValueError("boolean timestamp")
    try:
        result = float(value)
    except (TypeError, ValueError):
        if not isinstance(value, str):
            raise ValueError("invalid timestamp") from None
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timestamp needs a timezone")
        result = parsed.timestamp()
    if not math.isfinite(result):
        raise ValueError("timestamp must be finite")
    return result


def integer(value):
    """Reject malformed or fractional counters instead of silently resetting."""
    if isinstance(value, bool):
        raise ValueError("boolean counter")
    if isinstance(value, str) and not re.fullmatch(r"[0-9]+", value):
        raise ValueError("invalid counter")
    if not isinstance(value, (int, str, float)):
        raise ValueError("invalid counter")
    if isinstance(value, float) and (not math.isfinite(value) or not value.is_integer()):
        raise ValueError("counter must be a finite integer")
    result = int(value)
    if result < 0:
        raise ValueError("counter must be nonnegative")
    return result


def counter_bits(item, upload, download):
    """Use an explicit source format, or infer precision only from large values."""
    marker = item.get("counter_bits")
    if marker is not None:
        if type(marker) is not int or marker not in (32, 64):
            raise ValueError("unsupported accounting counter format")
        if marker == 32 and max(upload, download) >= (1 << 32):
            raise ValueError("32-bit marker contradicts accounting counters")
        return marker
    return 64 if max(upload, download) >= (1 << 32) else 32


def session_key(item):
    parts = [item.get(name) for name in ("src_ip", "nas_ip", "calling_station", "session_id")]
    if not all(isinstance(value, str) and value.strip() for value in parts):
        raise ValueError("missing session identity")
    source, nas, mac, session = [value.strip() for value in parts]
    mac = re.sub(r"[:.\-]", "", mac).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", mac):
        raise ValueError("invalid client MAC")
    return source.lower(), nas.lower(), mac, session


def identity(item):
    # Strings such as "false" must not be accepted as a verified identity.
    if item.get("identity_verified") is True and isinstance(item.get("device_id"), str) and item["device_id"]:
        return {"identity_verified": True, **{key: item.get(key, "") for key in IDENTITY_FIELDS}}
    return None


class UsageTracker:
    """Incremental, globally shared session highwater checkpoint.

    A single collector must feed reports from both servers into this tracker.
    Overlapping batches and restarts do not reemit previously observed counter
    intervals. Export a checkpoint only after output delivery is durable; this
    pure helper does not implement transport, locking, or delivery transactions.
    Terminal sessions remain in the checkpoint to reject replayed Stops. Source
    precision changes rebaseline to avoid charging old high words as new traffic;
    older version-1 checkpoints infer their previous precision conservatively.
    """

    VERSION = 1

    def __init__(self, state=None):
        self.sessions = {}
        if state is None:
            return
        if (not isinstance(state, dict) or type(state.get("version")) is not int
                or state["version"] != self.VERSION or not isinstance(state.get("sessions"), list)):
            raise ValueError("unsupported or malformed usage checkpoint")
        for saved in state["sessions"]:
            try:
                if not isinstance(saved, dict) or not isinstance(saved["key"], list) or len(saved["key"]) != 4:
                    raise ValueError("invalid session key")
                key = session_key(dict(zip(("src_ip", "nas_ip", "calling_station", "session_id"), saved["key"])))
                if list(key) != saved["key"] or key in self.sessions:
                    raise ValueError("noncanonical or duplicate session key")
                counters = {}
                for field in ("duration", "upload", "download"):
                    if type(saved[field]) is not int:
                        raise ValueError("invalid checkpoint counter")
                    counters[field] = integer(saved[field])
                if type(saved["stopped"]) is not bool or not isinstance(saved["display"], dict):
                    raise ValueError("invalid checkpoint metadata")
                display = saved["display"]
                if any(name not in DISPLAY_FIELDS for name in display):
                    raise ValueError("unknown checkpoint display field")
                verified = saved["identity"]
                if verified is not None and (not isinstance(verified, dict) or identity(verified) != verified):
                    raise ValueError("invalid verified identity checkpoint")
                if type(saved["last_seen"]) not in (int, float):
                    raise ValueError("invalid checkpoint receipt timestamp")
                last_seen = timestamp(saved["last_seen"])
                bits = saved.get("counter_bits", 64 if max(counters["upload"], counters["download"]) >= (1 << 32) else 32)
                if (type(bits) is not int or bits not in (32, 64)
                        or (bits == 32 and max(counters["upload"], counters["download"]) >= (1 << 32))):
                    raise ValueError("invalid checkpoint counter format")
                marked = saved.get("format_marked", False)
                if type(marked) is not bool:
                    raise ValueError("invalid checkpoint format provenance")
                value = {**counters, "stopped": saved["stopped"], "display": display,
                         "identity": verified, "last_seen": last_seen,
                         "counter_bits": bits, "format_marked": marked}
                self.sessions[key] = json.loads(json.dumps(value, allow_nan=False))
            except (KeyError, TypeError, ValueError, OverflowError) as error:
                raise ValueError("malformed usage session checkpoint") from error

    def export_state(self):
        """Return an independent plain JSON checkpoint, including terminal state."""
        saved = {"version": self.VERSION,
                 "sessions": [{"key": list(key), **value} for key, value in sorted(self.sessions.items())]}
        return json.loads(json.dumps(saved, allow_nan=False))

    def prune_before(self, cutoff):
        """Remove states with no observed reports since cutoff; return the count.

        This includes inactive terminal and live sessions. A later report for a
        pruned session establishes a fresh baseline, deliberately undercounting
        its unknown interval. The collector chooses its retention policy.
        """
        cutoff = timestamp(cutoff)
        expired = [key for key, state in self.sessions.items() if state["last_seen"] < cutoff]
        for key in expired:
            del self.sessions[key]
        return len(expired)

    def process(self, events, start, end):
        """Credit new increments wholly at report receipt times in [start, end).

        Earlier reports establish baselines without being credited. Old session
        times never move a checkpoint backward; counter decreases establish a
        new baseline and discard the ambiguous interval. Rates are interval
        averages, and verified identity may carry forward within a session.
        """
        start, end = timestamp(start), timestamp(end)
        if start >= end:
            raise ValueError("start must be before end")
        report = {"upload_bytes": 0, "download_bytes": 0, "intervals": 0,
                  "records": [], "baselines_missing": 0, "counter_resets": 0,
                  "invalid_records": 0, "counter_format_changes": 0}
        parsed = []
        for item in events:
            if not isinstance(item, dict):
                report["invalid_records"] += 1
                continue
            if item.get("event") not in ACCOUNTING_EVENTS:
                continue
            try:
                when = timestamp(item["timestamp"])
                key = session_key(item)
                beginning = item["event"] == "Acct-Start"
                duration = 0 if beginning else integer(item["session_time"])
                upload = 0 if beginning else integer(item["input_bytes"])
                download = 0 if beginning else integer(item["output_bytes"])
                bits = counter_bits(item, upload, download)
            except (KeyError, ValueError, TypeError, OverflowError):
                report["invalid_records"] += 1
                continue
            if when < end:
                parsed.append((when, key, duration, upload, download, item))
        # Stable ties: a Start establishes the zero baseline before same-time updates.
        parsed.sort(key=lambda row: (row[0], row[5]["event"] != "Acct-Start", row[2], row[3], row[4]))
        sessions = self.sessions
        for when, key, duration, upload, download, item in parsed:
            bits = counter_bits(item, upload, download)
            current_identity = identity(item)
            state = sessions.get(key)
            fingerprint = (duration, upload, download)
            if state is None:
                state = {"duration": duration, "upload": upload, "download": download,
                         "identity": current_identity,
                         "stopped": item["event"] == "Acct-Stop", "last_seen": when,
                         "counter_bits": bits, "format_marked": item.get("counter_bits") is not None,
                         "display": {name: item[name] for name in DISPLAY_FIELDS if item.get(name) not in (None, "")}}
                sessions[key] = state
                if item["event"] != "Acct-Start":
                    report["baselines_missing"] += 1
                continue
            state["last_seen"] = max(state["last_seen"], when)
            if state["stopped"] or item["event"] == "Acct-Start" or duration < state["duration"]:
                continue
            marked = item.get("counter_bits") is not None
            if state["counter_bits"] == 64 and state["format_marked"] and not marked and bits == 32:
                # An old logger on the other VM may still be reporting low words.
                continue
            if current_identity:
                state["identity"] = current_identity
            state["display"].update({name: item[name] for name in DISPLAY_FIELDS if item.get(name) not in (None, "")})
            if item["event"] == "Acct-Stop":
                state["stopped"] = True
            if marked and bits != state["counter_bits"]:
                # A logger upgrade adds previously unobserved high words. They
                # cannot be attributed to this interval; establish a new base.
                state.update(duration=duration, upload=upload, download=download,
                             counter_bits=bits, format_marked=True)
                report["counter_format_changes"] += 1
                continue
            state["counter_bits"] = max(state["counter_bits"], bits)
            state["format_marked"] = state["format_marked"] or marked
            if fingerprint == (state["duration"], state["upload"], state["download"]):
                continue
            if duration == state["duration"] and (upload < state["upload"] or download < state["download"]):
                continue
            previous = (state["duration"], state["upload"], state["download"])
            state.update(duration=duration, upload=upload, download=download)
            if upload < previous[1] or download < previous[2]:
                report["counter_resets"] += 1
                continue
            if when < start:
                continue
            upload_delta, download_delta = upload - previous[1], download - previous[2]
            seconds = duration - previous[0]
            # Counter coordinates identify an interval without receipt-time or host.
            digest = hashlib.sha256(json.dumps([key, previous, fingerprint], separators=(",", ":")).encode()).hexdigest()
            record = {**state["display"], "timestamp": when, "event": "Acct-Usage",
                      "src_ip": key[0], "nas_ip": key[1], "calling_station": key[2], "session_id": key[3],
                      "session_time": duration, "usage_id": digest,
                      "counter_bits": 64 if state["counter_bits"] == 64 else 0,
                      "counter_quality": "full_64bit" if state["counter_bits"] == 64 else "legacy_32bit",
                      "upload_delta_bytes": upload_delta, "download_delta_bytes": download_delta,
                      "interval_seconds": seconds, "upload_bps": upload_delta * 8 / seconds if seconds else None,
                      "download_bps": download_delta * 8 / seconds if seconds else None,
                      **(state["identity"] or {"identity_verified": False})}
            report["records"].append(record)
            report["upload_bytes"] += upload_delta
            report["download_bytes"] += download_delta
            report["intervals"] += 1
        return report

def window_usage(events, start, end):
    """Replay a window using fresh state; include prior baseline reports."""
    return UsageTracker().process(events, start, end)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", nargs="?", default="-", help="flat accounting JSONL file, or - for stdin")
    parser.add_argument("--start", required=True, help="inclusive epoch seconds or timezone-aware ISO timestamp")
    parser.add_argument("--end", required=True, help="exclusive epoch seconds or timezone-aware ISO timestamp")
    parser.add_argument("--format", choices=("report", "jsonl"), default="report")
    args = parser.parse_args(argv)
    source = sys.stdin
    try:
        if args.input != "-":
            source = open(args.input, encoding="utf-8")
        events = []
        for line in source:
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                events.append(None)  # Count bad JSON as an invalid record.
        report = window_usage(events, args.start, args.end)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    finally:
        if source is not sys.stdin:
            source.close()
    if args.format == "jsonl":
        for item in report["records"]:
            print(json.dumps(item, separators=(",", ":"), allow_nan=False))
    else:
        print(json.dumps(report, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
