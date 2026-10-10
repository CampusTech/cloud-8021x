"""Exercise actual runner stop contract without Docker or mirrored implementation."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("kms_runner_stop", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def stat(state="S", ticks="100"):
    return "92 (step-ca) " + " ".join([state] + ["0"] * 18 + [ticks] + ["0"] * 5) + "\n"


class StopContract(unittest.TestCase):
    def test_signal_failure_is_never_reported_as_retirement(self):
        # The preserved baseline test exposed discarded127; fixed shell failures also fail closed.
        error, _, proof = self.exercise(["S"], term_exit=127)
        self.assertIsNotNone(error)
        self.assertEqual(proof["builtin_term"]["exit"], 127)
        self.assertFalse(proof["retired"])

    def exercise(self, states, *, term_exit=0, listener=False, ticks="100"):
        calls = []
        state_sequence = iter(states)
        latest = states[-1]
        clock = iter(i * 0.5 for i in range(100))
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        out = Path(directory.name)

        def read(path):
            if path.endswith(".pid"):
                return "92\n"
            if path.endswith(".start-stat"):
                return stat()
            if path == "/proc/92/cmdline":
                return "/usr/bin/step-ca\x00/work/ec/ca.json\x00"
            if path == "/proc/net/tcp":
                return "header\n" + ("0: 0100007F:20FB 00000000:0000 0A 0 0 0 0\n" if listener else "")
            raise AssertionError("unexpected read " + path)

        def execute(*args, **kwargs):
            nonlocal latest
            calls.append(args)
            if args[:2] == ("kill", "-0"):
                return subprocess.CompletedProcess(args, 127, 'exec: "kill": executable file not found')
            if args[:2] == ("sh", "-c") and args[2].startswith("if [ -e"):
                latest = next(state_sequence, latest)
                return subprocess.CompletedProcess(args, 0, "retired\n" if latest is None else stat(latest, ticks))
            if args[:3] == ("sh", "-c", 'kill -TERM "$1"'):
                return subprocess.CompletedProcess(args, term_exit, "" if term_exit == 0 else "TERM failed")
            raise AssertionError("unexpected command " + repr(args))

        def docker(*args, **kwargs):
            self.assertEqual(args, ("inspect", runner.NAME))
            return subprocess.CompletedProcess(args, 0, json.dumps([{
                "Config": {"Labels": {"cloud8021x.owner": runner.OWNER}}, "State": {"Running": True}
            }]))

        with patch.object(runner, "OUT", out), patch.object(runner, "read", side_effect=read), patch.object(
            runner, "execute", side_effect=execute
        ), patch.object(runner, "docker", side_effect=docker), patch.object(
            runner.time, "monotonic", side_effect=lambda: next(clock)
        ), patch.object(runner.time, "sleep"):
            error = None
            try:
                runner.stop("step-ca-ec")
            except RuntimeError as exc:
                error = exc
        proof = json.loads((out / "stop-step-ca-ec.json").read_text())
        return error, calls, proof

    def test_missing_external_tool_uses_builtin_and_proves_delayed_retirement(self):
        error, calls, proof = self.exercise(["S", "S", "Z"])
        self.assertIsNone(error)
        self.assertIn(("kill", "-0", "92"), calls)
        self.assertIn(("sh", "-c", 'kill -TERM "$1"', "sh", "92"), calls)
        self.assertEqual(proof["external_kill_probe"]["exit"], 127)
        self.assertTrue(proof["retired"])
        self.assertTrue(proof["listener_released"])

    def test_already_retired_process_needs_no_signal(self):
        error, calls, proof = self.exercise([None])
        self.assertIsNone(error)
        self.assertTrue(proof["retired"] and proof["listener_released"])
        self.assertFalse(any(args[:2] == ("kill", "-0") for args in calls))

    def test_builtin_term_failure_prevents_successor(self):
        error, _, proof = self.exercise(["S"], term_exit=1)
        self.assertIsNotNone(error)
        self.assertIn("TERM", str(error))
        self.assertFalse(proof["retired"])

    def test_live_process_and_retained_listener_fail_closed(self):
        for states, listener in [(["S"], False), (["S", "Z"], True)]:
            with self.subTest(states=states, listener=listener):
                error, _, proof = self.exercise(states, listener=listener)
                self.assertIsNotNone(error)
                self.assertFalse(proof["retired"] and proof["listener_released"])

    def test_reused_pid_is_never_signalled(self):
        error, calls, _ = self.exercise(["S"], ticks="101")
        self.assertIsNotNone(error)
        self.assertFalse(any(args[:2] == ("kill", "-0") or args[:3] == ("sh", "-c", 'kill -TERM "$1"') for args in calls))


if __name__ == "__main__":
    unittest.main()
