# NOTE: this exercises the guard's DECISION function (`decide`) in-process. The
# LIVE hook wall — the harness actually denying an out-of-scope reviewer Write —
# cannot be asserted deterministically here (it needs a real dispatch + hook
# install). It was verified manually during SP-A: with the guard installed from a
# real plan, a dispatched reviewer's in-allowlist write succeeded and its
# out-of-scope write was denied by the harness. Re-run that live smoke test if
# the hook plumbing or its paths change.
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
import scripts.group_runner as gr
import scripts.write_guard_hook as wg


def _plan(d):
    entries = []
    for group in ("g1", "g2"):
        for panel in ("code", "security"):
            entries.append({
                "role": "panel_review", "group": group, "panel": panel,
                "out_file": os.path.join(
                    d, "findings-%s-%s-panel_review.json" % (group, panel))})
    return entries


class TestFanOutIntegration(unittest.TestCase):
    def test_full_coverage_when_all_written(self):
        with tempfile.TemporaryDirectory() as d:
            plan = _plan(d)
            for e in plan:  # simulate every reviewer writing its out_file
                with open(e["out_file"], "w") as fh:
                    json.dump({"findings": []}, fh)
            self.assertEqual(gr.pending_entries(plan), [])
            cov = gr.fan_out_coverage(plan)
            self.assertEqual(cov["groups_partial"], [])
            self.assertEqual(sorted(cov["groups_complete"]), ["g1", "g2"])
            self.assertEqual(cov["executed"], {"code": 2, "security": 2})

    def test_out_of_scope_write_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            plan = _plan(d)
            allow = wg.allowlist_from_plan(plan)
            ok_self, _ = wg.decide("Write", plan[0]["out_file"], allow)
            ok_repo, reason = wg.decide("Write", "skill/scripts/synthesize.py", allow)
            self.assertTrue(ok_self)
            self.assertFalse(ok_repo)
            self.assertIn("allowlist", reason)

    def test_resume_reruns_only_incomplete(self):
        with tempfile.TemporaryDirectory() as d:
            plan = _plan(d)
            # all but the last entry completed; the last is truncated (crash)
            for e in plan[:-1]:
                with open(e["out_file"], "w") as fh:
                    json.dump({"findings": []}, fh)
            with open(plan[-1]["out_file"], "w") as fh:
                fh.write('{"findings": [')  # truncated -> not done
            pending = gr.pending_entries(plan)
            self.assertEqual(pending, [plan[-1]])
            cov = gr.fan_out_coverage(plan)
            self.assertEqual(cov["groups_partial"], ["g2"])

    def test_e2e_write_guard_hook(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            plan = _plan(d)
            allowlist_path = os.path.join(d, ".panopticon", "write-allowlist.json")
            settings_path = os.path.join(d, ".claude", "settings.local.json")

            # Install the hook to set up the allowlist
            wg.install(plan, settings_path=settings_path, allowlist_path=allowlist_path)

            hook_script = os.path.abspath(wg.__file__)

            # Helper to run the hook with a payload
            def run_hook(tool_name, file_path):
                payload = {
                    "tool_name": tool_name,
                    "tool_input": {"file_path": file_path} if file_path else {}
                }
                env = os.environ.copy()
                env["PANOPTICON_WRITE_ALLOWLIST"] = allowlist_path
                proc = subprocess.run(
                    [sys.executable, hook_script],
                    input=json.dumps(payload),
                    text=True,
                    capture_output=True,
                    env=env
                )
                return proc.stdout.strip()

            # Test 1: In-scope write
            stdout = run_hook("Write", plan[0]["out_file"])
            self.assertEqual(stdout, "")  # No output means allowed

            # Test 2: Out-of-scope write
            stdout = run_hook("Write", os.path.join(d, "skill/scripts/synthesize.py"))
            self.assertIn("deny", stdout)
            self.assertIn("outside the fan-out allowlist", stdout)

            # Test 3: Non-write tool
            stdout = run_hook("Read", plan[0]["out_file"])
            self.assertEqual(stdout, "")
