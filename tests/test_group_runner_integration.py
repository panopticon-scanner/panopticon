"""Private hook/decision integration, not a live host dispatch.

The harness's live hook wall was verified manually during SP-A. These tests
exercise current domain cells, batch install, and a private hook subprocess.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

import scripts.group_runner as gr
import scripts.write_guard_hook as wg


def _plan(root):
    run_dir = os.path.join(root, ".panopticon", "runs", "wave5-test")
    os.makedirs(run_dir)
    return [{
        "id": "review-%s-%s" % (group, domain),
        "role": "domain_panel", "run_id": "wave5-test",
        "group": group, "domain": domain,
        "out_file": os.path.join(run_dir, "findings-%s-%s.json" % (group, domain)),
    } for group in ("Auth", "Billing") for domain in ("SEC", "COD")]


def _write_cell(entry, *, run_id=None, stamp=True):
    body = {"findings": []}
    if stamp:
        body["_panopticon"] = {
            "run_id": entry["run_id"] if run_id is None else run_id,
            "role": entry["role"], "group": entry["group"],
            "domain": entry["domain"],
        }
    with open(entry["out_file"], "w", encoding="utf-8") as fh:
        json.dump(body, fh)


class TestFanOutIntegration(unittest.TestCase):
    def test_full_domain_coverage_when_all_written(self):
        with tempfile.TemporaryDirectory() as root:
            plan = _plan(root)
            for entry in plan:
                _write_cell(entry)
            self.assertEqual(gr.pending_entries(plan), [])
            self.assertEqual(gr.fan_out_coverage(plan), {
                "planned": {"SEC": 2, "COD": 2},
                "executed": {"SEC": 2, "COD": 2},
                "groups_complete": ["Auth", "Billing"],
                "groups_partial": [],
            })

    def test_cell_a_decision_denies_cell_b_path(self):
        with tempfile.TemporaryDirectory() as root:
            cell_a, cell_b = _plan(root)[:2]
            grants = wg.allowlist_from_plan([cell_a])
            self.assertEqual(grants, {
                cell_a["id"]: [os.path.realpath(cell_a["out_file"])]})
            allow = wg.union_paths(grants)
            self.assertTrue(wg.decide("Write", cell_a["out_file"], allow)[0])
            allowed, reason = wg.decide("Write", cell_b["out_file"], allow)
            self.assertFalse(allowed)
            self.assertIn("allowlist", reason)

    def test_resume_reruns_truncated_wrong_and_missing_stamp(self):
        with tempfile.TemporaryDirectory() as root:
            plan = _plan(root)
            for entry in plan:
                _write_cell(entry)
            self.assertEqual(gr.pending_entries(plan), [])

            with open(plan[2]["out_file"], "w", encoding="utf-8") as fh:
                fh.write('{"findings": [')
            _write_cell(plan[3], run_id="old-run")
            self.assertEqual(gr.pending_entries(plan), plan[2:])
            self.assertEqual(gr.fan_out_coverage(plan), {
                "planned": {"SEC": 2, "COD": 2},
                "executed": {"SEC": 1, "COD": 1},
                "groups_complete": ["Auth"],
                "groups_partial": ["Billing"],
            })
            _write_cell(plan[3], stamp=False)
            self.assertEqual(gr.pending_entries(plan), plan[2:])

    def test_batch_install_and_private_hook_subprocess(self):
        with tempfile.TemporaryDirectory() as root:
            plan = _plan(root)
            allowlist_path = os.path.join(root, ".panopticon", "write-allowlist.json")
            settings_path = os.path.join(root, ".claude", "settings.local.json")
            wg.install(plan, settings_path=settings_path, allowlist_path=allowlist_path)
            with open(allowlist_path, encoding="utf-8") as fh:
                document = json.load(fh)
            self.assertEqual(set(document["entries"]), {e["id"] for e in plan})
            self.assertEqual(set(document["paths"]),
                             {os.path.realpath(e["out_file"]) for e in plan})
            self.assertEqual(wg.is_armed(settings_path, allowlist_path), (True, 4))

            def run_hook(tool_name, file_path):
                payload = {"tool_name": tool_name,
                           "tool_input": {"file_path": file_path}}
                env = os.environ.copy()
                env["PANOPTICON_WRITE_ALLOWLIST"] = allowlist_path
                env[wg.ENV_ENTRY_ID] = plan[0]["id"]
                return subprocess.run(
                    [sys.executable, os.path.abspath(wg.__file__)],
                    input=json.dumps(payload), text=True, capture_output=True,
                    env=env, cwd=root, timeout=30,
                )

            for tool, path, denied in (
                ("Write", plan[0]["out_file"], False),
                ("Write", plan[1]["out_file"], True),
                ("Read", plan[1]["out_file"], False),
            ):
                with self.subTest(tool=tool, path=path):
                    proc = run_hook(tool, path)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    if denied:
                        self.assertIn("peer entry's artifact is not writable",
                                      proc.stdout)
                    else:
                        self.assertEqual(proc.stdout, "")
