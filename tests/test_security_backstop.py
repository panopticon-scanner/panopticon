"""Strict reporting never supplies a verdict or a gate baseline."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from test_security_gate import _sarif

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "security_backstop", ROOT / ".github/scripts/security-backstop.py")
backstop = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backstop)
SHA = "a" * 40
IMAGE = "sha256:" + "b" * 64


def snapshot(root, level="error", missing=False):
    tools = root / "tools"
    tools.mkdir(exist_ok=True)
    if not missing:
        (tools / "semgrep.sarif").write_text(json.dumps(_sarif(level)))
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"selected": ["semgrep"],
                                   "produced": [] if missing else ["semgrep"],
                                   "missing": ["semgrep"] if missing else []}))
    return backstop.build_snapshot(tools, manifest, SHA, IMAGE, [])


def archive(data):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as zip_file:
        zip_file.writestr("snapshot.json", json.dumps(data))
    return output.getvalue()


class TestSnapshot(unittest.TestCase):
    def test_real_parser_serialization_and_no_snippets(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = snapshot(Path(tmp))
        self.assertEqual(data["version"], 1)
        self.assertEqual(data["commit"], SHA)
        self.assertEqual(data["image"], IMAGE)
        self.assertTrue(data["coverage"]["complete"])
        self.assertEqual(data["strict_verdict"], "fail")
        self.assertEqual(list(data["findings"].values()), ["HIGH"])
        encoded = json.dumps(data)
        self.assertNotIn("test finding", encoded)
        self.assertNotIn("app.py", encoded)
        self.assertEqual(backstop.validate_snapshot(json.loads(encoded)), data)

    def test_exact_coverage_summary_preserves_every_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = snapshot(Path(tmp))
        for complete in (True, False):
            data["coverage"] = {"complete": complete, "selected": 15, "produced": 12,
                                "missing": 3, "failure_count": 2, "excluded_scope": 4}
            summary = backstop.render_summary(data, None, "no history")
            expected = ("Coverage: %s; 15 selected, 12 produced, 3 missing, "
                        "2 failures, 4 excluded by scope." %
                        ("complete" if complete else "incomplete"))
            self.assertEqual([line for line in summary.splitlines()
                              if line.startswith("Coverage:")], [expected])

    def test_missing_coverage_is_red_even_without_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = snapshot(Path(tmp), missing=True)
        self.assertFalse(data["coverage"]["complete"])
        self.assertEqual(data["strict_verdict"], "fail")
        self.assertEqual(data["coverage"]["missing"], 1)

    def test_identity_ignores_severity_but_comparison_reports_regrade(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            previous = snapshot(root, "warning")
            current = snapshot(root, "error")
        delta = backstop.compare(current, previous)
        self.assertEqual(delta["added"], [])
        self.assertEqual(delta["removed"], [])
        self.assertEqual(delta["regraded"], list(current["findings"]))
        self.assertEqual(delta["severity_counts"]["HIGH"], 1)
        self.assertEqual(current["strict_verdict"], "fail")

    def test_added_removed_and_duplicate_count_changes(self):
        current = {"findings": {"a": "HIGH", "b": "LOW"}, "counts": {"a": 2, "b": 1},
                   "severity_counts": {"HIGH": 2, "LOW": 1}}
        previous = {"findings": {"a": "HIGH", "c": "LOW"}, "counts": {"a": 1, "c": 1},
                    "severity_counts": {"HIGH": 1, "LOW": 1}}
        delta = backstop.compare(current, previous)
        self.assertEqual(delta["added"], ["b"])
        self.assertEqual(delta["removed"], ["c"])
        self.assertEqual(delta["count_changed"], ["a"])
        self.assertEqual(delta["regraded"], [])

    def test_safe_bounded_markdown_and_incomplete_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = snapshot(Path(tmp))
        summary = backstop.render_summary(data, None, "<script>[evil](url)\n" * 1000)
        self.assertNotIn("<script>", summary)
        self.assertNotIn("[evil](url)", summary)
        self.assertLess(len(summary), 4000)
        self.assertIn("unavailable", summary)
        previous = json.loads(json.dumps(data))
        previous["coverage"]["complete"] = False
        self.assertIn("incomplete", backstop.render_summary(data, previous, ""))


class TestHistory(unittest.TestCase):
    def transport(self, responses):
        calls = []
        def fetch(args):
            calls.append(args)
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response
        return fetch, calls

    def test_selects_last_completed_scheduled_main_regardless_of_conclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = snapshot(Path(tmp))
        fetch, calls = self.transport([
            json.dumps([{"databaseId": 12, "headSha": SHA}]).encode(),
            json.dumps({"artifacts": [{"id": 34, "name": "strict-security-snapshot", "expired": False}]}).encode(),
            archive(data)])
        previous, reason = backstop.retrieve("owner/repo", fetch)
        self.assertEqual(previous, data)
        self.assertEqual(reason, "")
        self.assertIn("--event", calls[0])
        self.assertIn("schedule", calls[0])
        self.assertIn("main", calls[0])
        self.assertIn("completed", calls[0])
        self.assertNotIn("success", calls[0])
        self.assertIn("--limit", calls[0])
        self.assertEqual(len(calls), 3)
        self.assertTrue(all("--method" not in command for command in calls))

    def test_first_run_missing_corrupt_and_api_failure_are_unavailable(self):
        for responses in ([b"[]"], [b"bad json"], [OSError("offline")],
                          [b'[{"databaseId":12,"headSha":"' + SHA.encode() + b'"}]', b'{"artifacts":[]}'],
                          [b'[{"databaseId":12,"headSha":"' + SHA.encode() + b'"}]',
                           b'{"artifacts":[{"id":34,"name":"strict-security-snapshot","expired":false}]}', b'bad zip']):
            fetch, _ = self.transport(responses)
            previous, reason = backstop.retrieve("owner/repo", fetch)
            self.assertIsNone(previous)
            self.assertTrue(reason)

    def test_transport_timeout_and_output_limit(self):
        popen = subprocess.Popen
        def local_process(_command, **kwargs):
            return popen([sys.executable, "-c", "import time; time.sleep(2)"], **kwargs)
        with mock.patch.object(backstop.subprocess, "Popen", side_effect=local_process):
            with self.assertRaises(subprocess.TimeoutExpired):
                backstop.gh_read(["run", "list"], timeout=0.05)
        def large_process(_command, **kwargs):
            return popen([sys.executable, "-c", "print('x' * 100)"], **kwargs)
        with mock.patch.object(backstop.subprocess, "Popen", side_effect=large_process), mock.patch.object(backstop, "MAX_BYTES", 32):
            with self.assertRaises(ValueError):
                backstop.gh_read(["run", "list"])


class TestReportingCLI(unittest.TestCase):
    def test_red_gate_still_publishes_snapshot_and_summary(self):
        import scripts.security_gate as gate
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot(root)
            (root / "image").write_text(IMAGE)
            gate_args = ["--tools-dir", str(root / "tools"), "--manifest", str(root / "manifest.json")]
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(gate.main(gate_args), 1)
            args = ["report", *gate_args, "--commit", SHA,
                    "--image-file", str(root / "image"), "--history", str(root / "absent"),
                    "--output", str(root / "snapshot.json"), "--summary", str(root / "summary")]
            self.assertEqual(backstop.main(args), 0)
            self.assertEqual(json.loads((root / "snapshot.json").read_text())["strict_verdict"], "fail")
            self.assertIn("Comparison unavailable", (root / "summary").read_text())
            self.assertIn("**fail**", (root / "summary").read_text())

    def test_the_snapshot_is_built_in_the_mode_the_workflow_names(self):
        # The scheduled backstop reads the same redteam captures the gate
        # does; a snapshot evaluated in `standard` would drop the
        # policy-C-admitted suppressed set the gate counts, and the two
        # numbers on one step summary would disagree about one capture.
        import scripts.security_gate as gate
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot(root)
            (root / "image").write_text(IMAGE)
            args = ["report", "--tools-dir", str(root / "tools"),
                    "--manifest", str(root / "manifest.json"), "--commit", SHA,
                    "--image-file", str(root / "image"), "--history", str(root / "absent"),
                    "--output", str(root / "snapshot.json"), "--summary", str(root / "summary"),
                    "--security", "redteam"]
            with mock.patch.object(gate, "evaluate", wraps=gate.evaluate) as evaluate:
                self.assertEqual(backstop.main(args), 0)
            self.assertEqual(evaluate.call_args.kwargs.get("security_mode"), "redteam")
            with mock.patch.object(gate, "evaluate", wraps=gate.evaluate) as evaluate:
                self.assertEqual(backstop.main(args[:-2]), 0)
            self.assertEqual(evaluate.call_args.kwargs.get("security_mode"), "standard")

    def test_insufficient_capture_writes_summary_and_no_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = ["report", "--commit", SHA]
            for name in ("tools-dir", "manifest", "image-file", "history", "output", "summary"):
                args += ["--" + name, str(root / name)]
            self.assertEqual(backstop.main(args), 1)
            self.assertFalse((root / "output").exists())
            self.assertIn("insufficient", (root / "summary").read_text())

    def test_corrupt_snapshot_schema_and_commit_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = snapshot(Path(tmp))
        for field, value in (("version", 2), ("image", "latest"), ("counts", {}),
                             ("strict_verdict", "pass"), ("severity_counts", {})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                backstop.validate_snapshot({**data, field: value})
        fetch = mock.Mock(side_effect=[
            json.dumps([{"databaseId": 12, "headSha": "c" * 40}]).encode(),
            b'{"artifacts":[{"id":34,"name":"strict-security-snapshot","expired":false}]}',
            archive(data)])
        self.assertIsNone(backstop.retrieve("owner/repo", fetch)[0])

    def test_archive_layout_never_extracts_paths(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as zip_file:
            zip_file.writestr("../snapshot.json", "{}")
        fetch = mock.Mock(side_effect=[
            json.dumps([{"databaseId": 12, "headSha": SHA}]).encode(),
            b'{"artifacts":[{"id":34,"name":"strict-security-snapshot","expired":false}]}',
            output.getvalue()])
        self.assertIsNone(backstop.retrieve("owner/repo", fetch)[0])


class TestSnapshotBoundaries(unittest.TestCase):
    def test_clean_snapshot_passes_without_losing_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = snapshot(Path(tmp), level=None)
        self.assertTrue(data["coverage"]["complete"])
        self.assertEqual(data["strict_verdict"], "pass")
        self.assertEqual(data["findings"], {})

    def test_comparison_lists_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = snapshot(Path(tmp))
        prior = json.loads(json.dumps(data))
        prior["findings"] = {}
        prior["counts"] = {}
        data["findings"] = {f"{n:064x}": "HIGH" for n in range(100)}
        data["counts"] = {key: 1 for key in data["findings"]}
        summary = backstop.render_summary(data, prior, "")
        self.assertIn("added: 100 identities (first 20 shown)", summary)
        self.assertEqual(sum(line.startswith("- ") for line in summary.splitlines()), 20)
        self.assertLess(len(summary), 5000)

    def test_unparseable_selected_scanner_is_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot(root)
            (root / "tools/semgrep.sarif").write_text("{broken")
            data = backstop.build_snapshot(root / "tools", root / "manifest.json", SHA, IMAGE, [])
        self.assertFalse(data["coverage"]["complete"])
        self.assertEqual(data["coverage"]["failure_count"], 1)
        self.assertEqual(data["strict_verdict"], "fail")
