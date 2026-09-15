"""#1634: a credential a reviewer quoted-but-didn't-redact must not survive
into ANY artifact a synthesize run writes -- not just `findings[]`.

`build_report` copies `f["title"]` into `summary.top_issues` and
`groups[].key_findings` BEFORE `render.redact_report_secrets` ran, and that
backstop rewrote only `findings` and `discarded_claims`, so a token in a title
reached report.json's summary, the HTML (which reads `summary.top_issues`) and
every downstream producer verbatim. Two halves fix it and this module guards
both: redaction at the INPUT (so derived fields are computed from masked text)
and a backstop that walks the WHOLE report tree (so a producer that copies text
after it cannot reintroduce one).

The scan is deliberately a directory walk rather than a list of known
filenames: every file a run drops in the output directory is checked, so a new
artifact producer is covered by construction rather than by remembering to
extend a list here.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest

import scripts.redact as redact
import scripts.strain_report as strain_report
import scripts.synth.findings as findings_mod
import scripts.synth.render as render_mod
import scripts.synthesize as syn


# Distinct synthetic markers, one per input surface, each shaped like a GitHub
# token (`ghp_` + 36 token chars) -- a format scripts/redact.py ALREADY masks,
# so a leak here is an ordering/coverage defect and never a pattern-set gap
# (that is #1572, a different bug). Not credentials: 'A'*31 is not a secret.
MARKERS = {
    "title": "ghp_" + "TITLE" + "A" * 31,
    "description": "ghp_" + "DESC" + "B" * 32,
    "references": "ghp_" + "REFS" + "C" * 32,
    "discarded": "ghp_" + "DISCARDED" + "D" * 27,
    "reasoning": "ghp_" + "REASON" + "E" * 30,
    "chunked": "ghp_" + "CHUNKED" + "F" * 29,
}


def _findings_doc():
    """Three findings: one an advisor CONFIRMS (so it lands in `findings[]`,
    the summary and the group roll-up), one it REJECTS (so it lands in
    `discarded_claims`) and a bulky third so the split write has two active
    findings to chunk across `report.json` + `report_part2.json`. Between them
    the markers cover title, description and the evidence citations."""
    return {"findings": [
        {"id": "SEC-1", "domain": "SEC", "code": "SEC-A1A",
         "title": "authz bypass %s" % MARKERS["title"],
         "description": "credential quoted verbatim: %s" % MARKERS["description"],
         "severity": "HIGH", "confidence": "LIKELY", "panel": "security",
         "category": "authz", "source": "agent:reviewer",
         "references": ["evidence citation %s" % MARKERS["references"]],
         "location": {"file": "app/x.py", "line_start": 4}},
        {"id": "SEC-2", "domain": "SEC", "code": "SEC-A1A",
         "title": "second-hand claim %s" % MARKERS["discarded"],
         "description": "unsupported",
         "severity": "HIGH", "confidence": "POSSIBLE", "panel": "security",
         "category": "authz", "source": "agent:reviewer",
         "location": {"file": "app/y.py", "line_start": 9}},
        {"id": "SEC-3", "domain": "SEC", "code": "SEC-A1A",
         "title": "log injection",
         "description": ("padding %s " % MARKERS["chunked"]) + "z" * 900,
         "severity": "MEDIUM", "confidence": "POSSIBLE", "panel": "security",
         "category": "injection", "source": "agent:reviewer",
         "location": {"file": "app/z.py", "line_start": 11}},
    ]}


def _verdicts_doc(confirmed_id, rejected_id):
    """An advisor bundle keyed by finding id. Its `reasoning` carries its own
    marker: that text is merged into `finding.evidence.reasoning` INSIDE
    build_report, i.e. after the input redaction, so only the whole-tree
    backstop can mask it.

    The ids are the ones `load_findings` derives (a content hash), not the ones
    the file declares, so they are read back from the loader rather than
    guessed -- an unbound verdict would silently empty `discarded_claims` and
    make this guard vacuous."""
    return {"verdicts": [
        {"finding_id": confirmed_id, "verdict": "CONFIRMED",
         "reasoning": "advisor quoted it too: %s" % MARKERS["reasoning"]},
        {"finding_id": rejected_id, "verdict": "REJECTED",
         "reasoning": "not reachable"},
    ], "_panopticon": {"run_id": "R", "role": "domain_advisor",
                       "domain": "SEC", "group": "app", "stage": "primary"}}


def _run(tmpdir, max_bytes=None):
    """Run a real `synthesize.main()` over the marked findings.

    Inputs live in `<tmpdir>/in` and artifacts in `<tmpdir>/out`, so the
    artifact scan never re-reads the (legitimately marked) input files.
    Returns (out_dir, report_path, stdout).
    """
    in_dir = os.path.join(tmpdir, "in")
    v_dir = os.path.join(in_dir, "verdicts")
    out_dir = os.path.join(tmpdir, "out")
    os.makedirs(v_dir)
    os.makedirs(out_dir)
    fp = os.path.join(in_dir, "findings-app-security.json")
    with open(fp, "w", encoding="utf-8") as fh:
        json.dump(_findings_doc(), fh)
    with open(os.path.join(in_dir, "groups.json"), "w", encoding="utf-8") as fh:
        json.dump({"groups": [{"name": "app",
                               "files": ["app/x.py", "app/y.py"]}]}, fh)
    with contextlib.redirect_stderr(io.StringIO()):
        loaded = findings_mod.load_findings([fp])
    with open(os.path.join(v_dir, "verdicts-app-SEC.json"), "w",
              encoding="utf-8") as fh:
        json.dump(_verdicts_doc(loaded[0]["id"], loaded[1]["id"]), fh)
    out = os.path.join(out_dir, "report.json")

    real_write = render_mod.write_report

    def _small_write(report, out_path, max_bytes=max_bytes):
        return real_write(report, out_path, max_bytes=max_bytes)

    buf = io.StringIO()
    prev = os.getcwd()
    os.chdir(tmpdir)
    try:
        if max_bytes is not None:
            render_mod.write_report = _small_write
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            syn.main(["--target", "app", "--out", out,
                      "--groups", os.path.join(in_dir, "groups.json"),
                      "--verdicts-dir", v_dir, fp])
    finally:
        render_mod.write_report = real_write
        os.chdir(prev)
    return out_dir, out, buf.getvalue()


def _emit_strain(report_path):
    """The strain report is a separate entry script that reads the written
    report, so produce it here and let the same scan cover it."""
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    strain = strain_report.build_report(report.get("findings") or [],
                                        report.get("meta") or {}, "R")
    return strain_report.write_report(strain, report_path)


def scan_artifacts(out_dir, extra_text=()):
    """Every marker found in any file under `out_dir` (plus any extra text
    blobs, e.g. the terminal summary), as {marker_name: [where, ...]}.

    Walks the directory instead of naming files: report.json, the `_partN.json`
    splits, the `-discarded.json` sibling, `.json.html`, `-x0x.json` and
    `-strain.json` are all covered, and so is whatever a future producer
    writes beside them."""
    blobs = []
    for root, _dirs, files in os.walk(out_dir):
        for name in sorted(files):
            path = os.path.join(root, name)
            with open(path, encoding="utf-8", errors="replace") as fh:
                blobs.append((os.path.relpath(path, out_dir), fh.read()))
    blobs.extend(extra_text)
    hits = {}
    for name, marker in MARKERS.items():
        where = [label for label, text in blobs if marker in text]
        if where:
            hits[name] = where
    return hits


class TestNoMarkerSurvivesAnyArtifact(unittest.TestCase):
    def test_single_file_report(self):
        with tempfile.TemporaryDirectory() as d:
            out_dir, report_path, stdout = _run(d)
            _emit_strain(report_path)
            written = sorted(os.listdir(out_dir))
            # The run really did write the artifacts this guard claims to cover.
            self.assertIn("report.json", written)
            self.assertIn("report.json.html", written)
            self.assertIn("report-x0x.json", written)
            self.assertIn("report-strain.json", written)
            hits = scan_artifacts(out_dir, [("terminal summary", stdout)])
            self.assertEqual(hits, {}, "unredacted markers survived: %s" % hits)

    def test_the_derived_fields_are_populated_and_masked(self):
        """The two fields #1634 named, checked positively: they must carry the
        finding's text (so the assertion above is not passing on an empty
        summary) and that text must be masked."""
        with tempfile.TemporaryDirectory() as d:
            _out_dir, report_path, _stdout = _run(d)
            with open(report_path, encoding="utf-8") as fh:
                report = json.load(fh)
            top = report["summary"]["top_issues"]
            keyf = [k for g in report["groups"] for k in g["key_findings"]]
            # Non-vacuity: both derived fields really do carry the title.
            self.assertTrue(any("authz bypass" in t for t in top), top)
            self.assertTrue(any("authz bypass" in k for k in keyf), keyf)
            leaked = {name: vals for name, vals in (
                ("summary.top_issues", [t for t in top if MARKERS["title"] in t]),
                ("groups[].key_findings",
                 [k for k in keyf if MARKERS["title"] in k])) if vals}
            self.assertEqual(leaked, {}, "derived fields kept the marker")
            self.assertTrue(any("[REDACTED_TOKEN]" in t for t in top), top)
            self.assertTrue(any("[REDACTED_TOKEN]" in k for k in keyf), keyf)

    def test_split_report_with_discarded_sibling(self):
        """The same guard over the split write: `_partN.json` files plus the
        `-discarded.json` sibling, which only exist above max_bytes."""
        with tempfile.TemporaryDirectory() as d:
            out_dir, report_path, stdout = _run(d, max_bytes=1200)
            _emit_strain(report_path)
            written = sorted(os.listdir(out_dir))
            self.assertIn("report-discarded.json", written)
            self.assertTrue([w for w in written if "_part" in w], written)
            hits = scan_artifacts(out_dir, [("terminal summary", stdout)])
            self.assertEqual(hits, {}, "unredacted markers survived: %s" % hits)


class TestWholeTreeBackstopIsANoOpOnCleanReports(unittest.TestCase):
    """The backstop walks every string in the report, so it must be provably
    inert on a report that holds no secret -- structured fields (host
    capabilities, coverage, ids, paths, grades) come back byte-identical."""

    def _clean_report(self, d):
        in_dir = os.path.join(d, "in")
        out_dir = os.path.join(d, "out")
        os.makedirs(in_dir)
        os.makedirs(out_dir)
        fp = os.path.join(in_dir, "findings-app-security.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump({"findings": [
                {"id": "SEC-1", "domain": "SEC", "code": "SEC-A1A",
                 "title": "authz bypass", "description": "no credential here",
                 "severity": "HIGH", "confidence": "LIKELY", "panel": "security",
                 "category": "authz", "source": "agent:reviewer",
                 "references": ["docs/PANOPTICON.md", "CVE-2021-44228"],
                 "location": {"file": "app/x.py", "line_start": 4}}]}, fh)
        # A run artifact whose contents are structured, not prose: the posture
        # is copied into meta.host_capabilities VERBATIM, so it is the sharpest
        # test of "the walk changes nothing that is not a secret".
        with open(os.path.join(d, "host-capabilities.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"host": "claude", "schema_version": 1,
                       "probed_at": "2026-09-15T00:00:00Z",
                       "capabilities": {
                           "tool_policy_enforced": {
                               "state": "proven", "by": "probe:settings",
                               "detail": "deny rule at ~/.claude/settings.json",
                               "guid": "3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
                           "read_scope_confined": {
                               "state": "unproven", "by": None,
                               "detail": "sha256:" + "a" * 64}}}, fh)
        out = os.path.join(out_dir, "report.json")
        buf = io.StringIO()
        prev = os.getcwd()
        os.chdir(d)
        try:
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                syn.main(["--target", "app", "--out", out, "--run-dir", d, fp])
        finally:
            os.chdir(prev)
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)

    def test_golden_report_is_unchanged_by_the_whole_tree_walk(self):
        with tempfile.TemporaryDirectory() as d:
            report = self._clean_report(d)
        before = json.dumps(report, indent=2, sort_keys=True)
        after = json.dumps(redact.redact_tree(report), indent=2, sort_keys=True)
        self.assertEqual(before, after)
        # and the structured posture really did reach the report (so the
        # comparison above is not vacuous)
        caps = report["meta"]["host_capabilities"]["capabilities"]
        self.assertEqual(caps["tool_policy_enforced"]["state"], "proven")
        self.assertEqual(caps["tool_policy_enforced"]["guid"],
                         "3f2504e0-4f89-11d3-9a0c-0305e82c3301")

    def test_the_backstop_preserves_report_key_order(self):
        """write_report dumps insertion order and the key order is part of the
        artifact, so the in-place rewrite must not reshuffle it."""
        report = {"schema_version": 1, "meta": {"target": "app"},
                  "summary": {"gate": "PASS"}, "groups": [], "findings": [],
                  "cross_panel": {}, "discarded_claims": []}
        before = list(report)
        render_mod.redact_report_secrets(report)
        self.assertEqual(list(report), before)


if __name__ == "__main__":
    unittest.main()


class TestTwoPassFingerprintStability(unittest.TestCase):
    """#1634 F1: both synthesize passes must fingerprint the SAME text.

    `evidence.finding_fingerprint` keys an agent finding on its TITLE, and that
    fingerprint is the `queue_id` pass 1 writes into verify-queue.json -- the
    filename an advisor's verdict is stored under and the key `match_verdict`
    binds on. So redaction has to happen on the same side of the
    `--emit-verify-queue` early return in BOTH passes. Applied after it, pass 1
    queues the unredacted title and pass 2 recomputes from the redacted one:
    every queue_id changes, the advisor's verdict no longer binds, the finding
    drops to `unverified` and `coverage_certified` flips to False -- silently,
    reading exactly like an advisor that never answered, and triggered by
    precisely the input #1634 exists for (a credential quoted in a title).
    """

    MARKER = MARKERS["title"]

    def _finding(self):
        return {"findings": [
            {"id": "SEC-1", "domain": "SEC", "code": "SEC-A1A",
             "title": "hardcoded token %s" % self.MARKER,
             "description": "a credential is checked in",
             "severity": "HIGH", "confidence": "LIKELY", "panel": "security",
             "category": "secrets",
             "location": {"file": "app/x.py", "line_start": 4}}]}

    def test_queue_id_survives_redaction_across_both_passes(self):
        with tempfile.TemporaryDirectory() as d:
            src = os.path.join(d, "src")
            run = os.path.join(d, "run")
            out_dir = os.path.join(d, "out")
            v_dir = os.path.join(d, "verdicts")
            for p in (src, run, out_dir, v_dir):
                os.makedirs(p)
            fp = os.path.join(src, "findings-app-security.json")
            with open(fp, "w", encoding="utf-8") as fh:
                json.dump(self._finding(), fh)

            prev = os.getcwd()
            os.chdir(d)
            try:
                # Pass 1: the orchestrator's --emit-verify-queue run.
                with contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    syn.main(["--target", "app", "--run-dir", run,
                              "--emit-verify-queue", fp])
                with open(os.path.join(run, "verify-queue.json"),
                          encoding="utf-8") as fh:
                    queue = json.load(fh)
                entry = queue["entries"][0]
                queue_id, fid = entry["queue_id"], entry["finding"]["id"]

                # The advisor answers, addressed by that queue_id.
                with open(os.path.join(v_dir, "%s.json" % queue_id), "w",
                          encoding="utf-8") as fh:
                    json.dump({"finding_id": fid, "verdict": "CONFIRMED",
                               "run_id": queue["run_id"],
                               "reasoning": "reachable from the request path"}, fh)

                # Pass 2: the report run, same inputs.
                with contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    syn.main(["--target", "app", "--run-dir", run,
                              "--out", os.path.join(out_dir, "report.json"),
                              "--verdicts-dir", v_dir, fp])
            finally:
                os.chdir(prev)
            with open(os.path.join(out_dir, "report.json"), encoding="utf-8") as fh:
                report = json.load(fh)

            finding = report["findings"][0]
            stats = report["meta"]["coverage"]["verdicts"]
            # One assertion over every symptom: a divergence shows the queue_id
            # mismatch AND what it costs downstream, rather than stopping at
            # the first of five.
            self.assertEqual({
                "pass2_fingerprint": finding["fingerprint"],
                "evidence_status": finding["evidence"]["status"],
                "verdicts_matched": stats["matched"],
                "verdicts_unanswered": stats["unanswered"],
                "coverage_certified": report["summary"]["coverage_certified"],
            }, {
                "pass2_fingerprint": queue_id,
                "evidence_status": "advisor_confirmed",
                "verdicts_matched": 1,
                "verdicts_unanswered": 0,
                "coverage_certified": True,
            }, "pass 2 fingerprinted different text than pass 1")
            # and the whole point: the title is still masked everywhere
            self.assertNotIn(self.MARKER, json.dumps(report))
            # verify-queue.json is handed verbatim to the advisor, so it is a
            # shareable artifact too -- redacting at the input masks it, which
            # is only possible because the redaction now runs upstream of the
            # --emit-verify-queue branch.
            self.assertNotIn(self.MARKER, json.dumps(queue))
