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
filenames: every file a run drops in the report directory OR the run directory
is checked -- `verify-queue.json` lands in the latter -- so a new artifact
producer is covered by construction rather than by remembering to extend a
list here.
"""
import contextlib
import hashlib
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


def _verdicts_doc(confirmed_id, rejected_id, run_id):
    """An advisor bundle keyed by finding id. Its `reasoning` carries its own
    marker: that text is merged into `finding.evidence.reasoning` INSIDE
    build_report, i.e. after the input pass -- so it is not covered by the
    input pass, and the post-build pass is what masks it. (It lands inside the
    finding object, so the old two-key backstop reached it too; the marker is
    here to pin that the post-build pass is still load-bearing, not to claim
    the whole-tree walk is what saves it.)

    The ids are the ones `load_findings` derives (a content hash), not the ones
    the file declares, so they are read back from the loader rather than
    guessed -- an unbound verdict would silently empty `discarded_claims` and
    make this guard vacuous."""
    return {"verdicts": [
        {"finding_id": confirmed_id, "verdict": "CONFIRMED",
         "reasoning": "advisor quoted it too: %s" % MARKERS["reasoning"]},
        {"finding_id": rejected_id, "verdict": "REJECTED",
         "reasoning": "not reachable"},
    ], "_panopticon": {"run_id": run_id, "role": "domain_advisor",
                       "domain": "SEC", "group": "app", "stage": "primary"}}


def _run(tmpdir, max_bytes=None):
    """Run BOTH real synthesize passes over the marked findings.

    Pass 1 is the orchestrator's `--emit-verify-queue` run, which writes
    `verify-queue.json` into the RUN dir; pass 2 is the report run, which
    writes into the OUT dir. Three directories, deliberately: inputs in `src/`
    and the advisor's verdicts in `verdicts/` legitimately carry the markers
    and must never be scanned, while `run/` and `out/` are both scanned --
    `run/` is where synthesize's one non-report artifact lands, and scanning
    only `out/` would leave it structurally invisible to this guard.

    Returns (scan_dirs, report_path, stdout).
    """
    src_dir = os.path.join(tmpdir, "src")
    run_dir = os.path.join(tmpdir, "run")
    out_dir = os.path.join(tmpdir, "out")
    v_dir = os.path.join(tmpdir, "verdicts")
    for path in (src_dir, run_dir, out_dir, v_dir):
        os.makedirs(path)
    fp = os.path.join(src_dir, "findings-app-security.json")
    with open(fp, "w", encoding="utf-8") as fh:
        json.dump(_findings_doc(), fh)
    groups = os.path.join(src_dir, "groups.json")
    with open(groups, "w", encoding="utf-8") as fh:
        json.dump({"groups": [{"name": "app",
                               "files": ["app/x.py", "app/y.py"]}]}, fh)
    with contextlib.redirect_stderr(io.StringIO()):
        loaded = findings_mod.load_findings([fp])
    out = os.path.join(out_dir, "report.json")

    real_write = render_mod.write_report

    def _small_write(report, out_path, max_bytes=max_bytes):
        return real_write(report, out_path, max_bytes=max_bytes)

    buf = io.StringIO()
    prev = os.getcwd()
    os.chdir(tmpdir)
    try:
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            syn.main(["--target", "app", "--run-dir", run_dir,
                      "--groups", groups, "--emit-verify-queue", fp])
        # The advisor answers this run's queue, so the bundle carries the
        # queue's run_id -- match_verdict_by_id rejects a cross-run verdict.
        with open(os.path.join(run_dir, "verify-queue.json"),
                  encoding="utf-8") as fh:
            queue_run_id = json.load(fh)["run_id"]
        with open(os.path.join(v_dir, "verdicts-app-SEC.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(_verdicts_doc(loaded[0]["id"], loaded[1]["id"],
                                    queue_run_id), fh)
        if max_bytes is not None:
            render_mod.write_report = _small_write
        with contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(io.StringIO()):
            syn.main(["--target", "app", "--out", out, "--run-dir", run_dir,
                      "--groups", groups, "--verdicts-dir", v_dir, fp])
    finally:
        render_mod.write_report = real_write
        os.chdir(prev)
    return [out_dir, run_dir], out, buf.getvalue()


def _emit_strain(report_path):
    """`scripts/strain_report.py` is a LIBRARY with no production caller --
    no main(), no argparse, and nothing outside tests/ imports it -- so no
    synthesize run emits a strain report today. Produce one here from the
    written report (the only input shape a future caller should use: it copies
    `title` into signal.summary and `provenance.confirmation_reasoning` into
    signal.rationale verbatim, so it must be fed REPORT findings, never raw
    findings-*.json) and let the same scan cover it.

    Corollary for the directory walk: "covered by construction" holds for
    producers driven by `syn.main()`. This one is hand-produced, so it is the
    walk -- not the run -- that brings it into scope.
    """
    with open(report_path, encoding="utf-8") as fh:
        report = json.load(fh)
    strain = strain_report.build_report(report.get("findings") or [],
                                        report.get("meta") or {}, "R")
    return strain_report.write_report(strain, report_path)


def scan_artifacts(dirs, extra_text=()):
    """Every marker found in any file under any of `dirs` (plus any extra text
    blobs, e.g. the terminal summary), as {marker_name: [where, ...]}.

    Walks the directories instead of naming files: report.json, the
    `_partN.json` splits, the `-discarded.json` sibling, `.json.html`,
    `-x0x.json`, `-strain.json` and the run dir's `verify-queue.json` are all
    covered, and so is whatever a future producer writes beside them."""
    blobs = []
    for d in dirs:
        base = os.path.dirname(os.path.normpath(d))
        for root, _dirs, files in os.walk(d):
            for name in sorted(files):
                path = os.path.join(root, name)
                with open(path, encoding="utf-8", errors="replace") as fh:
                    blobs.append((os.path.relpath(path, base), fh.read()))
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
            scan_dirs, report_path, stdout = _run(d)
            _emit_strain(report_path)
            written = sorted(os.listdir(scan_dirs[0]))
            # The run really did write the artifacts this guard claims to cover.
            self.assertIn("report.json", written)
            self.assertIn("report.json.html", written)
            self.assertIn("report-x0x.json", written)
            self.assertIn("report-strain.json", written)
            # ... and the one artifact that lands OUTSIDE the report directory.
            self.assertIn("verify-queue.json", sorted(os.listdir(scan_dirs[1])))
            hits = scan_artifacts(scan_dirs, [("terminal summary", stdout)])
            self.assertEqual(hits, {}, "unredacted markers survived: %s" % hits)

    def test_the_derived_fields_are_populated_and_masked(self):
        """The two fields #1634 named, checked positively: they must carry the
        finding's text (so the assertion above is not passing on an empty
        summary) and that text must be masked."""
        with tempfile.TemporaryDirectory() as d:
            _dirs, report_path, _stdout = _run(d)
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
            scan_dirs, report_path, stdout = _run(d, max_bytes=1200)
            _emit_strain(report_path)
            written = sorted(os.listdir(scan_dirs[0]))
            self.assertIn("report-discarded.json", written)
            self.assertTrue([w for w in written if "_part" in w], written)
            hits = scan_artifacts(scan_dirs, [("terminal summary", stdout)])
            self.assertEqual(hits, {}, "unredacted markers survived: %s" % hits)


class TestWholeTreeBackstopIsANoOpOnCleanReports(unittest.TestCase):
    """The backstop walks every string in the report, so it must be provably
    inert on a report that holds no secret -- structured fields (host
    capabilities, coverage, ids, paths, grades) come back byte-identical."""

    def _clean_report(self, d):
        """A real synthesize run wired up so the sections Ruling 2 names are
        POPULATED, not empty. A string-free subtree is trivially inert under a
        string redactor, so an all-null meta.cost / meta.integrity /
        models_used would make the golden unable to detect a regression there.

        Inputs in src/, run artifacts in run/, the report in out/. Never a
        committed real report: those carry real (rotated) credentials.
        """
        src = os.path.join(d, "src")
        run = os.path.join(d, "run")
        out_dir = os.path.join(d, "out")
        for path in (src, run, out_dir):
            os.makedirs(path)
        sec = os.path.join(src, "findings-app-SEC.json")
        with open(sec, "w", encoding="utf-8") as fh:
            json.dump({"findings": [
                {"id": "SEC-1", "domain": "SEC", "code": "SEC-A1A",
                 "title": "authz bypass", "description": "no credential here",
                 "severity": "HIGH", "confidence": "LIKELY", "panel": "security",
                 "category": "authz",
                 "references": ["docs/PANOPTICON.md", "CVE-2021-44228"],
                 # -> meta.models_used: a panel model, a version and the
                 # advisor role derived from confirmed_by_model.
                 "provenance": {"model": "claude-opus-4-1",
                                "model_version": "20260101",
                                "discovered_by": "agent:domain_panel",
                                "confirmed_by_model": "claude-sonnet-4-5"},
                 "location": {"file": "app/x.py", "line_start": 4}}]}, fh)
        # Ingested but NOT declared by the plan -> meta.integrity
        # .unexpected_findings_files carries this real filename.
        cod = os.path.join(src, "findings-app-COD.json")
        with open(cod, "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        # Declared but absent -> meta.integrity.missing_planned_files carries
        # that real filename. Both halves of the reconcile therefore have
        # content for the walk to leave alone.
        absent = os.path.join(src, "findings-app-DAT.json")
        with open(os.path.join(run, "dispatch-plan-driver.json"), "w",
                  encoding="utf-8") as fh:
            json.dump([{"group": "app", "domain": "SEC", "out_file": sec},
                       {"group": "app", "domain": "DAT", "out_file": absent}], fh)
        # The fan-out content snapshot, keyed by realpath -> the #493 R4 check
        # actually runs (content_hashes_checked stops being null).
        with open(sec, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        with open(os.path.join(run, "out-file-hashes.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({os.path.realpath(sec): digest}, fh)
        # The host's token journal -> meta.cost.tokens is a populated dict
        # (phase names, an ISO timestamp, a host name), not null.
        with open(os.path.join(run, "usage.json"), "w", encoding="utf-8") as fh:
            json.dump({"total": 21053000, "host": "claude",
                       "collected_at": "2026-09-15T00:00:00Z",
                       "by_phase": {"review": 10290000, "verify": 6300000,
                                    "coverage": 4463000}}, fh)
        with open(os.path.join(run, "groups.json"), "w", encoding="utf-8") as fh:
            json.dump({"groups": [{"name": "app", "files": ["app/x.py"]}]}, fh)
        # A run artifact whose contents are structured, not prose: the posture
        # is copied into meta.host_capabilities VERBATIM, so it is the sharpest
        # test of "the walk changes nothing that is not a secret".
        with open(os.path.join(run, "host-capabilities.json"), "w",
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
                               "detail": "sha256:" + digest}}}, fh)
        out = os.path.join(out_dir, "report.json")
        buf = io.StringIO()
        prev = os.getcwd()
        os.chdir(d)
        try:
            with contextlib.redirect_stdout(buf), \
                    contextlib.redirect_stderr(io.StringIO()):
                syn.main(["--target", "app", "--out", out, "--run-dir", run,
                          "--groups", os.path.join(run, "groups.json"),
                          sec, cod])
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

    def test_the_golden_actually_populates_the_sections_it_claims_to_cover(self):
        """Guards the guard. A string-free subtree is inert under a string
        redactor, so the golden above proves nothing about a section that came
        back empty. Every section the whole-tree walk newly reaches is asserted
        to carry real strings."""
        with tempfile.TemporaryDirectory() as d:
            report = self._clean_report(d)
        meta = report["meta"]
        # meta.host_capabilities: verbatim posture, a UUID under an identity
        # key, a 64-hex digest, a ~/ settings path.
        caps = meta["host_capabilities"]["capabilities"]
        self.assertEqual(caps["tool_policy_enforced"]["state"], "proven")
        self.assertEqual(caps["tool_policy_enforced"]["guid"],
                         "3f2504e0-4f89-11d3-9a0c-0305e82c3301")
        self.assertTrue(caps["read_scope_confined"]["detail"].startswith("sha256:"))
        # meta.models_used: model names + the advisor role.
        self.assertEqual(sorted(m["model"] for m in meta["models_used"]),
                         ["claude-opus-4-1", "claude-sonnet-4-5"])
        # meta.cost.tokens: a populated dict, not the null slot.
        self.assertIsInstance(meta["cost"]["tokens"], dict)
        self.assertEqual(meta["cost"]["tokens"]["total"], 21053000)
        self.assertIn("review", meta["cost"]["tokens"]["by_phase"])
        # meta.integrity: real filenames on both halves of the reconcile, and
        # the #493 R4 content check actually ran. (The sha256 digests live in
        # the out-file-hashes.json artifact; the report carries the COUNT of
        # files checked, not the hashes themselves.)
        integ = meta["integrity"]
        self.assertTrue(integ["unexpected_findings_files"][0]
                        .endswith("findings-app-COD.json"), integ)
        self.assertTrue(integ["missing_planned_files"][0]
                        .endswith("findings-app-DAT.json"), integ)
        self.assertEqual(integ["content_hashes_checked"], 1)
        self.assertEqual(integ["content_mismatched_files"], [])

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
