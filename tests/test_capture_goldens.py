"""Tests for the generator of the normalization-contract goldens (#1525).

`capture_goldens.py` is the sole producer of `tests/goldens/tool-raw/`, and had
zero tests: a regression in `trim()` that dropped a payload's only
vulnerability-bearing entries would produce a golden that parses to nothing, and
nothing pinned that at the source. The downstream consumer
(`tests/tools/test_normalization_contract.py`) only fires after a human has
regenerated and committed a golden.

The module's own import-root `sys.path.insert` is derived from `__file__` and
is a no-op off the image (#1654); `trim` and `_trim_xml` are pure
bytes->bytes functions.
"""
import contextlib
import inspect
import io
import json
import os
import tempfile
import unittest
import unittest.mock
import xml.etree.ElementTree as ET

from _test_helpers import last
import scripts.capture_goldens as cg


class TestTrimJson(unittest.TestCase):
    def test_a_top_level_list_keeps_the_first_few(self):
        out = json.loads(cg.trim(json.dumps(list(range(10))).encode()))
        self.assertEqual(out, list(range(cg.KEEP)))

    def test_sarif_keeps_one_run_and_caps_results_and_rules(self):
        sarif = {"runs": [{"results": [{"i": i} for i in range(10)],
                           "tool": {"driver": {"rules": [{"id": str(i)}
                                                         for i in range(50)]}}},
                          {"results": []}]}
        out = json.loads(cg.trim(json.dumps(sarif).encode()))
        self.assertEqual(len(out["runs"]), 1)
        self.assertEqual(len(out["runs"][0]["results"]), cg.KEEP)
        self.assertEqual(len(out["runs"][0]["tool"]["driver"]["rules"]), 10)

    def test_osv_trims_the_nested_packages_level(self):
        # results[].packages[] nests two deep; trimming `results` alone left
        # every package behind it.
        payload = {"results": [{"packages": [{"name": "clean-%d" % i}
                                             for i in range(5)]
                                + [{"name": "bad", "vulnerabilities": [{"id": "V"}]}]},
                               {"packages": []}]}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        self.assertEqual(len(out["results"]), 1)
        packages = out["results"][0]["packages"]
        self.assertEqual([p["name"] for p in packages], ["bad"])

    def test_osv_falls_back_to_clean_packages_when_none_have_vulns(self):
        payload = {"results": [{"packages": [{"name": "c%d" % i} for i in range(9)]}]}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        self.assertEqual(len(out["results"][0]["packages"]), cg.KEEP)

    def test_a_trim_never_drops_the_only_findings_bearing_entries(self):
        # The invariant _has_vulns exists for: dependency-check lists every
        # dependency it saw and most are clean, so keeping the FIRST few
        # produced a golden that parsed to ZERO findings.
        payload = {"dependencies": [{"fileName": "clean-%d" % i} for i in range(8)]
                   + [{"fileName": "vulnerable", "vulnerabilities": [{"name": "CVE-1"}]}]}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        self.assertEqual([d["fileName"] for d in out["dependencies"]], ["vulnerable"])

    def test_all_clean_entries_still_yield_a_trimmed_list(self):
        payload = {"dependencies": [{"fileName": "c%d" % i} for i in range(8)]}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        self.assertEqual(len(out["dependencies"]), cg.KEEP)

    def test_every_list_key_is_trimmed(self):
        payload = {k: [{"n": i} for i in range(9)] for k in cg.LIST_KEYS}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        for key in cg.LIST_KEYS:
            self.assertEqual(len(out[key]), cg.KEEP, key)

    def test_a_dict_valued_list_key_is_capped_too(self):
        payload = {"vulnerabilities": {str(i): {"n": i} for i in range(9)}}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        self.assertEqual(len(out["vulnerabilities"]), cg.KEEP)

    def test_a_scalar_payload_is_returned_unchanged(self):
        self.assertEqual(cg.trim(b"5"), b"5")


class TestTrimXml(unittest.TestCase):
    def test_xml_is_trimmed_structurally_and_stays_well_formed(self):
        # Slicing XML at a byte offset produced an unclosed element that no
        # longer parsed. A golden that cannot be parsed is worse than a big one.
        doc = b"<BugCollection>" + b"".join(
            b"<BugInstance i='%d'><Class/></BugInstance>" % i for i in range(9)
        ) + b"<Errors/></BugCollection>"
        out = cg.trim(doc)
        root = ET.fromstring(out.decode("utf-8"))          # must still parse
        self.assertEqual(len(root.findall("BugInstance")), cg.KEEP)
        self.assertIsNotNone(root.find("Errors"))          # envelope preserved

    def test_unparseable_bytes_are_returned_unchanged(self):
        self.assertEqual(cg.trim(b"<not xml"), b"<not xml")

    def test_non_finding_children_are_never_dropped(self):
        doc = b"<r>" + b"".join(b"<other/>" for _ in range(9)) + b"</r>"
        root = ET.fromstring(cg.trim(doc).decode("utf-8"))
        self.assertEqual(len(root.findall("other")), 9)


class _Adapter:
    """Stand-in for a tool adapter, each hook independently riggable."""

    def __init__(self, applicable=True, raw=b'{"results": []}', parsed=None,
                 fail=None):
        self._applicable, self._raw = applicable, raw
        self._parsed = [{"id": "X-001"}] if parsed is None else parsed
        self._fail = fail

    def is_applicable(self, target):
        if self._fail == "is_applicable":
            raise RuntimeError("boom")
        return self._applicable

    def invoke(self, target):
        if self._fail == "invoke":
            raise RuntimeError("boom")
        return self._raw, 0

    def parse(self, raw, group):
        if self._fail == "parse":
            raise RuntimeError("boom")
        if self._fail == "reparse" and raw != self._raw:
            raise RuntimeError("trim broke it")
        return self._parsed


class TestMainStatusClassification(unittest.TestCase):
    """main()'s seven-way classification is how an operator learns WHY a golden
    is missing. A capture that silently reported 'ok' for a tool it never ran
    would leave a stale golden in place."""

    def _run(self, adapters, targets, argv_extra=()):
        with tempfile.TemporaryDirectory() as out_dir:
            argv = ["capture_goldens.py", out_dir] + list(argv_extra)
            out = io.StringIO()
            with unittest.mock.patch.object(cg, "ADAPTERS", adapters), \
                 unittest.mock.patch.object(cg, "TARGETS", targets), \
                 unittest.mock.patch.object(cg.sys, "argv", argv), \
                 contextlib.redirect_stdout(out):
                cg.main()
            return json.loads(out.getvalue()), sorted(os.listdir(out_dir))

    def _with_target(self, **kw):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: os.rmdir(d) if os.path.isdir(d) else None)
        return d, _Adapter(**kw)

    def test_missing_target_directory_is_no_target(self):
        report, written = self._run({"t": _Adapter()}, {"t": "/nonexistent/dir"})
        self.assertEqual(report["t"]["status"], "no-target")
        self.assertEqual(written, [])

    def test_unregistered_adapter_is_no_target(self):
        report, _ = self._run({}, {"t": "/tmp"}, argv_extra=["t"])
        self.assertEqual(report["t"]["status"], "no-target")

    def test_not_applicable_is_reported_not_captured(self):
        d, adapter = self._with_target(applicable=False)
        report, written = self._run({"t": adapter}, {"t": d})
        self.assertEqual(report["t"]["status"], "not-applicable")
        self.assertEqual(written, [])

    def test_each_hook_failure_gets_its_own_status(self):
        for fail, status in (("is_applicable", "is_applicable-error"),
                             ("invoke", "invoke-error"),
                             ("parse", "parse-error")):
            d, adapter = self._with_target(fail=fail)
            report, written = self._run({"t": adapter}, {"t": d})
            self.assertEqual(report["t"]["status"], status, fail)
            self.assertEqual(written, [], fail)

    def test_a_trim_that_breaks_parsing_writes_no_golden(self):
        # The guard that keeps an unusable golden out of the corpus.
        d, adapter = self._with_target(
            raw=json.dumps({"results": [{"i": i} for i in range(9)]}).encode(),
            fail="reparse")
        report, written = self._run({"t": adapter}, {"t": d})
        self.assertEqual(report["t"]["status"], "trim-broke-parse")
        self.assertEqual(written, [])

    def test_a_successful_capture_writes_the_golden_and_counts_both_sides(self):
        d, adapter = self._with_target(
            raw=json.dumps({"results": [{"i": i} for i in range(9)]}).encode())
        report, written = self._run({"t": adapter}, {"t": d})
        self.assertEqual(report["t"]["status"], "ok")
        self.assertEqual(written, ["t.raw"])
        self.assertLess(report["t"]["golden_bytes"], report["t"]["raw_bytes"])
        self.assertEqual(report["t"]["golden_findings"], 1)


class _RecordingAdapter(_Adapter):
    """Records every payload handed to parse(), so a test can prove WHICH bytes
    the pre-write verification actually checked."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.parsed_inputs = []

    def parse(self, raw, group):
        self.parsed_inputs.append(raw)
        return super().parse(raw, group)


class TestRedactBeforeWrite(unittest.TestCase):
    """#run12: three adapters (gitleaks, bandit, trivy) point at /mnt/panopticon
    -- the operator's own checkout -- so a real .env was in gitleaks' scan path
    and its live API key was committed to a public golden. capture_goldens.py had
    no redaction step of any kind, so whatever a scanner found got written
    verbatim. Redact on the way out, and say so in the report."""

    SECRET = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

    def _run(self, adapter):
        out_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(out_dir,
                                                            ignore_errors=True))
        target = tempfile.mkdtemp()
        self.addCleanup(lambda: os.rmdir(target) if os.path.isdir(target) else None)
        out = io.StringIO()
        with unittest.mock.patch.object(cg, "ADAPTERS", {"t": adapter}), \
             unittest.mock.patch.object(cg, "TARGETS", {"t": target}), \
             unittest.mock.patch.object(cg.sys, "argv",
                                        ["capture_goldens.py", out_dir]), \
             contextlib.redirect_stdout(out):
            cg.main()
        path = os.path.join(out_dir, "t.raw")
        written = open(path, "rb").read() if os.path.exists(path) else None
        return json.loads(out.getvalue())["t"], written

    def test_a_captured_secret_never_reaches_the_golden(self):
        raw = json.dumps({"results": [{"snippet": self.SECRET}]}).encode()
        report, written = self._run(_Adapter(raw=raw))
        self.assertEqual(report["status"], "ok")
        self.assertNotIn(self.SECRET.encode(), written)
        self.assertIn(b"[REDACTED_UUID]", written)

    def test_the_report_says_redaction_fired(self):
        """Silent redaction would hide that a scanner reached a real secret --
        which is itself the signal that the capture target is wrong."""
        raw = json.dumps({"results": [{"snippet": self.SECRET}]}).encode()
        report, _ = self._run(_Adapter(raw=raw))
        self.assertTrue(report.get("redacted"))

    def test_a_clean_payload_is_written_byte_identical(self):
        """Redaction decodes to str; a payload with nothing to mask must not be
        round-tripped through a lossy decode/encode."""
        raw = json.dumps({"results": [{"id": "X-001"}]}).encode()
        report, written = self._run(_Adapter(raw=raw))
        self.assertEqual(written, cg.trim(raw))
        self.assertFalse(report.get("redacted"))

    def test_the_pre_write_check_parses_the_redacted_bytes(self):
        """Order matters: redact, THEN verify. Verifying the pre-redaction bytes
        would certify a payload that is not the one committed.

        Guarded index (TST-B3A, #1653): a regression that bypasses the pre-write
        parse entirely leaves `parsed_inputs` EMPTY, and a raw `[-1]` then
        raises IndexError before this assertion is ever evaluated -- so the
        failure names the test's plumbing instead of the redaction invariant it
        exists to protect.
        """
        raw = json.dumps({"results": [{"snippet": self.SECRET}]}).encode()
        adapter = _RecordingAdapter(raw=raw)
        self._run(adapter)
        self.assertIn(b"[REDACTED_UUID]",
                      last(adapter.parsed_inputs, "pre-write parse call"))

    def test_redaction_that_breaks_parse_is_rejected_not_written(self):
        class _Picky(_Adapter):
            def parse(self, raw, group):
                if b"[REDACTED" in raw:
                    raise RuntimeError("redaction broke it")
                return self._parsed

        raw = json.dumps({"results": [{"snippet": self.SECRET}]}).encode()
        report, written = self._run(_Picky(raw=raw))
        self.assertEqual(report["status"], "trim-broke-parse")
        self.assertIsNone(written)


class TestRedactBytes(unittest.TestCase):
    SECRET = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

    def test_masks_and_flags(self):
        out, hit = cg.redact_bytes(("key %s\n" % self.SECRET).encode())
        self.assertTrue(hit)
        self.assertNotIn(self.SECRET.encode(), out)

    def test_clean_bytes_are_returned_unchanged_and_unflagged(self):
        src = b'{"a": 1}'
        out, hit = cg.redact_bytes(src)
        self.assertFalse(hit)
        self.assertIs(out, src)

    def test_it_is_the_production_capture_pass_not_a_second_flat_one(self):
        """Round 2 N4: this helper writes the committed goldens, so it must mask
        them exactly as a real run masks a real capture -- one pass, one set of
        semantics. A flat regex sweep over a JSON document is a different pass:
        it cannot tell a key from a value, and it silently RENAMED a bandit
        metrics key that happened to hold a UUID-shaped directory. The parsing
        pass leaves keys alone (and, because nothing in the values matched,
        returns the original object)."""
        payload = json.dumps({"runs": [{"properties": {"metrics": {
            "/src/build/3fa85f64-5717-4562-b3fc-2c963f66afa6/app.py": {"loc": 3}}}}]}
        ).encode("utf-8")
        out, hit = cg.redact_bytes(payload)
        self.assertFalse(hit)
        self.assertIs(out, payload)

    def test_undecodable_bytes_do_not_raise(self):
        src = b"\xff\xfe binary"
        out, hit = cg.redact_bytes(src)
        self.assertFalse(hit)
        self.assertIs(out, src)


class TestCaptureTargets(unittest.TestCase):
    def test_no_adapter_scans_the_operators_own_checkout(self):
        """#run12 root cause. Goldens are committed to a PUBLIC repo, and
        /mnt/panopticon is the operator's real working tree -- .env included --
        so pointing a SECRET SCANNER at it put a live API key in a public
        fixture. A capture target must be a corpus chosen for the purpose. The
        goldens README already documented these three as /src-mounted; only the
        code disagreed."""
        offenders = {n: t for n, t in cg.TARGETS.items()
                     if t == "/mnt/panopticon"}
        self.assertEqual(offenders, {})


class TestImportRootFromFile(unittest.TestCase):
    """#1654: the import root must come from the script's own location, not a
    literal, so the module works at `<root>/scripts/capture_goldens.py` under
    ANY root -- the image's `/opt/panopticon` and the repo's `skill/` alike."""

    def test_no_hardcoded_opt_panopticon_import_root_literal(self):
        src = inspect.getsource(cg)
        self.assertNotIn('"/opt/panopticon"', src)
        self.assertIn("os.path.abspath(__file__)", src)


class TestTargetsFunction(unittest.TestCase):
    """#1654: TARGETS becomes `targets(fixtures_root, src_root, probes_root)`,
    so the image layout is configuration, not a table edited in lockstep with
    the Dockerfiles."""

    PINNED = {
        "brakeman": "/opt/panopticon-fixtures/railsgoat",
        "bundler-audit": "/opt/panopticon-fixtures/railsgoat",
        "semgrep": "/opt/panopticon-fixtures/railsgoat",
        "spotbugs": "/opt/panopticon-fixtures/WebGoat",
        "dependency-check": "/opt/panopticon-fixtures/WebGoat",
        "roslyn-secguard": "/opt/panopticon-fixtures/AspGoat",
        "cargo-audit": "/opt/panopticon-fixtures/vulnerable-rust",
        "bandit": "/src",
        "gitleaks": "/src",
        "trivy": "/src",
        "osv-scanner": "/src",
        "gosec": "/mnt/gotify",
        "eslint-security": "/src",
        "npm-audit": "/mnt/npmprobe",
        "pip-audit": "/mnt/pipprobe",
    }

    def test_defaults_equal_the_pinned_table(self):
        self.assertEqual(cg.targets(), self.PINNED)

    def test_module_level_TARGETS_is_the_same_table(self):
        # main() reads the bare name `TARGETS`, not a fresh `targets()` call
        # each time, so a test can still substitute the whole mapping with
        # `mock.patch.object(cg, "TARGETS", {...})`.
        self.assertEqual(cg.TARGETS, self.PINNED)

    def test_a_custom_fixtures_root_moves_every_fixtures_backed_entry(self):
        out = cg.targets(fixtures_root="/tmp/fx")
        for name, path in self.PINNED.items():
            if path.startswith("/opt/panopticon-fixtures/"):
                self.assertEqual(
                    out[name], path.replace("/opt/panopticon-fixtures", "/tmp/fx"),
                    name)
            else:
                self.assertEqual(out[name], path, name)

    def test_a_custom_src_root_moves_every_src_entry(self):
        out = cg.targets(src_root="/tmp/src2")
        for name, path in self.PINNED.items():
            self.assertEqual(out[name], "/tmp/src2" if path == "/src" else path,
                             name)

    def test_a_custom_probes_root_moves_every_probe_entry(self):
        out = cg.targets(probes_root="/tmp/probes2")
        self.assertEqual(out["gosec"], "/tmp/probes2/gotify")
        self.assertEqual(out["npm-audit"], "/tmp/probes2/npmprobe")
        self.assertEqual(out["pip-audit"], "/tmp/probes2/pipprobe")
        untouched = set(self.PINNED) - {"gosec", "npm-audit", "pip-audit"}
        for name in untouched:
            self.assertEqual(out[name], self.PINNED[name], name)


class TestMainRootConfiguration(unittest.TestCase):
    """#1654: main() must resolve the same layered configuration (env var,
    then a `--*-root` flag, then a per-tool `--target`) that `targets()`
    exposes as a pure function -- an operator drives this through argv, not
    through the function directly."""

    def _run(self, argv_extra, env=None, adapters=None):
        adapters = adapters if adapters is not None else {"brakeman": _Adapter()}
        with tempfile.TemporaryDirectory() as out_dir:
            argv = ["capture_goldens.py", out_dir] + list(argv_extra)
            out = io.StringIO()
            clean_env = {k: v for k, v in os.environ.items()
                        if not k.startswith("PANOPTICON_")}
            clean_env.update(env or {})
            with unittest.mock.patch.object(cg, "ADAPTERS", adapters), \
                 unittest.mock.patch.dict(os.environ, clean_env, clear=True), \
                 unittest.mock.patch.object(cg.sys, "argv", argv), \
                 contextlib.redirect_stdout(out):
                cg.main()
            return json.loads(out.getvalue())

    def test_a_fixtures_root_env_var_moves_the_default_target(self):
        root = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        os.mkdir(os.path.join(root, "railsgoat"))
        report = self._run([], env={"PANOPTICON_FIXTURES_ROOT": root})
        self.assertEqual(report["brakeman"]["status"], "ok")

    def test_a_target_flag_beats_a_customized_root(self):
        bad_root = tempfile.mkdtemp()          # deliberately has no railsgoat/
        good = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(bad_root, ignore_errors=True))
        self.addCleanup(lambda: __import__("shutil").rmtree(good, ignore_errors=True))
        report = self._run(
            ["--fixtures-root", bad_root, "--target", "brakeman=%s" % good])
        self.assertEqual(report["brakeman"]["status"], "ok")

    def test_a_malformed_target_flag_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                self._run(["--target", "no-equals-sign"])
        self.assertEqual(ctx.exception.code, 2)

    def test_an_unknown_adapter_name_in_target_flag_is_a_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                self._run(["--target", "not-a-real-adapter=/x"],
                          adapters={"t": _Adapter()})
        self.assertEqual(ctx.exception.code, 2)

    def test_positional_form_is_unaffected_by_the_new_flags(self):
        report = self._run(["brakeman"],
                           adapters={"brakeman": _Adapter(), "other": _Adapter()})
        self.assertEqual(set(report), {"brakeman"})


if __name__ == "__main__":
    unittest.main()
