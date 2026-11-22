"""#3765: the three shared-reader faults behind the first-party advisory marker.

1. A lock or manifest that changes while it is read grants nothing: the bounded
   reader compares the descriptor's identity, size and times before and after the
   read, and the path's identity after it. A mismatch is a named refusal.
2. A scanner path outside the scan mount stays recognisably outside: `/Cargo.lock`
   and `file:///Cargo.lock` are not the review root's `Cargo.lock`.
3. Trivy carries a positive `vulnerability` kind from its own rule tags, and an
   identity parsed from a Trivy message is used only for such a record.

Each is taken to a verdict in both directions: a finding that must not be confirmed
without an advisor, and a finding that must still be reported, queued or confirmed
exactly as before. Fixtures only.
"""

import copy
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.evidence as evidence
import scripts.first_party_advisory as first_party_advisory
import scripts.ingest_tools as ingest_tools
import scripts.safe_write as safe_write
import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod
import scripts.tools.sarif_utils as sarif_utils
from tests.test_first_party_advisories import (
    NPM_MEMBER, PY_MEMBER, WORKSPACE_NAME, WORKSPACE_VERSION, _npm_tree, _py_tree,
    _write_lock, _write_manifest)

CARGO = (WORKSPACE_NAME, WORKSPACE_VERSION)
# One lock per ecosystem the marker reads, with its OSV ecosystem and local package.
LOCKS = (("Cargo.lock", "crates.io", CARGO), ("package-lock.json", "npm", NPM_MEMBER),
         ("uv.lock", "PyPI", PY_MEMBER))


def _tree(test, lock_name):
    d = tempfile.TemporaryDirectory()
    test.addCleanup(d.cleanup)
    root = os.path.realpath(d.name)
    if lock_name == "Cargo.lock":
        _write_lock(root)
        _write_manifest(root)
    elif lock_name == "package-lock.json":
        _npm_tree(root)
    else:
        _py_tree(root)
    return root


def _trivy(package, uri, *, tags=("vulnerability", "security", "LOW"), severity="2.0",
           text=None):
    advisory = "CVE-2099-12345"
    if text is None:
        text = ("Package: %s\nInstalled Version: %s\nVulnerability %s\nSeverity: LOW"
                % (package[0], package[1], advisory))
    properties = {"security-severity": severity}
    if tags is not None:
        properties["tags"] = list(tags)
    return {"runs": [{
        "tool": {"driver": {"name": "trivy", "rules": [{"id": advisory,
                                                        "properties": properties}]}},
        "results": [{"ruleId": advisory, "level": "note", "message": {"text": text},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": uri},
                         "region": {"startLine": 1}}}]}]}]}


def _osv(package, ecosystem, path, severity="LOW"):
    return {"results": [{"source": {"path": path}, "packages": [{
        "package": {"name": package[0], "version": package[1], "ecosystem": ecosystem},
        "vulnerabilities": [{"id": "GHSA-xxxx-yyyy-zzzz", "summary": "affected",
                             "database_specific": {"severity": severity}}],
        "groups": []}]}]}


def _ingest(root, name, document):
    tools = tempfile.mkdtemp(prefix="tools-out-", dir=root)
    with open(os.path.join(tools, name), "w", encoding="utf-8") as fh:
        json.dump(document, fh)
    return ingest_tools.ingest_dir(tools, "g1", target_root=root)


def _verdict(findings, answer=None):
    """What a run says of these findings -- the gate, and each finding's evidence
    status -- with NO advisor answer, or with every queued finding answered `answer`."""
    verdicts = {}
    if answer is not None:
        entries, _cut = evidence.build_verify_queue(copy.deepcopy(findings))
        verdicts = {entry["queue_id"]: {"finding_id": entry["finding"]["id"],
                                        "verdict": answer, "reasoning": "checked"}
                    for entry in entries}
    report = report_mod.build_report(report_mod.ReportInputs(
        run=report_mod.RunConfig(target="project", fail_on="high",
                                 timestamp="2026-11-22T00:00:00Z"),
        findings=findings_mod.FindingSet(findings=copy.deepcopy(findings), verdicts=verdicts,
                                         verdicts_supplied=True)))
    return report["summary"]["gate"], [f["evidence"]["status"] for f in report["findings"]]


class _Case(unittest.TestCase):

    def assert_advisor_path(self, findings):
        """Reported, not first-party, queued for the advisor, and not a PASS."""
        self.assertEqual(1, len(findings))
        self.assertFalse(evidence.is_first_party_advisory(findings[0]))
        self.assertNotIn("package_origin", findings[0]["tool_evidence"])
        self.assertNotIn("advisory_package", findings[0]["tool_evidence"])
        self.assertEqual(1, len(evidence.build_verify_queue(findings)[0]))
        self.assertEqual(("INCONCLUSIVE", ["tool_reported"]), _verdict(findings))

    def assert_first_party(self, findings):
        """Confirmed at ingest, with no advisor, as before #3765."""
        self.assertEqual(1, len(findings))
        self.assertTrue(evidence.is_first_party_advisory(findings[0]))
        self.assertEqual(([], 0), evidence.build_verify_queue(findings))
        self.assertEqual(("PASS", ["tool_confirmed"]), _verdict(findings))


class TestAFileThatChangesWhileItIsRead(_Case):
    """Fault 1. The reader's own seam (`safe_write._drain`) stands in for the race:
    it changes the file on disk at the moment the bytes are being read."""

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.dir = os.path.realpath(d.name)
        self.path = os.path.join(self.dir, "lock")
        with open(self.path, "wb") as fh:
            fh.write(b"full contents\n")

    def _during(self, change):
        real = safe_write._drain

        def drain(path, stream, limit):
            raw = real(path, stream, limit)
            change()
            return raw
        return mock.patch.object(safe_write, "_drain", side_effect=drain)

    def test_an_unchanged_file_is_read(self):
        self.assertEqual(b"full contents\n", safe_write.read_stable_regular_bytes(self.path, 64))
        self.assertEqual(b"full contents\n", safe_write.read_stable_regular_bytes(self.path, 14))

    def test_a_file_replaced_during_the_read_is_refused(self):
        # The probe: a different file sat at the path while it was read, and the real
        # one is back before the reader returns.
        other = os.path.join(self.dir, "other")

        def swap():
            with open(other, "wb") as fh:
                fh.write(b"full contents\n")
            os.replace(other, self.path)
        with self._during(swap), self.assertRaises(safe_write.UnstableFileError):
            safe_write.read_stable_regular_bytes(self.path, 64)

    def test_a_file_rewritten_in_place_is_refused_even_with_its_times_restored(self):
        before = os.stat(self.path)

        def rewrite():
            with open(self.path, "r+b") as fh:
                fh.write(b"FULL")                      # same size, same inode
            os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
        with self._during(rewrite), self.assertRaises(safe_write.UnstableFileError):
            safe_write.read_stable_regular_bytes(self.path, 64)
        self.assertEqual(before.st_mtime_ns, os.stat(self.path).st_mtime_ns)

    def test_a_file_that_grows_shrinks_or_vanishes_is_refused(self):
        def grow():
            with open(self.path, "ab") as fh:
                fh.write(b"more\n")

        def shrink():
            os.truncate(self.path, 4)

        def vanish():
            os.remove(self.path)
        for label, change in (("grow", grow), ("shrink", shrink), ("vanish", vanish)):
            with self.subTest(change=label):
                with open(self.path, "wb") as fh:
                    fh.write(b"full contents\n")
                with self._during(change), self.assertRaises(safe_write.UnstableFileError):
                    safe_write.read_stable_regular_bytes(self.path, 64)

    def test_a_symlink_swapped_in_for_the_file_is_refused(self):
        # The path must still name the FILE that was read, not a link back to it.
        kept = os.path.join(self.dir, "kept")

        def link():
            os.rename(self.path, kept)
            os.symlink(kept, self.path)
        with self._during(link), self.assertRaises(safe_write.UnstableFileError):
            safe_write.read_stable_regular_bytes(self.path, 64)

    def test_stability_is_judged_before_the_size_limit(self):
        # An oversized file that also changed is unstable, not oversized: the two
        # refusals are charged differently, and an unstable size proves nothing.
        def touch():
            os.utime(self.path, ns=(1, 1))
        with self._during(touch), self.assertRaises(safe_write.UnstableFileError):
            safe_write.read_stable_regular_bytes(self.path, 13)
        with self.assertRaises(safe_write.ReadLimitExceeded):
            safe_write.read_stable_regular_bytes(self.path, 13)

    def _in_a_directory(self):
        """The file one directory down, so the DIRECTORY can be swapped: that changes
        which file the path names without touching the file that was read."""
        first = os.path.join(self.dir, "d")
        os.makedirs(first)
        path = os.path.join(first, "lock")
        with open(path, "wb") as fh:
            fh.write(b"full contents\n")
        return first, path

    def test_a_path_that_names_another_file_afterwards_is_refused(self):
        first, path = self._in_a_directory()
        second = os.path.join(self.dir, "d2")
        os.makedirs(second)
        with open(os.path.join(second, "lock"), "wb") as fh:
            fh.write(b"full contents\n")              # same size; another file

        def swap():
            os.rename(first, os.path.join(self.dir, "gone"))
            os.rename(second, first)
        with self._during(swap), self.assertRaises(safe_write.UnstableFileError):
            safe_write.read_stable_regular_bytes(path, 64)

    def test_a_path_that_names_nothing_afterwards_is_refused(self):
        first, path = self._in_a_directory()

        def remove():
            os.rename(first, os.path.join(self.dir, "gone"))
        with self._during(remove), self.assertRaises(safe_write.UnstableFileError):
            safe_write.read_stable_regular_bytes(path, 64)

    def test_a_path_that_is_a_link_to_the_file_afterwards_is_refused(self):
        # The same file, but no longer AT the path: a link stands there instead.
        first, path = self._in_a_directory()
        gone = os.path.join(self.dir, "gone")
        second = os.path.join(self.dir, "d2")
        os.makedirs(second)
        os.symlink(os.path.join(gone, "lock"), os.path.join(second, "lock"))

        def swap():
            os.rename(first, gone)
            os.rename(second, first)
        with self._during(swap), self.assertRaises(safe_write.UnstableFileError):
            safe_write.read_stable_regular_bytes(path, 64)
        self.assertEqual(b"full contents\n", safe_write.read_regular_bytes(
            os.path.join(gone, "lock"), 64))

    def test_each_part_of_the_files_state_is_compared(self):
        status = os.stat(self.path)
        state = safe_write._file_state(status)
        self.assertEqual((status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns,
                          status.st_ctime_ns), state)

    def test_it_keeps_the_plain_readers_refusals(self):
        with self.assertRaises(safe_write.ReadLimitExceeded):
            safe_write.read_stable_regular_bytes(self.path, 13)
        with self.assertRaises(FileNotFoundError):
            safe_write.read_stable_regular_bytes(os.path.join(self.dir, "absent"), 64)
        link = os.path.join(self.dir, "link")
        os.symlink(self.path, link)
        with self.assertRaises(OSError) as refused:
            safe_write.read_stable_regular_bytes(link, 64)
        # Refused at open, before a byte is read; not read and then found unstable.
        self.assertNotIsInstance(refused.exception, safe_write.UnstableFileError)
        with self.assertRaises(safe_write.NonRegularFileError):
            safe_write.read_stable_regular_bytes(self.dir, 64)
        for limit in (0, -1, 1.5, True, None):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                safe_write.read_stable_regular_bytes(self.path, limit)
        self.assertTrue(issubclass(safe_write.UnstableFileError, OSError))

    def test_a_lock_swapped_for_a_local_only_prefix_grants_nothing(self):
        # The issue's probe, through the marker and to a verdict. The full lock holds a
        # registry copy of the workspace package's identity, so it is ambiguous; a
        # prefix without that copy reads as first-party. On the base the swapped read
        # confirmed the finding with no advisor.
        root = _tree(self, "Cargo.lock")
        lock = os.path.join(root, "Cargo.lock")
        with open(lock, encoding="utf-8") as fh:
            prefix = fh.read()
        full = prefix + ('\n[[package]]\nname = "%s"\nversion = "%s"\n'
                         'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                         % CARGO)
        with open(lock, "w", encoding="utf-8") as fh:
            fh.write(full)
        document = _osv(CARGO, "crates.io", "/src/Cargo.lock")
        self.assert_advisor_path(_ingest(root, "osv-scanner.json", document))   # the truth
        real = safe_write._drain
        swapped = []

        def drain(path, stream, limit):
            raw = real(path, stream, limit)
            if os.path.basename(path) == "Cargo.lock" and not swapped:
                swapped.append(True)
                raw = prefix.encode()                  # what a racing writer showed us
                with open(lock, "w", encoding="utf-8") as fh:
                    fh.write(full)                     # ...and the real lock is back
            return raw
        with mock.patch.object(safe_write, "_drain", side_effect=drain):
            findings = _ingest(root, "osv-scanner.json", document)
        self.assertEqual([True], swapped)
        self.assert_advisor_path(findings)

    def test_an_unstable_read_is_a_named_refusal_and_is_not_retried(self):
        root = _tree(self, "Cargo.lock")
        lock = os.path.join(root, "Cargo.lock")
        finding = {"id": "OS-001", "title": "%s %s: X" % CARGO, "source": "tool:osv-scanner",
                   "location": {"file": "Cargo.lock", "line_start": 1},
                   "tool_evidence": {"rule_id": "X", "package_name": CARGO[0],
                                     "vulnerable_versions": CARGO[1], "ecosystem": "crates.io"}}

        def touch():
            os.utime(lock, ns=(1, 1))
        cache = first_party_advisory.IngestCache()
        with self._during(touch) as drain:
            first_party_advisory.mark([finding], root, cache)
            calls = drain.call_count
            first_party_advisory.mark([finding], root, cache)     # same ingest, same cache
            self.assertEqual(calls, drain.call_count)
        self.assertNotIn("package_origin", finding["tool_evidence"])
        self.assertEqual([lock], cache.unstable_reads)
        self.assertEqual({lock: {}}, cache.package_origins)
        # A fresh ingest of the now-quiet file classifies, as before.
        first_party_advisory.mark([finding], root, first_party_advisory.IngestCache())
        self.assertEqual("first_party", finding["tool_evidence"]["package_origin"])

    def test_the_tool_disposition_counts_its_own_unstable_reads(self):
        # Per output file, a delta: the second tool's quiet reads are not charged with
        # the first one's.
        root = _tree(self, "Cargo.lock")
        tools = tempfile.mkdtemp(prefix="tools-out-", dir=root)
        with open(os.path.join(tools, "osv-scanner.json"), "w", encoding="utf-8") as fh:
            json.dump(_osv(CARGO, "crates.io", "/src/Cargo.lock"), fh)
        with open(os.path.join(tools, "trivy.sarif"), "w", encoding="utf-8") as fh:
            json.dump(_trivy(CARGO, "Cargo.lock"), fh)
        _findings, quiet = ingest_tools.ingest_dir_detailed(tools, "g1", target_root=root)
        for tool in ("osv-scanner", "trivy"):
            self.assertNotIn("advisory_manifest_changed_during_read", quiet[tool])
        real = safe_write._drain
        touched = []

        def drain(path, stream, limit):
            raw = real(path, stream, limit)
            if not touched:                                # the first read of the ingest
                touched.append(path)
                os.utime(path, ns=(1, 1))
            return raw
        with mock.patch.object(safe_write, "_drain", side_effect=drain):
            findings, dispositions = ingest_tools.ingest_dir_detailed(
                tools, "g1", target_root=root)
        self.assertEqual(2, len(findings))
        counts = {tool: row.get("advisory_manifest_changed_during_read")
                  for tool, row in dispositions.items()}
        self.assertEqual([1], [n for n in counts.values() if n is not None])
        self.assertEqual({"ok"}, {row["status"] for row in dispositions.values()})

    def test_a_manifest_that_changes_while_it_is_read_grants_nothing(self):
        for lock_name, ecosystem, package in LOCKS:
            with self.subTest(lock=lock_name):
                root = _tree(self, lock_name)
                document = _osv(package, ecosystem, "/src/" + lock_name)
                self.assert_first_party(_ingest(root, "osv-scanner.json", document))
                real = safe_write._drain

                def drain(path, stream, limit, lock_name=lock_name):
                    raw = real(path, stream, limit)
                    if os.path.basename(path) != lock_name:              # a manifest
                        os.utime(path, ns=(1, 1))
                    return raw
                with mock.patch.object(safe_write, "_drain", side_effect=drain):
                    self.assert_advisor_path(_ingest(root, "osv-scanner.json", document))

    def test_every_lock_and_manifest_goes_through_the_stable_reader(self):
        for lock_name, ecosystem, package in LOCKS:
            with self.subTest(lock=lock_name):
                root = _tree(self, lock_name)
                document = _osv(package, ecosystem, "/src/" + lock_name)
                seen = []
                real = safe_write.read_stable_regular_bytes

                def read(path, limit):
                    seen.append(os.path.relpath(path, root))
                    return real(path, limit)
                with mock.patch.object(safe_write, "read_stable_regular_bytes",
                                       side_effect=read), \
                        mock.patch.object(safe_write, "read_regular_bytes",
                                          side_effect=AssertionError("the plain reader")):
                    self.assert_first_party(_ingest(root, "osv-scanner.json", document))
                self.assertIn(lock_name, seen)
                self.assertGreaterEqual(len(seen), 2)             # the lock and a manifest


class TestAPathOutsideTheScanMount(_Case):
    """Fault 2. `/src/` is the mount; anything else absolute is not the review root."""

    def test_norm_uri_keeps_an_outside_path_outside(self):
        norm = sarif_utils.norm_uri
        for uri, expected in (
                ("/src/Cargo.lock", "Cargo.lock"), ("file:///src/Cargo.lock", "Cargo.lock"),
                ("/src/a/b.py", "a/b.py"), ("Cargo.lock", "Cargo.lock"), ("a/b.py", "a/b.py"),
                ("src/Cargo.lock", "src/Cargo.lock"), ("", ""),
                # Outside the mount: still absolute, with one leading slash.
                ("/Cargo.lock", "/Cargo.lock"), ("//Cargo.lock", "/Cargo.lock"),
                ("///Cargo.lock", "/Cargo.lock"), ("file:///Cargo.lock", "/Cargo.lock"),
                ("file:////Cargo.lock", "/Cargo.lock"), ("/etc/passwd", "/etc/passwd"),
                ("/srcx/Cargo.lock", "/srcx/Cargo.lock"), ("/src", "/src"),
                ("file:///usr/lib/x.so", "/usr/lib/x.so"),
                # A file URI with an authority is not a local path: kept whole.
                ("file://Cargo.lock", "file://Cargo.lock"),
                ("file://host/share/Cargo.lock", "file://host/share/Cargo.lock")):
            with self.subTest(uri=uri):
                self.assertEqual(expected, norm(uri))
        self.assertIsNone(norm(None))
        self.assertEqual(7, norm(7))

    def test_a_trivy_result_outside_the_mount_is_not_the_roots_lock(self):
        for lock_name, _ecosystem, package in LOCKS:
            root = _tree(self, lock_name)
            for uri in ("file:///" + lock_name, "/" + lock_name, "//" + lock_name,
                        "file://" + lock_name, "/tmp/elsewhere/" + lock_name,
                        "file:///srcx/" + lock_name):
                with self.subTest(uri=uri):
                    findings = _ingest(root, "trivy.sarif", _trivy(package, uri))
                    self.assert_advisor_path(findings)
                    self.assertNotEqual(lock_name, findings[0]["location"]["file"])
                    self.assertTrue(findings[0]["location"]["file"].startswith(("/", "file://")))
            for uri in (lock_name, "/src/" + lock_name, "file:///src/" + lock_name):
                with self.subTest(inside=uri):
                    findings = _ingest(root, "trivy.sarif", _trivy(package, uri))
                    self.assert_first_party(findings)
                    self.assertEqual(lock_name, findings[0]["location"]["file"])

    def test_an_osv_source_outside_the_mount_is_not_the_roots_lock(self):
        for lock_name, ecosystem, package in LOCKS:
            root = _tree(self, lock_name)
            for path in ("/" + lock_name, "//" + lock_name, "file:///" + lock_name,
                         "/tmp/elsewhere/" + lock_name):
                with self.subTest(path=path):
                    findings = _ingest(root, "osv-scanner.json", _osv(package, ecosystem, path))
                    self.assert_advisor_path(findings)
            for path in ("/src/" + lock_name, lock_name):
                with self.subTest(inside=path):
                    self.assert_first_party(
                        _ingest(root, "osv-scanner.json", _osv(package, ecosystem, path)))

    def test_an_outside_path_is_never_joined_onto_the_root(self):
        # The marker's own guard, given the path the normaliser now hands it.
        root = _tree(self, "Cargo.lock")
        for rel in ("/Cargo.lock", "file://Cargo.lock", "/src", os.path.join(root, "Cargo.lock")):
            with self.subTest(file=rel):
                finding = {"location": {"file": rel}}
                self.assertIsNone(first_party_advisory._lock_path(
                    root, finding, first_party_advisory.FIRST_PARTY_LOCKS))

    def test_a_high_finding_outside_the_mount_is_kept_and_can_still_gate(self):
        # The other direction: the finding is not dropped. On the base it was confirmed
        # with no advisor (FAIL, certified); now it waits for one, and gates once
        # confirmed -- or passes once rejected.
        root = _tree(self, "Cargo.lock")
        document = _trivy(CARGO, "/Cargo.lock", tags=("vulnerability", "security", "HIGH"),
                          severity="8.1")
        findings = _ingest(root, "trivy.sarif", document)
        self.assertEqual(1, len(findings))
        self.assertEqual("HIGH", findings[0]["severity"])
        self.assertEqual("/Cargo.lock", findings[0]["location"]["file"])
        self.assertEqual(("INCONCLUSIVE", ["tool_reported"]), _verdict(findings))
        self.assertEqual(("FAIL", ["tool_confirmed"]), _verdict(findings, "CONFIRMED"))
        self.assertEqual("PASS", _verdict(findings, "REJECTED")[0])


class TestATrivyRecordThatIsNotAVulnerability(_Case):
    """Fault 3. The message of any Trivy record could name a package and a version."""

    def test_only_a_vulnerability_tagged_record_carries_the_kind(self):
        root = _tree(self, "Cargo.lock")
        for tags, kind in ((("vulnerability", "security", "LOW"), "vulnerability"),
                           (("security", "vulnerability"), "vulnerability"),
                           (("misconfiguration", "security", "LOW"), None),
                           (("license", "security"), None), (("security", "LOW"), None),
                           ((), None), (None, None), (("Vulnerability",), None),
                           (("vulnerability-ish",), None),
                           (("secret", "security", "HIGH"), "secret"),
                           (("vulnerability", "secret"), "secret")):
            with self.subTest(tags=tags):
                findings = _ingest(root, "trivy.sarif", _trivy(CARGO, "Cargo.lock", tags=tags))
                self.assertEqual(1, len(findings))
                self.assertEqual(kind, findings[0]["tool_evidence"].get("kind"))
        self.assertEqual("vulnerability", sarif_utils.VULNERABILITY_KIND)

    def test_the_kind_is_trivys_alone(self):
        # Another SARIF adapter's rule tagged `vulnerability` gets no kind: the tag is
        # Trivy's vocabulary, and the marker never reads a message for another tool.
        root = _tree(self, "Cargo.lock")
        document = _trivy(CARGO, "Cargo.lock")
        document["runs"][0]["tool"]["driver"]["name"] = "semgrep"
        for name in ("semgrep.sarif", "gosec.sarif"):
            with self.subTest(output=name):
                findings = _ingest(root, name, document)
                self.assertEqual(1, len(findings))
                for finding in findings:
                    self.assertNotIn("kind", finding["tool_evidence"])
                    self.assertFalse(evidence.is_first_party_advisory(finding))

    def test_a_non_vulnerability_record_with_matching_text_is_not_first_party(self):
        for lock_name, _ecosystem, package in LOCKS:
            root = _tree(self, lock_name)
            for tags in (("misconfiguration", "security", "LOW"), ("license", "security"),
                         ("security", "LOW"), (), None, ("Vulnerability",)):
                with self.subTest(lock=lock_name, tags=tags):
                    self.assert_advisor_path(
                        _ingest(root, "trivy.sarif", _trivy(package, lock_name, tags=tags)))
            with self.subTest(lock=lock_name, tags="vulnerability"):
                self.assert_first_party(
                    _ingest(root, "trivy.sarif", _trivy(package, lock_name)))

    def test_a_secret_record_is_still_never_first_party(self):
        root = _tree(self, "Cargo.lock")
        for tags in (("secret", "security", "HIGH"), ("vulnerability", "secret")):
            with self.subTest(tags=tags):
                findings = _ingest(root, "trivy.sarif", _trivy(CARGO, "Cargo.lock", tags=tags))
                self.assertFalse(evidence.is_first_party_advisory(findings[0]))

    def test_the_marker_requires_the_kind_for_a_message_derived_identity(self):
        root = _tree(self, "Cargo.lock")
        title = "Package: %s\nInstalled Version: %s\nVulnerability X" % CARGO

        def origin(tool_evidence, source="tool:trivy"):
            finding = {"id": "TV-001", "title": title, "source": source,
                       "location": {"file": "Cargo.lock", "line_start": 1},
                       "tool_evidence": tool_evidence}
            first_party_advisory.mark([finding], root, first_party_advisory.IngestCache())
            return finding["tool_evidence"].get("package_origin")
        self.assertEqual("first_party", origin({"rule_id": "X", "kind": "vulnerability"}))
        for kind in (None, "misconfiguration", "secret", "Vulnerability", "", True, 1,
                     ["vulnerability"]):
            with self.subTest(kind=kind):
                tool_evidence = {"rule_id": "X"}
                if kind is not None:
                    tool_evidence["kind"] = kind
                self.assertIsNone(origin(tool_evidence))
        # An adapter that owns `package_name` needs no kind, as before.
        self.assertEqual("first_party", origin(
            {"rule_id": "X", "package_name": CARGO[0], "vulnerable_versions": CARGO[1],
             "ecosystem": "crates.io"}, source="tool:osv-scanner"))
        # ...and a Trivy finding cannot borrow that route by naming a package itself.
        self.assertIsNone(origin({"rule_id": "X", "package_name": CARGO[0],
                                  "vulnerable_versions": CARGO[1]}))

    def test_the_kind_is_not_part_of_a_findings_identity(self):
        root = _tree(self, "Cargo.lock")
        finding = _ingest(root, "trivy.sarif", _trivy(CARGO, "other/Cargo.lock"))[0]
        self.assertEqual("vulnerability", finding["tool_evidence"]["kind"])
        without = copy.deepcopy(finding)
        del without["tool_evidence"]["kind"]
        self.assertEqual(evidence.finding_fingerprint(without),
                         evidence.finding_fingerprint(finding))
        self.assertEqual(evidence.reconcile_key(without), evidence.reconcile_key(finding))
        self.assertFalse(ingest_tools.secret_class(finding))

    def test_the_report_schema_names_the_kind(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "skill", "reference", "report-schema.json")
        with open(path, encoding="utf-8") as fh:
            schema = json.load(fh)
        kind = schema["properties"]["findings"]["items"]["properties"]["tool_evidence"][
            "properties"]["kind"]
        self.assertEqual(["secret", "vulnerability"], kind["enum"])


if __name__ == "__main__":
    unittest.main()
