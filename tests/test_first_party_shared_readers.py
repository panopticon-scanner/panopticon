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
import types
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
    NPM_MEMBER, PY_MEMBER, WORKSPACE_NAME, WORKSPACE_VERSION, _npm_tree, _poetry_lock,
    _py_tree, _write_lock, _write_manifest)

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


_NO_BASES = object()


def _trivy(package, uri, *, tags=("vulnerability", "security", "LOW"), severity="2.0",
           text=None, base_id=None, bases=_NO_BASES):
    advisory = "CVE-2099-12345"
    if text is None:
        text = ("Package: %s\nInstalled Version: %s\nVulnerability %s\nSeverity: LOW"
                % (package[0], package[1], advisory))
    properties = {"security-severity": severity}
    if tags is not None:
        properties["tags"] = list(tags) if isinstance(tags, tuple) else tags
    artifact = {"uri": uri}
    if base_id is not None:
        artifact["uriBaseId"] = base_id
    run = {
        "tool": {"driver": {"name": "trivy", "rules": [{"id": advisory,
                                                        "properties": properties}]}},
        "results": [{"ruleId": advisory, "level": "note", "message": {"text": text},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": artifact,
                         "region": {"startLine": 1}}}]}]}
    if bases is not _NO_BASES:
        run["originalUriBaseIds"] = bases
    return {"runs": [run]}


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

        cache = first_party_advisory.IngestCache()
        with self._during(lambda: os.utime(lock, ns=(1, 1))) as drain:
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

    def test_the_count_is_of_advisories_an_unstable_read_decided(self):
        # Seat item 4. (a) Two tools at one unstable lock are each denied, and each
        # says so, though only the first one's read saw the change.
        root = _tree(self, "Cargo.lock")
        tools = tempfile.mkdtemp(prefix="tools-out-", dir=root)
        with open(os.path.join(tools, "osv-scanner.json"), "w", encoding="utf-8") as fh:
            json.dump(_osv(CARGO, "crates.io", "/src/Cargo.lock"), fh)
        with open(os.path.join(tools, "trivy.sarif"), "w", encoding="utf-8") as fh:
            json.dump(_trivy(CARGO, "Cargo.lock"), fh)
        real = safe_write._drain

        def unstable(name):
            def drain(path, stream, limit):
                raw = real(path, stream, limit)
                if os.path.basename(path) == name:
                    os.utime(path, ns=(1, 1))
                return raw
            return mock.patch.object(safe_write, "_drain", side_effect=drain)
        with unstable("Cargo.lock"):
            findings, dispositions = ingest_tools.ingest_dir_detailed(
                tools, "g1", target_root=root)
        self.assertEqual([False, False],
                         [evidence.is_first_party_advisory(f) for f in findings])
        self.assertEqual({"osv-scanner": 1, "trivy": 1},
                         {tool: row.get("advisory_manifest_changed_during_read")
                          for tool, row in dispositions.items()})
        # (b) An unstable manifest that decides nothing is not counted: the npm root's
        # package.json is unstable, the MEMBER's is quiet, and the member is confirmed.
        root = _tree(self, "package-lock.json")
        member_manifest = os.path.join(root, "packages", "lib", "package.json")
        self.assertTrue(os.path.isfile(member_manifest), os.listdir(root))
        root_manifest = os.path.join(root, "package.json")
        real_drain = safe_write._drain

        def only(target):
            def drain(path, stream, limit):
                raw = real_drain(path, stream, limit)
                if os.path.realpath(path) == target:
                    os.utime(path, ns=(1, 1))
                return raw
            return mock.patch.object(safe_write, "_drain", side_effect=drain)
        # A registry package beside it stays with the advisor for its own reason, and
        # is never counted, whichever manifest was unstable.
        document = _osv(NPM_MEMBER, "npm", "/src/package-lock.json")
        document["results"][0]["packages"].append({
            "package": {"name": "left-pad", "version": "1.3.0", "ecosystem": "npm"},
            "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc", "summary": "affected",
                                 "database_specific": {"severity": "LOW"}}],
            "groups": []})
        for target, confirmed, count in ((root_manifest, True, None),
                                         (member_manifest, False, 1)):
            with self.subTest(unstable=os.path.relpath(target, root)):
                tools = tempfile.mkdtemp(prefix="tools-out-", dir=root)
                with open(os.path.join(tools, "osv-scanner.json"), "w", encoding="utf-8") as fh:
                    json.dump(document, fh)
                with only(target):
                    findings, dispositions = ingest_tools.ingest_dir_detailed(
                        tools, "g1", target_root=root)
                self.assertEqual(2, len(findings))
                by_name = {f["tool_evidence"]["package_name"]: f for f in findings}
                self.assertEqual(confirmed,
                                 evidence.is_first_party_advisory(by_name[NPM_MEMBER[0]]))
                self.assertFalse(evidence.is_first_party_advisory(by_name["left-pad"]))
                self.assertEqual(count, dispositions["osv-scanner"].get(
                    "advisory_manifest_changed_during_read"))

    def test_a_manifest_refused_once_still_decides_through_the_cache(self):
        # Two locks reach one member manifest. Its read is unstable once and cached;
        # the second lock's advisory is denied by that same refusal and is counted too.
        for first, second, ecosystem, package, manifest, build in (
                ("package-lock.json", "npm-shrinkwrap.json", "npm", NPM_MEMBER,
                 "packages/lib/package.json", "npm"),
                ("uv.lock", "poetry.lock", "PyPI", PY_MEMBER,
                 "packages/lib/pyproject.toml", "python")):
            with self.subTest(locks=(first, second)):
                root = _tree(self, first)
                if build == "npm":
                    _npm_tree(root, lock_name=second)
                else:
                    _py_tree(root, lock=_poetry_lock(), lock_name=second)
                target = os.path.join(root, manifest)
                document = _osv(package, ecosystem, "/src/" + first)
                document["results"].append(
                    _osv(package, ecosystem, "/src/" + second)["results"][0])
                tools = tempfile.mkdtemp(prefix="tools-out-", dir=root)
                with open(os.path.join(tools, "osv-scanner.json"), "w", encoding="utf-8") as fh:
                    json.dump(document, fh)
                findings, quiet = ingest_tools.ingest_dir_detailed(
                    tools, "g1", target_root=root)
                self.assertEqual([True, True],
                                 [evidence.is_first_party_advisory(f) for f in findings])
                real = safe_write._drain
                reads = []

                def drain(path, stream, limit, target=target):
                    raw = real(path, stream, limit)
                    if os.path.realpath(path) == target:
                        reads.append(path)
                        os.utime(path, ns=(1, 1))
                    return raw
                with mock.patch.object(safe_write, "_drain", side_effect=drain):
                    findings, dispositions = ingest_tools.ingest_dir_detailed(
                        tools, "g1", target_root=root)
                self.assertEqual(1, len(reads))                    # read once, then cached
                self.assertEqual([False, False],
                                 [evidence.is_first_party_advisory(f) for f in findings])
                self.assertEqual(2, dispositions["osv-scanner"][
                    "advisory_manifest_changed_during_read"])

    def test_an_unstable_read_is_charged_to_the_budget(self):
        # Gate item 7: the bytes were read, whatever became of them.
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        paths = []
        for index in range(3):
            paths.append(os.path.join(os.path.realpath(d.name), "lock%d" % index))
            with open(paths[-1], "wb") as fh:
                fh.write(b"x" * 60)
        real = safe_write._drain

        def drain(path, stream, limit):
            raw = real(path, stream, limit)
            os.utime(path, ns=(1, 1))
            return raw
        cache = first_party_advisory.IngestCache()
        cache.manifest_bytes_remaining = 100
        with mock.patch.object(safe_write, "_drain", side_effect=drain):
            self.assertIsNone(first_party_advisory._read_budgeted_bytes(paths[0], 1000, cache))
            self.assertEqual(40, cache.manifest_bytes_remaining)
            self.assertFalse(cache.manifest_budget_exhausted)
            self.assertIsNone(first_party_advisory._read_budgeted_bytes(paths[1], 1000, cache))
            self.assertEqual(0, cache.manifest_bytes_remaining)
            self.assertTrue(cache.manifest_budget_exhausted)
            self.assertEqual(1, cache.budget_exhaustion_count)
            self.assertIsNone(first_party_advisory._read_budgeted_bytes(paths[2], 1000, cache))
            self.assertEqual(2, cache.budget_exhaustion_count)
        self.assertEqual(paths[:2], cache.unstable_reads)
        # A read that lands exactly on the budget exhausts it without a refusal.
        cache = first_party_advisory.IngestCache()
        cache.manifest_bytes_remaining = 60
        with mock.patch.object(safe_write, "_drain", side_effect=drain):
            self.assertIsNone(first_party_advisory._read_budgeted_bytes(paths[0], 1000, cache))
        self.assertEqual(0, cache.manifest_bytes_remaining)
        self.assertTrue(cache.manifest_budget_exhausted)
        # The error says how much was read.
        with mock.patch.object(safe_write, "_drain", side_effect=drain), \
                self.assertRaises(safe_write.UnstableFileError) as caught:
            safe_write.read_stable_regular_bytes(paths[0], 1000)
        self.assertEqual(60, caught.exception.bytes_read)

    def test_a_missing_lock_is_not_a_changed_one(self):
        # Gate item 9: only the unstable refusal is recorded, not every OSError.
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = os.path.realpath(d.name)
        cache = first_party_advisory.IngestCache()
        for path in (os.path.join(root, "absent.lock"), root):
            self.assertIsNone(first_party_advisory._read_budgeted_bytes(path, 1000, cache))
        self.assertEqual([], cache.unstable_reads)
        self.assertEqual(0, cache.unstable_touches)
        _write_manifest(root)                           # a manifest, and no lock at all
        tools = tempfile.mkdtemp(prefix="tools-out-", dir=root)
        with open(os.path.join(tools, "osv-scanner.json"), "w", encoding="utf-8") as fh:
            json.dump(_osv(CARGO, "crates.io", "/src/Cargo.lock"), fh)
        with mock.patch.object(safe_write, "read_stable_regular_bytes",
                               side_effect=FileNotFoundError(2, "gone")):
            findings, dispositions = ingest_tools.ingest_dir_detailed(
                tools, "g1", target_root=root)
        self.assertEqual([False], [evidence.is_first_party_advisory(f) for f in findings])
        self.assertNotIn("advisory_manifest_changed_during_read", dispositions["osv-scanner"])

    def test_the_stable_reader_opens_without_blocking_and_closes_what_it_opened(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = os.path.realpath(d.name)
        path = os.path.join(root, "f")
        with open(path, "wb") as fh:
            fh.write(b"abc")
        real_open = os.open
        opened = []

        def opener(target, flags, *args, **kwargs):
            # Asserted BEFORE the open: without O_NONBLOCK a FIFO would hang the test.
            self.assertTrue(flags & os.O_NONBLOCK, "the read must not block on a FIFO")
            self.assertTrue(flags & os.O_NOFOLLOW)
            fd = real_open(target, flags, *args, **kwargs)
            opened.append(fd)
            return fd

        def closed(fd):
            try:
                os.fstat(fd)
            except OSError:
                return True
            return False
        with mock.patch.object(safe_write.os, "open", side_effect=opener):
            self.assertEqual(b"abc", safe_write.read_stable_regular_bytes(path, 10))
            self.assertTrue(closed(opened[-1]))
            # A directory opens, is refused, and its descriptor is closed.
            with self.assertRaises(safe_write.NonRegularFileError):
                safe_write.read_stable_regular_bytes(root, 10)
            self.assertTrue(closed(opened[-1]))
            if hasattr(os, "mkfifo"):
                fifo = os.path.join(root, "fifo")
                os.mkfifo(fifo)
                with self.assertRaises(safe_write.NonRegularFileError):
                    safe_write.read_stable_regular_bytes(fifo, 10)
                self.assertTrue(closed(opened[-1]))
            # Over the limit: refused, and closed.
            with self.assertRaises(safe_write.ReadLimitExceeded):
                safe_write.read_stable_regular_bytes(path, 2)
            self.assertTrue(closed(opened[-1]))
        self.assertEqual(4 if hasattr(os, "mkfifo") else 3, len(opened))

    def test_the_stable_reader_needs_a_positive_integer_limit(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = os.path.join(d.name, "f")
        with open(path, "wb") as fh:
            fh.write(b"abc")
        for limit in (0, -1, -10 ** 9, True, False, 1.5, 3.0, "3", None, [3]):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError) as caught:
                    safe_write.read_stable_regular_bytes(path, limit)
                # The argument's own refusal, not the over-the-limit one (which is a
                # ValueError too and is what a limit of 0 or True would reach).
                self.assertIs(ValueError, type(caught.exception))
        self.assertEqual(b"abc", safe_write.read_stable_regular_bytes(path, 3))
        self.assertEqual(b"abc", safe_write.read_stable_regular_bytes(path, 1 << 20))

    def test_the_state_after_the_read_is_the_descriptors_own(self):
        # The open file is asked what it is after the read, not the path: a path that
        # answers with the earlier state must not hide a change to the file that was read.
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = os.path.join(os.path.realpath(d.name), "f")
        with open(path, "wb") as fh:
            fh.write(b"abc")
        earlier = os.stat(path, follow_symlinks=False)
        real = safe_write._drain

        def drain(target, stream, limit):
            raw = real(target, stream, limit)
            os.utime(target, ns=(1, 1))
            return raw
        with mock.patch.object(safe_write, "_drain", side_effect=drain), \
                mock.patch.object(safe_write.os, "stat", return_value=earlier), \
                self.assertRaises(safe_write.UnstableFileError):
            safe_write.read_stable_regular_bytes(path, 10)

    def _state(self, status, **changed):
        fields = {name: getattr(status, name) for name in
                  ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")}
        fields.update(changed)
        return types.SimpleNamespace(**fields)

    def test_a_different_device_alone_is_a_different_file(self):
        # Gates item 9 (M098): the same inode number on another device is another file.
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = os.path.join(os.path.realpath(d.name), "f")
        with open(path, "wb") as fh:
            fh.write(b"abc")
        real = os.stat(path, follow_symlinks=False)
        other = self._state(real, st_dev=real.st_dev + 1)
        self.assertNotEqual(safe_write._file_state(real), safe_write._file_state(other))
        self.assertEqual(safe_write._file_state(real),
                         safe_write._file_state(self._state(real)))
        # ... at the path afterwards,
        with mock.patch.object(safe_write.os, "stat", return_value=other), \
                self.assertRaises(safe_write.UnstableFileError):
            safe_write.read_stable_regular_bytes(path, 10)
        # ... and at the descriptor afterwards.
        real_fstat = os.fstat
        calls = []

        def fstat(fd):
            calls.append(fd)
            status = real_fstat(fd)
            return status if len(calls) == 1 else self._state(status, st_dev=status.st_dev + 1)
        with mock.patch.object(safe_write.os, "fstat", side_effect=fstat), \
                self.assertRaises(safe_write.UnstableFileError):
            safe_write.read_stable_regular_bytes(path, 10)
        self.assertEqual(2, len(calls))

    def test_the_first_state_is_the_opened_files_own(self):
        # Gates item 9 (M100). The file is opened, and then its path is made a
        # directory. What was opened is a regular file and is read; the path no longer
        # names it, so the read is unstable -- not "not a regular file", which is what
        # asking the PATH for the first state would say.
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = os.path.join(os.path.realpath(d.name), "f")
        with open(path, "wb") as fh:
            fh.write(b"abc")
        real_open = os.open

        def opener(target, flags, *args, **kwargs):
            fd = real_open(target, flags, *args, **kwargs)
            os.rename(target, target + ".moved")
            os.mkdir(target)
            return fd
        with mock.patch.object(safe_write.os, "open", side_effect=opener):
            with self.assertRaises(OSError) as caught:
                safe_write.read_stable_regular_bytes(path, 10)
        self.assertIs(safe_write.UnstableFileError, type(caught.exception))
        self.assertEqual(3, caught.exception.bytes_read)

    def test_any_failure_to_look_again_is_an_unstable_read(self):
        # Gates item 9 (M101) and item 6: not only a path that is gone. Whatever stops
        # the second look, at the path or at the descriptor, the bytes read are reported.
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = os.path.join(os.path.realpath(d.name), "f")
        with open(path, "wb") as fh:
            fh.write(b"abcde")
        for error in (PermissionError(13, "denied"), FileNotFoundError(2, "gone"),
                      NotADirectoryError(20, "not a directory"), OSError(5, "i/o")):
            with self.subTest(restat=type(error).__name__):
                with mock.patch.object(safe_write.os, "stat", side_effect=error):
                    with self.assertRaises(OSError) as caught:
                        safe_write.read_stable_regular_bytes(path, 10)
                self.assertIs(safe_write.UnstableFileError, type(caught.exception))
                self.assertEqual(5, caught.exception.bytes_read)
            with self.subTest(fstat=type(error).__name__):
                real_fstat = os.fstat
                calls = []

                def fstat(fd, error=error, calls=calls, real_fstat=real_fstat):
                    calls.append(fd)
                    if len(calls) == 1:
                        return real_fstat(fd)
                    raise error
                with mock.patch.object(safe_write.os, "fstat", side_effect=fstat):
                    with self.assertRaises(OSError) as caught:
                        safe_write.read_stable_regular_bytes(path, 10)
                self.assertIs(safe_write.UnstableFileError, type(caught.exception))
                self.assertEqual(5, caught.exception.bytes_read)
        # ... and so it is charged: six reads that fail at the second look exhaust a
        # budget of five files' worth, where they charged nothing.
        cache = first_party_advisory.IngestCache()
        cache.manifest_bytes_remaining = 25
        real_fstat = os.fstat
        seen = {}

        def failing(fd):
            seen[fd] = seen.get(fd, 0) + 1
            if seen[fd] == 1:
                return real_fstat(fd)
            del seen[fd]
            raise OSError(5, "i/o")
        with mock.patch.object(safe_write.os, "fstat", side_effect=failing):
            for _ in range(5):
                self.assertIsNone(first_party_advisory._read_budgeted_bytes(path, 1000, cache))
            self.assertEqual(0, cache.manifest_bytes_remaining)
            self.assertTrue(cache.manifest_budget_exhausted)
            self.assertEqual(1, cache.budget_exhaustion_count)
            self.assertIsNone(first_party_advisory._read_budgeted_bytes(path, 1000, cache))
            self.assertEqual(2, cache.budget_exhaustion_count)

    def test_an_earlier_unstable_read_does_not_colour_a_later_identity(self):
        # Gates item 9 (M034-M036). The count asks what was touched WHILE this identity
        # was being proved. An unstable manifest read earlier in the ingest, for another
        # identity, must not make a later one (unproved for its own reason, every file
        # quiet) look unstable.
        real = safe_write._drain

        def only(target):
            def drain(path, stream, limit):
                raw = real(path, stream, limit)
                if os.path.realpath(path) == target:
                    os.utime(path, ns=(1, 1))
                return raw
            return mock.patch.object(safe_write, "_drain", side_effect=drain)

        def ingest(root, document, target):
            tools = tempfile.mkdtemp(prefix="tools-out-", dir=root)
            with open(os.path.join(tools, "osv-scanner.json"), "w", encoding="utf-8") as fh:
                json.dump(document, fh)
            with only(target):
                return ingest_tools.ingest_dir_detailed(tools, "g1", target_root=root)
        # npm and Python: the root's manifest is unstable; the member's is quiet and
        # proves another version.
        for lock_name, ecosystem, package, manifest in (
                ("package-lock.json", "npm", NPM_MEMBER, "package.json"),
                ("uv.lock", "PyPI", PY_MEMBER, "pyproject.toml")):
            with self.subTest(lock=lock_name):
                d = tempfile.TemporaryDirectory()
                self.addCleanup(d.cleanup)
                root = os.path.realpath(d.name)
                if lock_name == "package-lock.json":
                    _npm_tree(root, member={"name": NPM_MEMBER[0], "version": "9.9.9"})
                else:
                    _py_tree(root, member='[project]\nname = "acme_lib"\nversion = "9.9.9"\n')
                findings, dispositions = ingest(
                    root, _osv(package, ecosystem, "/src/" + lock_name),
                    os.path.join(root, manifest))
                self.assertEqual([False], [evidence.is_first_party_advisory(f)
                                           for f in findings])
                self.assertNotIn("advisory_manifest_changed_during_read",
                                 dispositions["osv-scanner"])
        # Cargo reads a lock's manifests as one set, so the earlier read is another
        # lock's: the root's manifest is unstable, and `sub/` is quiet and unproved.
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = os.path.realpath(d.name)
        _write_lock(root)
        _write_manifest(root)
        os.mkdir(os.path.join(root, "sub"))
        _write_lock(os.path.join(root, "sub"))
        _write_manifest(os.path.join(root, "sub"), '[package]\nname = "%s"\nversion = "9.9.9"\n'
                        % WORKSPACE_NAME)
        document = _osv(CARGO, "crates.io", "/src/Cargo.lock")
        document["results"].append(_osv(CARGO, "crates.io", "/src/sub/Cargo.lock")["results"][0])
        findings, dispositions = ingest(root, document, os.path.join(root, "Cargo.toml"))
        self.assertEqual([False, False], [evidence.is_first_party_advisory(f) for f in findings])
        self.assertEqual(1, dispositions["osv-scanner"]["advisory_manifest_changed_during_read"])

    def test_a_quiet_ingest_discloses_no_count(self):
        root = _tree(self, "Cargo.lock")
        tools = tempfile.mkdtemp(prefix="tools-out-", dir=root)
        with open(os.path.join(tools, "osv-scanner.json"), "w", encoding="utf-8") as fh:
            json.dump(_osv(CARGO, "crates.io", "/src/Cargo.lock"), fh)
        with open(os.path.join(tools, "trivy.sarif"), "w", encoding="utf-8") as fh:
            json.dump(_trivy(CARGO, "Cargo.lock"), fh)
        _findings, quiet = ingest_tools.ingest_dir_detailed(tools, "g1", target_root=root)
        for tool in ("osv-scanner", "trivy"):
            self.assertNotIn("advisory_manifest_changed_during_read", quiet[tool])
            self.assertEqual("ok", quiet[tool]["status"])

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
                # ... and each ecosystem's loop says an unstable manifest decided it.
                tools = tempfile.mkdtemp(prefix="tools-out-", dir=root)
                with open(os.path.join(tools, "osv-scanner.json"), "w", encoding="utf-8") as fh:
                    json.dump(document, fh)
                with mock.patch.object(safe_write, "_drain", side_effect=drain):
                    _findings, dispositions = ingest_tools.ingest_dir_detailed(
                        tools, "g1", target_root=root)
                self.assertEqual(1, dispositions["osv-scanner"].get(
                    "advisory_manifest_changed_during_read"))

    def test_an_identity_unproved_for_its_own_reason_is_not_counted(self):
        # Seat r2 survivor: with every file quiet, a local package its manifest does not
        # prove stays with the advisor and no unstable read is claimed.
        for lock_name, ecosystem, package in LOCKS:
            with self.subTest(lock=lock_name):
                d = tempfile.TemporaryDirectory()
                self.addCleanup(d.cleanup)
                root = os.path.realpath(d.name)
                if lock_name == "Cargo.lock":
                    _write_lock(root)
                    _write_manifest(root, '[package]\nname = "%s"\nversion = "9.9.9"\n'
                                    % WORKSPACE_NAME)
                elif lock_name == "package-lock.json":
                    _npm_tree(root, member={"name": NPM_MEMBER[0], "version": "9.9.9"})
                else:
                    _py_tree(root, member='[project]\nname = "acme_lib"\nversion = "9.9.9"\n')
                tools = tempfile.mkdtemp(prefix="tools-out-", dir=root)
                with open(os.path.join(tools, "osv-scanner.json"), "w", encoding="utf-8") as fh:
                    json.dump(_osv(package, ecosystem, "/src/" + lock_name), fh)
                findings, dispositions = ingest_tools.ingest_dir_detailed(
                    tools, "g1", target_root=root)
                self.assertEqual([False], [evidence.is_first_party_advisory(f)
                                           for f in findings])
                self.assertNotIn("advisory_manifest_changed_during_read",
                                 dispositions["osv-scanner"])

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


def _main_location(uri):
    """`location.file` as origin/main's `norm_uri` spells it (before the inert pass)."""
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
    return uri[len("/src/"):] if uri.startswith("/src/") else uri.lstrip("/")


class TestAPathOutsideTheScanMount(_Case):
    """Fault 2. A path the scanner located outside the scan mount was read as the
    review root's own file.

    The second gate ruling (at e232fdec): outside is a FACT on the finding, not a
    spelling of its path. `location.file`, the fingerprint and the reconcile key are
    exactly main's; the scanner adapter records `tool_evidence.uri_base: "outside"`,
    and the marker refuses a finding that carries it before any lock is read."""

    def test_which_paths_are_outside(self):
        outside = sarif_utils.path_outside_mount
        for uri in ("/Cargo.lock", "//Cargo.lock", "///Cargo.lock", "file:///Cargo.lock",
                    "file:////Cargo.lock", "/etc/passwd", "/srcx/Cargo.lock", "/src", "/",
                    "file:///", "//src/Cargo.lock", "file:////src/Cargo.lock", "///src/x",
                    "file://Cargo.lock", "file://host/src/Cargo.lock", "file://src/x",
                    "file://localhost/src/x", "file://", "/SRC/x", "/tmp/elsewhere/uv.lock"):
            with self.subTest(outside=uri):
                self.assertIs(True, outside(uri))
        for uri in ("/src/Cargo.lock", "file:///src/Cargo.lock", "/src/a/b.py", "/src/",
                    "/src//x", "Cargo.lock", "a/b.py", "src/Cargo.lock", "", "./x", "../x",
                    "x:y/z", "https://example.invalid/x", "file:x", "file:/x",
                    None, 7, ["/x"], b"/x"):
            with self.subTest(inside=uri):
                self.assertIs(False, outside(uri))

    def test_which_results_are_outside(self):
        outside = sarif_utils.artifact_outside_mount
        table = {"ROOTPATH": {"uri": "file:///src/"}, "ELSEWHERE": {"uri": "file:///etc/"},
                 "NOSLASH": {"uri": "file:///src"}, "": {"uri": "file:///etc/"},
                 "7": {"uri": "file:///src/"}, "NOURI": {}, "STRING": "file:///src/",
                 "CHAINED": {"uri": "file:///src/", "uriBaseId": "ROOTPATH"}}
        run = {"originalUriBaseIds": table}
        for artifact, expected in (
                ({"uri": "a/b.py"}, False),
                ({"uri": "a/b.py", "uriBaseId": "ROOTPATH"}, False),
                ({"uri": "a/b.py", "uriBaseId": "ELSEWHERE"}, True),
                ({"uri": "a/b.py", "uriBaseId": "NOSLASH"}, True),
                ({"uri": "a/b.py", "uriBaseId": "NOURI"}, True),
                ({"uri": "a/b.py", "uriBaseId": "STRING"}, True),
                ({"uri": "a/b.py", "uriBaseId": "CHAINED"}, True),
                # A falsy id the run defines is an id.
                ({"uri": "a.py", "uriBaseId": ""}, True),
                # A numeric id is not the key "7".
                ({"uri": "a.py", "uriBaseId": 7}, True),
                ({"uri": "a.py", "uriBaseId": ["ROOTPATH"]}, True),
                # A base the run never defines is a bare symbol: as no base.
                ({"uri": "a.py", "uriBaseId": "MISSING"}, False),
                ({"uri": "a.py", "uriBaseId": "%SRCROOT%"}, False),
                ({"uri": "a.py", "uriBaseId": None}, False),
                # An absolute uri ignores its base, and is judged for itself.
                ({"uri": "/src/a.py", "uriBaseId": "ELSEWHERE"}, False),
                ({"uri": "file:///src/a.py", "uriBaseId": "ELSEWHERE"}, False),
                ({"uri": "/a.py", "uriBaseId": "ROOTPATH"}, True),
                ({"uri": "file:///a.py", "uriBaseId": "ROOTPATH"}, True),
                ({"uri": "/a.py"}, True), ({"uri": "//src/a.py"}, True),
                ({"uri": "file://host/a.py"}, True),
                # A scheme that is not a file path: its base is not applied.
                ({"uri": "https://example.invalid/a.py", "uriBaseId": "ELSEWHERE"}, False),
                # Nothing located: nothing to be outside.
                ({}, False), ({"uri": 7}, False), ({"uri": None, "uriBaseId": "ELSEWHERE"}, False),
                ({"uriBaseId": "ELSEWHERE"}, False),
                ("a.py", False), (["a.py"], False), (None, False), (7, False)):
            with self.subTest(artifact=artifact):
                self.assertIs(expected, outside(artifact, run))
        # No table, or a null one, defines nothing.
        for undefined in ({}, {"originalUriBaseIds": None}, {"originalUriBaseIds": {}}, None, 7):
            with self.subTest(undefined=undefined):
                self.assertIs(False, outside({"uri": "a.py", "uriBaseId": "X"}, undefined))
        # A table that is there but is not an object defines every id, unreadably.
        for bad in ([], "", False, 0, ["X"], "X", 7):
            with self.subTest(table=bad):
                self.assertIs(True, outside({"uri": "a.py", "uriBaseId": "X"},
                                            {"originalUriBaseIds": bad}))

    def test_only_the_scan_mount_itself_is_an_inside_base(self):
        inside = sarif_utils.is_scan_mount
        for base in ("file:///src/", "/src/", "file:/src/", "FILE:///src/"):
            with self.subTest(inside=base):
                self.assertTrue(inside(base))
        for base in ("file:///src", "/src", "file:///src//", "file:////src/", "//src/",
                     "file:///src/sub/", "file:///", "/", "", "src/", "./src/", "file:src/",
                     "file://localhost/src/", "file://host/src/", "https://x/src/",
                     "http:///src/", "urn:/src/", "C:/src/",
                     # What the parser itself refuses.
                     "file://[::1/src/", "//[/src/",
                     # A query or a fragment, even an empty one.
                     "file:///src/?other/", "file:///src/#shadow/", "file:///src/?", "/src/#",
                     "file:///src/#/tests/fixtures/",
                     # Percent-escapes are never decoded and never accepted.
                     "file:///src/%2e%2e/", "file:///%73rc/", "/src%2f",
                     # Control characters and padding, which a URL parser strips.
                     "file:///src/a\n/", "file:///src/\n", "\tfile:///src/", " file:///src/",
                     "\x01file:///src/", "\x01/src/", "\x1ffile:///src/", "file:///SRC/",
                     "/SRC/", "/Src/",
                     "file:///src/ ", "fi\tle:///src/", "/s\nrc/", "/src/\x00", "/src/\x7f",
                     "/src/\u202e", "file:///src/../src/", "/src/./",
                     None, 7, b"/src/", ["/src/"], {"uri": "/src/"}):
            with self.subTest(outside=base):
                self.assertFalse(inside(base))

    def test_a_table_of_bases_and_uris_to_the_advisor_queue(self):
        # One column: inside or outside, asserted at the marker. Every row goes through
        # ingest; "outside" means the advisor still has the finding, "inside" that it is
        # first-party. Each directory a mis-read spelling would name is really there,
        # with a lock and a manifest that would prove the package.
        # And for EVERY row the location, fingerprint and reconcile key are main's:
        # the location by main's own three-line rule, the two keys by ingesting the
        # same uri with no base at all.
        from scripts.tools.base import inert_text
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = os.path.realpath(d.name)
        _write_lock(root)
        _write_manifest(root)
        nested = ("sub", "?other", "#shadow", "file:", "urn:outside", "C:", "%2e%2e",
                  "a\\x0a", "a#b", "a?b", "a%20b", "x:y", "a\\b", "a\\x1b[31m", "etc",
                  "xU+D800", "xU+DCE9", "U+0041",
                  "outside", os.path.join("file:", "outside"), os.path.join("C:", "outside"))
        for name in nested:
            os.makedirs(os.path.join(root, name), exist_ok=True)
            _write_lock(os.path.join(root, name))
            _write_manifest(os.path.join(root, name))
        mount = {"ROOTPATH": {"uri": "file:///src/"}}

        def at(base):
            return {"ROOTPATH": {"uri": base}}
        rows = (
            # uri, bases, inside
            ("Cargo.lock", _NO_BASES, True), ("Cargo.lock", mount, True),
            ("sub/Cargo.lock", mount, True), ("sub/Cargo.lock", _NO_BASES, True),
            ("Cargo.lock", at("/src/"), True), ("Cargo.lock", at("file:/src/"), True),
            ("Cargo.lock", None, True), ("Cargo.lock", {}, True),
            ("/src/Cargo.lock", at("file:///etc/"), True),
            ("/src/sub/Cargo.lock", _NO_BASES, True),
            # A base that is not exactly the mount.
            ("Cargo.lock", at("file:///"), False), ("Cargo.lock", at("file:///etc/"), False),
            ("Cargo.lock", at("file:///src"), False), ("Cargo.lock", at("file:///src//"), False),
            ("Cargo.lock", at("file:///src/sub/"), False),
            ("Cargo.lock", at("file:///src/?other/"), False),
            ("Cargo.lock", at("file:///src/#shadow/"), False),
            ("Cargo.lock", at("file:///src/#/sub/"), False),
            ("Cargo.lock", at("file:/outside/"), False), ("Cargo.lock", at("urn:outside/"), False),
            ("Cargo.lock", at("C:/outside/"), False), ("Cargo.lock", at("file:"), False),
            ("Cargo.lock", at("urn:outside"), False), ("Cargo.lock", at("C:\\repo\\"), False),
            ("Cargo.lock", at("file:///src/%2e%2e/"), False),
            ("Cargo.lock", at("file:///src/a\n/"), False),
            ("Cargo.lock", at("file:///src/\n"), False), ("Cargo.lock", at(" file:///src/"), False),
            ("Cargo.lock", at("\x01file:///src/"), False), ("Cargo.lock", at("\x01/src/"), False),
            ("Cargo.lock", at("file:///SRC/"), False), ("Cargo.lock", at("/SRC/"), False),
            ("Cargo.lock", at("//src/"), False), ("Cargo.lock", at("file:////src/"), False),
            ("Cargo.lock", at("file://host/src/"), False), ("Cargo.lock", at("src/"), False),
            ("Cargo.lock", at("file://localhost/src/"), False),
            ("Cargo.lock", at(""), False), ("Cargo.lock", at(None), False),
            ("Cargo.lock", [], False), ("Cargo.lock", "", False), ("Cargo.lock", False, False),
            ("Cargo.lock", {"ROOTPATH": {"uri": "file:///src/", "uriBaseId": "TOP"},
                            "TOP": {"uri": "file:///"}}, False),
            # A relative uri that is not plain, under the mount and with no base.
            ("../src/Cargo.lock", mount, False), ("sub/../Cargo.lock", mount, False),
            ("?other/Cargo.lock", mount, False), ("#shadow/Cargo.lock", mount, False),
            ("%2e%2e/Cargo.lock", mount, False), ("a%20b/Cargo.lock", mount, False),
            ("a#b/Cargo.lock", mount, False), ("a?b/Cargo.lock", mount, False),
            ("x:y/Cargo.lock", mount, False), ("file:/Cargo.lock", mount, False),
            ("a\n/Cargo.lock", mount, False), ("a\x1b[31m/Cargo.lock", mount, False),
            ("a\\b/Cargo.lock", mount, False), ("a\\x0a/Cargo.lock", mount, False),
            ("Cargo.lock?x", mount, False), ("Cargo.lock#x", mount, False),
            # A lone surrogate is shown as U+XXXX, with no backslash (seat r3 item 2).
            ("x" + chr(0xd800) + "/Cargo.lock", mount, False),
            ("x" + chr(0xd800) + "/Cargo.lock", _NO_BASES, False),
            ("/src/x" + chr(0xdce9) + "/Cargo.lock", _NO_BASES, False),
            ("../src/Cargo.lock", _NO_BASES, False), ("sub/../Cargo.lock", _NO_BASES, False),
            ("?other/Cargo.lock", _NO_BASES, False), ("#shadow/Cargo.lock", _NO_BASES, False),
            ("%2e%2e/Cargo.lock", _NO_BASES, False), ("a%20b/Cargo.lock", _NO_BASES, False),
            ("a#b/Cargo.lock", _NO_BASES, False), ("a?b/Cargo.lock", _NO_BASES, False),
            ("x:y/Cargo.lock", _NO_BASES, False), ("urn:outside/Cargo.lock", _NO_BASES, False),
            ("C:/Cargo.lock", _NO_BASES, False), ("file:/outside/Cargo.lock", _NO_BASES, False),
            ("a\n/Cargo.lock", _NO_BASES, False), ("a\x1b[31m/Cargo.lock", _NO_BASES, False),
            ("a\\b/Cargo.lock", _NO_BASES, False), ("a\\x0a/Cargo.lock", _NO_BASES, False),
            # The same names reached through an absolute path inside the mount.
            ("/src/%2e%2e/Cargo.lock", _NO_BASES, False), ("/src/a#b/Cargo.lock", _NO_BASES, False),
            ("file:///src/a?b/Cargo.lock", _NO_BASES, False),
            ("/src/a\n/Cargo.lock", _NO_BASES, False), ("/src/x:y/Cargo.lock", _NO_BASES, False),
            # Only the surrogate range is the renderer's spelling: `U+0041` is a name.
            ("U+0041/Cargo.lock", mount, True), ("U+0041/Cargo.lock", _NO_BASES, True),
            # The earlier rounds' spellings.
            ("/Cargo.lock", _NO_BASES, False), ("//Cargo.lock", _NO_BASES, False),
            ("file:///Cargo.lock", _NO_BASES, False), ("//src/Cargo.lock", _NO_BASES, False),
            ("file:////src/Cargo.lock", _NO_BASES, False), ("file://Cargo.lock", _NO_BASES, False),
            ("/etc/Cargo.lock", _NO_BASES, False),
        )
        keys = {}
        for uri, bases, inside in rows:
            with self.subTest(uri=uri, bases=bases):
                findings = _ingest(root, "trivy.sarif", _trivy(
                    CARGO, uri, base_id=None if bases is _NO_BASES else "ROOTPATH", bases=bases))
                (self.assert_first_party if inside else self.assert_advisor_path)(findings)
                finding = findings[0]
                self.assertEqual(inert_text(_main_location(uri), mode="path"),
                                 finding["location"]["file"])
                if uri not in keys:
                    plain = _ingest(root, "trivy.sarif", _trivy(CARGO, uri))[0]
                    plain["tool_evidence"].pop("uri_base", None)
                    keys[uri] = (plain["location"], evidence.finding_fingerprint(plain),
                                 evidence.reconcile_key(plain))
                self.assertEqual(keys[uri], (finding["location"],
                                             evidence.finding_fingerprint(finding),
                                             evidence.reconcile_key(finding)))
                if inside:
                    self.assertNotIn("uri_base", finding["tool_evidence"])

    def test_the_flag_is_what_the_marker_refuses_on(self):
        # A finding the marker would confirm, refused for the flag alone; and the
        # refusal comes before any lock or manifest is read.
        root = _tree(self, "Cargo.lock")
        genuine = _ingest(root, "trivy.sarif", _trivy(CARGO, "Cargo.lock"))
        self.assert_first_party(genuine)
        for value in ("outside", "inside", "", None, True, 0, ["outside"]):
            with self.subTest(uri_base=value):
                findings = _ingest(root, "trivy.sarif", _trivy(CARGO, "Cargo.lock"))
                for key in ("package_origin", "advisory_package"):
                    findings[0]["tool_evidence"].pop(key, None)
                findings[0]["tool_evidence"]["uri_base"] = value
                with mock.patch.object(first_party_advisory, "_read_budgeted_bytes",
                                       side_effect=AssertionError("a file was read")):
                    first_party_advisory.mark(findings, root, first_party_advisory.IngestCache())
                self.assertFalse(evidence.is_first_party_advisory(findings[0]))
                self.assertNotIn("package_origin", findings[0]["tool_evidence"])
        # The scanner adapters set it, for each lock, and only then.
        for lock_name, ecosystem, package in LOCKS:
            root = _tree(self, lock_name)
            for document, name, uri in (
                    (_trivy(package, "/" + lock_name), "trivy.sarif", "/" + lock_name),
                    (_trivy(package, "file://" + lock_name), "trivy.sarif", lock_name),
                    (_trivy(package, lock_name, base_id="ROOTPATH",
                            bases={"ROOTPATH": {"uri": "file:///etc/"}}), "trivy.sarif",
                     lock_name),
                    (_osv(package, ecosystem, "/" + lock_name), "osv-scanner.json",
                     "/" + lock_name),
                    (_osv(package, ecosystem, "//" + lock_name), "osv-scanner.json",
                     "//" + lock_name),
                    (_osv(package, ecosystem, "//src/" + lock_name), "osv-scanner.json",
                     "//src/" + lock_name),
                    (_osv(package, ecosystem, "file://" + lock_name), "osv-scanner.json",
                     lock_name)):
                with self.subTest(lock=lock_name, tool=name, uri=uri):
                    findings = _ingest(root, name, document)
                    self.assert_advisor_path(findings)
                    self.assertEqual("outside", findings[0]["tool_evidence"]["uri_base"])
                    self.assertEqual(_main_location(uri), findings[0]["location"]["file"])
            for document, name in (
                    (_trivy(package, lock_name), "trivy.sarif"),
                    (_trivy(package, "/src/" + lock_name), "trivy.sarif"),
                    (_trivy(package, lock_name, base_id="ROOTPATH",
                            bases={"ROOTPATH": {"uri": "file:///src/"}}), "trivy.sarif"),
                    (_trivy(package, lock_name, base_id="%SRCROOT%"), "trivy.sarif"),
                    (_osv(package, ecosystem, "/src/" + lock_name), "osv-scanner.json"),
                    (_osv(package, ecosystem, lock_name), "osv-scanner.json")):
                with self.subTest(lock=lock_name, inside=name):
                    findings = _ingest(root, name, document)
                    self.assert_first_party(findings)
                    self.assertNotIn("uri_base", findings[0]["tool_evidence"])

    def test_the_flag_is_not_part_of_a_findings_identity_and_is_in_the_schema(self):
        root = _tree(self, "Cargo.lock")
        flagged = _ingest(root, "trivy.sarif", _trivy(CARGO, "/Cargo.lock"))[0]
        self.assertEqual("outside", flagged["tool_evidence"]["uri_base"])
        bare = copy.deepcopy(flagged)
        del bare["tool_evidence"]["uri_base"]
        self.assertEqual(evidence.finding_fingerprint(bare), evidence.finding_fingerprint(flagged))
        self.assertEqual(evidence.reconcile_key(bare), evidence.reconcile_key(flagged))
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "..", "skill", "reference", "report-schema.json"),
                  encoding="utf-8") as fh:
            text = fh.read()
        schema = json.loads(text)

        def find(node):
            if isinstance(node, dict):
                if "uri_base" in node and isinstance(node["uri_base"], dict):
                    yield node["uri_base"]
                for value in node.values():
                    yield from find(value)
            elif isinstance(node, list):
                for value in node:
                    yield from find(value)
        entries = list(find(schema))
        self.assertTrue(entries)
        for entry in entries:
            self.assertEqual(["outside"], entry["enum"])

    def test_nothing_else_about_an_outside_result_changes(self):
        # The location a suppression, the coverage ledger and the legacy reader see is
        # main's, so a result under an outside base is counted and filtered as on main.
        import scripts.tools.legacy_sarif as legacy_sarif
        for uri, expected in (("/abs/x.py", "abs/x.py"), ("file:///abs/x.py", "abs/x.py"),
                              ("//Cargo.lock", "Cargo.lock"), ("/src/a/b.py", "a/b.py"),
                              ("file:///src/a.py", "a.py"), ("a.py", "a.py"),
                              ("file://host/x", "host/x"), ("//src/x", "src/x")):
            with self.subTest(uri=uri):
                self.assertEqual(expected, sarif_utils.norm_uri(uri))
                self.assertEqual(expected, _main_location(uri))
                self.assertEqual(expected, sarif_utils.CaptureCoverage().seen(uri))
                self.assertEqual(expected, legacy_sarif._sarif_path(uri))
        document = _trivy(CARGO, "Cargo.lock", base_id="tests/fixtures",
                          bases={"tests/fixtures": {"uri": "file:///etc/"}})
        self.assertEqual({"Cargo.lock"}, legacy_sarif._result_paths(document))
        # No synthetic location exists any more, whatever the id says.
        root = _tree(self, "Cargo.lock")
        for base_id in ("tests/fixtures", "vendor", "node_modules/a", "x" * 5000, "", ".."):
            with self.subTest(id=base_id[:20]):
                findings = _ingest(root, "trivy.sarif", _trivy(
                    CARGO, "Cargo.lock", base_id=base_id, severity="8.1",
                    tags=("vulnerability", "security", "HIGH"),
                    bases={base_id: {"uri": "file:///etc/"}}))
                self.assert_advisor_path(findings)
                self.assertEqual("Cargo.lock", findings[0]["location"]["file"])
                self.assertNotIn("unresolved", json.dumps(findings))

    def test_a_result_with_no_file_is_not_a_located_path(self):
        # Only a non-empty string is a path.
        import scripts.tools.legacy_sarif as legacy_sarif
        for artifact in ({}, {"uri": 7}, {"uri": None}, {"uri": ["a.py"]}, "a.py", None, 7,
                         {"uriBaseId": "ROOTPATH"}):
            with self.subTest(artifact=artifact):
                document = _trivy(CARGO, "x")
                document["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                    "artifactLocation"] = artifact
                self.assertEqual(set(), legacy_sarif._result_paths(document))
        self.assertEqual({"a.py"}, legacy_sarif._result_paths(_trivy(CARGO, "a.py")))
        for uri in ("", "/", "file:///", "/src/", "file:///src/", "///"):
            for bases in (_NO_BASES, {"ROOTPATH": {"uri": "file:///etc/"}}):
                with self.subTest(empty=uri, bases=bases):
                    self.assertEqual(set(), legacy_sarif._result_paths(_trivy(
                        CARGO, uri, base_id=None if bases is _NO_BASES else "ROOTPATH",
                        bases=bases)))

    def test_the_marker_matches_only_a_plain_relative_location(self):
        # Asked of the location itself, whichever adapter wrote it, with each
        # directory really on disk and holding a lock.
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = os.path.realpath(d.name)
        cut = chr(0x2026)                       # inert_text's mark for a cut value
        plain = ("sub", os.path.join("sub", "x:y"), "a b", "a+b", "a@b", "caf" + chr(0xe9),
                 # Not the surrogate spelling: too few digits, lower case, no plus.
                 "U+D80", "u+d800", "U+d800", "U+dce9x", "UD800", "U+",
                 # Gates item 5: outside D800-DFFF, `U+XXXX` is an ordinary name.
                 "U+0041", "U+D7FF", "U+E000", "U+FFFF", "U+C800", "xU+0041y",
                 "U+D8ab", "U+D8", "U+Dx00",
                 "a.b", "~a", "a=b&c", "[a]")
        refused = ("xU+D800", "U+DCE9", "aU+DFFFb", "U+DBFF", "U+DC00", "U+D8AB", "U+DFAB",
                   "x:y", "C:", "a%20b", "%2e%2e", "a?b", "a#b", "a\\b", "a\\x0a",
                   "a\nb", "a\tb", "a\x1fb", "a\x01b", "a\x7fb", "a" + cut,
                   os.path.join("sub", "a%b"), os.path.join("sub", "a" + cut))
        for name in plain + refused:
            os.makedirs(os.path.join(root, name), exist_ok=True)
            _write_lock(os.path.join(root, name))

        def lock_path(rel):
            return first_party_advisory._lock_path(
                root, {"location": {"file": rel}}, ("Cargo.lock",))
        for name in plain:
            with self.subTest(plain=name):
                rel = name.replace(os.sep, "/") + "/Cargo.lock"
                self.assertEqual(os.path.join(root, name, "Cargo.lock"), lock_path(rel))
                self.assertEqual(os.path.join(root, name, "Cargo.lock"), lock_path("./" + rel))
        for name in refused:
            with self.subTest(refused=name):
                self.assertIsNone(lock_path(name.replace(os.sep, "/") + "/Cargo.lock"))
        for rel in ("file:Cargo.lock", "file:/Cargo.lock", "urn:x/Cargo.lock",
                    "sub/../sub/Cargo.lock", "/Cargo.lock", "", "sub//Cargo.lock"):
            with self.subTest(refused=rel):
                self.assertIsNone(lock_path(rel))

    def test_an_osv_source_path_must_be_plain_too(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = os.path.realpath(d.name)
        for name in ("sub", "%2e%2e", "a#b", "a\\x0a"):
            os.makedirs(os.path.join(root, name))
            _write_lock(os.path.join(root, name))
            _write_manifest(os.path.join(root, name))
        for path, inside in (("/src/sub/Cargo.lock", True), ("/src/%2e%2e/Cargo.lock", False),
                             ("/src/a#b/Cargo.lock", False), ("/src/a\n/Cargo.lock", False)):
            with self.subTest(path=path):
                findings = _ingest(root, "osv-scanner.json", _osv(CARGO, "crates.io", path))
                (self.assert_first_party if inside else self.assert_advisor_path)(findings)

    def test_a_symbolic_base_with_no_table_keeps_a_relative_path(self):
        # The repo's own semgrep fixture: a relative uri, `%SRCROOT%`, no table.
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "fixtures", "semgrep.sarif"), encoding="utf-8") as fh:
            document = json.load(fh)
        document["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"] = {"uri": "tests/fixtures/vulnerable.py",
                                   "uriBaseId": "%SRCROOT%"}
        self.assertNotIn("originalUriBaseIds", document["runs"][0])
        findings = sarif_utils.sarif_to_findings(document, "semgrep", "g1", "XX")
        self.assertEqual("tests/fixtures/vulnerable.py", findings[0]["location"]["file"])

    def test_the_golden_captures_keep_their_paths(self):
        # Trivy's own capture (ROOTPATH = file:///src/) and semgrep's (%SRCROOT%, no
        # table) both resolve inside the mount, exactly as before.
        here = os.path.dirname(os.path.abspath(__file__))
        for name, tool in (("trivy.raw", "trivy"), ("semgrep.raw", "semgrep")):
            with self.subTest(golden=name):
                with open(os.path.join(here, "goldens", "tool-raw", name), encoding="utf-8") as fh:
                    document = json.load(fh)
                findings = sarif_utils.sarif_to_findings(document, tool, "g1", "XX")
                self.assertTrue(findings)
                for finding in findings:
                    path = finding["location"]["file"]
                    self.assertFalse(path.startswith(("/", "file:")), path)
                    self.assertNotIn("unresolved", path)

    def test_an_osv_source_outside_the_mount_is_not_the_roots_lock(self):
        for lock_name, ecosystem, package in LOCKS:
            root = _tree(self, lock_name)
            for path in ("/" + lock_name, "//" + lock_name, "file:///" + lock_name,
                         "/tmp/elsewhere/" + lock_name):
                with self.subTest(path=path):
                    findings = _ingest(root, "osv-scanner.json", _osv(package, ecosystem, path))
                    self.assert_advisor_path(findings)
                    self.assertEqual(_main_location(path), findings[0]["location"]["file"])
            for path in ("/src/" + lock_name, lock_name):
                with self.subTest(inside=path):
                    self.assert_first_party(
                        _ingest(root, "osv-scanner.json", _osv(package, ecosystem, path)))

    def test_an_osv_record_at_the_bare_root_has_no_source_path(self):
        root = _tree(self, "Cargo.lock")
        for path in ("/", "file:///", "///", "//"):
            with self.subTest(path=path):
                findings = _ingest(root, "osv-scanner.json", _osv(CARGO, "crates.io", path))
                self.assertEqual("manifest (crates.io)", findings[0]["location"]["file"])
                self.assert_advisor_path(findings)

    def test_a_high_finding_outside_the_mount_is_kept_and_can_still_gate(self):
        # The other direction: the finding is not dropped. On the base it was confirmed
        # with no advisor (FAIL, certified); now it waits for one, and gates once
        # confirmed -- or passes once rejected. Its location is main's.
        root = _tree(self, "Cargo.lock")
        for document in (
                _trivy(CARGO, "/Cargo.lock", tags=("vulnerability", "security", "HIGH"),
                       severity="8.1"),
                _trivy(CARGO, "Cargo.lock", tags=("vulnerability", "security", "HIGH"),
                       severity="8.1", base_id="ROOTPATH",
                       bases={"ROOTPATH": {"uri": "file:///etc/"}})):
            findings = _ingest(root, "trivy.sarif", document)
            self.assertEqual(1, len(findings))
            self.assertEqual("HIGH", findings[0]["severity"])
            self.assertEqual("Cargo.lock", findings[0]["location"]["file"])
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
                           # Seat item 2: the tag is exact, and tags is a list.
                           ((" vulnerability",), None), (("vulnerability ",), None),
                           (("x vulnerability",), None), (("vulnerability security",), None),
                           (("x", "vulnerabilit", "y"), None),
                           ({"vulnerability": True}, None), ("vulnerability", None),
                           ("vulnerability security", None), (("vulnerability", 7, None),
                                                              "vulnerability"),
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
                         ("security", "LOW"), (), None, ("Vulnerability",),
                         (" vulnerability",), ("vulnerability ",), ("x vulnerability",),
                         {"vulnerability": True}, "vulnerability"):
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
