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


class TestAPathOutsideTheScanMount(_Case):
    """Fault 2. `/src/` is the mount; anything else absolute is not the review root."""

    def test_norm_uri_keeps_an_outside_path_outside(self):
        norm = sarif_utils.norm_uri
        for uri, expected in (
                ("/src/Cargo.lock", "Cargo.lock"), ("file:///src/Cargo.lock", "Cargo.lock"),
                ("/src/a/b.py", "a/b.py"), ("Cargo.lock", "Cargo.lock"), ("a/b.py", "a/b.py"),
                ("src/Cargo.lock", "src/Cargo.lock"), ("", ""),
                # Outside the mount: still absolute, with one leading slash.
                ("/Cargo.lock", "/Cargo.lock"), ("//Cargo.lock", "//Cargo.lock"),
                ("///Cargo.lock", "/Cargo.lock"), ("file:///Cargo.lock", "/Cargo.lock"),
                ("file:////Cargo.lock", "file:////Cargo.lock"), ("/etc/passwd", "/etc/passwd"),
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

    def test_a_relative_uri_is_resolved_against_its_base(self):
        # Seat review at da20a72b, item 1: real Trivy writes a RELATIVE uri with
        # `uriBaseId: ROOTPATH` and the base in the run's `originalUriBaseIds`. A base
        # that is not the scan mount puts the file outside, as an absolute path is.
        for lock_name, _ecosystem, package in LOCKS:
            root = _tree(self, lock_name)
            for base in ("file:///", "file:///etc/", "file:///srcx/", "file:///src",
                         "/", "/etc/", "https://example.invalid/", "file://host/src/",
                         "relative/", "src/", "", 7, None, ["file:///src/"],
                         # Seat r2 item 1: a scheme and no slash is not a place either.
                         "C:\\repo\\", "urn:outside", "x:", "file:", "mailto:a@b",
                         # Seat r2 item 2: two leading slashes are an authority.
                         "//src/", "file:////src/",
                         "src/a:b/", "./:/"):
                with self.subTest(lock=lock_name, base=base):
                    findings = _ingest(root, "trivy.sarif", _trivy(
                        package, lock_name, base_id="ROOTPATH",
                        bases={"ROOTPATH": {"uri": base}}))
                    self.assert_advisor_path(findings)
                    self.assertNotEqual(lock_name, findings[0]["location"]["file"])
            for label, bases in (("a table that is a list", ["file:///src/"]),
                                 ("an entry that is a string", {"ROOTPATH": "file:///src/"}),
                                 ("an entry with no uri", {"ROOTPATH": {}}),
                                 ("a chained base", {"ROOTPATH": {"uri": "src/", "uriBaseId": "TOP"},
                                                     "TOP": {"uri": "file:///"}}),
                                 # A base that names another base is not followed, even
                                 # when its own uri is the mount.
                                 ("a chained mount", {"ROOTPATH": {"uri": "file:///src/",
                                                                   "uriBaseId": "TOP"},
                                                      "TOP": {"uri": "file:///"}})):
                with self.subTest(lock=lock_name, unresolved=label):
                    findings = _ingest(root, "trivy.sarif", _trivy(
                        package, lock_name, base_id="ROOTPATH", bases=bases))
                    self.assert_advisor_path(findings)
                    self.assertNotEqual(lock_name, findings[0]["location"]["file"])
            for base in ("file:///src/", "/src/"):
                with self.subTest(lock=lock_name, inside=base):
                    findings = _ingest(root, "trivy.sarif", _trivy(
                        package, lock_name, base_id="ROOTPATH",
                        bases={"ROOTPATH": {"uri": base}}))
                    self.assert_first_party(findings)
                    self.assertEqual(lock_name, findings[0]["location"]["file"])
            # A base the run never defines is a bare symbol (semgrep and CodeQL write
            # `%SRCROOT%` with no table): the run says nothing about where it is, so
            # the uri reads as it does with no base at all.
            for label, bases in (("no table", _NO_BASES), ("an empty table", {}),
                                 ("another id", {"SRCROOT": {"uri": "file:///etc/"}})):
                with self.subTest(lock=lock_name, undefined=label):
                    findings = _ingest(root, "trivy.sarif", _trivy(
                        package, lock_name, base_id="ROOTPATH", bases=bases))
                    self.assert_first_party(findings)
                    self.assertEqual(lock_name, findings[0]["location"]["file"])

    def test_two_leading_slashes_are_an_authority_and_stay_whole(self):
        # Seat r2 item 2: `//src/x` is authority `src`, as `file://src/x` is. It is not
        # the mount, whatever follows.
        norm = sarif_utils.norm_uri
        for uri in ("//src/Cargo.lock", "file:////src/Cargo.lock", "//Cargo.lock",
                    "file:////Cargo.lock", "//src/x", "//", "file:////", "file://src/x"):
            with self.subTest(uri=uri):
                self.assertEqual(uri, sarif_utils.repo_path(uri))
                self.assertEqual(norm(uri), norm(norm(uri)))
                self.assertNotEqual("Cargo.lock", norm(uri))
        # One slash, or three and more, is a plain absolute path.
        for uri, expected in (("/src//Cargo.lock", "Cargo.lock"), ("/src/Cargo.lock", "Cargo.lock"),
                              ("///src/Cargo.lock", "Cargo.lock"), ("///Cargo.lock", "/Cargo.lock"),
                              ("file://///src/Cargo.lock", "Cargo.lock")):
            with self.subTest(uri=uri):
                self.assertEqual(expected, norm(uri))
        for lock_name, _ecosystem, package in LOCKS:
            root = _tree(self, lock_name)
            for uri in ("//src/" + lock_name, "file:////src/" + lock_name, "//" + lock_name):
                with self.subTest(lock=lock_name, uri=uri):
                    findings = _ingest(root, "trivy.sarif", _trivy(package, uri))
                    self.assert_advisor_path(findings)
                    self.assertEqual(uri, findings[0]["location"]["file"])

    def test_an_empty_id_the_run_defines_still_decides(self):
        # Seat r2 survivor: a falsy id is an id. Defined as outside, it is outside.
        root = _tree(self, "Cargo.lock")
        for base, inside in (("file:///etc/", False), ("file:///src/", True)):
            with self.subTest(base=base):
                findings = _ingest(root, "trivy.sarif", _trivy(
                    CARGO, "Cargo.lock", base_id="", bases={"": {"uri": base}}))
                (self.assert_first_party if inside else self.assert_advisor_path)(findings)
        self.assertEqual("/unresolved-uri-base./a.py", sarif_utils.artifact_uri(
            {"uri": "a.py", "uriBaseId": ""}, {"originalUriBaseIds": {"": {"uri": "file:///etc/"}}}))

    def test_the_legacy_located_paths_resolve_the_base_too(self):
        import scripts.tools.legacy_sarif as legacy_sarif
        document = _trivy(CARGO, "Cargo.lock", base_id="ROOTPATH",
                          bases={"ROOTPATH": {"uri": "file:///etc/"}})
        self.assertEqual({"/unresolved-uri-base.ROOTPATH/Cargo.lock"},
                         legacy_sarif._result_paths(document))
        document = _trivy(CARGO, "a/b.py", base_id="ROOTPATH",
                          bases={"ROOTPATH": {"uri": "file:///src/"}})
        self.assertEqual({"a/b.py"}, legacy_sarif._result_paths(document))

    def test_a_base_does_not_move_an_absolute_uri(self):
        # SARIF applies uriBaseId to a relative uri only. semgrep writes an absolute
        # `/src/...` uri with `uriBaseId: %SRCROOT%` and no table: that stays inside.
        root = _tree(self, "Cargo.lock")
        for uri, base_id, bases, inside in (
                ("/src/Cargo.lock", "%SRCROOT%", _NO_BASES, True),
                ("file:///src/Cargo.lock", "ROOTPATH", {"ROOTPATH": {"uri": "file:///"}}, True),
                ("/Cargo.lock", "ROOTPATH", {"ROOTPATH": {"uri": "file:///src/"}}, False),
                ("file:///Cargo.lock", "ROOTPATH", {"ROOTPATH": {"uri": "file:///src/"}},
                 False)):
            with self.subTest(uri=uri):
                findings = _ingest(root, "trivy.sarif", _trivy(
                    CARGO, uri, base_id=base_id, bases=bases))
                (self.assert_first_party if inside else self.assert_advisor_path)(findings)

    def test_artifact_uri(self):
        # Gate ruling at 59891979: nothing is resolved. A relative uri under the scan
        # mount itself is returned as it is; under any other defined base it is outside.
        resolve = sarif_utils.artifact_uri
        table = {"ROOTPATH": {"uri": "file:///src/"}, "ELSEWHERE": {"uri": "file:///etc/"},
                 "NOSLASH": {"uri": "file:///src"}, "": {"uri": "file:///etc/"},
                 "7": {"uri": "file:///src/"}}
        run = {"originalUriBaseIds": table}
        for artifact, expected in (
                ({"uri": "a/b.py"}, "a/b.py"),
                ({"uri": "a/b.py", "uriBaseId": "ROOTPATH"}, "a/b.py"),
                ({"uri": "a/b.py", "uriBaseId": "ELSEWHERE"},
                 "/unresolved-uri-base.ELSEWHERE/a/b.py"),
                ({"uri": "a/b.py", "uriBaseId": "NOSLASH"}, "/unresolved-uri-base.NOSLASH/a/b.py"),
                ({"uri": "a.py", "uriBaseId": ""}, "/unresolved-uri-base./a.py"),
                # A numeric id is not the key "7".
                ({"uri": "a.py", "uriBaseId": 7}, "/unresolved-uri-base.7/a.py"),
                ({"uri": "/src/a.py", "uriBaseId": "%SRCROOT%"}, "/src/a.py"),
                ({"uri": "/src/a.py", "uriBaseId": "ELSEWHERE"}, "/src/a.py"),
                ({"uri": "file:///src/a.py", "uriBaseId": "ELSEWHERE"}, "file:///src/a.py"),
                ({"uri": "a.py", "uriBaseId": None}, "a.py"),
                ({"uri": "a.py", "uriBaseId": "MISSING"}, "a.py"),
                ({}, None), ({"uri": 7}, 7), ({"uri": None, "uriBaseId": "ROOTPATH"}, None),
                ("a.py", None), (["a.py"], None), (None, None), (7, None)):
            with self.subTest(artifact=artifact):
                self.assertEqual(expected, resolve(artifact, run))
        # No table, or a null one, defines nothing: the uri is read as it is.
        for undefined in ({}, {"originalUriBaseIds": None}, {"originalUriBaseIds": {}}, None):
            with self.subTest(undefined=undefined):
                self.assertEqual("a.py", resolve({"uri": "a.py", "uriBaseId": "X"}, undefined))
        # A table that is there but is not an object defines every id, unreadably.
        for bad in ([], "", False, 0, ["X"], "X", 7):
            with self.subTest(table=bad):
                self.assertEqual("/unresolved-uri-base.X/a.py", resolve(
                    {"uri": "a.py", "uriBaseId": "X"}, {"originalUriBaseIds": bad}))

    def test_a_base_id_cannot_spell_a_directory_a_suppression_knows(self):
        # Seat r3 item 1: the id is the scanner's text. Written as its own path
        # segments, `tests/fixtures` or `vendor` made the outside path a fixture or a
        # vendored one, and a HIGH was suppressed: PASS, certified, no finding.
        root = _tree(self, "Cargo.lock")
        ids = ("tests/fixtures", "x/testdata/y", "node_modules/a", "vendor/x", "__pycache__/x",
               "vendor", "node_modules", "testdata", "tests", "fixtures", "__pycache__", "..",
               "", ".", "a/../b", "/vendor/", "vendor/", "/", "a b", "a\nb", "ROOTPATH",
               "%SRCROOT%", "tests\\fixtures", "caf" + chr(0xe9), 7)
        for base_id in ids:
            with self.subTest(id=base_id):
                document = _trivy(CARGO, "Cargo.lock", base_id=base_id, severity="8.1",
                                  tags=("vulnerability", "security", "HIGH"),
                                  bases={str(base_id) if base_id == 7 else base_id:
                                         {"uri": "file:///etc/"}} if base_id != 7 else [])
                findings = _ingest(root, "trivy.sarif", document)
                self.assertEqual(1, len(findings))
                self.assert_advisor_path(findings)
                self.assertEqual(("INCONCLUSIVE", ["tool_reported"]), _verdict(findings))
                path = findings[0]["location"]["file"]
                parts = path.split("/")
                # One fixed-prefix segment holds the id; the uri follows, and nothing else.
                self.assertEqual(["", parts[1], "Cargo.lock"], parts)
                self.assertTrue(parts[1].startswith("unresolved-uri-base."))
                self.assertRegex(parts[1], r"\Aunresolved-uri-base\.[A-Za-z0-9._-]*\Z")
                self.assertEqual(path, sarif_utils.norm_uri(path))
        # Distinct ids stay distinct where their characters allow.
        resolve = sarif_utils.artifact_uri
        table = {"A": {"uri": "file:///etc/"}, "B": {"uri": "file:///etc/"}}
        self.assertEqual("/unresolved-uri-base.A/x", resolve(
            {"uri": "x", "uriBaseId": "A"}, {"originalUriBaseIds": table}))
        self.assertEqual("/unresolved-uri-base.B/x", resolve(
            {"uri": "x", "uriBaseId": "B"}, {"originalUriBaseIds": table}))
        self.assertEqual("/unresolved-uri-base.tests_fixtures/x", resolve(
            {"uri": "x", "uriBaseId": "tests/fixtures"},
            {"originalUriBaseIds": {"tests/fixtures": {"uri": "file:///etc/"}}}))

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
        # One column: inside or outside. Every row goes through ingest; "outside" means
        # the advisor still has the finding, "inside" that it is first-party. Each
        # directory the head could wrongly have read is really there, with a lock and a
        # manifest that would prove the package.
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = os.path.realpath(d.name)
        _write_lock(root)
        _write_manifest(root)
        nested = ("sub", "?other", "#shadow", "file:", "urn:outside", "C:", "%2e%2e",
                  "a\\x0a", "a#b", "a?b", "a%20b", "x:y", "a\\b", "a\\x1b[31m", "etc",
                  "xU+D800", "xU+DCE9",
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
            # The earlier rounds' spellings.
            ("/Cargo.lock", _NO_BASES, False), ("//Cargo.lock", _NO_BASES, False),
            ("file:///Cargo.lock", _NO_BASES, False), ("//src/Cargo.lock", _NO_BASES, False),
            ("file:////src/Cargo.lock", _NO_BASES, False), ("file://Cargo.lock", _NO_BASES, False),
            ("/etc/Cargo.lock", _NO_BASES, False),
        )
        for uri, bases, inside in rows:
            with self.subTest(uri=uri, bases=bases):
                findings = _ingest(root, "trivy.sarif", _trivy(
                    CARGO, uri, base_id=None if bases is _NO_BASES else "ROOTPATH", bases=bases))
                (self.assert_first_party if inside else self.assert_advisor_path)(findings)

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
                 "a.b", "~a", "a=b&c", "[a]")
        refused = ("xU+D800", "U+DCE9", "aU+DFFFb",
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

    def test_a_result_with_no_file_is_not_a_located_path(self):
        # Gate item 6: only a string is a path.
        import scripts.tools.legacy_sarif as legacy_sarif
        for artifact in ({}, {"uri": 7}, {"uri": None}, {"uri": ["a.py"]}, "a.py", None, 7,
                         {"uriBaseId": "ROOTPATH"}):
            with self.subTest(artifact=artifact):
                document = _trivy(CARGO, "x")
                document["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                    "artifactLocation"] = artifact
                self.assertEqual(set(), legacy_sarif._result_paths(document))
        self.assertEqual({"a.py"}, legacy_sarif._result_paths(_trivy(CARGO, "a.py")))
        # Seat r3 item 3: nor is an empty path, however it is spelled.
        for uri in ("", "/", "file:///", "/src/", "file:///src/", "///"):
            with self.subTest(empty=uri):
                self.assertEqual(set(), legacy_sarif._result_paths(_trivy(CARGO, uri)))

    def test_repo_path_passes_a_non_string_through(self):
        for value in (None, 7, ["a"], {"a": 1}, b"/src/a"):
            with self.subTest(value=value):
                self.assertIs(value, sarif_utils.repo_path(value))
                self.assertIs(value, sarif_utils.norm_uri(value))

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

    def test_one_spelling_everywhere_and_it_is_idempotent(self):
        # Seat item 3.
        norm = sarif_utils.norm_uri
        for uri in ("/", "file:///", "///", ""):
            with self.subTest(empty=uri):
                self.assertEqual("", norm(uri))
        for uri, expected in (("/src//x", "x"), ("///src///x", "x"),
                              ("/src/", ""), ("/src", "/src")):
            with self.subTest(uri=uri):
                self.assertEqual(expected, norm(uri))
        for uri in ("/Cargo.lock", "//Cargo.lock", "file:///Cargo.lock", "//src/x", "/src//x",
                    "/src/x", "x", "a/b", "file://host/x", "file://Cargo.lock", "/", "",
                    "/src", "/srcx/y", "file:///etc/passwd", "src/x"):
            with self.subTest(idempotent=uri):
                once = norm(uri)
                self.assertEqual(once, norm(once))
        # The coverage ledger and the legacy SARIF reader spell a path as findings do.
        import scripts.tools.legacy_sarif as legacy_sarif
        for uri in ("/Cargo.lock", "//Cargo.lock", "file:///Cargo.lock", "/src/a/b.py",
                    "file:///src/a.py", "a.py", "//src/x", "file://host/x"):
            with self.subTest(spelled=uri):
                coverage = sarif_utils.CaptureCoverage()
                self.assertEqual(sarif_utils.repo_path(uri), coverage.seen(uri))
                self.assertEqual(sarif_utils.repo_path(uri), legacy_sarif._sarif_path(uri))
                self.assertEqual(norm(uri), sarif_utils.repo_path(uri))
        coverage = sarif_utils.CaptureCoverage()
        for empty in ("/", "file:///", "", None, 7):
            self.assertIsNone(coverage.seen(empty))
        self.assertEqual(set(), coverage.paths)

    def test_an_osv_record_at_the_bare_root_has_no_source_path(self):
        root = _tree(self, "Cargo.lock")
        for path in ("/", "file:///", "///"):
            with self.subTest(path=path):
                findings = _ingest(root, "osv-scanner.json", _osv(CARGO, "crates.io", path))
                self.assertEqual("manifest (crates.io)", findings[0]["location"]["file"])
                self.assert_advisor_path(findings)

    def test_an_outside_path_is_rendered_inertly(self):
        # Seat item 2: the outside branch goes through the same neutraliser.
        from scripts.tools.base import inert_text
        for uri in ("/a\x1b[31mb/Cargo.lock", "file:///a\x00b/Cargo.lock", "/a\nb", "/a\u202eb",
                    "file://ho\x1bst/x"):
            with self.subTest(uri=uri):
                out = sarif_utils.norm_uri(uri)
                self.assertEqual(inert_text(out, mode="path"), out)
                for raw in ("\x1b", "\x00", "\n", "\u202e"):
                    self.assertNotIn(raw, out)

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
