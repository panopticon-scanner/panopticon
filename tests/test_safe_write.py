"""`scripts.safe_write`: the ONE no-follow `.panopticon` artifact open (#1735).

The primitive lived in `phases/runio`, which `run_manifest` may not import --
`phases/*` imports `run_manifest`, so the arrow only goes one way (layout rule
3) -- and neither may `synth/*`. Depending only on stdlib and the stdlib-only
`claim_scope` makes the guard reachable from all three, so every
`.panopticon`-resident writer can use the same guard.

runio keeps its private spellings as aliases of these functions: ~15 call
sites and the suite's one `mock.patch` target say `runio._open_w_nofollow`,
and a SECOND implementation behind that name is exactly the drift layout rule
4 exists to prevent -- so the identity is pinned here.
"""
import errno
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import pytest

import scripts.discovery as discovery
import scripts.run_manifest as run_manifest
import scripts.safe_write as safe_write
import scripts.setup_flow as setup_flow
import scripts.strain_report as strain_report
import scripts.tool_capture as tool_capture
from scripts.phases import runio
from scripts.phases import setup as setup_phase
from scripts.phases import validate as validate_phase


class TestBoundedRegularRead(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.root = self._d.name
        self.addCleanup(self._d.cleanup)

    def test_exact_limit_is_inclusive_and_overflow_has_a_typed_outcome(self):
        path = os.path.join(self.root, "artifact.json")
        with open(path, "wb") as stream:
            stream.write(b"1234")
        self.assertEqual(safe_write.read_regular_bytes(path, 4), b"1234")
        with self.assertRaises(safe_write.ReadLimitExceeded):
            safe_write.read_regular_bytes(path, 3)

    def test_nonregular_leaf_has_an_errno_bearing_typed_outcome(self):
        for kind in ("directory", "fifo"):
            path = os.path.join(self.root, kind)
            if kind == "directory":
                os.mkdir(path)
            else:
                os.mkfifo(path)
            with self.subTest(kind=kind), \
                    self.assertRaises(safe_write.NonRegularFileError) as raised:
                safe_write.read_regular_bytes(path, 4)
            self.assertEqual(raised.exception.errno, errno.EINVAL)

    def test_io_errors_keep_their_native_type(self):
        denied = PermissionError(13, "denied")
        with mock.patch.object(safe_write.os, "open", side_effect=denied), \
                self.assertRaises(PermissionError) as raised:
            safe_write.read_regular_bytes(os.path.join(self.root, "input"), 4)
        self.assertIs(raised.exception, denied)


class TestHardLinkedArtifacts(unittest.TestCase):
    """#3235: a second name for an artifact's bytes is refused before anything is truncated or
    appended, so a link to a file outside the tree is never written through."""

    def _linked(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, d, True)
        outside = os.path.join(d, "outside.txt")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("keep me\n")
        pano = os.path.join(d, "repo", ".panopticon")
        os.makedirs(pano)
        artifact = os.path.join(pano, "report.json")
        os.link(outside, artifact)
        return outside, artifact

    def test_the_truncating_writer_refuses_and_leaves_the_other_name_whole(self):
        outside, artifact = self._linked()
        with self.assertRaisesRegex(OSError, "hard links"):
            safe_write.open_w_nofollow(artifact)
        with open(outside, encoding="utf-8") as fh:
            self.assertEqual("keep me\n", fh.read())

    def test_the_appending_writer_refuses_too(self):
        outside, artifact = self._linked()
        with self.assertRaisesRegex(OSError, "hard links"):
            safe_write.open_a_nofollow(artifact)
        with open(outside, encoding="utf-8") as fh:
            self.assertEqual("keep me\n", fh.read())

    def test_a_sole_existing_file_is_still_truncated_and_rewritten(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, d, True)
        path = os.path.join(d, ".panopticon", "a.json")
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("a much longer previous body\n")
        with safe_write.open_w_nofollow(path) as fh:
            fh.write("new\n")
        with open(path, encoding="utf-8") as fh:
            self.assertEqual("new\n", fh.read())


class TestAtomicWrite(unittest.TestCase):
    """#3535: one atomic text/bytes writer owns staging and confinement."""

    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.root = self._d.name
        self.addCleanup(self._d.cleanup)
        self.pano = os.path.join(self.root, ".panopticon")
        os.makedirs(self.pano)
        self.path = os.path.join(self.pano, "runs", "tag", "artifact.json")

    def test_final_name_is_confined_before_parent_creation(self):
        events = []
        real_confine = safe_write.confine_artifact_path
        real_makedirs = os.makedirs

        def confine(path):
            events.append(("confine", os.fspath(path)))
            return real_confine(path)

        def makedirs(path, *args, **kwargs):
            events.append(("makedirs", os.fspath(path)))
            return real_makedirs(path, *args, **kwargs)

        with mock.patch.object(safe_write, "confine_artifact_path",
                               side_effect=confine), \
                mock.patch.object(safe_write.os, "makedirs",
                                  side_effect=makedirs):
            safe_write.atomic_write(self.path, "text")

        self.assertEqual(events[0], ("confine", self.path))
        mkdir_indexes = [i for i, event in enumerate(events)
                         if event[0] == "makedirs"]
        self.assertTrue(mkdir_indexes)
        self.assertGreater(events.index(("confine", self.path + ".tmp")),
                           max(mkdir_indexes))

    def test_text_and_bytes_replace_prior_files_without_staging_litter(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w", encoding="utf-8") as stream:
            stream.write("old and longer")
        safe_write.atomic_write(self.path, "new\n")
        with open(self.path, encoding="utf-8") as stream:
            self.assertEqual(stream.read(), "new\n")
        safe_write.atomic_write(self.path, b"\x00binary\xff")
        with open(self.path, "rb") as stream:
            self.assertEqual(stream.read(), b"\x00binary\xff")
        self.assertFalse(os.path.lexists(self.path + ".tmp"))

    def test_final_symlink_and_staging_plants_are_never_written_through(self):
        victim = os.path.join(self.root, "victim")
        with open(victim, "w", encoding="utf-8") as stream:
            stream.write("PRECIOUS")
        os.makedirs(os.path.dirname(self.path))
        os.symlink(victim, self.path)
        with self.assertRaises(ValueError):
            safe_write.atomic_write(self.path, "new")
        self.assertTrue(os.path.islink(self.path))
        os.unlink(self.path)

        os.symlink(victim, self.path + ".tmp")
        with self.assertRaises(ValueError):
            safe_write.atomic_write(self.path, "new")
        with open(victim, encoding="utf-8") as stream:
            self.assertEqual(stream.read(), "PRECIOUS")
        self.assertFalse(os.path.lexists(self.path + ".tmp"))

    def test_hard_link_and_fifo_at_staging_name_are_refused_untouched(self):
        os.makedirs(os.path.dirname(self.path))
        victim = os.path.join(self.root, "victim")
        with open(victim, "w", encoding="utf-8") as stream:
            stream.write("PRECIOUS")
        os.link(victim, self.path + ".tmp")
        with self.assertRaises(safe_write.UnsafeStagingPathError):
            safe_write.atomic_write(self.path, "new")
        with open(victim, encoding="utf-8") as stream:
            self.assertEqual(stream.read(), "PRECIOUS")
        self.assertTrue(os.path.samefile(victim, self.path + ".tmp"))
        os.unlink(self.path + ".tmp")

        if hasattr(os, "mkfifo"):
            os.mkfifo(self.path + ".tmp")
            with self.assertRaises(safe_write.UnsafeStagingPathError):
                safe_write.atomic_write(self.path, "new")
            self.assertTrue(stat.S_ISFIFO(os.lstat(self.path + ".tmp").st_mode))

    def test_replace_failure_preserves_prior_file_and_cleans_stage(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w", encoding="utf-8") as stream:
            stream.write("old")
        with mock.patch.object(safe_write.os, "replace",
                               side_effect=OSError("rename failed")), \
                self.assertRaisesRegex(OSError, "rename failed"):
            safe_write.atomic_write(self.path, "new")
        with open(self.path, encoding="utf-8") as stream:
            self.assertEqual(stream.read(), "old")
        self.assertFalse(os.path.lexists(self.path + ".tmp"))

    def test_fsync_is_opt_in_for_text_and_bytes(self):
        with mock.patch.object(safe_write.os, "fsync") as fsync:
            safe_write.atomic_write(self.path, "text")
            fsync.assert_not_called()
            safe_write.atomic_write(self.path, b"bytes", fsync=True)
            fsync.assert_called_once()
        with open(self.path, "rb") as stream:
            self.assertEqual(stream.read(), b"bytes")

    def test_tool_capture_preserves_its_private_file_mode(self):
        tool_capture._atomic_write(self.path, b"capture")
        self.assertEqual(0o600, stat.S_IMODE(os.stat(self.path).st_mode))


def _validate_atomic_writer(root, out):
    validate_phase._write_baseline(out, lambda stream: stream.write("baseline"))
    return out


def _setup_flow_atomic_writer(_root, out):
    setup_flow._replace(out, "setup report\n")
    return out


def _setup_manifest_atomic_writer(root, _out):
    setup_phase._rewrite_setup_manifest(root, {"z": 1})
    return run_manifest.manifest_path(root, "setup")


def _strain_atomic_writer(_root, out):
    return strain_report.write_report({"z": 1}, out)


def _diff_hunks_atomic_writer(root, out):
    discovery.write_diff_hunks(root, None, "none", out, 0, False)
    return out


def _discovery_result_atomic_writer(_root, out):
    discovery._write_result({"groups": {}}, SimpleNamespace(out=out))
    return out


def _tool_capture_atomic_writer(_root, out):
    return tool_capture._atomic_write(out, b"capture")


def _run_manifest_atomic_writer(root, _out):
    run_manifest._rewrite(root, {"z": 1})
    return run_manifest.manifest_path(root)


_ATOMIC_WRITERS = (
    ("validate", _validate_atomic_writer, False, str, 0o644),
    ("setup-flow", _setup_flow_atomic_writer, False, str, 0o644),
    ("setup-manifest", _setup_manifest_atomic_writer, False, str, 0o644),
    ("strain", _strain_atomic_writer, False, str, 0o644),
    ("diff-hunks", _diff_hunks_atomic_writer, False, str, 0o644),
    ("discovery-result", _discovery_result_atomic_writer, False, str, 0o644),
    ("tool-capture", _tool_capture_atomic_writer, True, bytes, 0o600),
    ("run-manifest", _run_manifest_atomic_writer, False, str, 0o644),
)


@pytest.mark.parametrize("_name,invoke,expected_fsync,body_type,expected_mode",
                         _ATOMIC_WRITERS,
                         ids=[case[0] for case in _ATOMIC_WRITERS])
def test_every_atomic_writer_routes_once_through_the_shared_helper(
        tmp_path, _name, invoke, expected_fsync, body_type, expected_mode):
    root = str(tmp_path)
    (tmp_path / ".panopticon").mkdir()
    out = str(tmp_path / ".panopticon" / "runs" / "tag" / "output.json")
    calls = []

    def record(path, data, fsync=False, mode=0o644):
        calls.append((os.fspath(path), data, fsync, mode))
        return os.fspath(path)

    with mock.patch.object(safe_write, "atomic_write", side_effect=record):
        expected_path = invoke(root, out)

    assert len(calls) == 1
    path, body, used_fsync, used_mode = calls[0]
    assert path == expected_path
    assert isinstance(body, body_type)
    assert used_fsync is expected_fsync
    assert used_mode == expected_mode
    if body_type is str and body.lstrip().startswith("{"):
        json.loads(body)


_CONFINED_ATOMIC_WRITERS = tuple(
    case for case in _ATOMIC_WRITERS if case[0] != "strain")


@pytest.mark.parametrize("_name,invoke,_expected_fsync,_body_type,_expected_mode",
                         _CONFINED_ATOMIC_WRITERS,
                         ids=[case[0] for case in _CONFINED_ATOMIC_WRITERS])
def test_each_atomic_writer_refuses_its_inferred_panopticon_escape_before_mkdir(
        tmp_path, _name, invoke, _expected_fsync, _body_type, _expected_mode):
    pano = tmp_path / ".panopticon"
    outside = tmp_path / "outside"
    pano.mkdir()
    outside.mkdir()
    (pano / "escape").symlink_to(outside, target_is_directory=True)
    nested_root = pano / "escape" / "review"
    out = nested_root / "output.json"

    with pytest.raises(ValueError, match="escapes .panopticon"):
        invoke(str(nested_root), str(out))

    assert list(outside.iterdir()) == []


def test_strain_operator_output_outside_panopticon_remains_writable(tmp_path):
    path = strain_report.write_report({"z": 1}, str(tmp_path / "report.json"))
    with open(path, encoding="utf-8") as stream:
        assert json.load(stream) == {"z": 1}


@pytest.mark.parametrize("invoke", (_diff_hunks_atomic_writer,
                                    _discovery_result_atomic_writer),
                         ids=("diff-hunks", "discovery-result"))
def test_discovery_operator_outputs_outside_panopticon_remain_writable(tmp_path,
                                                                       invoke):
    out = str(tmp_path / "operator.json")
    invoke(str(tmp_path), out)
    with open(out, encoding="utf-8") as stream:
        assert json.load(stream)["schema_version"] == 1


class TestOneImplementation(unittest.TestCase):
    """runio's names ARE these functions -- not copies of them."""

    def test_runio_aliases_are_this_modules_functions(self):
        self.assertIs(runio._open_w_nofollow, safe_write.open_w_nofollow)
        self.assertIs(runio._open_staging_nofollow,
                      safe_write.open_staging_nofollow)
        self.assertIs(runio._open_a_nofollow, safe_write.open_a_nofollow)
        self.assertIs(runio._confine_artifact_path,
                      safe_write.confine_artifact_path)

    def test_consumers_can_import_the_guard_without_the_phases_package(self):
        skill = os.path.dirname(os.path.dirname(os.path.abspath(safe_write.__file__)))
        probe = ("import sys; sys.path.insert(0, sys.argv[1]); "
                 "import scripts.safe_write as safe_write; "
                 "safe_write.confine_artifact_path('/repo/.panopticon/report.json'); "
                 "assert not any(m.startswith('scripts.phases') for m in sys.modules)")
        with tempfile.TemporaryDirectory() as root:
            subprocess.run([sys.executable, "-I", "-c", probe, skill], cwd=root,
                           check=True, capture_output=True, timeout=30)


class TestNoFollowOpen(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.root = self._d.name
        self.addCleanup(self._d.cleanup)
        self.pano = os.path.join(self.root, ".panopticon")
        os.makedirs(self.pano)

    def _victim(self):
        victim = os.path.join(self.root, "victim.txt")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("PRECIOUS")
        return victim

    def _internal_link(self, name):
        referent = os.path.join(self.pano, "referent-%s" % name)
        with open(referent, "w", encoding="utf-8") as fh:
            fh.write("PRECIOUS")
        artifact = os.path.join(self.pano, name)
        os.symlink(os.path.basename(referent), artifact)
        return artifact, referent

    def test_a_planted_symlink_out_of_the_tree_is_refused(self):
        # The plantable attack: the link points at a file the invoking user can
        # write. The whole-path confinement answers it FIRST -- loudly, and
        # before any byte moves -- so the O_NOFOLLOW fallback below is only ever
        # reached by a link that stays inside `.panopticon`.
        victim = self._victim()
        artifact = os.path.join(self.pano, "artifact.json")
        os.symlink(victim, artifact)
        with self.assertRaises(ValueError):
            safe_write.open_w_nofollow(artifact)
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")

    def test_write_text_wraps_an_external_artifact_link_path_refusal(self):
        victim = self._victim()
        artifact = os.path.join(self.pano, "artifact.txt")
        os.symlink(victim, artifact)

        with self.assertRaises(safe_write.ArtifactPathError) as raised:
            safe_write.write_text(artifact, "NEW")

        self.assertIs(type(raised.exception.cause), ValueError)
        self.assertIn("escapes .panopticon", str(raised.exception.cause))
        self.assertTrue(os.path.islink(artifact))
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")

    def test_write_text_does_not_relabel_an_encoding_error_as_a_path_refusal(self):
        artifact = os.path.join(self.pano, "artifact.txt")
        with self.assertRaises(UnicodeEncodeError) as raised:
            safe_write.write_text(artifact, "\ud800")
        self.assertIs(type(raised.exception), UnicodeEncodeError)

    def test_a_planted_symlink_is_replaced_not_written_through(self):
        victim = self._victim()
        artifact = os.path.join(self.root, "artifact.json")   # no .panopticon segment
        os.symlink(victim, artifact)
        with safe_write.open_w_nofollow(artifact) as fh:
            fh.write("{}")
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")
        self.assertFalse(os.path.islink(artifact))
        self.assertTrue(os.path.isfile(artifact))

    def test_an_internal_artifact_symlink_is_refused_not_replaced(self):
        # #3269 G9: confinement admits this link because its referent stays
        # inside `.panopticon`. The final-leaf guard must still make one loud
        # refusal; unlink-and-retry silently destroys the planted evidence.
        artifact, referent = self._internal_link("artifact.json")
        with self.assertRaisesRegex(safe_write.ArtifactSymlinkError,
                                    "refusing.*artifact.*symlink"):
            safe_write.open_w_nofollow(artifact)
        self.assertTrue(os.path.islink(artifact))
        with open(referent, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_write_refuses_a_fifo_even_when_a_reader_allows_the_open(self):
        artifact = os.path.join(self.pano, "artifact.json")
        os.mkfifo(artifact)
        reader = os.open(artifact, os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, reader)

        with self.assertRaises(safe_write.NonRegularFileError) as raised:
            safe_write.open_w_nofollow(artifact)

        self.assertEqual(raised.exception.errno, errno.EINVAL)
        self.assertTrue(stat.S_ISFIFO(os.lstat(artifact).st_mode))

    def test_staging_open_has_the_exact_exclusive_bounded_flags(self):
        staging = os.path.join(self.pano, "artifact.json.tmp")
        seen = []
        real_open = os.open

        def recording(path, flags, mode):
            seen.append((flags, mode))
            return real_open(path, flags, mode)

        with mock.patch.object(safe_write.os, "open", side_effect=recording):
            with safe_write.open_staging_nofollow(staging) as stream:
                stream.write("{}")
        expected = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        self.assertEqual(seen, [(expected, 0o644)])

    def test_append_does_not_follow_a_planted_symlink(self):
        victim = self._victim()
        artifact = os.path.join(self.root, "ledger.jsonl")    # no .panopticon segment
        os.symlink(victim, artifact)
        with safe_write.open_a_nofollow(artifact) as fh:
            fh.write("line\n")
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")
        self.assertFalse(os.path.islink(artifact))

    def test_append_refuses_an_internal_artifact_symlink_without_deleting_it(self):
        artifact, referent = self._internal_link("ledger.jsonl")
        with self.assertRaisesRegex(safe_write.ArtifactSymlinkError,
                                    "refusing.*artifact.*symlink"):
            safe_write.open_a_nofollow(artifact)
        self.assertTrue(os.path.islink(artifact))
        with open(referent, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")

    def test_remove_artifact_unlinks_a_leaf_symlink_without_touching_its_target(self):
        victim = self._victim()
        artifact = os.path.join(self.pano, "stale-x0x.json")
        os.symlink(victim, artifact)

        safe_write.remove_artifact(artifact)
        safe_write.remove_artifact(artifact)  # an absent sibling is already removed

        self.assertFalse(os.path.lexists(artifact))
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")

    def test_remove_artifact_refuses_an_escaping_parent(self):
        outside = os.path.join(self.root, "outside")
        os.makedirs(outside)
        victim = os.path.join(outside, "report-x0x-failures.json")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("PRECIOUS")
        os.symlink(outside, os.path.join(self.pano, "runs"))

        with self.assertRaises(ValueError):
            safe_write.remove_artifact(
                os.path.join(self.pano, "runs", "report-x0x-failures.json"))

        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")

    def test_confine_rejects_a_symlinked_intermediate_component(self):
        outside = os.path.join(self.root, "outside")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(self.pano, "runs"))
        with self.assertRaises(ValueError):
            safe_write.confine_artifact_path(
                os.path.join(self.pano, "runs", "tag", "report.json"))
        # a path with no `.panopticon` segment is not an artifact path
        safe_write.confine_artifact_path(os.path.join(self.root, "elsewhere.json"))

    def test_internal_links_remain_valid_for_writes_but_not_for_relink_parents(self):
        run = os.path.join(self.pano, "runs", "tag")
        os.makedirs(run)
        os.symlink("tag", os.path.join(self.pano, "runs", "latest"))
        artifact = os.path.join(self.pano, "runs", "latest", "report.json")
        safe_write.confine_artifact_path(artifact)
        with self.assertRaises(runio.DriverError):
            runio._confine_link_parent(artifact)

    def test_an_ancestor_link_preserves_the_lexical_anchor_and_resolves_for_relink(self):
        alias = os.path.join(self.root, "alias")
        os.symlink(self.root, alias)
        artifact = os.path.join(alias, ".panopticon", "runs", "report.json")
        safe_write.confine_artifact_path(artifact)
        self.assertEqual(runio._confine_link_parent(artifact),
                         os.path.join(os.path.realpath(self.pano), "runs"))

    def test_a_nested_anchor_cannot_reanchor_an_escaping_intermediate_link(self):
        outside = os.path.join(self.root, "outside")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(self.pano, "escape"))
        artifact = os.path.join(self.pano, "escape", ".panopticon", "report.json")
        with self.assertRaises(ValueError):
            safe_write.confine_artifact_path(artifact)
        with self.assertRaises(runio.DriverError):
            runio._confine_link_parent(artifact)

    def test_publication_stages_every_file_before_publishing_the_main_last(self):
        targets = [(os.path.join(self.pano, name), os.path.join(self.pano, name + ".tmp"),
                    name) for name in ("main.json", "part.json", "discarded.json")]
        real_replace = os.replace
        published = []

        def replace(source, destination):
            for final, temp, text in targets:
                with open(final if final in published else temp, encoding="utf-8") as stream:
                    self.assertEqual(stream.read(), text)
            real_replace(source, destination)
            published.append(destination)

        with mock.patch.object(safe_write.os, "replace", side_effect=replace):
            paths = safe_write.publish_texts(iter(targets))
        self.assertEqual(paths, [target[0] for target in targets])
        self.assertEqual(published, list(reversed(paths)))
        self.assertEqual(sorted(os.listdir(self.pano)),
                         ["discarded.json", "main.json", "part.json"])

    def test_publication_refuses_an_escaping_parent_before_creation_or_cleanup(self):
        outside = os.path.join(self.root, "outside")
        os.makedirs(outside)
        victim = os.path.join(outside, "staging.tmp")
        with open(victim, "w", encoding="utf-8") as stream:
            stream.write("PRECIOUS")
        os.symlink(outside, os.path.join(self.pano, "runs"))
        for suffix in ("staging.tmp", "new/staging.tmp"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                safe_write.publish_texts([(os.path.join(self.pano, "report.json"),
                                           os.path.join(self.pano, "runs", suffix), "{}")])
        with open(victim, encoding="utf-8") as stream:
            self.assertEqual(stream.read(), "PRECIOUS")
        self.assertEqual(os.listdir(outside), ["staging.tmp"])


if __name__ == "__main__":
    unittest.main()
