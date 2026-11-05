"""#3452: `driver persist` is a separate process that reads the run manifest
and dispatch request and then writes the reply to the request's `out_file` --
so it makes first contact itself (read-only), before any of that is read."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import scripts.driver as driver
import scripts.first_contact as first_contact
import scripts.phases.persist as persist
import scripts.phases.requests as requests
from tests._test_helpers import (PLANTED_ARTIFACT_DIRS, adopt_panopticon, plant_artifact_dir,
                                 plant_latest_link)


def _reply(path):
    body = {"findings": [{"title": "issue", "severity": "HIGH", "domain": "SEC", "code": "SEC-A1A",
                          "category": "authz", "description": "d", "source_role": "domain_panel",
                          "location": {"file": "src/app.py", "line_start": 1}}],
            "_panopticon": {"run_id": "r" * 32, "role": "domain_panel",
                            "domain": "SEC", "group": "app"}}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(body, fh)
    return path


def _plant_bound_pair(root, out_file):
    """A REAL, unstamped `.panopticon/` whose manifest records the hash of the
    dispatch request beside it -- the pair `find_entry` accepts -- naming an
    `out_file` of the planter's choosing."""
    pano = os.path.join(root, ".panopticon")
    os.makedirs(pano, exist_ok=True)
    manifest = {"schema_version": 1, "run_id": "r" * 32, "review_root": os.path.abspath(root)}

    def write_manifest():
        with open(os.path.join(pano, "run-manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
    write_manifest()
    request = {"run_id": "r" * 32, "checkpoint": "review", "entries": [
        {"id": "review-app-SEC", "out_file": out_file, "run_id": "r" * 32,
         "role": "domain_panel", "domain": "SEC", "group": "app", "delivery": "return_json"}]}
    raw = json.dumps(request).encode("utf-8")
    path = requests.request_path(root)          # where persist will look for it
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(raw)
    manifest["dispatch_request"] = {"sha256": hashlib.sha256(raw).hexdigest()}
    write_manifest()
    assert requests.request_path(root) == path

class TestPersistMakesFirstContact(unittest.TestCase):
    def _persist(self, root, reply):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = driver.main(["persist", "review-app-SEC", "--file", reply, root])
        return rc, err.getvalue()

    def test_each_planted_artifact_dir_halts_before_the_request_is_read(self):
        for kind in PLANTED_ARTIFACT_DIRS:
            with self.subTest(kind), tempfile.TemporaryDirectory() as d, \
                    tempfile.TemporaryDirectory() as elsewhere:
                reply = _reply(os.path.join(elsewhere, "reply.txt"))
                plant_artifact_dir(d, kind, elsewhere)
                with mock.patch.object(persist, "find_entry", wraps=persist.find_entry) as find:
                    rc, err = self._persist(d, reply)
                self.assertEqual(2, rc)
                self.assertTrue(err.startswith("driver persist: "), err)
                self.assertEqual(1, err.count("\n"), err)
                find.assert_not_called()

    def test_an_unstamped_artifact_dir_with_a_bound_request_halts_on_h2(self):
        # The persist-only hole `artifact_root` alone would leave: a REAL
        # directory, so no symlink check fires, whose manifest vouches for its
        # own request. Unstamped, so first contact's H2 refuses it -- and the
        # out_file it names, outside the tree, is never written.
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as elsewhere:
            target = os.path.join(elsewhere, "findings-app-SEC.json")
            _plant_bound_pair(d, target)
            rc, err = self._persist(d, _reply(os.path.join(elsewhere, "reply.txt")))
            self.assertEqual((2, "driver persist: %s\n" % first_contact.H2), (rc, err))
            self.assertFalse(os.path.exists(target))

    def test_a_stamped_artifact_dir_with_its_latest_link_reaches_the_request(self):
        with tempfile.TemporaryDirectory() as raw, tempfile.TemporaryDirectory() as elsewhere:
            d = os.path.realpath(raw)       # the spelling the stamp binds and persist resolves
            adopt_panopticon(d)
            plant_latest_link(d)
            rc, err = self._persist(d, _reply(os.path.join(elsewhere, "reply.txt")))
        # Past first contact: the answer is find_entry's, not a halt.
        self.assertEqual((1, "driver persist: no entry 'review-app-SEC' in the current "
                             "dispatch request\n"), (rc, err))


def _tree_state(*roots):
    """Every path under `roots` with its bytes (links as their target), for a
    "nothing was written anywhere" comparison."""
    state = {}
    for root in roots:
        for top, dirs, names in os.walk(root):
            for name in dirs + names:
                p = os.path.join(top, name)
                if os.path.islink(p):
                    state[p] = ("link", os.readlink(p))
                elif os.path.isfile(p):
                    with open(p, "rb") as fh:
                        state[p] = ("file", fh.read())
                else:
                    state[p] = ("dir",)
    return state


class TestPersistConfinesTheOutFile(unittest.TestCase):
    """#3464: on a STAMPED tree, a request whose record and file were edited
    together still names its own `out_file`, and the stamp does not sign that
    record -- so persist confines the destination to this tree's `.panopticon/`."""

    def _stamped(self):
        from tests._test_helpers import our_manifest
        import scripts.run_manifest as run_manifest
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        run_manifest.write_manifest(d, our_manifest(d, {
            "schema_version": 1, "run_id": "0123456789abcdef", "host": "claude",
            "security_mode": "standard", "created": "2026-09-20T00:00:00Z",
            "review_root": d, "target": d}))
        return d

    def _dir(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        return d

    def _request(self, d, out_file):
        requests.write_dispatch_request(d, "RID", "scout", None, [
            {"id": "scout-app", "out_file": out_file, "delivery": "return_json"}])

    def _persist(self, d):
        reply = os.path.join(self._dir(), "reply.txt")
        with open(reply, "w", encoding="utf-8") as fh:
            fh.write('{"domains": [], "files": [], "tools": []}')
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = driver.main(["persist", "scout-app", "--file", reply, d])
        return rc, err.getvalue()

    def _refused(self, d, out_file, *watched, rc=1):
        self._request(d, out_file)
        before = _tree_state(d, *watched)
        got, err = self._persist(d)
        self.assertEqual(rc, got, err)
        self.assertEqual(1, err.count("\n"), err)
        self.assertEqual(before, _tree_state(d, *watched))     # nothing written anywhere
        return err

    def test_an_out_file_outside_the_tree_is_refused(self):
        d, elsewhere = self._stamped(), self._dir()
        err = self._refused(d, os.path.join(elsewhere, "scout-app.json"), elsewhere)
        self.assertIn("names an out_file outside .panopticon", err)

    def test_an_out_file_under_another_trees_artifact_dir_is_refused(self):
        d, other = self._stamped(), self._stamped()
        target = os.path.join(other, ".panopticon", "runs", "t", "scout-app.json")
        err = self._refused(d, target, other)
        self.assertIn("names an out_file outside .panopticon", err)

    def test_a_dotdot_out_of_the_artifact_dir_is_refused(self):
        d = self._stamped()
        err = self._refused(d, os.path.join(d, ".panopticon", "runs", "..", "..", "scout-app.json"))
        self.assertIn("names an out_file outside .panopticon", err)

    def test_a_relative_out_file_is_measured_where_it_would_be_written(self):
        # Review round 1: the writer resolves a relative out_file against the
        # process cwd, not the review root -- so run from elsewhere, a forged
        # `.panopticon/...` would pass a root-joined check and land in the cwd.
        d, cwd = self._stamped(), self._dir()
        with contextlib.chdir(cwd):
            err = self._refused(d, os.path.join(".panopticon", "runs", "t", "scout-app.json"), cwd)
        self.assertIn("names an out_file outside .panopticon", err)

    def test_a_symlinked_intermediate_halts_at_first_contact(self):
        # A planted `runs/evil -> elsewhere` is a stray link, so first contact's
        # H3 halts before the confinement is even reached (exit 2).
        d, elsewhere = self._stamped(), self._dir()
        os.makedirs(os.path.join(d, ".panopticon", "runs"), exist_ok=True)
        os.symlink(elsewhere, os.path.join(d, ".panopticon", "runs", "evil"))
        self._refused(d, os.path.join(d, ".panopticon", "runs", "evil", "scout-app.json"),
                      elsewhere, rc=2)

    def test_a_run_folder_out_file_still_persists(self):
        d = self._stamped()
        run = os.path.join(d, ".panopticon", "runs", "t")
        os.makedirs(run, exist_ok=True)
        os.symlink("t", os.path.join(d, ".panopticon", "runs", "latest"))
        out = os.path.join(run, "scout-app.json")
        self._request(d, out)
        rc, err = self._persist(d)
        self.assertEqual((0, ""), (rc, err))
        self.assertTrue(os.path.isfile(out))
