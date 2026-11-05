"""#3452: `driver persist` is a separate process that reads the run manifest
and dispatch request and then writes the reply to the request's `out_file` --
so it makes first contact itself (read-only), before any of that is read."""
import contextlib
import hashlib
import io
import json
import os
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
