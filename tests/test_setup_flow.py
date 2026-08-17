import json
import os
import tempfile
import unittest
from unittest import mock

import setup_flow


def _repo(with_committed=False):
    d = os.path.realpath(tempfile.mkdtemp())
    os.makedirs(os.path.join(d, "src", "checkout"))
    with open(os.path.join(d, "src", "checkout", "pay.py"), "w") as fh:
        fh.write("x = 1\n")
    os.makedirs(os.path.join(d, ".panopticon"))
    if with_committed:
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n")
    return d


class TestSetupFlow(unittest.TestCase):
    def test_provision_seeds_gitignore_and_config(self):
        d = _repo()
        res = setup_flow.provision(d)
        self.assertTrue(os.path.isfile(os.path.join(d, ".panopticon", "config.json")))
        self.assertIn(".panopticon/*", open(os.path.join(d, ".gitignore")).read())
        self.assertTrue(res["config_created"])

    def test_committed_matrix_preserves_order(self):
        d = _repo(with_committed=True)
        cm = setup_flow.committed_matrix(d)
        self.assertEqual(cm["Checkout"]["match"], ["src/checkout/**"])
        self.assertEqual(cm["Checkout"]["panels"], ["SEC"])

    def test_ingest_writes_draft_with_affinity_floor(self):
        d = _repo()
        proposal = {"groups": [{"capability": "Checkout",
                                "match": ["src/checkout/**"], "tests": []}]}
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump(proposal, fh)
        res = setup_flow.ingest_proposal(d, pp)
        self.assertTrue(res["ok"])
        self.assertTrue(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml.draft")))
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml")))

    def test_ingest_malformed_proposal_fails_no_draft(self):
        d = _repo()
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump({"groups": [{"capability": "", "match": []}]}, fh)
        res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertTrue(res["errors"])
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_ingest_missing_proposal_fails_no_draft(self):
        d = _repo()
        res = setup_flow.ingest_proposal(d, os.path.join(d, ".panopticon", "nope.json"))
        self.assertFalse(res["ok"])
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_scan_brief_includes_vocabulary_hints(self):
        d = _repo()
        vocab = {"names": ["Auth"], "hints": {"Auth": ["**/auth/**", "**/login/**"]}}
        path = setup_flow.render_scan_brief(d, vocab)
        brief = open(path).read()
        self.assertIn("Auth", brief)
        self.assertIn("**/auth/**", brief)  # the hint globs reach the classifier

    def test_readiness_returns_checks(self):
        d = _repo()
        checks = setup_flow.readiness(d, host="claude",
                                      runner=lambda *a, **k: type("R", (), {"returncode": 1})())
        names = {c[0] for c in checks}
        self.assertIn("target-root", names)

    def test_readiness_checks_driver_roles_not_legacy(self):
        # #5.0-15: enforced-shells must verify the driver's scout/domain_panel/
        # domain_advisor shells, NOT the retired panel_review/lens_sweep.
        import dispatch
        d = _repo()
        with mock.patch.object(dispatch, "_is_registered", return_value=False):
            checks = setup_flow.readiness(
                d, host="claude",
                runner=lambda *a, **k: type("R", (), {"returncode": 0})())
        es = next(c for c in checks if c[0] == "enforced-shells")
        self.assertFalse(es[1])                       # unregistered -> not ok
        for role in ("scout", "domain_panel", "domain_advisor"):
            self.assertIn(role, es[2])
        self.assertNotIn("panel_review", es[2])
        self.assertNotIn("lens_sweep", es[2])

    def test_readiness_generic_host_enforced_shells_informational(self):
        # #5.0-15: the generic host runs unenforced -> informational (None), not FAIL.
        d = _repo()
        checks = setup_flow.readiness(
            d, host="generic",
            runner=lambda *a, **k: type("R", (), {"returncode": 0})())
        es = next(c for c in checks if c[0] == "enforced-shells")
        self.assertIsNone(es[1])


if __name__ == "__main__":
    unittest.main()
