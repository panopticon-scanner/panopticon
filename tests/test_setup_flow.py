import json
import os
import tempfile
import unittest

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

    def test_readiness_returns_checks(self):
        d = _repo()
        checks = setup_flow.readiness(d, host="claude",
                                      runner=lambda *a, **k: type("R", (), {"returncode": 1})())
        names = {c[0] for c in checks}
        self.assertIn("target-root", names)


if __name__ == "__main__":
    unittest.main()
