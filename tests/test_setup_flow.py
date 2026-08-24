import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.setup_flow as setup_flow
import shutil


def _repo(test_case, with_committed=False):
    d = os.path.realpath(tempfile.mkdtemp())
    os.makedirs(os.path.join(d, "src", "checkout"))
    with open(os.path.join(d, "src", "checkout", "pay.py"), "w") as fh:
        fh.write("x = 1\n")
    os.makedirs(os.path.join(d, ".panopticon"))
    test_case.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
    if with_committed:
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n")
    return d


def test_check_groups_manifest_reports_corrupt_yaml(tmp_path):
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text("not: [valid yaml: [")
    name, ok, detail = setup_flow._check_groups_manifest(str(tmp_path))
    assert name == "groups-manifest"
    assert ok is False
    assert "corrupt" in detail.lower() or "parse" in detail.lower()


class TestSetupFlow(unittest.TestCase):
    def _gitignore(self, repo):
        with open(os.path.join(repo, ".gitignore"), encoding="utf-8") as fh:
            return fh.read()

    def test_provision_seeds_gitignore_and_config(self):
        d = _repo(self)
        res = setup_flow.provision(d)
        self.assertTrue(os.path.isfile(os.path.join(d, ".panopticon", "config.json")))
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            self.assertIn(".panopticon/*", fh.read())
        self.assertTrue(res["config_created"])

    def test_provision_leaves_blanket_panopticon_ignore_untouched(self):
        # #1135: a repo that already blanket-ignores .panopticon/ must NOT have
        # its .gitignore rewritten -- no in-place migration to .panopticon/*, no
        # !.panopticon/ re-exposing the directory.
        d = _repo(self)
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write("node_modules/\n.panopticon/\n")
        res = setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertIn(".panopticon/", gi)
        self.assertNotIn(".panopticon/*", gi)   # not migrated
        self.assertNotIn("!.panopticon/", gi)   # dir not re-exposed
        self.assertFalse(res["groups_yml_committable"])
        self.assertIn("git add -f", res.get("gitignore_note", ""))

    def test_provision_fresh_repo_adds_committable_block(self):
        d = _repo(self)  # no .gitignore
        res = setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertIn(".panopticon/*", gi)
        self.assertIn("!.panopticon/groups.yml", gi)
        self.assertTrue(res["groups_yml_committable"])

    def test_provision_appends_negations_to_star_form(self):
        # .panopticon/* already present (committable-compatible), negations
        # missing -> append them (pure append), never rewrite the existing line.
        d = _repo(self)
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write(".panopticon/*\n")
        res = setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertEqual(gi.count(".panopticon/*"), 1)   # not duplicated
        self.assertIn("!.panopticon/groups.yml", gi)
        self.assertTrue(res["groups_yml_committable"])

    def test_provision_gitignore_idempotent_second_run_noop(self):
        d = _repo(self)
        setup_flow.provision(d)
        after_first = self._gitignore(d)
        res2 = setup_flow.provision(d)
        self.assertEqual(res2["gitignore_added"], [])
        self.assertEqual(self._gitignore(d), after_first)   # byte-identical

    def test_committed_matrix_preserves_order(self):
        d = _repo(self, with_committed=True)
        cm = setup_flow.committed_matrix(d)
        self.assertEqual(cm["Checkout"]["match"], ["src/checkout/**"])
        self.assertEqual(cm["Checkout"]["panels"], ["SEC"])

    def test_ingest_writes_draft_with_affinity_floor(self):
        d = _repo(self)
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
        d = _repo(self)
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump({"groups": [{"capability": "", "match": []}]}, fh)
        res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertTrue(res["errors"])
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_ingest_missing_proposal_fails_no_draft(self):
        d = _repo(self)
        res = setup_flow.ingest_proposal(d, os.path.join(d, ".panopticon", "nope.json"))
        self.assertFalse(res["ok"])
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_ingest_oversized_proposal_refused(self):
        # #1107: a target-shipped proposal over the byte cap is refused before parse
        d = _repo(self)
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            fh.write("[" + "0," * 600000 + "0]")   # > 1 MiB of JSON
        res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertTrue(any("exceeds" in e for e in res["errors"]))
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_scan_brief_includes_vocabulary_hints(self):
        d = _repo(self)
        vocab = {"names": ["Auth"], "hints": {"Auth": ["**/auth/**", "**/login/**"]}}
        path = setup_flow.render_scan_brief(d, vocab)
        with open(path, encoding="utf-8") as fh:
            brief = fh.read()
        self.assertIn("Auth", brief)
        self.assertIn("**/auth/**", brief)  # the hint globs reach the classifier

    def test_repo_spine_summary(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "src", "app"))
            os.makedirs(os.path.join(d, "tests"))
            with open(os.path.join(d, "src", "app", "main.py"), "w") as fh:
                fh.write("print(1)")
            with open(os.path.join(d, "package.json"), "w") as fh:
                fh.write("{}")
            with open(os.path.join(d, "pyproject.toml"), "w") as fh:
                fh.write("[project]")
            summary = setup_flow._repo_spine_summary(d)
            self.assertIn("top-level: src", summary)
            self.assertIn("package.json", summary)
            self.assertIn("pyproject.toml", summary)

    def test_sanitize_spine_token_neutralizes_adversarial_input(self):
        # #run7 TST-A2D: _sanitize_spine_token (#1120 prompt-injection defense for
        # untrusted repo dir names embedded in the scan brief) had NO adversarial
        # coverage. Lock the invariants: control chars + backticks are stripped;
        # whitespace/quote survivors are repr()-escaped so a crafted dir name
        # can't break out of its brief line.
        san = setup_flow._sanitize_spine_token
        self.assertEqual(san("ab`c"), "abc")                 # backtick stripped
        self.assertNotIn("`", san("`rm -rf /`"))
        self.assertEqual(san("a\x00b\x1fc\x7f"), "abc")      # control bytes stripped
        self.assertNotIn("\n", san("line1\nIGNORE PREVIOUS"))  # newline stripped
        self.assertNotIn("\t", san("a\tb"))
        self.assertEqual(san("two words"), repr("two words"))  # space -> repr()
        self.assertEqual(san('say "hi"'), repr('say "hi"'))    # quotes -> repr()
        self.assertEqual(san("it's"), repr("it's"))
        self.assertEqual(san("src"), "src")                  # clean token untouched

    def test_readiness_returns_checks(self):
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        checks = setup_flow.readiness(d, host="claude",
                                      runner=lambda *a, **k: type("R", (), {"returncode": 1})())
        check_dict = {c[0]: (c[1], c[2]) for c in checks}
        self.assertIn("target-root", check_dict)
        self.assertTrue(check_dict["target-root"][0])

    def test_readiness_checks_driver_roles_not_legacy(self):
        # #5.0-15: enforced-shells must verify the driver's scout/domain_panel/
        # domain_advisor shells, NOT the retired panel_review/lens_sweep.
        import dispatch
        d = _repo(self)
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
        d = _repo(self)
        checks = setup_flow.readiness(
            d, host="generic",
            runner=lambda *a, **k: type("R", (), {"returncode": 0})())
        es = next(c for c in checks if c[0] == "enforced-shells")
        self.assertIsNone(es[1])

    def test_readiness_probes_carry_timeout(self):
        # #1106: every docker/codex readiness probe must be bounded.
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        seen = []
        def runner(cmd, **kw):
            seen.append(kw.get("timeout"))
            return type("R", (), {"returncode": 0})()
        setup_flow.readiness(d, host="codex", runner=runner)  # docker + codex probes
        self.assertTrue(seen)
        self.assertTrue(all(t == setup_flow._PROBE_TIMEOUT for t in seen), seen)

    def test_readiness_hung_probe_is_failed_check_not_crash(self):
        # A probe that times out (or a missing binary) becomes a failed check,
        # never an unhandled exception that freezes the preflight (#1106).
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        def runner(cmd, **kw):
            raise setup_flow.subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        checks = {c[0]: c[1] for c in setup_flow.readiness(
            d, host="claude", runner=runner)}
        self.assertFalse(checks["docker"])

    def test_readiness_docker_ok_but_tools_image_absent(self):
        # #run7 TST-A2F: the common "Docker installed but the panopticon-tools
        # image isn't built" state (docker ok, tools-image absent) had no
        # coverage -- every prior runner returned one fixed rc for all commands.
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        def runner(cmd, **kw):
            rc = 1 if cmd[:3] == ["docker", "image", "inspect"] else 0
            return type("R", (), {"returncode": rc})()
        checks = {c[0]: (c[1], c[2]) for c in setup_flow.readiness(
            d, host="generic", runner=runner)}
        self.assertTrue(checks["docker"][0])
        self.assertFalse(checks["tools-image"][0])
        self.assertIn("image absent", checks["tools-image"][1])

    def test_readiness_driver_roles_parity_guard_trips_on_drift(self):
        # #run7 ARC-A4C: _driver_roles is a hand-maintained shadow of the active
        # dispatch.ROLE_FILES roles. If a role is renamed/removed there, readiness
        # must fail loudly rather than silently drop that shell from the check.
        import dispatch
        d = _repo(self)
        shrunk = {k: v for k, v in dispatch.ROLE_FILES.items()
                  if k != "domain_advisor"}
        with mock.patch.object(dispatch, "ROLE_FILES", shrunk):
            with self.assertRaises(RuntimeError):
                setup_flow.readiness(
                    d, host="claude",
                    runner=lambda *a, **k: type("R", (), {"returncode": 0})())

    def test_ingest_missing_bundled_data_fails_no_draft(self):
        # #run7 TST-A2B: the bundled-vocabulary-missing branch (a broken install)
        # was unreachable in tests -- drive it via a bogus data path.
        d = _repo(self)
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/**"]}]}, fh)
        with mock.patch.object(setup_flow, "_VOCAB_PATH", "/nonexistent/vocab.yml"):
            res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertTrue(any("missing" in e for e in res["errors"]))
        self.assertFalse(os.path.isfile(
            os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_ingest_malformed_bundled_vocab_fails_no_draft(self):
        # #run7 TST-A2B: the vocab/affinity load-error branch (verr/aerr) -- a
        # present-but-corrupt bundle must fail loudly with a data error, no draft.
        d = _repo(self)
        bad = os.path.join(d, "bad_vocab.yml")
        with open(bad, "w") as fh:
            fh.write("capabilities: not-a-list\n")   # load_vocabulary -> error
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/**"]}]}, fh)
        with mock.patch.object(setup_flow, "_VOCAB_PATH", bad):
            res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertTrue(any("data error" in e for e in res["errors"]))
        self.assertFalse(os.path.isfile(
            os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_provision_treats_globstar_panopticon_ignore_as_blanket(self):
        # #run7 ARC-A2B: a `**/`-prefixed blanket ignore also excludes the
        # .panopticon directory, so git can't re-include groups.yml out of it.
        # Provision must leave it untouched (not append a committable block that
        # can't take effect) and report groups.yml not committable.
        d = _repo(self)
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write("node_modules/\n**/.panopticon/\n")
        res = setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertNotIn(".panopticon/*", gi)   # not migrated
        self.assertNotIn("!.panopticon/", gi)   # dir not re-exposed
        self.assertFalse(res["groups_yml_committable"])


class TestSeedGroupsManifestInjection(unittest.TestCase):
    """#1108: hostile top-level directory names must not inject YAML structure
    into the seeded groups.yml -- the seeder validates via the schema and
    serializes with yaml.safe_dump instead of hand-formatting untrusted text."""

    def test_injection_dir_names_are_dropped_and_file_parses(self):
        import yaml as _yaml
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        # a benign dir plus two hostile top-level names: a YAML metacharacter
        # (':') and an embedded newline -- both legal on POSIX, both would break
        # or inject under naive "%s:" text-templating.
        for sub, fname in (("app", "main.py"), ("ev:il", "f.py"), ("ev\nil", "g.py")):
            os.makedirs(os.path.join(d, sub))
            with open(os.path.join(d, sub, fname), "w") as fh:
                fh.write("x = 1\n")
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        path, created, names = setup_flow._seed_groups_manifest(d)
        self.assertTrue(created)
        with open(path, encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh.read())          # parses cleanly -> no injection
        self.assertEqual(set(doc["groups"]), {"app"})  # hostile names dropped
        self.assertEqual(doc["groups"]["app"]["match"], ["app/**"])
        self.assertEqual(names, ["app"])

    def test_atomic_create_never_clobbers_a_racing_manifest(self):
        # #run7 COD-F1B: the top-of-function isfile() guard is a fast path, not a
        # lock. If a manifest appears AFTER that check (a concurrent seed), the
        # O_EXCL create must refuse to truncate it -- created=False, bytes intact.
        # Simulate the race by masking ONLY the manifest path on the fast-path
        # check so execution falls through to the atomic create against a file
        # that already exists on disk.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "app"))
        with open(os.path.join(d, "app", "main.py"), "w") as fh:
            fh.write("x = 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        path = os.path.join(d, ".panopticon", "groups.yml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("groups:\n  Winner:\n    match: ['src/**']\n")
        real_isfile = os.path.isfile
        target = os.path.realpath(path)
        def masked(p):
            return False if os.path.realpath(p) == target else real_isfile(p)
        with mock.patch("os.path.isfile", side_effect=masked):
            _p, created, _names = setup_flow._seed_groups_manifest(d)
        self.assertFalse(created)
        with open(path, encoding="utf-8") as fh:
            self.assertIn("Winner", fh.read())   # existing manifest not clobbered


if __name__ == "__main__":
    unittest.main()
