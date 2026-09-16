"""Tests for scripts.phases.evidence_scope -- the bounded evidence closure the
backup advisor is granted (#1638 P16, owner ruling D4).

Run-13's redaction-order defect was CONFIRMED by the primary advisor and then
returned NEEDS_MORE_INFO by the backup, because the backup was granted only the
claim's own `location.file` and the defect lived in the call ORDER between that
file and two others. Synthesis prefers the backup, so the finding was published
as unverifiable. The closure is the fix: the claim's file, the producers its own
evidence names, and a one-hop in-repo import neighbourhood, capped.
"""
import os
import tempfile
import unittest

import scripts.phases.evidence_scope as evidence_scope


def _write(root, rel, text=""):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path) or root, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return rel


class _Repo(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        self.addCleanup(self._t.cleanup)


class TestClosure(_Repo):

    def _run13_repo(self):
        """The run-13 shape: render.py holds the redaction call, grading.py and
        synthesize.py are the two call sites the claim names, and synthesize.py
        imports render."""
        _write(self.root, "synth/__init__.py")
        _write(self.root, "synth/render.py", "import os\n")
        _write(self.root, "synth/grading.py", "import os\n")
        _write(self.root, "synth/report.py", "import os\n")
        _write(self.root, "synthesize.py",
               "import synth.render as render_mod\n")
        return ["synth/render.py", "synth/grading.py", "synth/report.py",
                "synthesize.py"]

    def test_closure_is_claim_file_then_named_producers_then_imports(self):
        files = self._run13_repo()
        claim = {"location": {"file": "synth/render.py"},
                 "description": "redact runs after synth/grading.py grades and "
                                "after synthesize.py has already rendered"}
        self.assertEqual(
            evidence_scope.closure(self.root, claim, files),
            ["synth/render.py", "synth/grading.py", "synthesize.py"])

    def test_closure_adds_same_group_importers_of_the_claim_file(self):
        # The "orchestration call sites" the run-13 backup could not see: a
        # claim naming nothing still reaches the files that import it.
        files = self._run13_repo()
        claim = {"location": {"file": "synth/render.py"},
                 "description": "the call order is wrong"}
        self.assertEqual(evidence_scope.closure(self.root, claim, files),
                         ["synth/render.py", "synthesize.py"])

    def test_closure_adds_the_claim_files_own_one_hop_imports(self):
        _write(self.root, "synth/__init__.py")
        _write(self.root, "synth/grading.py", "import os\n")
        _write(self.root, "synth/render.py", "from . import grading\n")
        files = ["synth/render.py", "synth/grading.py"]
        claim = {"location": {"file": "synth/render.py"}, "description": "x"}
        self.assertEqual(evidence_scope.closure(self.root, claim, files),
                         ["synth/render.py", "synth/grading.py"])

    def test_closure_reads_every_evidence_field_the_ruling_names(self):
        for rel in ("a.py", "b.py", "c.py", "d.py", "e.py", "claim.py"):
            _write(self.root, rel, "import os\n")
        claim = {"location": {"file": "claim.py"},
                 "description": "see a.py",
                 "exploit_scenario": "reached from b.py",
                 "remediation": "fix c.py too",
                 "evidence": {"reasoning": "traced through d.py"},
                 "references": ["e.py:12"]}
        self.assertEqual(
            evidence_scope.closure(self.root, claim, ["claim.py"]),
            ["claim.py", "a.py", "b.py", "c.py", "d.py", "e.py"])

    def test_a_named_path_outside_the_root_is_ignored_not_a_fallback(self):
        # Ruling 4: an escaping NAMED path contributes nothing (#1096); it does
        # not widen the grant and it does not trigger the whole-group fallback.
        _write(self.root, "claim.py", "import os\n")
        claim = {"location": {"file": "claim.py"},
                 "description": "compare with ../../etc/shadow and "
                                "/etc/passwd and ../outside.py"}
        self.assertEqual(evidence_scope.closure(self.root, claim, ["claim.py"]),
                         ["claim.py"])

    def test_a_named_path_that_does_not_exist_is_ignored(self):
        _write(self.root, "claim.py", "import os\n")
        claim = {"location": {"file": "claim.py"},
                 "description": "probably in imaginary/module.py"}
        self.assertEqual(evidence_scope.closure(self.root, claim, ["claim.py"]),
                         ["claim.py"])

    def test_a_non_python_claim_gets_location_and_named_paths_only(self):
        _write(self.root, "config/app.yml", "key: value\n")
        _write(self.root, "src/loader.py", "import os\n")
        _write(self.root, "src/reader.py", "import config\n")
        claim = {"location": {"file": "config/app.yml"},
                 "description": "consumed by src/loader.py"}
        self.assertEqual(
            evidence_scope.closure(self.root, claim,
                                   ["config/app.yml", "src/loader.py",
                                    "src/reader.py"]),
            ["config/app.yml", "src/loader.py"])

    def test_closure_truncates_at_the_cap(self):
        named = ["mod%02d.py" % i for i in range(30)]
        for rel in named + ["claim.py"]:
            _write(self.root, rel, "import os\n")
        claim = {"location": {"file": "claim.py"},
                 "description": " ".join(named)}
        got = evidence_scope.closure(self.root, claim, ["claim.py"])
        self.assertEqual(len(got), evidence_scope.CAP)
        self.assertEqual(got[0], "claim.py")
        self.assertEqual(got[1:], named[:evidence_scope.CAP - 1])

    def test_an_unresolvable_claim_location_yields_no_closure(self):
        # The whole-group fallback is `grant`'s job, not `closure`'s.
        for bad in ({}, {"location": None}, {"location": {}},
                    {"location": {"file": ""}},
                    {"location": {"file": "../../etc/passwd"}}):
            self.assertEqual(evidence_scope.closure(self.root, bad, ["a.py"]),
                             [], bad)


class TestGrant(_Repo):

    def test_grant_unions_the_claims_closures_and_records_the_cap(self):
        _write(self.root, "a.py", "import os\n")
        _write(self.root, "b.py", "import os\n")
        _write(self.root, "c.py", "import os\n")
        files = ["a.py", "b.py", "c.py"]
        scope = [{"location": {"file": "a.py"}, "description": "with b.py"},
                 {"location": {"file": "b.py"}, "description": "with a.py"}]
        self.assertEqual(
            evidence_scope.grant(self.root, files, scope),
            {"granted": ["a.py", "b.py"], "cap": evidence_scope.CAP,
             "truncated": False})

    def test_grant_flags_truncation_when_any_claim_overflows(self):
        named = ["mod%02d.py" % i for i in range(30)]
        for rel in named + ["claim.py"]:
            _write(self.root, rel, "import os\n")
        scope = [{"location": {"file": "claim.py"},
                  "description": " ".join(named)}]
        got = evidence_scope.grant(self.root, ["claim.py"], scope)
        self.assertTrue(got["truncated"])
        self.assertEqual(len(got["granted"]), evidence_scope.CAP)

    def test_grant_falls_back_to_the_whole_group_for_an_unlocatable_claim(self):
        _write(self.root, "a.py", "import os\n")
        files = ["a.py", "b.py", "c.py"]
        scope = [{"location": {"file": "a.py"}}, {"location": {}}]
        self.assertEqual(evidence_scope.grant(self.root, files, scope),
                         {"granted": files, "cap": evidence_scope.CAP,
                          "truncated": False})


if __name__ == "__main__":
    unittest.main()
