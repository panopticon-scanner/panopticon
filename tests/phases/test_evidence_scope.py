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
import re
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
             "truncated": False, "entry_cap": evidence_scope.ENTRY_CAP,
             "entry_truncated": False, "omitted": 0, "floor_count": 2})

    def test_grant_flags_truncation_when_any_claim_overflows(self):
        named = ["mod%02d.py" % i for i in range(30)]
        for rel in named + ["claim.py"]:
            _write(self.root, rel, "import os\n")
        scope = [{"location": {"file": "claim.py"},
                  "description": " ".join(named)}]
        got = evidence_scope.grant(self.root, ["claim.py"], scope)
        self.assertTrue(got["truncated"])
        self.assertEqual(len(got["granted"]), evidence_scope.CAP)

    def test_grant_stops_at_the_entry_ceiling(self):
        # Fix round 1, F3: `CAP` bounds ONE claim (D4's own signature), so a
        # 25-claim chunk could union 276 files over a 2-file group while telling
        # the advisor "truncated: no". `ENTRY_CAP` bounds the union, claim order
        # preserved, and says so.
        named = ["mod%03d.py" % i for i in range(11)]
        scope = []
        for c in range(30):
            claim_file = "claim%02d.py" % c
            _write(self.root, claim_file, "import os\n")
            block = ["c%02d_%s" % (c, n) for n in named]
            for rel in block:
                _write(self.root, rel, "import os\n")
            scope.append({"location": {"file": claim_file},
                          "description": " ".join(block)})
        got = evidence_scope.grant(self.root, ["claim00.py"], scope)
        self.assertEqual(len(got["granted"]), evidence_scope.ENTRY_CAP)
        self.assertEqual(got["entry_cap"], evidence_scope.ENTRY_CAP)
        self.assertTrue(got["entry_truncated"])
        self.assertFalse(got["truncated"])       # no single claim overflowed CAP
        # The floor first -- every claim's own file, always (fix round 2, N3) --
        # then the EXTRAS in claim order, so the first claims keep whole,
        # coherent neighbourhoods and the tail is what goes short.
        floor = ["claim%02d.py" % c for c in range(30)]
        self.assertEqual(got["granted"][:30], floor)
        # 48 - 30 floor files = 18 extras: all 11 of claim 0's, then 7 of
        # claim 1's, and nothing at all for claims 2..29.
        self.assertEqual(got["granted"][30:],
                         ["c00_%s" % n for n in named]
                         + ["c01_%s" % n for n in named][:7])

    def test_a_grant_within_the_entry_ceiling_is_not_entry_truncated(self):
        _write(self.root, "a.py", "import os\n")
        _write(self.root, "b.py", "import os\n")
        got = evidence_scope.grant(
            self.root, ["a.py", "b.py"],
            [{"location": {"file": "a.py"}, "description": "with b.py"}])
        self.assertFalse(got["entry_truncated"])
        self.assertEqual(got["entry_cap"], evidence_scope.ENTRY_CAP)

    def test_grant_falls_back_to_the_whole_group_for_an_unlocatable_claim(self):
        _write(self.root, "a.py", "import os\n")
        files = ["a.py", "b.py", "c.py"]
        scope = [{"location": {"file": "a.py"}}, {"location": {}}]
        self.assertEqual(evidence_scope.grant(self.root, files, scope),
                         {"granted": files, "cap": evidence_scope.CAP,
                          "truncated": False,
                          "entry_cap": evidence_scope.ENTRY_CAP,
                          "entry_truncated": False, "omitted": 0,
                          "floor_count": 0})


if __name__ == "__main__":
    unittest.main()


class TestEntryCeilingNeverStarvesAClaim(_Repo):
    """Fix round 2, N3/N4. `ENTRY_CAP` bounds the closure EXTRAS, never a
    claim's own `location.file`. The ceiling used to drop whatever came after
    it, the claim file included -- and the read guard ENFORCES the grant, so a
    starved claim could only ever answer NEEDS_MORE_INFO, which is now
    `backup_scope_limited`: gate-eligible at 1.5 and permanently unrefutable.
    That is the #1029 floor (`paths[:cap] or [location.file]`), and it holds
    ahead of both caps."""

    def _claims(self, n, extras_per_claim=1):
        scope = []
        for i in range(n):
            own = "c%03d.py" % i
            _write(self.root, own, "import os\n")
            extras = ["x%03d_%02d.py" % (i, j) for j in range(extras_per_claim)]
            for rel in extras:
                _write(self.root, rel, "import os\n")
            scope.append({"location": {"file": own},
                          "description": " ".join(extras)})
        return scope

    def test_every_claim_keeps_its_own_file_past_the_ceiling(self):
        scope = self._claims(60)
        got = evidence_scope.grant(self.root, ["c000.py"], scope)
        own = ["c%03d.py" % i for i in range(60)]
        self.assertEqual(got["granted"], own)          # all 60, zero extras
        self.assertTrue(got["entry_truncated"])
        self.assertEqual(got["omitted"], 60)           # every extra dropped

    def test_the_ceiling_bounds_extras_not_the_floor(self):
        # 10 claims, 20 extras each: the 10 claim files are always granted and
        # the extras fill the REMAINING budget up to ENTRY_CAP.
        scope = self._claims(10, extras_per_claim=20)
        got = evidence_scope.grant(self.root, ["c000.py"], scope)
        own = {"c%03d.py" % i for i in range(10)}
        self.assertTrue(own <= set(got["granted"]))
        self.assertEqual(len(got["granted"]), evidence_scope.ENTRY_CAP)
        self.assertTrue(got["entry_truncated"])

    def test_omitted_counts_distinct_files(self):
        # N4: the dedupe check preceded the ceiling check, so one file named by
        # three claims incremented `omitted` three times and the prompt
        # over-reported.
        _write(self.root, "a.py", "import os\n")
        _write(self.root, "b.py", "import os\n")
        _write(self.root, "shared.py", "import os\n")
        scope = [{"location": {"file": "a.py"}, "description": "shared.py"},
                 {"location": {"file": "b.py"}, "description": "shared.py"}]
        got = evidence_scope.grant(self.root, ["a.py"], scope, entry_cap=0)
        self.assertEqual(got["omitted"], 1)            # one DISTINCT file

    def test_entry_cap_zero_fails_closed_to_the_floor(self):
        # N4: `granted or list(files)` handed back the WHOLE GROUP when the
        # ceiling emptied the grant -- a ceiling of zero yielding an unbounded
        # read. The floor is the floor; nothing widens past it.
        _write(self.root, "a.py", "import os\n")
        _write(self.root, "b.py", "import os\n")
        got = evidence_scope.grant(
            self.root, ["a.py", "b.py", "c.py"],
            [{"location": {"file": "a.py"}, "description": "with b.py"}],
            entry_cap=0)
        self.assertEqual(got["granted"], ["a.py"])
        self.assertTrue(got["entry_truncated"])


class TestAClaimFileThatResolvesToNothing(_Repo):
    """Fix round 3, D2 -- a REGRESSION introduced by the entry-ceiling commit.
    `_claim_floor` confined BEFORE it normalized, so a `location.file` of `"./"`
    or whitespace passed confinement, normalized to None, and dropped out of the
    floor without triggering the fallback -- and the same commit had removed
    `granted or list(files)`. The result was `granted: []`: a backup entry
    dispatched with a deny-all read fence, so the advisor could open nothing and
    the only answer left was NEEDS_MORE_INFO -> `backup_scope_limited`,
    gate-eligible at 1.5, permanently unrefutable. Exactly what `_claim_floor`'s
    own docstring says it exists to prevent, through a field its confinement
    docstring calls "LLM/panel-supplied (steerable by injection)"."""

    UNRESOLVABLE = ("./", " ", "  ", "", None, ".", "./.", "\t")

    def test_a_claim_file_that_normalizes_to_nothing_falls_back(self):
        _write(self.root, "a.py", "import os\n")
        files = ["a.py", "b.py", "c.py"]
        for bad in self.UNRESOLVABLE:
            got = evidence_scope.grant(
                self.root, files,
                [{"location": {"file": "a.py"}}, {"location": {"file": bad}}])
            self.assertEqual(got["granted"], files, repr(bad))

    def test_a_claim_file_that_does_not_exist_falls_back(self):
        # The same failure by another route: a grant of one path the advisor
        # cannot open is an empty fence in everything but name.
        _write(self.root, "a.py", "import os\n")
        files = ["a.py", "b.py"]
        got = evidence_scope.grant(
            self.root, files, [{"location": {"file": "ghost.py"}}])
        self.assertEqual(got["granted"], files)

    def test_a_grant_is_never_empty(self):
        # The invariant, stated once: whatever the claims say, the backup is
        # given something to read or the whole group.
        _write(self.root, "a.py", "import os\n")
        for bad in self.UNRESOLVABLE:
            for cap in (0, 12):
                got = evidence_scope.grant(
                    self.root, ["a.py", "b.py"],
                    [{"location": {"file": bad}}], entry_cap=cap)
                self.assertTrue(got["granted"], (bad, cap))


class TestTheGrantRecordsItsFloor(_Repo):
    """Fix round 3, D5. `entry_truncated` means "closure EXTRAS were omitted",
    which is why a 60-file floor under a 48-file ceiling reports `false` -- but
    the advisor's echoed `evidence_scope` then read `entry_cap: 48,
    entry_truncated: false` next to 60 granted files, which is internally
    incoherent. `floor_count` is the missing number: how much of the grant is
    claim files, which the ceiling never bounds."""

    def test_floor_count_explains_a_grant_larger_than_its_cap(self):
        scope = []
        for i in range(60):
            own = "c%03d.py" % i
            _write(self.root, own, "import os\n")
            scope.append({"location": {"file": own}})
        got = evidence_scope.grant(self.root, ["c000.py"], scope)
        self.assertEqual(len(got["granted"]), 60)
        self.assertEqual(got["floor_count"], 60)
        self.assertGreater(got["floor_count"], got["entry_cap"])
        self.assertFalse(got["entry_truncated"])     # no EXTRA was omitted
        self.assertEqual(got["omitted"], 0)

    def test_floor_count_is_the_distinct_claim_files(self):
        for rel in ("a.py", "b.py", "x.py"):
            _write(self.root, rel, "import os\n")
        got = evidence_scope.grant(
            self.root, ["a.py", "b.py", "x.py"],
            [{"location": {"file": "a.py"}, "description": "x.py"},
             {"location": {"file": "a.py"}},
             {"location": {"file": "b.py"}}])
        self.assertEqual(got["floor_count"], 2)      # a.py, b.py -- not x.py


class TestTheRecordedShapeIsWrittenDownWhereItIsPromised(unittest.TestCase):
    """Fix round 4, N3 -- and round 2's N4 before it, on the other docstring.
    Both `grant()` and `verify._backup_grant` open by naming the dict they
    return, and `PANOPTICON.md` gives the same list as the shape the advisor
    copies into `evidence_scope`. Three hand-maintained copies of one shape drift
    the moment a key is added; this derives the list from the function instead,
    so adding a key fails here rather than quietly leaving two of the three
    stale."""

    def _keys(self):
        with tempfile.TemporaryDirectory() as d:
            root = os.path.realpath(d)
            _write(root, "a.py", "import os\n")
            return evidence_scope.grant(root, ["a.py"],
                                        [{"location": {"file": "a.py"}}])

    @staticmethod
    def _declared(doc):
        """The `{a, b, c}` shape list the docstring opens with. The SUMMARY
        list, not a mention anywhere in the prose -- round 3 added `floor_count`
        to `grant()`'s body three paragraphs down and left the summary reading
        six keys, which is precisely the drift that looks fixed."""
        body = re.search(r"\{([a-z_,\s]+)\}", doc.replace("\n", " "))
        return sorted(n.strip() for n in body.group(1).split(",") if n.strip())

    def test_grant_names_every_key_it_returns(self):
        self.assertEqual(self._declared(evidence_scope.grant.__doc__),
                         sorted(self._keys()))

    def test_the_driver_side_docstring_names_them_too(self):
        import scripts.phases.verify as verify
        self.assertEqual(self._declared(verify._backup_grant.__doc__),
                         sorted(self._keys()))
