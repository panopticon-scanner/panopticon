"""The virtualenv scope's own tests (#1762 ARC-2609514778, part 4 of 4).

`scripts.venv_scope` was lifted out of `run_tools` whole in split 4, so the
centre of this file is a PARITY golden rather than new behaviour: the walk's
answer over one fixture tree, both partitions of it, and the twenty-four
exclusion argvs the tools get, captured from the tree before the move and
compared string for string after it. The argv IS the behaviour -- a flag, a
value, its POSITION or bandit's comma-joined order changing is the scan looking
somewhere else -- and the manifest rows are a published contract
`security_gate` and `ingest_tools.scan_skipped_venvs` read back, so nothing in
either may drift.

The golden is a LITERAL on purpose, emitted by the command in the PR's
implementation notes from the commit this split branched from. It must be
regenerated, from the then-current main, by any later change that legitimately
alters a reason, a note, a flag spelling or the depth bound; a difference
produced by anything else is the change being wrong.

Below it is everything that came out of `tests/test_run_tools_core.py` with the
block, names and bodies unchanged: eighteen self-contained tests of the walk,
the partition and the argv builder, gathered into three classes by the claim
they were making. What stayed behind stayed on purpose -- every one of those
also drives production code that did NOT move (`run_tools()` and `main()`
building a whole dispatch, `tools_manifest.write_manifest` publishing a row,
`scanner_config`'s staged bandit ini) -- so `tests/test_run_tools_core.py` keeps
three sibling classes, and the `_venv`, `_plant` and `HOSTILE` fixtures are
copied rather than shared so that no moved body had to change.
"""
import json
import os
import tempfile
import unittest

import scripts.run_tools as rt
import scripts.venv_scope as vs


def _plant_venv(root, rel, marker=True, shape=True):
    """A virtualenv as a creator leaves one: the marker AND an interpreter."""
    os.makedirs(os.path.join(root, rel), exist_ok=True)
    if marker:
        with open(os.path.join(root, rel, "pyvenv.cfg"), "w",
                  encoding="utf-8") as fh:
            fh.write("home = /usr/bin\nversion = 3.12.0\n")
    if shape:
        os.makedirs(os.path.join(root, rel, "bin"), exist_ok=True)
        with open(os.path.join(root, rel, "bin", "python"), "w",
                  encoding="utf-8") as fh:
            fh.write("")


def _plant_the_golden_tree(root):
    """The one fixture tree every golden case below runs over.

    Five shapes, each a branch of the block: a virtualenv with marker AND
    shape, a marker with no environment under it, one AT the depth bound and
    one past it, one under a pruned directory, and one whose NAME no exclusion
    value can carry. Plus ordinary source, which must stay unflagged.
    """
    _plant_venv(root, ".venv")                              # marker + shape
    _plant_venv(root, "marker-only", shape=False)           # a claim, no env
    _plant_venv(root, os.path.join("a", "b", ".venv"))      # at the bound
    _plant_venv(root, os.path.join("a", "b", "c", ".venv"))  # past the bound
    _plant_venv(root, os.path.join("node_modules", "venv"))  # under a pruned dir
    _plant_venv(root, "a,b")                                # inexpressible name
    os.makedirs(os.path.join(root, "src"), exist_ok=True)    # real source


def _cases(mod):
    """`{case: json}` for the whole parity table, through the REAL functions.

    One walk, both partitions of its answer, and the argv every tool gets:
    `sorted(_VENV_EXCLUDE_FLAG)` (the two repeatable knobs), bandit's single
    comma-joined value, and `gitleaks`, which has no knob at all -- each with
    zero, one and two directories and with `target` set and unset, because the
    parameter is still accepted and must stay unread.
    """
    out = {}
    with tempfile.TemporaryDirectory() as d:
        _plant_the_golden_tree(d)
        found = mod.find_virtualenvs(d)
        out["find_virtualenvs"] = json.dumps(found, sort_keys=True)
        for mode in ("standard", "redteam"):
            out["partition/%s" % mode] = json.dumps(
                mod.partition_venv_dirs(found, mode), sort_keys=True)
        lists = {"none": [], "one": found[:1], "two": [found[0], found[2]]}
        for tool in sorted(mod._VENV_EXCLUDE_FLAG) + ["bandit", "gitleaks"]:
            for count in sorted(lists):
                for label, target in (("no-target", None), ("target", d)):
                    out["argv/%s/%s/%s" % (tool, count, label)] = json.dumps(
                        mod._with_venv_excludes(tool, list(rt.TOOL_CMD[tool]),
                                                lists[count], target),
                        sort_keys=True)
    return out


# Captured from the tree at the commit this split branched from, BEFORE any code
# moved. A difference here is the extraction being wrong: fix the extraction,
# never this table.
GOLDEN = {
    "argv/bandit/none/no-target":
        '["bandit", "-q", "-r", '
        '"--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees", "/src", '
        '"-s", "B101,B404,B110,B112", "-f", "sarif"]',
    "argv/bandit/none/target":
        '["bandit", "-q", "-r", '
        '"--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees", "/src", '
        '"-s", "B101,B404,B110,B112", "-f", "sarif"]',
    "argv/bandit/one/no-target":
        '["bandit", "-q", "-r", '
        '"--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees,/src/.venv", '
        '"/src", "-s", "B101,B404,B110,B112", "-f", "sarif"]',
    "argv/bandit/one/target":
        '["bandit", "-q", "-r", '
        '"--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees,/src/.venv", '
        '"/src", "-s", "B101,B404,B110,B112", "-f", "sarif"]',
    "argv/bandit/two/no-target":
        '["bandit", "-q", "-r", '
        '"--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees,/src/.venv,/'
        'src/a/b/.venv", "/src", "-s", "B101,B404,B110,B112", "-f", "sarif"]',
    "argv/bandit/two/target":
        '["bandit", "-q", "-r", '
        '"--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees,/src/.venv,/'
        'src/a/b/.venv", "/src", "-s", "B101,B404,B110,B112", "-f", "sarif"]',
    "argv/gitleaks/none/no-target":
        '["gitleaks", "detect", "--no-git", "--source", "/src", "--report-format", "sarif", '
        '"--report-path", "/dev/stdout", "--no-banner", "--redact"]',
    "argv/gitleaks/none/target":
        '["gitleaks", "detect", "--no-git", "--source", "/src", "--report-format", "sarif", '
        '"--report-path", "/dev/stdout", "--no-banner", "--redact"]',
    "argv/gitleaks/one/no-target":
        '["gitleaks", "detect", "--no-git", "--source", "/src", "--report-format", "sarif", '
        '"--report-path", "/dev/stdout", "--no-banner", "--redact"]',
    "argv/gitleaks/one/target":
        '["gitleaks", "detect", "--no-git", "--source", "/src", "--report-format", "sarif", '
        '"--report-path", "/dev/stdout", "--no-banner", "--redact"]',
    "argv/gitleaks/two/no-target":
        '["gitleaks", "detect", "--no-git", "--source", "/src", "--report-format", "sarif", '
        '"--report-path", "/dev/stdout", "--no-banner", "--redact"]',
    "argv/gitleaks/two/target":
        '["gitleaks", "detect", "--no-git", "--source", "/src", "--report-format", "sarif", '
        '"--report-path", "/dev/stdout", "--no-banner", "--redact"]',
    "argv/semgrep/none/no-target":
        '["semgrep", "scan", "--config", "/opt/semgrep-rules", "--metrics=off", '
        '"--disable-version-check", "--sarif", "--quiet", "/src"]',
    "argv/semgrep/none/target":
        '["semgrep", "scan", "--config", "/opt/semgrep-rules", "--metrics=off", '
        '"--disable-version-check", "--sarif", "--quiet", "/src"]',
    "argv/semgrep/one/no-target":
        '["semgrep", "scan", "--config", "/opt/semgrep-rules", "--metrics=off", '
        '"--disable-version-check", "--sarif", "--quiet", "--exclude=.venv", "/src"]',
    "argv/semgrep/one/target":
        '["semgrep", "scan", "--config", "/opt/semgrep-rules", "--metrics=off", '
        '"--disable-version-check", "--sarif", "--quiet", "--exclude=.venv", "/src"]',
    "argv/semgrep/two/no-target":
        '["semgrep", "scan", "--config", "/opt/semgrep-rules", "--metrics=off", '
        '"--disable-version-check", "--sarif", "--quiet", "--exclude=.venv", '
        '"--exclude=a/b/.venv", "/src"]',
    "argv/semgrep/two/target":
        '["semgrep", "scan", "--config", "/opt/semgrep-rules", "--metrics=off", '
        '"--disable-version-check", "--sarif", "--quiet", "--exclude=.venv", '
        '"--exclude=a/b/.venv", "/src"]',
    "argv/trivy/none/no-target":
        '["trivy", "fs", "--skip-db-update", "--offline-scan", "--format", "sarif", "/src"]',
    "argv/trivy/none/target":
        '["trivy", "fs", "--skip-db-update", "--offline-scan", "--format", "sarif", "/src"]',
    "argv/trivy/one/no-target":
        '["trivy", "fs", "--skip-db-update", "--offline-scan", "--format", "sarif", '
        '"--skip-dirs=.venv", "/src"]',
    "argv/trivy/one/target":
        '["trivy", "fs", "--skip-db-update", "--offline-scan", "--format", "sarif", '
        '"--skip-dirs=.venv", "/src"]',
    "argv/trivy/two/no-target":
        '["trivy", "fs", "--skip-db-update", "--offline-scan", "--format", "sarif", '
        '"--skip-dirs=.venv", "--skip-dirs=a/b/.venv", "/src"]',
    "argv/trivy/two/target":
        '["trivy", "fs", "--skip-db-update", "--offline-scan", "--format", "sarif", '
        '"--skip-dirs=.venv", "--skip-dirs=a/b/.venv", "/src"]',
    "find_virtualenvs":
        '[{"path": ".venv", "reason": "pyvenv.cfg"}, {"path": "a,b", "reason": "pyvenv.cfg"}, '
        '{"path": "a/b/.venv", "reason": "pyvenv.cfg"}, {"path": "marker-only", "reason": '
        '"pyvenv.cfg-without-shape"}]',
    "partition/redteam":
        '[[], [{"path": ".venv", "reason": "pyvenv.cfg", "skipped": false}, {"note": "scanned: '
        'the directory name cannot be handed to an exclusion knob without changing its meaning '
        '(only [A-Za-z0-9._-] path components can), so it is scanned rather than expressed as a '
        'pattern", "path": "a,b", "reason": "pyvenv.cfg", "skipped": false}, {"path": '
        '"a/b/.venv", "reason": "pyvenv.cfg", "skipped": false}, {"note": "scanned: a '
        'pyvenv.cfg with no interpreter or site-packages under it is not an installed '
        'environment", "path": "marker-only", "reason": "pyvenv.cfg-without-shape", "skipped": '
        'false}]]',
    "partition/standard":
        '[[{"path": ".venv", "reason": "pyvenv.cfg"}, {"path": "a/b/.venv", "reason": '
        '"pyvenv.cfg"}], [{"path": ".venv", "reason": "pyvenv.cfg", "skipped": true}, {"note": '
        '"scanned: the directory name cannot be handed to an exclusion knob without changing '
        'its meaning (only [A-Za-z0-9._-] path components can), so it is scanned rather than '
        'expressed as a pattern", "path": "a,b", "reason": "pyvenv.cfg", "skipped": false}, '
        '{"path": "a/b/.venv", "reason": "pyvenv.cfg", "skipped": true}, {"note": "scanned: a '
        'pyvenv.cfg with no interpreter or site-packages under it is not an installed '
        'environment", "path": "marker-only", "reason": "pyvenv.cfg-without-shape", "skipped": '
        'false}]]',
}


class TestTheVirtualenvScopeSurvivesTheExtraction(unittest.TestCase):
    """One walk, two partitions and twenty-four argvs, all through the public
    functions, against the table captured before the move. The comparison is the
    serialised answer and not a spot check: a reason, a note, a `skipped` flag, a
    flag spelling, its position on the argv and the order of bandit's
    comma-joined value are each part of what a scanner or the gate reads."""

    def test_every_case_lands_exactly_the_golden(self):
        cases = _cases(vs)
        for case in sorted(GOLDEN):
            with self.subTest(case=case):
                self.assertEqual(cases[case], GOLDEN[case])

    def test_the_golden_pins_every_case_and_no_stale_one(self):
        self.assertEqual(sorted(_cases(vs)), sorted(GOLDEN))

    def test_the_golden_can_mean_the_string_it_is_compared_to(self):
        # The literal's own precondition. `json.dumps` runs with
        # `ensure_ascii=True`, so the moment a path or a note carries a
        # non-ASCII character the SERIALISED answer holds `\uXXXX` as six ASCII
        # bytes while a Python literal of the same source decodes it to ONE
        # character -- and the comparison above fails for a reason that has
        # nothing to do with the change under test. A backslash in a path does
        # the same. Either case means the golden must be escaped deliberately,
        # and this says so at the point of failure.
        for case, text in sorted(GOLDEN.items()):
            with self.subTest(case=case):
                self.assertNotIn("\\", text,
                                 "a backslash in the golden cannot survive the "
                                 "round trip through a Python string literal")
                self.assertTrue(text.isascii(),
                                "json.dumps escapes non-ASCII to \\uXXXX; this "
                                "literal holds the decoded character")


class TestTheVirtualenvWalkAndItsExclusionKnobs(unittest.TestCase):
    """#1638 P09 (D8): keep the scanners out of virtualenvs in the first place.

    The eight self-contained tests of `tests/test_run_tools_core.py`'s
    `TestVirtualenvExclusion`, which keeps the rest: MOSTLY tests that drive a
    whole `run_tools()`/`main()` dispatch to prove the flags reach a real argv,
    plus two `collect_sanitization` cases, the repo's own committed `.bandit`
    spellings, and two `_is_excluded`/`select_adapters` checks on ruling 3's
    root manifests.
    """

    def _venv(self, root, rel, marker=True, shape=True):
        """A virtualenv as a creator leaves one: the marker AND an interpreter.

        #1839: the marker alone is a claim the target can make in one file, so
        `find_virtualenvs` wants the structure too. `shape=False` plants the
        bare marker this fixture used to write.
        """
        os.makedirs(os.path.join(root, rel), exist_ok=True)
        if marker:
            with open(os.path.join(root, rel, "pyvenv.cfg"), "w") as fh:
                fh.write("home = /usr/bin\nversion = 3.12.0\n")
        if shape:
            os.makedirs(os.path.join(root, rel, "bin"), exist_ok=True)
            with open(os.path.join(root, rel, "bin", "python"), "w") as fh:
                fh.write("")

    def test_find_virtualenvs_reports_marker_first_then_name(self):
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, "env")                       # metadata, odd name
            self._venv(d, ".venv")                     # pipenv in-project
            self._venv(d, "venv", marker=False)        # name fallback only
            os.makedirs(os.path.join(d, "src"))        # real source
            self.assertEqual(
                vs.find_virtualenvs(d),
                [{"path": ".venv", "reason": "pyvenv.cfg"},
                 {"path": "env", "reason": "pyvenv.cfg"},
                 {"path": "venv", "reason": "name"}])
    def test_find_virtualenvs_is_depth_bounded(self):
        # Venvs live near the root; an unbounded walk is paid on every scan.
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, os.path.join("a", "b", ".venv"))        # depth 3: found
            self._venv(d, os.path.join("a", "b", "c", ".venv"))   # depth 4: not
            self.assertEqual([v["path"] for v in vs.find_virtualenvs(d)],
                             ["a/b/.venv"])
    def test_find_virtualenvs_does_not_descend_into_one(self):
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, ".venv")
            self._venv(d, os.path.join(".venv", "venv"))
            self.assertEqual([v["path"] for v in vs.find_virtualenvs(d)], [".venv"])
    def test_an_option_shaped_directory_name_is_not_passed_at_all(self):
        # F7 built the attached `--flag=value` form so a directory named `-rf`
        # could never read as an OPTION. #1839 round 1 goes further: the
        # allowlist refuses a leading `-` outright, so such a directory is
        # SCANNED and named on its manifest row. The attached form stays as
        # belt for every name that does get through.
        cmd = vs._with_venv_excludes(
            "semgrep", list(rt.TOOL_CMD["semgrep"]), [{"path": "-rf", "reason": "name"}])
        self.assertEqual(cmd, list(rt.TOOL_CMD["semgrep"]))
        self.assertNotIn("-rf", " ".join(cmd))
        for arg in vs._with_venv_excludes(
                "semgrep", list(rt.TOOL_CMD["semgrep"]),
                [{"path": ".venv", "reason": "name"}]):
            if arg.startswith("--exclude"):
                self.assertEqual(arg, "--exclude=.venv")   # attached, one arg
    def test_a_symlink_out_of_the_target_is_not_a_virtualenv(self):
        # F1: `os.walk` will not DESCEND a symlink, but `isfile` follows one, so
        # a link pointing at a venv outside the target was stat'd and flagged.
        with tempfile.TemporaryDirectory() as d, \
                tempfile.TemporaryDirectory() as outside:
            self._venv(outside, "real")
            os.symlink(os.path.join(outside, "real"), os.path.join(d, "linked"))
            os.symlink(os.path.join(outside, "real"), os.path.join(d, ".venv"))
            self.assertEqual(vs.find_virtualenvs(d), [])
    def test_a_symlink_inside_the_target_is_still_a_virtualenv(self):
        # Confinement, not blanket symlink rejection: a link that stays inside
        # the target resolves to a real venv of the target.
        with tempfile.TemporaryDirectory() as d:
            self._venv(d, os.path.join("build", "env"))
            os.symlink(os.path.join(d, "build", "env"), os.path.join(d, "linked"))
            self.assertEqual([v["path"] for v in vs.find_virtualenvs(d)],
                             ["build/env", "linked"])
    def test_partition_skips_every_venv_under_standard(self):
        dirs = [{"path": ".venv", "reason": "pyvenv.cfg"},
                {"path": "venv", "reason": "name"}]
        skip, rows = vs.partition_venv_dirs(dirs, "standard")
        self.assertEqual(skip, dirs)
        self.assertEqual(rows, [{"path": ".venv", "reason": "pyvenv.cfg",
                                 "skipped": True},
                                {"path": "venv", "reason": "name",
                                 "skipped": True}])
    def test_partition_scans_every_detected_dir_under_redteam(self):
        # #1740 admitted the name-only kind; #1839 ruling 2 admits the
        # marker-confirmed kind for the same reason, one step further on.
        dirs = [{"path": ".venv", "reason": "pyvenv.cfg"},
                {"path": "venv", "reason": "name"}]
        skip, rows = vs.partition_venv_dirs(dirs, "redteam")
        self.assertEqual(skip, [])
        self.assertEqual(rows, [{"path": ".venv", "reason": "pyvenv.cfg",
                                 "skipped": False},
                                {"path": "venv", "reason": "name",
                                 "skipped": False}])


class TestAPlantedMarkerOrGlobNameCannotNarrowTheScan(unittest.TestCase):
    """run-14 SEC-1486247143 (#1839): the reviewed repo does not choose what the
    scanners look at.

    Two target-authored levers on the path CI's merge gate runs -- a planted
    `pyvenv.cfg` and a directory named with a glob metacharacter -- and every
    assertion is on the walk's answer, the partition or the ARGV, because that is
    the only place the narrowing was visible. The six self-contained tests of
    `tests/test_run_tools_core.py`'s `TestATargetFileCannotNarrowTheScan`, which
    keeps the manifest row and the end-to-end dispatch; the third lever, a
    committed `.bandit`, is in the sibling class in
    tests/test_run_tools_dispatch.py.
    """

    def _plant(self, root):
        """The reproduction probe's tree: the repo's real source under a planted
        marker file, plus a directory literally named `*` that IS a virtualenv
        by shape -- so only the metacharacter keeps it out of the knobs."""
        os.makedirs(os.path.join(root, "src"))
        with open(os.path.join(root, "src", "app.py"), "w") as fh:
            fh.write("import os\n")
        for rel in ("src", "*"):
            os.makedirs(os.path.join(root, rel), exist_ok=True)
            with open(os.path.join(root, rel, vs.VENV_MARKER), "w") as fh:
                fh.write("home = /usr\n")
        os.makedirs(os.path.join(root, "*", "bin"))
        with open(os.path.join(root, "*", "bin", "python"), "w") as fh:
            fh.write("")

    def test_a_bare_marker_beside_real_source_is_not_a_virtualenv(self):
        # One committed file removed `src/` from three scanners. A virtualenv
        # has a SHAPE as well as a marker; a marker alone is a claim.
        with tempfile.TemporaryDirectory() as d:
            self._plant(d)
            found = {v["path"]: v["reason"] for v in vs.find_virtualenvs(d)}
        self.assertEqual(found["src"], vs.VENV_MARKER_NO_SHAPE)
        self.assertEqual(found["*"], vs.VENV_MARKER)
    def test_the_walk_still_descends_a_directory_it_would_not_skip(self):
        # `src/` is scanned, so a REAL venv inside it must still be found --
        # the old code stopped walking at anything it flagged.
        with tempfile.TemporaryDirectory() as d:
            self._plant(d)
            os.makedirs(os.path.join(d, "src", ".venv", "bin"))
            for rel in (os.path.join("src", ".venv", vs.VENV_MARKER),
                        os.path.join("src", ".venv", "bin", "python")):
                with open(os.path.join(d, rel), "w") as fh:
                    fh.write("")
            found = {v["path"]: v["reason"] for v in vs.find_virtualenvs(d)}
        self.assertEqual(found["src/.venv"], vs.VENV_MARKER)
    def test_neither_plant_is_handed_to_a_scanner_in_either_mode(self):
        for mode in rt.SECURITY_MODES:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d:
                self._plant(d)
                skip, rows = vs.partition_venv_dirs(vs.find_virtualenvs(d), mode)
                self.assertEqual([e["path"] for e in skip], [])
                by_path = {r["path"]: r for r in rows}
                # NAMED, not silently absent: a directory nobody can express as
                # an exclusion must be scanned AND disclosed.
                self.assertFalse(by_path["src"]["skipped"])
                self.assertFalse(by_path["*"]["skipped"])
                self.assertIn(vs.VENV_MARKER, by_path["src"]["note"])
                self.assertIn("exclusion", by_path["*"]["note"])
    def test_no_scanner_is_ever_handed_a_glob_pattern(self):
        # `--exclude` and `--skip-dirs` take GLOBS, so a directory named `*`
        # was "skip the whole tree" -- the attached `--flag=value` form (#1638
        # P09 F7) stops an OPTION, not a pattern.
        dirs = [{"path": "*", "reason": vs.VENV_MARKER},
                {"path": "lib[0]", "reason": "name"},
                {"path": "q?", "reason": vs.VENV_MARKER},
                {"path": ".venv", "reason": vs.VENV_MARKER}]
        for tool, flag in (("semgrep", "--exclude="), ("trivy", "--skip-dirs=")):
            cmd = vs._with_venv_excludes(tool, list(rt.TOOL_CMD[tool]), dirs)
            self.assertEqual([a for a in cmd if a.startswith(flag)],
                             ["%s.venv" % flag], tool)
        cmd = vs._with_venv_excludes("bandit", list(rt.TOOL_CMD["bandit"]), dirs)
        entries = [a for a in cmd if a.startswith("--exclude=")][0]
        entries = entries[len("--exclude="):].split(",")
        self.assertIn("/src/.venv", entries)
        for planted in ("/src/*", "/src/lib[0]", "/src/q?"):
            self.assertNotIn(planted, entries)
    def test_a_marker_confirmed_virtualenv_is_scanned_under_redteam(self):
        # #1740 ruled that under redteam a finding may not be lost to a
        # directory NAME. A file the same target WROTE is more
        # attacker-controlled than a name, not less.
        skip, rows = vs.partition_venv_dirs(
            [{"path": ".venv", "reason": vs.VENV_MARKER}], "redteam")
        self.assertEqual(skip, [])
        self.assertEqual(rows, [{"path": ".venv", "reason": vs.VENV_MARKER,
                                 "skipped": False}])
    def test_a_real_virtualenv_is_still_skipped_under_standard(self):
        # The #1638 P09 cost saving stands where the target is not the threat --
        # and the manifest row is what `security_gate` reads back to say so.
        skip, rows = vs.partition_venv_dirs(
            [{"path": ".venv", "reason": vs.VENV_MARKER},
             {"path": "venv", "reason": "name"}], "standard")
        self.assertEqual([e["path"] for e in skip], [".venv", "venv"])
        self.assertEqual(rows, [{"path": ".venv", "reason": vs.VENV_MARKER,
                                 "skipped": True},
                                {"path": "venv", "reason": "name",
                                 "skipped": True}])


class TestNoTargetDirectoryNameReachesAnExclusionKnob(unittest.TestCase):
    """#1839 fix round 1 (review C1/I1/I2): the DIRECTORY NAME is target input too.

    Each exclusion knob reads its value in its OWN language and none of them can
    quote, so a name reaches one only through an ALLOWLIST: `{src,q}` is trivy
    doublestar ALTERNATION, `a,b` splits bandit's comma-joined value, and `*` is
    the whole tree out of semgrep's scope. The four self-contained tests of
    `tests/test_run_tools_core.py`'s `TestNoTargetTextReachesAScannerConfig`,
    which keeps the two about the scanner-owned staged config -- those files are
    `scanner_config`'s and did not move -- and the one that drives
    `run_tools()`'s own convenience default.
    """

    # Names the ALLOWLIST must refuse. `a\x00b` is refused by the predicate but
    # cannot be planted on disk (the kernel rejects it), so it is tested against
    # the predicate only, in `_PREDICATE_ONLY`.
    HOSTILE = ("x\ntests = B101", "a,b", "{src,q}", "-rf", "sr c",
               "pkg\rskips = B602", "caf\u00e9", "*", "q?", "lib[0]")
    _PREDICATE_ONLY = ("a\x00b",)

    def test_no_hostile_name_is_expressible_as_an_exclusion(self):
        # An ALLOWLIST, not a denylist: the four glob metacharacters round 0
        # refused are a subset of what a matcher can read. trivy matches
        # `--skip-dirs` with doublestar, whose language includes `{a,b}`
        # alternation, so `{src,q}` removed `src` from trivy on one `mkdir`.
        for name in self.HOSTILE + self._PREDICATE_ONLY:
            self.assertFalse(vs.expressible_as_exclusion(name), repr(name))
        for name in (".venv", "venv", "env", "a/b/.venv", "my-venv",
                     "venv.old", "_env", "V1.2_env"):
            self.assertTrue(vs.expressible_as_exclusion(name), repr(name))
    def test_a_relative_component_is_never_expressible(self):
        for name in (".", "..", "a/..", "../a", "a//b", "a/", "/a", "", "-a/b"):
            self.assertFalse(vs.expressible_as_exclusion(name), repr(name))
    def test_bandit_always_carries_the_scanner_owned_exclusions(self):
        # bandit's ini is fail-OPEN on arrival: `parse_ini_file` catches a parse
        # failure, warns, and bandit runs on CLI args alone. So the CLI carries
        # the exclusions unconditionally -- under redteam there is no venv to
        # skip, and the ini used to be the only thing carrying `.worktrees`.
        cmd = vs._with_venv_excludes("bandit", list(rt.TOOL_CMD["bandit"]), [])
        flag = [a for a in cmd if a.startswith("--exclude=")]
        self.assertEqual(len(flag), 1, cmd)
        entries = flag[0][len("--exclude="):].split(",")
        for owned in rt.BANDIT_SCANNER_EXCLUDES:
            self.assertIn(owned, entries)
    def test_a_bare_marker_row_is_refused_by_the_argv_builder_too(self):
        # Belt: the skip list and the argv are built in different functions, so
        # the rule is enforced in both. A caller that hands the raw list in gets
        # no flag for it.
        dirs = [{"path": "src", "reason": vs.VENV_MARKER_NO_SHAPE},
                {"path": ".venv", "reason": vs.VENV_MARKER}]
        cmd = vs._with_venv_excludes("semgrep", list(rt.TOOL_CMD["semgrep"]), dirs)
        self.assertEqual([a for a in cmd if a.startswith("--exclude=")],
                         ["--exclude=.venv"])
