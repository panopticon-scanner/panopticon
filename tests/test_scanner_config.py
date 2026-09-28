"""The scanner-owned configuration block's own tests (#1762 ARC-2609514778).

`scripts.scanner_config` was lifted out of `run_tools` whole in split 1 of 3, so
the centre of this file is a PARITY golden rather than new behaviour: the docker
argv every tool pinned to a scanner-owned config is launched with, captured from
the tree before the move and compared token for token after it. A pure
extraction that changes one flag, one path or one flag's POSITION is not a pure
extraction, and nothing else in the suite compares a whole argv.
"""
import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

import scripts.run_tools as rt
import scripts.scanner_config as sc

from tests.run_tools_test_helpers import _FakeResult

# Four tokens on the argv are host-specific and cannot be pinned: the docker
# binary `executable.resolve` found, the scan target's own temporary directory,
# the per-launch scratch the staged config lives in and the per-launch cidfile
# (each a fresh `mkdtemp`, by design). Each is replaced by a placeholder and
# NOTHING else is: every flag, every value and the order they sit in are
# compared literally.
_DOCKER = "<docker>"
_TARGET = "<target>"
_STAGED = "<staged>"
_CIDFILE = "<cidfile>"


def _normalise(argv, target):
    """*argv* with the four host-specific tokens replaced by placeholders.

    The staged config keeps its BASENAME (`bandit.ini`, `.trivyignore`): which
    file was staged is the claim, and only the scratch directory holding it is
    unpinnable. The cidfile has no such half -- the whole path is per-launch.
    """
    inside = "%s/" % rt.SCANNER_CONFIG_MOUNT
    out, previous = [_DOCKER], None
    for token in argv[1:]:
        original = token
        if previous == "--cidfile":
            token = _CIDFILE
        elif token.startswith(target + ":"):
            token = _TARGET + token[len(target):]
        elif ":" + inside in token:
            host, mount = token.split(":", 1)
            token = "%s/%s:%s" % (_STAGED, os.path.basename(host), mount)
        out.append(token)
        previous = original
    return out


def _argv_cases():
    """Every case the golden pins: each tool `SCANNER_OWNED_CONFIG` stages, in
    both security modes, with and without a `.bandit` in the target.

    The third dimension is not decoration. The owner ruling of 2026-09-25 on
    #1924 splits bandit's `--ini` by MODE *and* by whether the operator
    committed one, and that branch also takes bandit's own `-s` list off the
    argv (`_without_skip_list`) -- four argv shapes from one table entry, all of
    them built by moved code.
    """
    for tool in sorted(rt.SCANNER_OWNED_CONFIG):
        for mode in rt.SECURITY_MODES:
            for planted in (False, True):
                yield ("%s/%s/%s" % (tool, mode,
                                     "own-ini" if planted else "no-ini"),
                       tool, mode, planted)


def _dispatch_argv(tool, security_mode, planted):
    """The normalised docker argv one faked launch of *tool* really builds.

    Through `run_tools()`, the public entry the dispatch tests already use, so
    the golden is the argv the production loop assembles and not one this test
    composes from the pieces. The three container ceilings are pinned to their
    documented defaults because they are read from the environment at import:
    an operator with `PANOPTICON_TOOL_CPUS` set would otherwise fail a parity
    check about something this split does not touch.
    """
    calls = []

    def runner(cmd, **_kw):
        calls.append(list(cmd))
        return _FakeResult(returncode=0, stdout=b'{"runs":[]}', stderr=b'')
    with tempfile.TemporaryDirectory() as d:
        if planted:
            with open(os.path.join(d, ".bandit"), "w", encoding="utf-8") as fh:
                fh.write("[bandit]\nexclude = vendor\ntests = B101\n")
        with mock.patch.object(rt, "CONTAINER_MEMORY", "6g"), \
                mock.patch.object(rt, "CONTAINER_CPUS", "4"), \
                mock.patch.object(rt, "CONTAINER_PIDS_LIMIT", "1024"), \
                contextlib.redirect_stderr(io.StringIO()):
            rt.run_tools(d, [tool], os.path.join(d, "out"), runner=runner,
                         venv_dirs=[], security_mode=security_mode)
        if len(calls) != 1:
            raise AssertionError("expected one docker launch for %s, got %d"
                                 % (tool, len(calls)))
        return _normalise(calls[0], os.path.abspath(d))


# Captured from the tree at the commit this split branched from, BEFORE any code
# moved (the command is in the PR's implementation notes). A difference here is
# the extraction being wrong: fix the extraction, never this table.
GOLDEN = {
    "bandit/redteam/no-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/bandit.ini:/panopticon-config/bandit.ini:ro", "--network", "none",
        "-v", "<target>:/src:ro", "panopticon-tools", "bandit", "--ini",
        "/panopticon-config/bandit.ini", "--ignore-nosec", "-q", "-r",
        "--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees",
        "/src", "-s", "B101,B404,B110,B112", "-f", "sarif"
    ],
    "bandit/redteam/own-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/bandit.ini:/panopticon-config/bandit.ini:ro", "--network", "none",
        "-v", "<target>:/src:ro", "panopticon-tools", "bandit", "--ini",
        "/panopticon-config/bandit.ini", "--ignore-nosec", "-q", "-r",
        "--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees",
        "/src", "-s", "B101,B404,B110,B112", "-f", "sarif"
    ],
    "bandit/standard/no-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/bandit.ini:/panopticon-config/bandit.ini:ro", "--network", "none",
        "-v", "<target>:/src:ro", "panopticon-tools", "bandit", "--ini",
        "/panopticon-config/bandit.ini", "-q", "-r",
        "--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees",
        "/src", "-s", "B101,B404,B110,B112", "-f", "sarif"
    ],
    "bandit/standard/own-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "--network",
        "none", "-v", "<target>:/src:ro", "panopticon-tools", "bandit", "--ini",
        "/src/.bandit", "-q", "-r",
        "--exclude=.svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.worktrees",
        "/src", "-f", "sarif"
    ],
    "trivy/redteam/no-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/.trivyignore:/panopticon-config/.trivyignore:ro", "--network",
        "none", "-v", "<target>:/src:ro", "panopticon-tools", "trivy", "fs",
        "--skip-db-update", "--offline-scan", "--format", "sarif",
        "--ignorefile=/panopticon-config/.trivyignore", "/src"
    ],
    "trivy/redteam/own-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/.trivyignore:/panopticon-config/.trivyignore:ro", "--network",
        "none", "-v", "<target>:/src:ro", "panopticon-tools", "trivy", "fs",
        "--skip-db-update", "--offline-scan", "--format", "sarif",
        "--ignorefile=/panopticon-config/.trivyignore", "/src"
    ],
    "trivy/standard/no-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/.trivyignore:/panopticon-config/.trivyignore:ro", "--network",
        "none", "-v", "<target>:/src:ro", "panopticon-tools", "trivy", "fs",
        "--skip-db-update", "--offline-scan", "--format", "sarif",
        "--ignorefile=/panopticon-config/.trivyignore", "/src"
    ],
    "trivy/standard/own-ini": [
        "<docker>", "run", "--cidfile", "<cidfile>", "--rm", "--memory", "6g",
        "--memory-swap", "6g", "--cpus", "4", "--pids-limit", "1024", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "-w", "/panopticon-empty-cwd", "-v",
        "<staged>/.trivyignore:/panopticon-config/.trivyignore:ro", "--network",
        "none", "-v", "<target>:/src:ro", "panopticon-tools", "trivy", "fs",
        "--skip-db-update", "--offline-scan", "--format", "sarif",
        "--ignorefile=/panopticon-config/.trivyignore", "/src"
    ],
}


class TestTheDockerArgvSurvivesTheExtraction(unittest.TestCase):
    """#1762 split 1/3 is a pure move, and this is what "pure" is allowed to
    mean: every scanner-owned config launch builds the same argv it built
    before the block left `run_tools`.

    The argv is the whole product of this block -- the `--ini`/`--ignorefile`
    pin, the `-v` config mount, the suppression knob under redteam, the skip
    list that comes off when the operator's own ini is honoured -- and each of
    those is assembled by a different moved function. One golden per case
    catches a dropped flag, a re-ordered insert and a mount that lost its `:ro`
    in the same assertion.
    """

    def test_every_scanner_owned_config_argv_matches_the_pre_split_golden(self):
        for label, tool, mode, planted in _argv_cases():
            with self.subTest(case=label):
                self.assertEqual(GOLDEN[label],
                                 _dispatch_argv(tool, mode, planted))

    def test_the_golden_pins_every_case_and_no_stale_one(self):
        # Vacuity guard. A `SCANNER_OWNED_CONFIG` that lost an entry, or a mode
        # that stopped being generated, makes the loop above pass by iterating
        # over less -- which is the one way a golden goes quiet.
        self.assertEqual(sorted(GOLDEN),
                         sorted(label for label, *_rest in _argv_cases()))


class TestTheStagedConfigIsTheScannersOwn(unittest.TestCase):
    """The three assertions that read nothing but this module's own constants.

    Moved here unchanged from `tests/test_run_tools_core.py` and
    `tests/test_run_tools_dispatch.py` when #1762 part 1 moved what they pin:
    every other test of the staged config drives the whole dispatch loop and so
    still belongs beside `run_tools`.
    """

    def test_the_ini_holds_exactly_one_key_and_no_target_text(self):
        lines = [ln for ln in sc.BANDIT_INI_TEXT.splitlines() if ln.strip()]
        self.assertEqual(lines[0], "[bandit]")
        self.assertEqual(len([ln for ln in lines if "=" in ln]), 1)
        self.assertEqual(len(lines), 2)
        value = lines[1].split("=", 1)[1]
        for owned in sc.BANDIT_SCANNER_EXCLUDES:
            self.assertIn(owned, [e.strip() for e in value.split(",")])

    def test_no_scanner_owned_exclude_entry_can_split_or_inject(self):
        # A future entry with a comma would inject a second exclusion; one with
        # a newline would inject a second ini KEY. Neither is a target input --
        # which is exactly why it has to be pinned here rather than validated at
        # runtime on data nobody can supply.
        for entry in tuple(sc.BANDIT_DEFAULT_EXCLUDES) + tuple(sc.BANDIT_SCANNER_EXCLUDES):
            for char in (",", "\n", "\r", "="):
                self.assertNotIn(char, entry, entry)

    def test_the_ignorefile_declares_nothing(self):
        # Every non-comment line would be a vulnerability id trivy stops
        # reporting, so there are none -- and no target-derived text either.
        active = [ln for ln in sc.TRIVY_IGNOREFILE_TEXT.splitlines()
                  if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertEqual(active, [])


class TestTheTwoModulesShareOneLedger(unittest.TestCase):
    """`run_tools` binds the two posture ledgers by name (`write_manifest`'s own
    `scanner_config=` keyword would shadow the module inside it), so the whole
    claim rests on both names addressing ONE dict: `run_tools()` clears it, the
    recorders here fill it, `write_manifest` reads it back. Rebind either side
    and the manifest would publish an empty posture with nothing failing."""

    def test_the_posture_ledgers_are_the_same_object_in_both_modules(self):
        for name in ("_SUPPRESSION_POSTURE", "_SCANNER_CONFIG_POSTURE"):
            with self.subTest(ledger=name):
                self.assertIs(getattr(rt, name), getattr(sc, name))

    def test_a_moved_name_a_test_may_patch_is_not_also_bound_on_run_tools(self):
        # A second binding is a patch target that reaches nothing: the moved code
        # looks these up in `scanner_config`, so an alias here would let
        # `mock.patch.object(run_tools, ...)` pass while changing no behaviour.
        for name in ("SUPPRESSION_COMMENTS", "_adapter_ignore_overlay",
                     "_ignore_path_identity", "_scanner_owned_config",
                     "_record_suppression_posture", "_record_scanner_config",
                     "_suppression_flag_on", "_adapter_security_mode",
                     "_staged_scanner_file", "_gitleaks_ignore_overlay",
                     "_insert_flags", "_without_skip_list"):
            with self.subTest(name=name):
                self.assertTrue(hasattr(sc, name), "%s left scanner_config" % name)
                self.assertFalse(hasattr(rt, name),
                                 "%s is bound on run_tools too; patching it "
                                 "there would be silently ineffective" % name)


if __name__ == "__main__":
    unittest.main()
