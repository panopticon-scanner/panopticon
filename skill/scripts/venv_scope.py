#!/usr/bin/env python3
"""The virtualenv scope: which directories the scanners are kept OUT of.

Three answers, one block. WHERE the virtualenvs under the target are --
`find_virtualenvs`, a depth-bounded, confinement-checked walk keyed on a
`pyvenv.cfg` marker plus the SHAPE of an installed environment, with the
conventional `venv`/`.venv` names as the fallback. WHICH of them a scanner's
exclusion knob may be handed at all -- `partition_venv_dirs` under the security
mode, `expressible_as_exclusion` on the directory NAME and `has_venv_shape` on
the evidence, because both the name and the marker are target input. And WHAT
that comes out as on each tool's argv -- `_with_venv_excludes`, plus bandit's
single comma-joined `--exclude=` value, composed here because its venv half is.

`partition_venv_dirs` returns the skip list AND the manifest rows, and the ROWS
are `tools_manifest.write_manifest`'s to publish, as `excluded_dirs` beside the
`depth_bound` this walk is bounded by: one row per DETECTED directory either way,
`skipped` saying whether the scanners were told to leave it alone, so a report
can state that a directory was scanned instead of leaving a reader to infer it
from an absence. `ingest_tools` reads those rows back (`scan_skipped_venvs`) and
imports `has_venv_shape` and `VENV_MARKER` from here rather than restating them,
so the scan side and the ingest side cannot come to disagree about what a
virtualenv is (#1839).

Separate from `run_tools` because that module was 2215 lines, outside this repo's
own 700-line ratchet, and absorbing every new scanner policy because nothing
pushed back (#1762, ARC-2609514778). This is part 4 of that split and it moved
the block whole: no argv byte, no manifest row and no message changed, and
`tests/test_venv_scope.py` compares the walk, both partitions and twenty-four
argv shapes against a golden captured before the move.

The arrow points ONE way: nothing here imports `run_tools`, which imports this.
`VENV_MAX_DEPTH` is `tools_manifest`'s because the manifest publishes it as
`depth_bound`; the two bandit exclude tuples are `scanner_config`'s because the
staged ini is built from them; `REDTEAM` is `tools.base`'s, the one owner of the
`--security` vocabulary. This module reads all three and none of them reads it.
Stdlib-only.
"""
import os
import re

# The two tuples bandit's single `--exclude=` value starts from: `scanner_config`
# owns them (`BANDIT_INI_TEXT` is built from them at import) and this module owns
# what gets added to them. No cycle -- `scanner_config` imports nothing here.
from scripts.scanner_config import BANDIT_DEFAULT_EXCLUDES, BANDIT_SCANNER_EXCLUDES
# The `--security` vocabulary's one owner (`scanner_config` reads `REDTEAM` from
# here too). `run_tools` keeps its own pair of the same names for its argparse
# `choices`: `security_gate` imports it, so it must not import the gate.
from scripts.tools.base import REDTEAM
# The walk bound, bound at `def` time as `find_virtualenvs`' `max_depth` default.
# It lives with the manifest that publishes it as `depth_bound` (part 3).
from scripts.tools_manifest import VENV_MAX_DEPTH


# #1638 P09 (owner ruling D8): virtualenvs are vendored code, so the scanners
# are kept out of them rather than only having their findings dropped at ingest.
# `pyvenv.cfg` is the marker every creator writes (venv, virtualenv, uv, pipenv,
# in-project poetry); the conventional names are the fallback for a venv built
# by something that wrote no marker. Depth-bounded by `VENV_MAX_DEPTH`, which is
# bound above out of `tools_manifest` (the manifest publishes it as
# `depth_bound`): venvs live near the root, and this walk is paid on every scan.
VENV_MARKER = "pyvenv.cfg"
VENV_DIR_NAMES = ("venv", ".venv")
_VENV_WALK_PRUNE = {".git", "node_modules", "__pycache__"}

# #1839 (run-14 SEC-1486247143): the marker alone is a CLAIM the reviewed
# repository can make in one committed file, and on the strength of it the
# runner told semgrep, trivy and bandit to skip the directory holding it -- so
# `src/pyvenv.cfg` removed `src/` from the scan CI's merge gate reads, silently.
# A directory flagged on the marker must also have the SHAPE of an installed
# environment; a bare marker beside real source gets this reason instead and is
# never handed to a scanner's exclusion knob.
VENV_MARKER_NO_SHAPE = "pyvenv.cfg-without-shape"
# Where every creator puts an interpreter (venv, virtualenv, uv, pipenv,
# in-project poetry all write `bin/python`; Windows layouts use `Scripts`).
_VENV_INTERPRETERS = (("bin", "python"), ("bin", "python3"),
                      ("Scripts", "python.exe"), ("Scripts", "pythonw.exe"))
_VENV_SITE_PACKAGES = "site-packages"
# How many `lib/` entries `has_venv_shape` will look at. A real venv has one
# `python3.x` directory there; the bound is what stops a hostile sibling list
# from turning one stat into a million (review round 1 N7).
_VENV_LIB_SCAN = 64


def has_venv_shape(directory):
    """True when *directory* is STRUCTURED like an installed Python environment.

    An interpreter where a creator puts one, or a `lib/python*/site-packages`
    (POSIX) / `Lib/site-packages` (Windows) tree. At most one `listdir` per
    candidate directory, bounded to its first `_VENV_LIB_SCAN` entries, so
    neither the walk above nor the ingest's per-directory lookup can be made
    expensive by a `lib/` holding a million names beside a marker.

    The interpreter may be a SYMLINK out of the target, and that is deliberate:
    `python -m venv` creates `bin/python` as a link to the base interpreter, so
    refusing a link here would misclassify almost every real virtualenv. It is
    one more reason this predicate is a cost increase for an attacker rather
    than a proof (see below).

    Not a proof of authenticity, and not offered as one: a target can write
    three files as easily as one. It is the cheap half of #1839. The dear half
    is `partition_venv_dirs`, which stops handing ANY virtualenv to a scanner's
    exclusion knob under `--security redteam` and discloses every one it still
    skips under `standard`.
    """
    for parts in _VENV_INTERPRETERS:
        if os.path.isfile(os.path.join(directory, *parts)):
            return True
    for lib in ("lib", "Lib"):
        libdir = os.path.join(directory, lib)
        if os.path.isdir(os.path.join(libdir, _VENV_SITE_PACKAGES)):
            return True
        try:
            names = sorted(os.listdir(libdir))[:_VENV_LIB_SCAN]
        except OSError:
            continue
        for name in names:
            if name.startswith("python") and os.path.isdir(
                    os.path.join(libdir, name, _VENV_SITE_PACKAGES)):
                return True
    return False


# An ALLOWLIST of what a directory name may contain before any scanner's
# exclusion knob will be handed it (#1839; review round 1 C1/I1 replaced the
# four-character denylist this started as).
#
# Each knob reads the value in its OWN language and none of them can quote:
#   semgrep `--exclude`   gitignore-flavoured globs
#   trivy `--skip-dirs`   doublestar globs -- which include `{a,b}` ALTERNATION,
#                         so `{src,q}` removes a `src/` the target does not own
#   bandit `--exclude`    a COMMA-joined list, substring-matched, so a directory
#                         named `a,b` injects the bare entry `b` and blinds
#                         bandit on every path containing the letter b
# A denylist has to enumerate every one of those languages correctly, forever. An
# allowlist has to be right once: a name outside it is SCANNED and named on its
# manifest row (`skipped: false` + a `note`), which is the fail-closed direction
# ruling 5 asks for. Conservative on purpose -- `+`, `@`, `~`, `!`, spaces and
# every non-ASCII letter are refused even where some matchers would carry them,
# because the cost of refusing is a directory that gets scanned.
_EXPRESSIBLE_COMPONENT = re.compile(r"\A[A-Za-z0-9._][A-Za-z0-9._-]*\Z")


def expressible_as_exclusion(path):
    """True when *path* can be handed to a scanner's exclusion knob AS ITSELF.

    Every `/`-separated component must match `_EXPRESSIBLE_COMPONENT`: ASCII
    letters, digits, `.`, `_` and `-`, never leading `-` (which the attached
    `--flag=value` form already defends against, kept as belt), and never the
    relative components `.`/`..` or an empty one.

    A directory whose name no exclusion value can carry is scanned, and the
    manifest row says why -- turning it into a wildcard would hand the target the
    whole tree, and dropping it silently would be the same loss without the
    disclosure.
    """
    text = str(path)
    if not text or text in (".", ".."):
        return False
    parts = text.split("/")
    return all(part not in (".", "..") and _EXPRESSIBLE_COMPONENT.match(part)
               for part in parts)


def find_virtualenvs(target, max_depth=VENV_MAX_DEPTH):
    """Virtualenv directories under *target*, repo-relative, with their reason.

    Returns ``[{"path": ".venv", "reason": <one of VENV_MARKER, "name",
    VENV_MARKER_NO_SHAPE>}, ...]`` sorted by path. A directory flagged as a venv
    is never descended into (a venv inside a venv is the same exclusion), and
    `reason` is what the tools manifest discloses so a report can say what was
    pruned and on what evidence. #1839: the third reason is the one that is NOT
    a virtualenv -- a `pyvenv.cfg` with no environment under it -- which is
    reported, walked into, and never skipped.

    CONFINED to the target, like the ingest half: `os.walk` will not descend a
    symlink, but `os.path.isfile` follows one, so a link pointing at a venv
    OUTSIDE the target would otherwise be stat'd and flagged (#1638 P09 F1).
    Every candidate is resolved and anything landing outside the resolved root
    is skipped -- and not walked into either. A link that stays inside the
    target still counts: it resolves to a venv of this target.

    DEPTH-BOUNDED, so this list is a subset of what ingest prunes: the manifest
    records what the SCANNERS were told to skip, while `ingest_tools` drops a
    finding from a virtualenv (or a `site-packages`) at ANY depth. A venv nested
    deeper than *max_depth* costs scan time and produces no findings.
    """
    root = os.path.realpath(target)
    found = {}
    for dirpath, dirnames, _files in os.walk(root, followlinks=False):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == os.curdir else rel.count(os.sep) + 1
        dirnames[:] = [d for d in sorted(dirnames) if d not in _VENV_WALK_PRUNE]
        if depth >= max_depth:
            dirnames[:] = []
            continue
        keep = []
        for name in dirnames:
            child = os.path.join(dirpath, name)
            real = os.path.realpath(child)
            if not (real == root or real.startswith(root + os.sep)):
                continue      # resolves outside the target: not ours to flag
            marker = os.path.isfile(os.path.join(child, VENV_MARKER))
            if marker and has_venv_shape(child):
                reason = VENV_MARKER
            elif name in VENV_DIR_NAMES:
                reason = "name"
            elif marker:
                # #1839: a marker with no environment under it. Reported, so an
                # operator sees the plant, and KEPT in the walk -- as far as the
                # scan is concerned this is ordinary source, so a real
                # virtualenv nested inside it must still be found.
                reason = VENV_MARKER_NO_SHAPE
                keep.append(name)
            else:
                keep.append(name)
                continue
            found[os.path.relpath(child, root).replace(os.sep, "/")] = reason
        dirnames[:] = keep   # never walk into a directory already excluded
    return [{"path": p, "reason": found[p]} for p in sorted(found)]


# #1839: why a DETECTED directory was scanned anyway. Published on the manifest
# row, because "not in the skip list" and "nobody looked" are indistinguishable
# from an absence.
_NOT_A_VENV_NOTE = ("scanned: a %s with no interpreter or site-packages under "
                    "it is not an installed environment" % VENV_MARKER)
_UNEXPRESSIBLE_NOTE = ("scanned: the directory name cannot be handed to an "
                       "exclusion knob without changing its meaning (only "
                       "[A-Za-z0-9._-] path components can), so it is scanned "
                       "rather than expressed as a pattern")


def partition_venv_dirs(venv_dirs, security_mode="standard"):
    """Split detected virtualenvs into (told-to-skip, manifest rows) (#1740).

    `find_virtualenvs` flags a directory three ways, and they are not the same
    claim. `pyvenv.cfg` plus the shape of an environment is EVIDENCE the tree is
    installed; `"name"` is a convention -- a directory called `venv` with
    nothing in it saying so; `VENV_MARKER_NO_SHAPE` is a marker file with no
    environment under it, which is not a virtualenv at all.

    Under `--security redteam` the target is untrusted and a finding may not be
    lost to a directory NAME, which is what `security_gate` enforces at ingest.
    Telling semgrep, trivy and bandit to skip `app/venv/` made that enforcement
    moot for three scanners: there was no finding left to re-admit. #1740
    stopped handing the name-only directories to any exclusion knob under
    redteam; #1839 extends that to the marker-confirmed ones, because a file the
    same target WROTE is more attacker-controlled than a name it chose, not
    less. So under redteam this function hands the scanners NOTHING.

    Under `standard` the skip stands, which is #1638 P09's whole point (58
    bandit findings from run-13's `.venv/` bought 46 of 128 advisor dispatches)
    -- but it is no longer invisible: `ingest_tools.scan_skipped_venvs` reads
    the rows back out of the manifest and the drop is tallied and named under
    `ingest_tools.MARKER_VENV_SEGMENT`, on `security_gate`'s verdict line and in
    `meta.coverage.tools_suppressed`.

    TWO kinds are never skipped, in either mode (#1839):
      - a marker with no environment under it, which is ordinary source;
      - a directory whose name cannot be expressed as an exclusion (a path
        component outside `[A-Za-z0-9._-]`: a glob metacharacter, a brace, a
        comma, whitespace, a control byte, non-ASCII, or a leading `-`).
    Both are disclosed: the row says `skipped: False` and carries a `note`
    saying why, because a directory nobody can express as an exclusion must be
    scanned AND visible, not dropped from the list.

    The second return value is what `write_manifest` publishes, one row per
    DETECTED directory either way -- `skipped` says whether the scanners were
    told to leave it alone, so a report can say the directory was scanned
    rather than leaving the reader to infer it from an absence.
    """
    redteam = security_mode == REDTEAM
    skip, rows = [], []
    for entry in venv_dirs or ():
        path, reason = entry["path"], entry["reason"]
        if reason == VENV_MARKER_NO_SHAPE:
            note = _NOT_A_VENV_NOTE
        elif not expressible_as_exclusion(path):
            note = _UNEXPRESSIBLE_NOTE
        else:
            note = None
        skipped = note is None and not redteam
        if skipped:
            skip.append(entry)
        row = {"path": path, "reason": reason, "skipped": skipped}
        if note:
            row["note"] = note
        rows.append(row)
    return skip, rows


# The exclusion knob each legacy SARIF scanner already exposes, repeated once
# per venv directory. NOT listed, deliberately: `gitleaks` (v8 has no path-
# exclusion flag -- its allowlist is a config file, and inventing one would just
# make the tool exit 2) and `gosec` (`./...` loads Go packages, so it never
# enters a Python virtualenv at all). `bandit` has one too but takes a single
# comma-separated value, so it is built separately below. Whatever a scanner
# still reports from a venv is dropped by ingest_tools anyway -- this half only
# saves the walk.
_VENV_EXCLUDE_FLAG = {"semgrep": "--exclude", "trivy": "--skip-dirs"}


def _bandit_exclude_value(venv_dirs):
    """bandit's single `--exclude=` value: its own parser defaults, the
    exclusions the scanner owns, then this run's virtualenvs as CONTAINER paths
    (`/src/...`, which is where bandit sees them; it substring-matches, so the
    anchored form cannot catch an unrelated `prevent.py`). Deduplicated, order
    preserved.

    Nothing in it is read out of the target (#1839). It used to merge the
    `exclude` entries of the target's own `.bandit` -- a file `run_tools` also
    PINNED with `--ini`, so the reviewed repository chose bandit's `exclude`,
    and through the same file its `tests` and `skips`: a committed
    `tests = B999` would have reduced the merge gate's Python SAST to one check,
    which no exclusion merge mitigates.

    A directory NAME is target input too (review round 1 C1): this value is
    comma-joined and bandit substring-matches each entry, so a venv named `a,b`
    used to inject the bare entry `b`. Only `expressible_as_exclusion` paths get
    in, and only marker- or name-confirmed ones -- a `VENV_MARKER_NO_SHAPE` row
    is not a virtualenv and belongs in no exclusion (belt for
    `partition_venv_dirs`, which builds the skip list in another function).
    """
    entries = list(BANDIT_DEFAULT_EXCLUDES) + list(BANDIT_SCANNER_EXCLUDES)
    entries += ["/src/%s" % d["path"] for d in _excludable(venv_dirs)]
    return ",".join(dict.fromkeys(entries))


def _excludable(venv_dirs):
    """The rows a scanner's exclusion knob may be handed at all (#1839)."""
    return [d for d in venv_dirs or ()
            if d.get("reason") != VENV_MARKER_NO_SHAPE
            and expressible_as_exclusion(d["path"])]


def _with_venv_excludes(tool, cmd, venv_dirs, target=None):
    """`cmd` with this tool's own exclusion knob set for each venv directory.

    The flags go BEFORE the trailing `/src` positional so the scan target stays
    last, in the ATTACHED `--flag=value` form so a directory named `-rf` can
    never read as an option, and the paths are root-relative because that is
    what both repeatable tools match against (trivy cleans `--skip-dirs` and
    compares it to the path relative to the scan root, so a container-absolute
    `/src/.venv` would silently match nothing).

    #1839: only an `expressible_as_exclusion` path is ever passed, in either
    form. Both repeatable flags take PATTERNS, so a directory literally named
    `*` was `--exclude=*` -- the whole tree out of semgrep's and trivy's scope on
    one `mkdir` -- and bandit's comma-joined value splits on a name holding a
    comma. Such a directory is scanned and named on its manifest row by
    `partition_venv_dirs` instead. *target* is accepted and NO LONGER READ: the
    bandit value is composed from scanner-owned entries only.

    bandit gets its `--exclude=` on EVERY run, venv or none: its scanner-owned
    entries (`.worktrees` and bandit's own parser defaults) have to reach the
    argv whether or not the ini arrived, because an ini that fails to arrive is
    fail-open. semgrep and trivy keep the "no venv, no flag" shape -- their
    scanner-owned exclusions are in their own configs, not here.

    Accepted trade-off (#1638 P09 F4): trivy's python-pkg analyzer reads
    `.dist-info`/`.egg-info` METADATA under `site-packages`, so skipping the
    venv also drops that installed-package surface. Ruling 3 protects the five
    ROOT-level manifests (`requirements*.txt`, `pyproject.toml`, `Pipfile.lock`,
    `poetry.lock`, `uv.lock`), which no skip-dir covers; a target whose only
    dependency evidence is an installed venv loses trivy's view of it, and
    ingest's `site-packages` rule would have dropped those findings regardless.
    """
    if tool == "bandit":
        extra = ["--exclude=%s" % _bandit_exclude_value(venv_dirs)]
    else:
        flag = _VENV_EXCLUDE_FLAG.get(tool)
        if not flag or not venv_dirs:
            return cmd
        extra = ["%s=%s" % (flag, d["path"]) for d in _excludable(venv_dirs)]
    at = cmd.index("/src") if "/src" in cmd else len(cmd)
    return cmd[:at] + extra + cmd[at:]
