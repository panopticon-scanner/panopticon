#!/usr/bin/env python3
"""Detect the panopticon-tools Docker image and run selected scanners against a
read-only mount of the target. Scan-time network is DISABLED for all tools
(assets are baked into the image); parse-only adapters never execute target
code; roslyn-secguard executes target build logic inside a no-egress,
no-secret container (recorded in report meta); pip-audit/npm-audit run only
under --online. Degrades gracefully when Docker is absent. Stdlib-only.
"""
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts import groups_schema
from scripts import executable
from scripts.tools import ADAPTERS, ONLINE_ONLY
from scripts.tools import egress
from scripts.tools.base import drain_stderr_async
from scripts import plan_contract
from scripts import redact
from scripts import safe_write
from scripts.progress import NullProgress, make_progress
from scripts.tools.legacy_sarif import LEGACY_SARIF_TOOLS, TOOL_CMD

# JS/TS SAST runs via the eslint-security ADAPTER (bundled flat config);
# the legacy bare-eslint tool can never run on arbitrary targets (eslint >=9
# requires a project eslint.config.js) and was retired from language selection
# (calibration 2026-08-03: perpetual "tool eslint exited 2; skipping").
LANG_TOOL = {"python": "bandit", "go": "gosec"}

# Phase 1 adapters selected by ecosystem detection; they are dispatched through
# _run_adapter.py inside the panopticon-tools container.
PHASE1_ADAPTERS = {"pip-audit", "npm-audit", "osv-scanner", "eslint-security"}

# Phase 2 adapters selected by applicability to the target repo.
PHASE2_ADAPTERS = {
    "brakeman", "bundler-audit", "spotbugs", "dependency-check",
    "cargo-audit", "roslyn-secguard",
}

# Always-on SARIF scanners select_tools seeds regardless of language.
BASE_TOOLS = {"semgrep", "gitleaks", "trivy"}


def recommendable_tools(languages=None, target=None):
    """The scanner universe the scout may recommend from.

    Ungated (no args) this is the full ground truth run_tools can select (#1053):
    the always-on SARIF tools + every language-keyed SAST tool + the Phase-1/2
    adapters. An ungrounded scout would otherwise invent pytest/pylint/ruff/...
    (none are adapters), which #1031 could only disclose as requested_unavailable
    noise after the fact. Excludes the retired bare `eslint` (eslint >=9 can't run
    on arbitrary targets; JS/TS SAST runs via the eslint-security adapter).

    run-9 (E1): a scout handed the FULL universe requests brakeman/gosec/cargo-audit
    /spotbugs/roslyn-secguard/... on a pure-Python repo -- tools the runner can
    never select, so each becomes a `requested_unavailable` disclosure. Passing
    `languages` (from detect_languages) filters the language-keyed SAST to those
    languages, and `target` filters the adapters to those actually applicable
    (select_adapters) -- so the scout sees exactly the set the runner would select
    and cannot manufacture cross-language over-request noise. The always-on SARIF
    tools stay offered (broadly applicable)."""
    lang_tools = set(LANG_TOOL.values())
    if languages is not None:
        lang_tools = {LANG_TOOL[lang] for lang in languages if lang in LANG_TOOL}
    adapters = PHASE1_ADAPTERS | PHASE2_ADAPTERS
    if target is not None:
        adapters &= set(select_adapters(target).keys())
    return sorted(BASE_TOOLS | lang_tools | adapters)

# Max seconds to let a single docker-run tool invocation run before it's killed;
# prevents a hung tool from blocking the whole batch (CD-007).
TOOL_TIMEOUT = 900
# The gating docker probe runs before any tool; bound it so a wedged daemon
# socket cannot hang the whole scan pipeline (#1112).
DOCKER_PROBE_TIMEOUT = 30

# #run8 OPS-D1A: bound the blast radius of an adversarial target that drives a
# scanner to allocate pathologically. TOOL_TIMEOUT bounds wall-clock and
# MAX_TOOL_OUTPUT_BYTES bounds captured stdout, but NEITHER bounds the
# in-container memory/CPU/PID footprint while a tool runs -- an OOM inside the
# container (a recursive archive fed to dependency-check, a pathological input
# to a SAST parser) can exhaust or destabilize the host/CI runner well before
# the 900s timeout or the output cap is reached. Every `docker run` gets a hard
# resource ceiling. Operators can retune via env without a code change; setting
# a value to the empty string drops that individual flag (e.g. on a cgroup that
# rejects --pids-limit).
CONTAINER_MEMORY = os.environ.get("PANOPTICON_TOOL_MEMORY", "6g")
CONTAINER_CPUS = os.environ.get("PANOPTICON_TOOL_CPUS", "4")
CONTAINER_PIDS_LIMIT = os.environ.get("PANOPTICON_TOOL_PIDS", "1024")


def _privilege_drop_flags():
    """Privilege-drop flags applied to every tool/adapter container (#run10
    SEC-C1A).

    This dispatch path runs attacker-influenced build logic -- a .csproj/.targets
    can execute arbitrary code through build targets, and the module's own
    docstring calls the roslyn path 'executes target build logic'. The container
    had CPU/memory/PID ceilings and `--network none`, but nothing stopped a
    process inside it from using Linux capabilities or gaining new privileges via
    a setuid binary.

    --cap-drop=ALL: a scanner needs no capabilities; dropping them removes the
      whole capability-abuse class (raw sockets, mknod, chroot, ptrace-by-cap).
    --security-opt=no-new-privileges: a setuid/setgid binary inside the image can
      no longer raise privileges beyond the starting set.

    NOT applied here: `--read-only`. Scanners legitimately write inside the
    container (dependency-check unpacks, dotnet/MSBuild builds, tools spill to
    /tmp), so a read-only rootfs needs a tuned tmpfs per tool and must be
    validated against a real tool round -- a broken tool round is a worse
    outcome than this residual. Tracked rather than half-applied.
    """
    return ["--cap-drop=ALL", "--security-opt=no-new-privileges"]


def _resource_limit_flags():
    """docker-run resource-ceiling flags applied to every tool/adapter container.

    --memory-swap is pinned equal to --memory so an adversarial allocation is
    OOM-killed at the ceiling rather than spilling into swap and merely dragging
    the host to a crawl. Any flag whose env override is empty is omitted."""
    flags = []
    if CONTAINER_MEMORY:
        flags += ["--memory", CONTAINER_MEMORY, "--memory-swap", CONTAINER_MEMORY]
    if CONTAINER_CPUS:
        flags += ["--cpus", CONTAINER_CPUS]
    if CONTAINER_PIDS_LIMIT:
        flags += ["--pids-limit", CONTAINER_PIDS_LIMIT]
    return flags


def validate_output_dir(target, out_dir):
    """Reject default artifact output through a target-controlled symlink."""
    logical_root = os.path.join(os.path.abspath(target), ".panopticon")
    candidate = os.path.abspath(out_dir)
    try:
        under_artifacts = os.path.commonpath([logical_root, candidate]) == logical_root
    except ValueError:
        under_artifacts = False
    if under_artifacts:
        safe_root = plan_contract.artifact_root(target)
        if os.path.commonpath([os.path.realpath(safe_root), os.path.realpath(candidate)]) \
                != os.path.realpath(safe_root):
            raise ValueError("scanner output escapes the target artifact directory")
    return out_dir


def docker_available(image="panopticon-tools", runner=None, target=None):
    """Check if the specified Docker image is available."""
    runner = runner or subprocess.run
    try:
        root = target or os.getcwd()
        resolved = executable.resolve("docker", root, os.environ.get("PATH", ""))
        docker_env = executable.sanitize_startup_environment(os.environ)
        docker_env["PATH"] = resolved.path_env
        res = runner([resolved.path, "image", "inspect", image],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     timeout=DOCKER_PROBE_TIMEOUT, env=docker_env)
        return getattr(res, "returncode", 1) == 0
    except (FileNotFoundError, executable.ExecutableResolutionError):
        # docker binary genuinely absent -- the one benign case; stay quiet.
        return False
    except Exception as e:  # noqa: BLE001
        # A wedged daemon (TimeoutExpired), socket permission denial, broken
        # pipe, etc. are real faults, not "no docker here". Swallowing them
        # silently let the whole tool-scan phase no-op while the run reported
        # success (OPS-E1A). Return False (skip) but say WHY on stderr.
        print("docker probe for image %r failed: %s: %s"
              % (image, type(e).__name__, e), file=sys.stderr)
        return False


_LANG_EXTS = {".py": "python", ".go": "go",
              ".js": "javascript", ".jsx": "javascript",
              ".ts": "typescript", ".tsx": "typescript"}
_DETECT_PRUNE = {".git", ".venv", "venv", "node_modules", "__pycache__",
                 ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", "tmp",
                 # #1138: vendored / generated / sample trees carry foreign-language
                 # files that are NOT the project's own source. A single stray file
                 # here used to trigger that language's SAST tool (e.g. a vendored
                 # .go making gosec run on a Python repo), which then produced
                 # nothing and read as a "selected-but-unproduced" tool-coverage
                 # gap. Prune the dirs where a foreign-language file is definitively
                 # not project source; conservatively leave tests/ alone (a real
                 # test suite IS legitimate language surface).
                 "vendor", "third_party", "third-party", "testdata", "fixtures",
                 "examples", "example", "dist", "build", "target", "site-packages",
                 "docs"}


def detect_languages(target):
    """Best-effort language detection by source-file extension.

    The bare CLI invocation (README/CI) passes no --languages, which previously
    meant the language-keyed SAST tools (bandit/gosec/eslint) NEVER ran
    (calibration 2026-08-03). Walks with noise-dir pruning; stops once every
    known language is seen.
    """
    found = set()
    want = set(_LANG_EXTS.values())
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames
                       if d not in _DETECT_PRUNE and not d.startswith(".")]
        for fn in filenames:
            lang = _LANG_EXTS.get(os.path.splitext(fn)[1].lower())
            if lang:
                found.add(lang)
                if found == want:
                    return sorted(found)
    return sorted(found)


# #1638 P09 (owner ruling D8): virtualenvs are vendored code, so the scanners
# are kept out of them rather than only having their findings dropped at ingest.
# `pyvenv.cfg` is the marker every creator writes (venv, virtualenv, uv, pipenv,
# in-project poetry); the conventional names are the fallback for a venv built
# by something that wrote no marker. Depth-bounded: venvs live near the root,
# and this walk is paid on every scan.
VENV_MARKER = "pyvenv.cfg"
VENV_DIR_NAMES = ("venv", ".venv")
VENV_MAX_DEPTH = 3
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


# #1740 (ARC-F2A): the scan half of the security mode `security_gate` keys on.
# Mirrored here rather than imported, because `security_gate` imports THIS
# module (through `ingest_tools`) and the runner must not depend on the gate.
REDTEAM = "redteam"
SECURITY_MODES = ("standard", REDTEAM)

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

# bandit's own parser default for --exclude, restated because bandit PREFERS a
# command-line --exclude over both that default and the `.bandit` ini's
# `exclude` (its `_log_option_source` takes the arg whenever it differs from the
# default) instead of merging them. Passing one without these would silently
# WIDEN the scan -- the opposite of what the flag is for.
BANDIT_DEFAULT_EXCLUDES = (".svn", "CVS", ".bzr", ".hg", ".git", "__pycache__",
                           ".tox", ".eggs", "*.egg")


# #1839 (run-14 SEC-752508850): the exclusions the SCANNER owns, beside bandit's
# own parser defaults above. `.git` is already there; a NESTED CHECKOUT is not,
# and #run7's real failure was a worktree-heavy tree. bandit substring-matches
# each entry against the path, so one spelling covers `/src/.worktrees/...` at
# any depth. This list replaces what used to be read out of the target's own
# `.bandit`: the scan's exclusions are the scanner's to choose.
BANDIT_SCANNER_EXCLUDES = (".worktrees",)
# Where the generated ini is bind-mounted in bandit's container, and its
# basename. A DIRECTORY mount, so the scratch can be created, filled and removed
# as a unit and the container never sees a half-written file.
BANDIT_INI_MOUNT = "/panopticon-bandit"
BANDIT_INI_NAME = "bandit.ini"


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


# The SCANNER-OWNED `--ini`, in full and for every run. A CONSTANT (review round
# 1 C1): the only thing this file exists to do is pre-empt bandit's discovery
# walk, and interpolating anything target-derived into it handed the reviewed
# repository the rest of the `[bandit]` section instead. Read from bandit 1.9.4:
#   * `cli/main.py:_get_options_from_ini` walks the scan targets for `.bandit`
#     files ONLY when `--ini` is absent, and exits 2 on finding two of them
#     (#run7) -- so `--ini` pre-empts that walk completely;
#   * every key it returns is fed through `_log_option_source`, which prefers the
#     INI whenever the CLI left that option at its parser default. Our argv sets
#     only `-s`, `-r`, `-q`, `-f` and `--exclude`, so `tests`, `skips`,
#     `configfile`, `targets`, `recursive`, `aggregate`, `number`, `level`,
#     `confidence` and `verbose` were all the target's to choose through one
#     directory name. `configfile` is the worst of them: it points bandit's whole
#     plugin profile at a file inside the reviewed tree.
#   * bandit reads NO other config by discovery -- `pyproject.toml` (`[tool.
#     bandit]`) and `setup.cfg` are only read when named by `-c/--configfile`
#     (`core/config.py`), which this ini never sets and the argv never passes, so
#     no scratch cwd is needed for them the way brakeman needs one.
# `exclude` is belt: the CLI carries the same entries on every bandit run, which
# is what matters, because an ini that fails to arrive or fails to parse is
# fail-OPEN (see `_scanner_owned_bandit_ini`).
BANDIT_INI_TEXT = ("[bandit]\nexclude = %s\n"
                   % ",".join(dict.fromkeys(list(BANDIT_DEFAULT_EXCLUDES)
                                            + list(BANDIT_SCANNER_EXCLUDES))))


@contextlib.contextmanager
def _scanner_owned_bandit_ini(tool, cmd):
    """`(cmd, docker mount flags)` with bandit pointed at an ini WE wrote, or
    `(None, None)` when that file could not be staged.

    #run7 is real: bandit AUTO-DISCOVERS `.bandit` files by walking the scanned
    tree, and a nested checkout (a git worktree, a vendored repo) carrying a
    second one makes it ERROR ("Multiple .bandit files found -- ... choose one
    with --ini") and emit EMPTY output -- a selected-but-unproduced tool that
    silently blocked coverage certification on a worktree-heavy checkout.
    `--ini` is the escape hatch bandit itself names, but pinning the TARGET's
    copy handed the reviewed repository the scan's scope (#1839). The file is
    generated here instead, in a scratch directory bind-mounted read-only, and
    pinned UNCONDITIONALLY -- so the discovery walk never runs whether or not
    the target ships a `.bandit`, and that file never reaches the argv at all.
    Same shape as `tools/brakeman.py` and `tools/bundler_audit.py`, which
    answer the same problem with a config they generate themselves.

    The file exists to pre-empt bandit's `.bandit` discovery by the `--ini`
    FLAG (bandit 1.9.4 reads `pyproject.toml`/`setup.cfg` only via `-c`, which
    nothing sets) and to keep bandit's stderr free of a config warning that
    `phases/tools.py` would otherwise surface -- so the mount stays even though
    its contents are pure belt.
    The contents are `BANDIT_INI_TEXT`, a module constant, so no directory name
    can reach them (review round 1 C1).

    World-readable on purpose: the tools image runs as `USER scanner`, so a 0700
    scratch would be an `--ini` bandit cannot read. The contents are a generated
    exclusion list with nothing private in them. An ini that does not arrive is
    fail-OPEN, not fail-closed -- bandit 1.9.4's `utils.parse_ini_file` CATCHES a
    parse failure or a missing `[bandit]` section, warns
    ("Unable to parse config file ... or missing [bandit] section") and runs on
    the CLI args alone (review round 1 N1; round 0's docstring claimed exit 2,
    which is wrong). That is why the exclusions are on the argv unconditionally
    and this file is belt: what it still guarantees is that bandit's DISCOVERY
    walk never runs, which is #run7's failure.

    A staging failure -- a full or read-only `$TMPDIR`, an `EACCES` on `chmod` --
    yields `(None, None)` instead of raising through the dispatch loop, so it
    costs bandit (which lands in the manifest's `missing`, fail-closed for that
    tool) and not the eight scanners queued behind it (review round 1 N3).
    """
    if tool != "bandit":
        yield cmd, []
        return
    scratch = staging_error = None
    try:
        scratch = tempfile.mkdtemp(prefix="pano-bandit-ini-")
        os.chmod(scratch, 0o755)
        ini_path = os.path.join(scratch, BANDIT_INI_NAME)
        with open(ini_path, "w", encoding="utf-8") as fh:
            fh.write(BANDIT_INI_TEXT)
        os.chmod(ini_path, 0o644)
    except OSError as exc:
        staging_error = exc
    try:
        if staging_error is not None:
            print("tool bandit skipped: the scanner-owned config could not be "
                  "staged (%s); recording as missing (fail-closed, #1839)"
                  % staging_error, file=sys.stderr)
            yield None, None
        else:
            yield (cmd[:1]
                   + ["--ini", "%s/%s" % (BANDIT_INI_MOUNT, BANDIT_INI_NAME)]
                   + cmd[1:]),\
                ["-v", "%s:%s:ro" % (scratch, BANDIT_INI_MOUNT)]
    finally:
        if scratch is not None:
            shutil.rmtree(scratch, ignore_errors=True)


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


def select_tools(languages, has_deps):
    """Select security scanners based on detected languages and dependency status."""
    tools = ["semgrep", "gitleaks"]
    if has_deps:
        tools.append("trivy")
    for lang in languages or []:
        t = LANG_TOOL.get(str(lang).lower())
        if t and t not in tools:
            tools.append(t)
    return tools


def select_adapters(target: str, adapters: dict | None = None) -> dict:
    """Return the subset of adapters applicable to the target repo."""
    adapters = adapters or ADAPTERS
    return {name: adapter for name, adapter in adapters.items() if adapter.is_applicable(target)}


def _is_excluded(rel, exclude_globs):
    """True if a repo-relative path matches any exclusion glob.

    #1740 fix round 2: GITIGNORE semantics, through the one translator
    `discovery` reads the same committed `exclude_paths:` lines with
    (`groups_schema.matched_glob`). It was `fnmatch` here, where `*` spans `/`
    and a trailing `/` matches nothing -- so `tests/*` covered the whole
    subtree on this side and only the direct children on discovery's, and
    `docs/` covered a tree there and nothing here. Subtree is spelled `**`.
    """
    rel = str(rel).replace(os.sep, "/")
    return groups_schema.matched_glob(rel, exclude_globs, "run_tools") is not None


def partition_by_exclusion(adapters, target, exclude_globs):
    """Split applicable adapters into (required, excluded_scope).

    An adapter is `excluded_scope` when it exposes ``applicable_files`` and
    EVERY such file matches an --exclude glob: its entire surface is outside the
    gate's scope, so a missing run cannot hide a gate-relevant finding — it is
    disclosed, not required. Adapters without file-level applicability (their
    trigger is a manifest/lockfile, not an excludable source tree) stay
    required. With no exclusions, nothing is demoted.
    """
    required, excluded_scope = [], []
    for name, adapter in adapters.items():
        lister = getattr(adapter, "applicable_files", None)
        files = list(lister(target)) if callable(lister) else []
        if exclude_globs and files and all(
                _is_excluded(os.path.relpath(f, target), exclude_globs) for f in files):
            excluded_scope.append(name)
        else:
            required.append(name)
    return required, excluded_scope


def collect_sanitization(adapters, target):
    """`{adapter: report}` for every adapter that discloses what it did NOT scan.

    The sibling of `partition_by_exclusion` and the same shape of channel: the
    runner asks the adapter a question ON THE HOST, in process, and hands the
    answer to `write_manifest`. An adapter answers by exposing
    `sanitization_report(target)`; today only pip-audit does (#1646), where the
    answer is "these requirement lines were not audited, because auditing them
    would have run the target's build backend".

    A parallel field, never an overload of `excluded_scope`: that one names
    adapters whose whole surface fell outside the gate's scope, and folding a
    PARTIAL audit into it would read as "this adapter was not required".

    Tolerant: the method reads target-controlled files, so a crash inside it
    must cost the disclosure, never the scan. The failure is announced --
    silently dropping the disclosure is the same species of hole the field
    exists to close.
    """
    out = {}
    for name, adapter in sorted(adapters.items()):
        reporter = getattr(adapter, "sanitization_report", None)
        if not callable(reporter):
            continue
        try:
            report = reporter(target)
        except Exception as exc:   # noqa: BLE001 -- disclosure must not sink the scan
            print("adapter %s could not report what it sanitized: %s" % (name, exc),
                  file=sys.stderr)
            continue
        if isinstance(report, dict):
            out[name] = report
    return out


def filter_online(chosen, online):
    """Drop ONLINE_ONLY adapters unless --online was given, with a notice."""
    if online:
        return list(chosen)
    kept = [t for t in chosen if t not in ONLINE_ONLY]
    for t in chosen:
        if t in ONLINE_ONLY:
            print("adapter %s needs network; skipped (offline substitute: "
                  "osv-scanner). Re-run with --online to include it." % t,
                  file=sys.stderr)
    return kept


# #1646 C1(b) / #1877: the container working directory for EVERY scanner
# dispatch. The image ends `WORKDIR /src` and `/src` is the target mount, so a
# container that starts there hands its scanner the reviewed repository as the
# directory its OWN config resolution walks from -- pip deciding a requirement
# is a local archive on a bare SUFFIX match and running a committed
# `evil.tar.gz`'s build backend, npm reading `.npmrc`, semgrep
# `.semgrepignore`, gitleaks `.gitleaksignore`. The rule is now uniform rather
# than one adapter's exemption: every scanner container starts OUTSIDE the
# mount. Docker CREATES a `-w` directory that does not exist, so this one is
# empty by construction and needs nothing in the image, and no argv changes --
# every tool already names its scan root by absolute path.
#
# TWO scanners are the exception, and both say so EXPLICITLY (`-w /src`)
# rather than leaning on the image's WORKDIR. For each, the cwd is a SCAN
# INPUT rather than a config-lookup surface, so moving it does not harden the
# scan, it deletes it:
#   gosec -- its argv is the CWD-RELATIVE go package pattern `./...`, which
#     go/packages resolves through `go list` from the module root, so a
#     container started anywhere else scans an empty directory.
#   eslint-security -- under flat config the `files`/`ignores` base path is
#     the process cwd whenever the config is named with `--config`, and
#     anything outside that base is classified "external". Measured on the
#     pinned eslint 10.9.0: from a scratch cwd the adapter produced NO output
#     and exit 2, "located outside of the base path". A config-object
#     `basePath` was tried first and does not widen the root base.
# Each adapter makes the same call at the Popen level, for the same reason and
# with the argument recorded against it there and in
# tests/tools/test_adapter_cwd_confinement.py's allowlist.
#
# Belt and braces: the adapters ALSO pass their own scratch cwd to `run_tool`
# (`tools.base.scratch_cwd`), so an `invoke()` that runs outside this
# dispatcher -- a host-side test, a future runner -- is confined too, with no
# docker flag in front of it.
ADAPTER_EMPTY_CWD = "/panopticon-empty-cwd"
# Where the target is mounted inside every scanner container. One name, so the
# `-v` mount and the `-w` working directory cannot come to disagree about which
# path the two mount-cwd scanners are pointed at. (`_with_venv_excludes` and bandit's `--ini`
# pin still spell it literally; both are outside #1877's scope.)
TARGET_MOUNT = "/src"
DISPATCH_KEEPS_TARGET_CWD = ("gosec", "eslint-security")


def _working_dir_flags(tool):
    """`-w` for *tool*'s container: outside the mount for every scanner but
    the two in DISPATCH_KEEPS_TARGET_CWD, for which the cwd is a scan input
    (see above)."""
    inside = tool in DISPATCH_KEEPS_TARGET_CWD
    return ["-w", TARGET_MOUNT if inside else ADAPTER_EMPTY_CWD]

MAX_TOOL_OUTPUT_BYTES = 50 * 1024 * 1024


def _popen_runner(cmd, stdout=None, stderr=None, timeout=None, env=None):
    """The default PRODUCTION runner (#1111 / run7 COD-A2A).

    Returns a live subprocess.Popen so _capture_run streams the child's stdout
    through _stream_and_write's bounded sink -- the memory guard #1111 advertised
    but never reached, because the old default (subprocess.run) buffers the ENTIRE
    output in memory before returning and thus always took the drop path. `timeout`
    is accepted for call-signature parity with the subprocess.run seam but is NOT
    honored here: Popen has no timeout=, so the wall-clock bound is enforced by
    _stream_and_write's watchdog instead (which also bounds a hung streaming read,
    something a single subprocess.run timeout could not do mid-buffer)."""
    return subprocess.Popen(cmd, stdout=stdout, stderr=stderr, env=env)


class _DockerRunner:
    """Bind one runner seam to the trusted Docker child environment."""

    def __init__(self, runner, env):
        self._panopticon_runner = runner
        self._panopticon_env = env

    def __call__(self, cmd, **kwargs):
        kwargs["env"] = self._panopticon_env
        return self._panopticon_runner(cmd, **kwargs)


class _DockerContext:
    """The resolved Docker identity and the exact environment bound to it."""

    def __init__(self, executable_path, env):
        self.executable = executable_path
        self.env = env


def _capture_run(label, tool, docker, out_path, runner, docker_context=None):
    """Run one docker tool/adapter invocation and land its stdout at out_path.

    Streams stdout into a bounded sink so adversarial/large target output does
    not accumulate unbounded in orchestrator memory (#1111). On exceeding the
    byte cap the output is truncated with a marker and a stderr notice, but the
    file is still written so the tool is recorded as produced rather than
    silently skipped.
    """
    try:
        os.remove(out_path)
    except OSError:
        pass
    # #run9 OPS-D1A: give a `docker run` a --cidfile so _stream_and_write can
    # `docker kill` the real container on a watchdog timeout -- proc.kill() reaches
    # only the CLI client. The cidfile must NOT pre-exist (docker refuses to start),
    # so it lives in a fresh temp dir cleaned up here. Inserted right after `run`.
    docker_bin = cidfile = cid_dir = None
    if (docker_context is not None and len(docker) >= 2
            and docker[0] == docker_context.executable and docker[1] == "run"):
        docker_bin = docker_context.executable
        cid_dir = tempfile.mkdtemp(prefix="pano-cid-")
        cidfile = os.path.join(cid_dir, "cid")
        docker = docker[:2] + ["--cidfile", cidfile] + docker[2:]
    try:
        proc = runner(docker, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      timeout=TOOL_TIMEOUT)
        # Backward compat: tests may inject a CompletedProcess-like runner.
        if hasattr(proc, "stdout") and isinstance(proc.stdout, (bytes, type(None))):
            return _write_completed(label, tool, proc, out_path)
        return _stream_and_write(label, tool, proc, out_path,
                                 docker_bin=docker_bin, cidfile=cidfile,
                                 docker_env=(docker_context.env
                                             if docker_context is not None else None))
    except subprocess.TimeoutExpired:
        print("%s %s timed out after %ss; skipping" % (label, tool, TOOL_TIMEOUT),
              file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print("%s %s failed: %s; skipping" % (label, tool, e), file=sys.stderr)
    finally:
        if cid_dir:
            shutil.rmtree(cid_dir, ignore_errors=True)
    return None


def _write_completed(label, tool, res, out_path):
    """Legacy path for runner callables that return a CompletedProcess."""
    if getattr(res, "returncode", 1) not in (0, 1):
        excerpt = (getattr(res, "stderr", b"") or b"")[-500:].decode(
            "utf-8", errors="replace").strip()
        print("%s %s exited %s; skipping%s" % (
            label, tool, res.returncode,
            (" — " + excerpt) if excerpt else ""), file=sys.stderr)
        return None
    out_bytes = res.stdout or b""
    if len(out_bytes) > MAX_TOOL_OUTPUT_BYTES:
        print("%s %s output exceeded %d byte limit; skipping" % (
            label, tool, MAX_TOOL_OUTPUT_BYTES), file=sys.stderr)
        return None
    if not out_bytes.strip():
        print("%s %s produced no output on a selected target; recording as "
              "missing (fail-closed, #1051)" % (label, tool), file=sys.stderr)
        return None
    return _atomic_write(out_path, _redact_capture(tool, out_bytes))


# #1335: semgrep's SARIF carries NO scanned-files signal -- `invocations` is
# just {executionSuccessful: true}, and tool.driver.rules lists the CONFIG's
# rules whether or not any file matched. So a semgrep whose ruleset covers none
# of the target's languages scans 0 files and emits an artifact byte-identical
# in shape to a genuinely clean run. The one witness is semgrep's own stderr,
# which exists only at run time -- capture it into the artifact while we have it.
_SEMGREP_SCANNED = re.compile(rb"\bran\s+\d+\s+rules?\s+on\s+(\d+)\s+files?\b",
                              re.IGNORECASE)


def _semgrep_scanned_files(stderr):
    """The M in semgrep's `Ran N rules on M files`, or None if it isn't there.

    None means "no claim": semgrep's summary wording is English prose and has
    drifted across versions, so an unrecognised line must leave the artifact
    unannotated and the disposition exactly as it is today. Fabricating a 0
    would strip coverage credit from a scanner that really did run.
    """
    m = _SEMGREP_SCANNED.search(stderr or b"")
    return int(m.group(1)) if m else None


def _annotate_scanned_files(payload, count):
    """Record `count` as runs[0].properties.panopticon_scanned_files.

    Tolerant by design: output that is not a SARIF document with at least one
    run object is returned untouched. This runs on every semgrep capture, and a
    malformed artifact is already handled (and reported) by the ingest walk --
    it must not become a write failure here.
    """
    try:
        doc = json.loads(payload)
        run = doc["runs"][0]
        if not isinstance(run, dict):
            return payload
    except (ValueError, KeyError, IndexError, TypeError):
        return payload
    run.setdefault("properties", {})["panopticon_scanned_files"] = count
    return json.dumps(doc).encode("utf-8")


# Per-tool post-capture annotation, keyed by tool name: signals that exist only
# while the child runs and would otherwise be lost to the artifact.
_STDERR_ANNOTATORS = {"semgrep": _semgrep_scanned_files}


def _annotate_from_stderr(tool, payload, stderr):
    """Apply `tool`'s stderr annotation, if it has one. Identity otherwise."""
    reader = _STDERR_ANNOTATORS.get(tool)
    if reader is None:
        return payload
    count = reader(stderr)
    return payload if count is None else _annotate_scanned_files(payload, count)


def _drain(stream):
    """Read and discard the rest of a stream past the byte cap so the child is
    never left blocked on a full pipe. #run7 QAL-D1A: shared by both truncation
    branches in _stream_and_write (previously an inline duplicate)."""
    while stream.read(64 * 1024):
        pass


def _stream_and_write(label, tool, proc, out_path, timeout=TOOL_TIMEOUT,
                      docker_bin=None, cidfile=None, docker_env=None):
    """Stream stdout from a Popen-like object with an explicit byte cap AND a
    wall-clock deadline.

    The byte cap keeps a large/adversarial target's output from accumulating in
    memory (#1111). The deadline is enforced by a watchdog that kills the child
    at `timeout`: a Popen has no ``timeout=`` of its own, so without it a hung or
    trickle-slow tool would block the streaming ``read()`` (or the post-cap
    ``_drain`` of an infinite producer) forever -- restoring the bound that the
    old buffered ``subprocess.run(timeout=...)`` path provided (#run7 COD-A2A)."""
    timed_out = {"hit": False}

    def _kill_container():
        # #run9 OPS-D1A: proc.kill() SIGKILLs the `docker run` CLI client, which
        # cannot forward the signal to the daemon -- the `--rm` container keeps
        # running (and is never removed). When we recorded its id via --cidfile,
        # stop it directly. Best-effort: an empty/absent cidfile (container not
        # started yet) or a docker error is a no-op.
        if not (docker_bin and cidfile):
            return
        try:
            with open(cidfile, encoding="utf-8") as fh:
                cid = fh.read().strip()
        except OSError:
            return
        if not cid:
            return
        try:
            subprocess.run([docker_bin, "kill", cid], capture_output=True, timeout=10,
                           env=docker_env)
        except (subprocess.SubprocessError, OSError):
            pass

    def _watchdog():
        # Kill the child so the blocking read()/drain unblocks at EOF, and stop the
        # container it launched (OPS-D1A) so a hung tool leaves nothing running.
        timed_out["hit"] = True
        try:
            proc.kill()
        except Exception:
            pass
        _kill_container()

    timer = threading.Timer(timeout, _watchdog)
    timer.daemon = True
    timer.start()
    # #1510: drain stderr concurrently from the start. Reading stdout to EOF
    # first deadlocks against any scanner that fills its 64KB stderr pipe before
    # emitting stdout -- the parent waits on stdout the blocked child cannot
    # write, and only the watchdog breaks it, costing the whole scan timeout and
    # that tool's coverage. Shared with tools/base.run_tool, which already had it.
    join_stderr = drain_stderr_async(proc)
    try:
        with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as spool:
            truncated = False
            try:
                while True:
                    chunk = proc.stdout.read(64 * 1024)
                    if not chunk:
                        break
                    room = MAX_TOOL_OUTPUT_BYTES - spool.tell()
                    if room <= 0:
                        truncated = True
                        _drain(proc.stdout)   # discard remaining stdout, unstored
                        break
                    if len(chunk) > room:
                        spool.write(chunk[:room])
                        truncated = True
                        _drain(proc.stdout)
                        break
                    spool.write(chunk)
                # The watchdog guarantees the child terminates, so wait() is bounded.
                rc = proc.wait()
                stderr = join_stderr()
            finally:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
                try:
                    proc.stderr.close()
                except Exception:
                    pass
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    _kill_container()      # OPS-D1A: stop the container, not just the client

            # A watchdog kill lands rc < 0 (signal). Only treat it as a timeout
            # when the child did NOT finish cleanly first -- else a tool that
            # completed a hair before the deadline (rc 0/1) would be misreported.
            if timed_out["hit"] and rc not in (0, 1):
                print("%s %s timed out after %ss; skipping" % (label, tool, timeout),
                      file=sys.stderr)
                return None

            if rc not in (0, 1):
                excerpt = (stderr or b"")[-500:].decode("utf-8", errors="replace").strip()
                print("%s %s exited %s; skipping%s" % (
                    label, tool, rc,
                    (" — " + excerpt) if excerpt else ""), file=sys.stderr)
                return None

            if spool.tell() == 0:
                print("%s %s produced no output on a selected target; recording as "
                      "missing (fail-closed, #1051)" % (label, tool), file=sys.stderr)
                return None

            if truncated:
                # Both numbers describe RAW bytes: the cap is measured on the
                # stream as it arrives (above), which is the only count that
                # bounds memory. `_whole_lines` and `_redact_capture` run after,
                # and either can change the retained prefix's length, so the
                # marker is a statement about what the child produced and what
                # was kept -- not about the size of the file on disk (#1639 P11).
                # Cutting on a raw byte count can also split a token in half,
                # and a fragment matches none of the length-anchored patterns:
                # `_whole_lines` drops the partial last line so the fragment
                # goes with it, EXCEPT on output with no line breaks (a compact
                # single-line SARIF) or a last line over `_TRUNCATE_TRIM_MAX`,
                # where the prefix is kept as cut and a split value can survive
                # as an unmatched fragment.
                marker = (
                    "\n\n[TRUNCATED by panopticon: output exceeded %d byte limit; "
                    "only the first %d bytes were retained]\n" % (
                        MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_BYTES)
                ).encode("utf-8")
                print("%s %s output exceeded %d byte limit; truncated and retained "
                      "with marker" % (label, tool, MAX_TOOL_OUTPUT_BYTES),
                      file=sys.stderr)
                # Write only up to the cap, redacted, then append the marker for
                # the tail -- appended AFTER the pass so panopticon's own text
                # is never rewritten by it.
                spool.seek(0)
                return _atomic_write(
                    out_path,
                    _redact_capture(
                        tool, _whole_lines(spool.read(MAX_TOOL_OUTPUT_BYTES)))
                    + marker)

            spool.seek(0)
            # Redaction is LAST: the semgrep annotator rewrites the payload on
            # its way out, so a choke point ahead of it could be reopened by it.
            return _atomic_write(
                out_path,
                _redact_capture(tool,
                                _annotate_from_stderr(tool, spool.read(), stderr)))
    finally:
        timer.cancel()


# Which tools' captures this run put through `_redact_capture`. A run_tools()
# call clears it and `write_manifest` reads it back, so the artifact reports what
# the runner OBSERVED itself doing rather than restating an intention (#1639 P11
# F5): replace the choke point with identity and the manifest's claim goes false.
# Module-level because the pass runs three call frames below the run loop --
# threading a ledger through _capture_run/_write_completed/_stream_and_write
# would put plumbing in five signatures to carry one bit.
_REDACTED_CAPTURES: set[str] = set()

# What egress each tool was granted this run, keyed by tool name (#1645). Same
# construction and the same reason as the ledger above: `run_tools()` clears it
# and fills it WHERE THE ARGV IS BUILT, so the manifest reports what the runner
# observed itself doing -- take the flags away and the claim goes with them,
# rather than a `proxied:` string surviving as an intention nothing enforces.
# Values are `"none"`, `"proxied:<allowlist>"` or the fail-closed
# `"excluded:online egress unavailable"` (scripts.tools.egress).
_NETWORK_POSTURE: dict[str, str] = {}

# Above this size a capture is re-serialized in json.dumps' default layout
# instead of the producer's own: matching the layout costs one extra
# serialization of the ORIGINAL document to verify the guess, which is free on a
# normal capture and not worth it on a huge one (only reached when redaction
# fired, and every consumer parses the file rather than reading it).
_STYLE_PROBE_MAX_BYTES = 4 * 1024 * 1024
# The producer's indentation, read off the head of the document.
_JSON_INDENT = re.compile(r"[\[{]\n(\x20+)\S")


def _json_style(text):
    """`json.dumps` kwargs guessed from how `text` itself is laid out.

    A guess: the caller VERIFIES it reproduces the original before using it, so
    being wrong costs one comparison rather than a reformatted file.
    """
    head = text[:4096]
    m = _JSON_INDENT.search(head)
    if m:
        return {"indent": len(m.group(1))}
    return {} if '": ' in head or '", "' in head else {"separators": (",", ":")}


# How much of a retained prefix `_whole_lines` may give up to end on a line
# boundary. A last line longer than this is not line-oriented output, and the
# evidence in it is worth more than the fragment risk.
_TRUNCATE_TRIM_MAX = 64 * 1024


def _whole_lines(prefix):
    """Drop a trailing partial line from a capture the byte cap cut (#1639 P11
    F2).

    The cap is measured on the RAW stream -- the only count that bounds memory
    (ruling 4) -- so it can land in the middle of a token, and the length-
    anchored patterns do not match a fragment: `ghp_QQQQQQQQQQ` is not a
    credential but it is not masked either. Scanner output is line-oriented, so
    ending on the last newline drops the split value instead of keeping half of
    it.

    Bounded both ways: a capture with no newline at all (a compact single-line
    SARIF), or whose last line is longer than `_TRUNCATE_TRIM_MAX`, keeps its
    prefix exactly as cut -- the trim must never empty a file or throw away
    megabytes of retained evidence to tidy one line, and for those shapes the
    fragment risk is what the marker comment documents.
    """
    cut = prefix.rfind(b"\n")
    if cut == -1 or len(prefix) - (cut + 1) > _TRUNCATE_TRIM_MAX:
        return prefix
    return prefix[:cut + 1]


def _redact_capture(tool, data):
    """The ONE redaction choke point for a raw scanner capture (#1639 P11).

    `.panopticon/tools/<tool>.sarif|json` is what an operator copies into a CI
    job's artifacts, and nothing masked it: the report's pass
    (`redact.redact_tree`, #1634) walks the REPORT tree, which these files are
    not part of, and a secret scanner's output is a file full of other people's
    credentials by construction. Every write path calls this immediately before
    `_atomic_write`, and `TestRawCaptureRedaction` reads run_tools' own AST to
    keep it that way for the next path somebody adds.

    Structure is preserved by PARSING, not by trusting the patterns to stay
    inside a string (fix round 1 F1). A JSON capture -- which is every capture
    but spotbugs' XML -- goes through `redact.redact_tree`, the same per-leaf
    walk the report uses since #1661, so a pattern can never span two fields:
    `ruleId`, `locations`, `region` line numbers and `level` survive because the
    walk never sees them as text. The flat pass had no such guarantee, and the
    PEM rule broke it -- an unterminated `-----BEGIN` in one snippet closed on a
    later result's `-----END` and swallowed every result in between. Non-JSON
    captures (spotbugs' XML) still take the flat pass, where every pattern but
    the PEM body is anchored to a character class that cannot cross a `"`, and
    the PEM body -- which has to cross quotes, since source code embeds a key
    one quoted literal per line -- is bounded to 16 KiB and cannot span two
    `-----BEGIN` blocks. So a flat-pass match over a structured document is
    bounded rather than open-ended; it is not the guarantee parsing gives, which
    is why JSON never takes this path. That length bound has a cost worth
    knowing before you publish a capture: a PEM block whose body runs longer
    than 16 KiB is not masked AT ALL -- header included -- so a capture quoting
    one very large key can still carry it verbatim.

    Whichever path runs, it is `scripts/redact.py`'s pattern set -- never a
    second copy: two redactors drift, and the one reached only by raw captures
    would drift silently.

    The tree walk masks string LEAVES, not dict KEYS -- the report's contract
    since #1661, and the right one here: a SARIF key comes from the tool's own
    schema, and the target-derived keys that do exist (npm-audit's per-package
    objects) are identifiers, not quoted secrets. The flat pass did mask a key,
    but only as a side effect of not knowing what a key was, which is the same
    blindness that let it eat three results.

    Bytes in, bytes out, because bytes are what the writer holds. The document
    is re-serialized ONLY when redaction actually fired, in the producer's own
    layout where that is recognisable; a capture with nothing to mask is
    returned as the exact bytes the scanner produced, so all fifteen committed
    real-scanner goldens are byte-identical through this function and a payload
    that is not valid UTF-8 (decoded here with errors="replace") is never
    rewritten by a pass that had nothing to do. When the pass DOES fire on such
    a payload its bytes are not preserved: it was decoded with replacement, so
    every byte that was not valid UTF-8 comes back as U+FFFD alongside the
    masked secret.
    """
    _REDACTED_CAPTURES.add(tool)
    text = data.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except ValueError:
        if tool == "eslint-security":
            # Broken scanner JSON can contain arbitrary source fragments too.
            # Discard it without converting whole-capture failure into a clean scan.
            return b"panopticon: unusable ESLint capture\n"
        masked = redact.redact(text)        # XML/plain-text captures
    else:
        # The parse is bounded by MAX_TOOL_OUTPUT_BYTES, and ingest already
        # parses this same file, so it adds no ceiling the pipeline lacked.
        if tool == "eslint-security":
            from scripts.tools.eslint_security import sanitize_capture
            try:
                # Work on a copy so changed source diagnostics force serialization.
                cleaned = sanitize_capture(json.loads(text))
            except ValueError:
                # Invalid metadata or a malformed neighboring row must not
                # disable parser-text sanitization. No trustworthy document
                # can be retained; publish only an unparseable static marker.
                return b"panopticon: unusable ESLint capture\n"
        else:
            cleaned = parsed
        scrubbed = redact.redact_tree(cleaned)
        if scrubbed == parsed:
            return data
        style = {}
        if len(text) <= _STYLE_PROBE_MAX_BYTES:
            probe = _json_style(text)
            if json.dumps(parsed, **probe) == text:
                style = probe
        masked = json.dumps(scrubbed, **style)
    if masked == text:
        return data
    # Disclosed, not silent: for most scanners a secret in the capture means the
    # scan surface was wrong. Only ever reached when a capture is being written,
    # so it cannot crowd out the driver's no-output failure note (#1317).
    note = ("capture diagnostics or secret-shaped values sanitized before writing"
            if tool == "eslint-security" else
            "capture carried secret-shaped values; masked before writing")
    print("%s %s" % (tool, note), file=sys.stderr)
    return masked.encode("utf-8")


def _atomic_write(out_path, data):
    """Atomically replace out_path with data.

    #1735: every SARIF capture goes through here, and `out_path` is under
    `.panopticon/tools/` in the REVIEWED tree. `mkstemp` leaves no plantable
    staging name, but it stages in `dirname(out_path)` -- so a target that
    commits `.panopticon/tools` as a directory symlink has every capture
    written, and then `os.replace`d, outside the tree. O_NOFOLLOW would never
    see that (it guards the final component only); the whole-path confinement
    is the guard that does.
    """
    safe_write.confine_artifact_path(out_path)
    fd, temp_path = tempfile.mkstemp(
        prefix=".%s-" % os.path.basename(out_path),
        dir=os.path.dirname(out_path) or ".")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, out_path)
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass
    return out_path


def run_tools(target, tools, out_dir, image="panopticon-tools",
              runner=None, online=False, progress=None, venv_dirs=None,
              run_id=None):
    """Run selected security tools and adapters in Docker against target.

    Legacy SARIF tools use their hard-coded ``TOOL_CMD`` invocation. New Phase 1
    adapters are dispatched through ``scripts/_run_adapter.py`` inside the
    container so the same fat image is used for local and CI runs.

    `venv_dirs` (#1638 P09) are the virtualenvs the scanners that expose an
    exclusion knob are told to skip; None detects them here, so a direct caller
    gets the exclusion without asking -- through `partition_venv_dirs`, so the
    default can never hand a scanner something the rules forbid. main() passes
    its own list so the walk is done once and the manifest discloses exactly what
    the scan was told to skip.

    `run_id` (#1645) names this run's egress network and proxy sidecar, so a
    leftover from a crashed run is recognisable. The whole loop runs inside one
    `scripts.tools.egress.session`: with an ONLINE_ONLY adapter selected that
    session is a `--internal` network plus an allowlisting proxy, and with none
    selected it is inert and every argv below is byte-identical to before.
    """
    runner = runner or _popen_runner   # #run7 COD-A2A: stream by default, don't buffer-then-drop
    # This run's redaction ledger starts empty, so `write_manifest` reports what
    # THIS scan's captures went through and never inherits a previous one's
    # (#1639 P11 F5).
    _REDACTED_CAPTURES.clear()
    # #1839 (review round 1 I2): the default PARTITIONS. The raw
    # `find_virtualenvs` list still holds the rows nothing may be told to skip
    # -- a `pyvenv.cfg` with no environment under it, a name no exclusion value
    # can carry -- so handing it straight to the knobs reproduced the finding on
    # this module's own convenience path. `standard` is the conservative default
    # for a caller that named no mode: it skips MORE than redteam would.
    if venv_dirs is None:
        venv_dirs = partition_venv_dirs(find_virtualenvs(target))[0]
    validate_output_dir(target, out_dir)
    os.makedirs(out_dir, exist_ok=True)
    tools = filter_online(tools, online)
    resolved = executable.resolve("docker", target, os.environ.get("PATH", ""))
    docker_bin = resolved.path
    docker_env = executable.sanitize_startup_environment(os.environ)
    docker_env["PATH"] = resolved.path_env
    docker_context = _DockerContext(docker_bin, docker_env)

    # One environment for scanner launches and every egress control-plane
    # command. The wrapper preserves the injected runner seam while making an
    # unsafe nested PATH impossible in production.
    docker_runner = _DockerRunner(runner, docker_env)
    # #1317: NullProgress by default, so the five call sites below need no
    # `if progress:` guard and the runner's behaviour is byte-identical unless
    # a caller opts in.
    progress = progress or NullProgress()
    total = len(tools)
    progress.header(target, total)
    # #1645: what the runner OBSERVED itself granting each tool, the same
    # construction as `_REDACTED_CAPTURES` above -- cleared here, filled where
    # the argv is built, read back by `write_manifest`. A claim written from
    # intent would survive the flags going away; this one does not.
    _NETWORK_POSTURE.clear()
    with egress.session(docker_bin, tools, docker_runner, run_id=run_id,
                        max_seconds=TOOL_TIMEOUT * total
                        + egress.SIDECAR_SLACK) as online_egress:
        written = _run_selected(target, tools, out_dir, image, docker_runner,
                                progress, total, venv_dirs, docker_context,
                                online_egress)
    progress.footer(len(written), total)
    return written


def _run_selected(target, tools, out_dir, image, runner, progress, total,
                  venv_dirs, docker_context, online_egress):
    """The dispatch loop, one docker invocation per selected tool.

    Split out of `run_tools` only so the `egress.session` context (#1645) does
    not re-indent sixty lines of unchanged dispatch; it returns the paths it
    wrote, exactly as the loop did inline.
    """
    written = []
    docker_bin = docker_context.executable
    for index, tool in enumerate(tools, 1):
        # #1645 ruling 2: an online adapter whose egress could not be
        # established does NOT fall back to Docker's default bridge. It is
        # skipped, and `write_manifest` turns this posture into an
        # `excluded_scope` entry carrying the reason -- so the gap is
        # certified against, exactly like an absent scanner.
        if online_egress.refuses(tool):
            _NETWORK_POSTURE[tool] = egress.UNAVAILABLE
            progress.note("[%d/%d] %s skipped: online egress unavailable"
                          % (index, total, tool))
            continue
        # Legacy SARIF path (kept for backward compatibility). Gitleaks uses
        # its adapter so the scanner-owned rule config reaches production.
        cmd = TOOL_CMD.get(tool)
        if cmd and tool != "gitleaks":
            cmd = list(cmd)   # never mutate the shared TOOL_CMD entry
            cmd = _with_venv_excludes(tool, cmd, venv_dirs)   # #1638 P09
            out_path = os.path.join(out_dir, "%s.sarif" % tool)
            # #1839 / #run7: bandit's config is the SCANNER's, a constant
            # staged in a scratch this target never controls and mounted
            # read-only beside the target mount. No-op for every other tool.
            with _scanner_owned_bandit_ini(tool, cmd) as (cmd, ini_mount):
                if cmd is None:          # staging failed: bandit only (N3)
                    progress.note("[%d/%d] %s skipped: scanner-owned config "
                                  "could not be staged" % (index, total, tool))
                    continue
                docker = ([docker_bin, "run", "--rm"] + _resource_limit_flags()
                          + _privilege_drop_flags() + _working_dir_flags(tool)
                          + ini_mount
                          + ["--network", "none",
                             "-v", "%s:%s:ro" % (os.path.abspath(target), TARGET_MOUNT),
                             image] + cmd)
                _NETWORK_POSTURE[tool] = egress.NO_NETWORK
                with progress.tool(tool, index, total) as step:
                    done = step.finish(
                        _capture_run("tool", tool, docker, out_path, runner,
                                     docker_context=docker_context))
            if done:
                written.append(done)
            continue

        # Phase 1 adapter dispatch path.
        adapter = ADAPTERS.get(tool)
        if adapter:
            ext = "sarif" if tool in LEGACY_SARIF_TOOLS else "json"
            out_path = os.path.join(out_dir, "%s.%s" % (tool, ext))
            docker = ([docker_bin, "run", "--rm"] + _resource_limit_flags()
                      + _privilege_drop_flags())
            if online_egress.serves(tool):
                docker.extend(online_egress.flags_for(tool))
                _NETWORK_POSTURE[tool] = online_egress.posture_for(tool)
            else:
                docker.extend(["--network", "none"])
                _NETWORK_POSTURE[tool] = egress.NO_NETWORK
            docker.extend(_working_dir_flags(tool))
            # Mount the checkout's adapter code over the image's baked-in copy
            # so local adapter fixes take effect without an image rebuild
            # (calibration 2026-08-03: fixed adapters silently kept failing
            # because the image carried the stale code).
            scripts_dir = os.path.dirname(os.path.abspath(__file__))
            docker.extend([
                "-v", "%s:%s:ro" % (os.path.abspath(target), TARGET_MOUNT),
                "-v", "%s:/opt/panopticon/scripts:ro" % scripts_dir, image,
                "python3", "/opt/panopticon/scripts/_run_adapter.py", tool])
            with progress.tool(tool, index, total) as step:
                done = step.finish(
                    _capture_run("adapter", tool, docker, out_path, runner,
                                 docker_context=docker_context))
            if done:
                written.append(done)
            continue

        # Neither path claims it. Not silent-but-fine: the manifest already
        # discloses it (selected without produced puts it in `missing`), so
        # this line is the log catching up with what the artifact will say,
        # not a new control.
        progress.note("[%d/%d] %s skipped: no runner registered"
                      % (index, total, tool))
    return written


def _excluded_dir_row(d):
    """One `excluded_dirs` row for the manifest.

    #1740: `skipped` is the whole point of the row under redteam -- a name-only
    venv is DETECTED and scanned anyway. True for a caller that passed
    `find_virtualenvs` output directly, which is the pre-#1740 meaning of this
    list. #1839: `note` is present only when the runner had a reason of its own
    for scanning a directory it detected -- a marker with no environment under
    it, or a name no exclusion pattern can express -- so an operator reading
    `skipped: false` under `standard` is not left to guess which.
    """
    row = {"path": str(d["path"]), "reason": str(d["reason"]),
           "skipped": bool(d.get("skipped", True))}
    if d.get("note"):
        row["note"] = str(d["note"])
    return row


def write_manifest(path, selected, written, excluded_scope=(), run_id=None,
                   excluded_dirs=(), depth_bound=VENV_MAX_DEPTH, sanitized=None,
                   network=None, exclude_globs=()):
    """Write the exact selected/produced scanner set for coverage gating.

    `excluded_scope` names adapters that were applicable but whose entire
    surface fell under the gate's --exclude globs; they are disclosed (never
    required), and are kept out of `selected` so the missing-set invariant
    holds.

    `excluded_dirs` (#1638 P09) are the virtualenv directories this scan
    DETECTED, as ``{"path", "reason", "skipped"[, "note"]}`` rows -- so a report can say
    what was pruned and on what evidence (`pyvenv.cfg` or the conventional
    name) rather than leaving a silent hole in the scanned surface. #1740:
    `skipped` is what separates the two, because under `--security redteam` a
    name-only directory is detected and scanned anyway; it defaults to True, so
    a caller handing `find_virtualenvs` output straight in still publishes this
    list's pre-#1740 meaning. `depth_bound` is how deep
    the walk that found them looked: the list is what the SCANNERS were told to
    skip, and ingest drops virtualenv findings at any depth, so a reader knows
    the list is bounded rather than exhaustive. Additive: both fields are new in
    this schema version and every consumer reads them optionally, so an older
    manifest without them still loads.

    `sanitized` (#1646) is what an adapter refused to hand its scanner, per
    adapter: `{"pip-audit": {"source", "kept", "dropped": [{"line", "reason"}],
    "hashes_stripped"}}`. pip-audit is now given a GENERATED requirements file
    holding only bare PEP 508 lines, because resolving an editable/local/VCS/URL
    requirement runs the reviewed repo's build backend -- so the dependency
    audit can be PARTIAL, and this is where it says by how much and which lines.
    Stated on every manifest, `{}` included, so its absence cannot be read as
    "nothing was dropped" on a run that never measured.

    `exclude_globs` (#1740 fix round 1) are the `--exclude` path globs this
    scan was given -- the driver passes the repository's committed
    `exclude_paths:`, CI passes its own. `excluded_scope` beside it names the
    ADAPTERS those globs disqualified; this is the policy itself, so a reader
    can tell "no adapter was excluded" from "no policy was applied". Stated on
    every manifest, `[]` included, like `sanitized`.

    `file_coverage` carries bounded scanner file facts derived from the exact
    written capture. Partial source coverage leaves produced/missing unchanged;
    ingestion independently derives the same facts for legacy raw arrays.

    `redacted` (#1639 P11) says whether every capture this run wrote went
    through the redaction choke point, read off the ledger `_redact_capture`
    keeps -- an observation, so replacing the choke point with identity makes
    the claim go false rather than leaving a stale `true` behind. The tools
    phase copies it into `tools-ran.json`.

    `network` (#1645) is the egress each tool was given: `"none"` for the
    `--network none` containers, `"proxied:<allowlist>"` for an ONLINE_ONLY
    adapter that ran behind this run's proxy, and `"excluded:online egress
    unavailable"` for one that could not be given an egress path and was
    therefore NOT run. "pip-audit: produced" has never said what that scanner
    could reach while it ran, and this is where the answer goes. Defaults to
    the ledger `run_tools()` filled while building each argv -- an observation,
    like `redacted` -- and an explicit value is for a caller that did not run
    the loop. The third posture also MOVES the adapter: it leaves `selected`
    for `excluded_scope`, the shape the gate already reads as "applicable, not
    required by scope, disclosed"; the network refusal independently prevents
    coverage certification. An adapter left in both lists would read as a
    required scanner that went missing (and `security_gate` rejects the
    overlap outright).
    """
    network = {str(k): str(v) for k, v in
               (_NETWORK_POSTURE if network is None else network).items()}
    refused = sorted(t for t, posture in network.items()
                     if posture.startswith(egress.EXCLUDED_PREFIX))
    selected = [t for t in selected if t not in set(refused)]
    excluded_scope = list(excluded_scope) + refused
    selected = list(dict.fromkeys(str(tool) for tool in selected))
    produced = sorted({os.path.splitext(os.path.basename(p))[0] for p in written})
    file_coverage = {}
    for capture_path in written:
        if os.path.basename(capture_path) == "eslint-security.json":
            from scripts.tools.eslint_security import file_coverage as eslint_coverage
            try:
                with open(capture_path, "rb") as capture:
                    data = capture.read(MAX_TOOL_OUTPUT_BYTES + 1)
                if len(data) <= MAX_TOOL_OUTPUT_BYTES:
                    file_coverage["eslint-security"] = eslint_coverage(json.loads(data))
            except (OSError, ValueError):
                pass  # ingestion retains the whole-capture failure path
    payload = {"schema_version": 1, "run_id": run_id,
               "file_coverage": file_coverage,
               "selected": selected, "produced": produced,
               "missing": sorted(set(selected) - set(produced)),
               # #1639 P11 F5: what the runner OBSERVED, not what it intends --
               # every capture written this run passed `_redact_capture`. False
               # when nothing was written (there is nothing to vouch for) and
               # false if any capture reached disk without the pass, so the
               # phase can copy the answer into `tools-ran.json` instead of
               # asserting another module's behaviour with a literal.
               "redacted": bool(produced) and all(
                   tool in _REDACTED_CAPTURES for tool in produced),
               "excluded_scope": sorted(dict.fromkeys(str(t) for t in excluded_scope)),
               "network": network,
               "sanitized": dict(sanitized or {}),
               "exclude_globs": [str(g) for g in exclude_globs or ()],
               "excluded_dirs": [_excluded_dir_row(d) for d in excluded_dirs or ()],
               "depth_bound": depth_bound}
    # #1735: the driver points --manifest at `<run folder>/tools-manifest.json`,
    # inside the reviewed tree. Confine before the makedirs (a symlinked
    # intermediate would be traversed by it) and never open through a link.
    safe_write.confine_artifact_path(path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with safe_write.open_w_nofollow(path) as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    return payload


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="panopticon tool runner")
    ap.add_argument("--target", default=".")
    ap.add_argument("--out", default=os.path.join(".panopticon", "tools"))
    ap.add_argument("--tools", nargs="*", default=None)
    ap.add_argument("--languages", nargs="*", default=[])
    ap.add_argument("--deps", action="store_true")
    ap.add_argument("--online", action="store_true", help="allow pip-audit/npm-audit to reach their advisory APIs")
    ap.add_argument("--manifest", default=None,
                    help="Write selected/produced scanner coverage JSON")
    ap.add_argument("--run-id", default=None,
                    help="Stamp this run's id into the manifest so synthesize can "
                         "refuse to certify against another run's manifest (#17)")
    ap.add_argument("--progress", action="store_true",
                    help="Emit one stderr line per tool as the scan proceeds "
                         "(#1317). OFF by default: the driver builds its "
                         "tool-scan failure note from this process's first 300 "
                         "stderr characters, and progress would crowd the real "
                         "error out of it. CI passes it; the driver must not.")
    ap.add_argument("--exclude", action="append", default=[],
                    help="Path glob whose files are out of gate scope; an "
                         "adapter applicable only to excluded files is disclosed "
                         "as excluded_scope, not required (repeatable). Pass the "
                         "same globs the gate uses.")
    # #1740: the same flag `security_gate` takes, and the same meaning -- under
    # redteam a directory is not excluded from the scan on its NAME alone. Only
    # the virtualenv skip reads it; every other decision here is mode-blind.
    ap.add_argument("--security", dest="security_mode", default="standard",
                    choices=list(SECURITY_MODES),
                    help="redteam: scan virtualenvs detected by NAME alone "
                         "(no pyvenv.cfg), so the gate has findings to re-admit")
    a = ap.parse_args(argv)
    excluded_scope = []
    if a.tools is not None:
        if a.exclude:
            # partition_by_exclusion iterates adapters.items(), so it needs a
            # DICT (as select_adapters returns below) -- a list here raised an
            # uncaught AttributeError, crashing the whole CLI before any scan on
            # the documented `--tools ... --exclude ...` combination (COD-X0X).
            matched_adapters = {t: ADAPTERS[t] for t in a.tools if t in ADAPTERS}
            required_names, excluded_scope = partition_by_exclusion(
                matched_adapters, a.target, a.exclude)
            chosen = required_names + [t for t in a.tools if t not in ADAPTERS]
        else:
            chosen = a.tools
    else:
        selected_adapters = select_adapters(a.target)
        required_names, excluded_scope = partition_by_exclusion(
            selected_adapters, a.target, a.exclude)
        phase1 = [name for name in required_names if name in PHASE1_ADAPTERS]
        phase2 = [name for name in required_names if name in PHASE2_ADAPTERS]
        languages = a.languages or detect_languages(a.target)
        chosen = select_tools(languages, a.deps) + phase1 + phase2
    effective = filter_online(chosen, a.online)
    # #1646: what the adapters refused to hand their scanners. Computed from the
    # EFFECTIVE set (an adapter filtered out offline audited nothing, so it has
    # nothing to disclose) and before the docker check, because the answer is a
    # filesystem read that holds on the skip path too.
    sanitized = collect_sanitization(
        {t: ADAPTERS[t] for t in effective if t in ADAPTERS}, a.target)
    # #1638 P09: one walk, two consumers. #1740: and one mode decides which of
    # the detected directories the scanners are actually told to skip.
    skip_dirs, venv_rows = partition_venv_dirs(find_virtualenvs(a.target),
                                               a.security_mode)
    if not docker_available(target=a.target):
        print("panopticon-tools image not available; skipping tool scan", file=sys.stderr)
        # Still disclose the skip through the coverage manifest. Without this,
        # a caller who passed --manifest as its coverage-gating signal cannot
        # tell 'docker absent, whole scan skipped' from '--manifest never
        # passed' -- both leave no file. Every OTHER skip surface in this module
        # stays visible via write_manifest's `missing` list (produced=[] -> the
        # whole selected set lands in `missing`), so this one must too, rather
        # than returning success (0) with the artifact silently discarded
        # (COD-X0X #1406). The selection above is pure filesystem/logic and needs
        # no docker, so `effective` is a faithful record of what WOULD have run.
        if a.manifest:
            write_manifest(a.manifest, effective, [], excluded_scope=excluded_scope,
                           run_id=a.run_id, excluded_dirs=venv_rows,
                           sanitized=sanitized, exclude_globs=a.exclude)
        return 0
    paths = run_tools(a.target, effective, a.out, online=a.online,
                      progress=make_progress(a.progress), venv_dirs=skip_dirs,
                      run_id=a.run_id)
    if a.manifest:
        write_manifest(a.manifest, effective, paths, excluded_scope=excluded_scope,
                       run_id=a.run_id, excluded_dirs=venv_rows,
                       sanitized=sanitized, exclude_globs=a.exclude)
    print("\n".join(paths))
    return 0


if __name__ == "__main__":
    sys.exit(main())
