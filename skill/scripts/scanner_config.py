#!/usr/bin/env python3
"""The configuration the SCANNER owns, and the posture it publishes about it.

Three claims in three shapes. The configuration files this runner STAGES for a
scanner instead of letting the reviewed repository choose them (bandit's
`--ini`, trivy's `--ignorefile`); the ignore FILE it overlays out of the way
(gitleaks' `.gitleaksignore`); and the inline suppression COMMENT knobs it
passes under `--security redteam`. With them travel two of the four ledgers
`run_tools.write_manifest` reads back, so `tools-manifest.json` reports what the
runner OBSERVED itself doing rather than restating an intention (the other two,
the network posture and the gitleaks ignore-file posture, stayed with the
dispatch loop that fills them).

Separate from `run_tools` because it is a POLICY surface, and it grew like one:
#1762 (ARC-2609514778) found `run_tools.py` at 2215 lines, outside this repo's
own 700-line ratchet, having absorbed the whole post-run scanner-policy series
because nothing pushed back on it. This is part 1 of 3 of that split, and it
moved the block whole -- no string, flag, path, message or exception changed, and
`tests/test_scanner_config.py` pins the docker argv of every staged tool against
a golden captured before the move.

The arrow points ONE way: nothing here imports `run_tools`, which imports this.
That is why the two bandit exclude tuples live here (`BANDIT_INI_TEXT` is built
from them at import) while `_bandit_exclude_value` and `_excludable` stayed
behind -- they read the virtualenv detector, and following them would have
dragged it across and closed the loop. Stdlib-only.
"""
import contextlib
import os
import shutil
import stat
import sys
import tempfile

from scripts.tools.base import REDTEAM, SECURITY_FLAG

# Where the target is mounted inside every scanner container. One name, so the
# `-v` mount and the `-w` working directory cannot come to disagree about which
# path the two mount-cwd scanners are pointed at. (`run_tools._with_venv_excludes`
# and bandit's `--ini` pin still spell it literally; both are outside #1877's
# scope.)
TARGET_MOUNT = "/src"

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
# Where the generated configuration is bind-mounted in a scanner's container,
# and the basenames that live there. ONE FILE mount per launch --
# `<scratch>/<name>:/panopticon-config/<name>:ro` -- holding only the file that
# launch's tool is pinned to, so the container never sees a directory of ours
# and no host directory needs a permission of its own (review Q4-bis).
SCANNER_CONFIG_MOUNT = "/panopticon-config"
BANDIT_INI_NAME = "bandit.ini"
TRIVY_IGNOREFILE_NAME = ".trivyignore"
# The target's OWN bandit ini as bandit sees it, honoured under `standard` only
# (owner ruling of 2026-09-25 on #1924; see `_scanner_owned_config`). Spelled
# literally, like `run_tools._with_venv_excludes`' `/src` prefixes, because it is
# a pinned argv token, not a mount this module composes from `TARGET_MOUNT` above.
TARGET_BANDIT_INI = "/src/.bandit"

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
# fail-OPEN (see `_scanner_owned_config`).
BANDIT_INI_TEXT = ("[bandit]\nexclude = %s\n"
                   % ",".join(dict.fromkeys(list(BANDIT_DEFAULT_EXCLUDES)
                                            + list(BANDIT_SCANNER_EXCLUDES))))

# The SCANNER-OWNED `--ignorefile`, on every trivy run and in BOTH security
# modes (#1839, run-14 SEC-284952751). Every id in a `.trivyignore` is a finding
# trivy stops reporting, so a reviewed repository that could choose that file
# would choose what its own dependency and secret scan said.
#
# BELT, and this comment is the only honest word for it (fix round 1 §B):
# measured in the real-image round, trivy 0.74.0 resolves the default
# `.trivyignore` against the WORKING DIRECTORY, which has been a per-launch
# scratch since #1877 -- a `.trivyignore` at the scan root was already not read,
# on main as well as here. So this flag closes nothing that was open; it pins
# the posture explicitly against a version that reads the scan root, and it
# keeps the answer independent of whichever directory trivy resolves from. A
# CONSTANT that declares nothing, so the ignore list is the scanner's; `#` is a
# comment line in trivy's format (trivy 0.74.0, `Dockerfile ARG
# TRIVY_VERSION=0.74.0`).
TRIVY_IGNOREFILE_TEXT = (
    "# panopticon: the scan's ignore list is the scanner's, not the reviewed\n"
    "# repository's (#1839). Deliberately empty -- it names no advisory.\n")

# Per tool, the scanner-owned configuration file staged into that launch's
# config mount, the flag that pins it and HOW that flag is spelled:
# `{tool: (flag, basename, text, attached)}`. The FLAG is passed on every launch
# of either tool, so neither scanner's own discovery walk runs whether or not
# the target ships the file it looks for -- what the flag NAMES is this file,
# except for bandit under `standard`, where the owner ruling of 2026-09-25
# leaves the operator's own `.bandit` in place. `attached` is `--flag=value` in
# one token, which is how trivy's neighbours on the same argv are already
# spelled (`--skip-dirs=`, bandit's `--exclude=`); bandit's `--ini <path>` stays
# two tokens, the form #1839's first increment pinned and its tests read
# (review Q4).
SCANNER_OWNED_CONFIG = {
    "bandit": ("--ini", BANDIT_INI_NAME, BANDIT_INI_TEXT, False),
    "trivy": ("--ignorefile", TRIVY_IGNOREFILE_NAME, TRIVY_IGNOREFILE_TEXT,
              True),
}

# Per tool: the inline suppression COMMENT its scan honours in the target's own
# source, and the flag that stops it (#1839, run-14 SEC-284952751). Read as:
#   a flag       -- verified present in the pinned image (2026-09-26) and passed
#                   under `--security redteam`.
#   flag None    -- the tool honours such a comment and no knob for it was
#                   verified at the pin. The residual is DISCLOSED on the
#                   manifest rather than guessed at on the argv: a flag a
#                   scanner rejects is a tool that exits non-zero and produces
#                   no SARIF, which is the #1452 selected-but-unproduced class.
#   comment None -- assessed, and this argv honours no inline comment at all, so
#                   the manifest says `n/a` rather than implying a gap.
# A tool ABSENT from this table has not been assessed, and has no manifest row:
# that is not the same claim as `n/a`.
SUPPRESSION_COMMENTS = {
    # BELT, not the lever (fix round 1 §B). Measured in the pinned image:
    # semgrep 1.177.0 REPORTS a `# nosemgrep`'d result either way, marking it
    # `suppressions: [{"kind": "inSource"}]` in its SARIF, and `--disable-nosem`
    # does not change that output at all. What decides is the INGEST --
    # `tools/sarif_utils.sarif_to_findings` drops such a result under `standard`
    # and counts it, keeps it under `redteam` -- so this row's value is true
    # because of the mode, enforced there. The flag stays because it is the
    # documented knob and a later semgrep may act on it.
    "semgrep": ("# nosemgrep", "--disable-nosem"),
    "bandit": ("# nosec", "--ignore-nosec"),
    # gitleaks dispatches through its ADAPTER, which appends this flag itself
    # (`tools/legacy_sarif.py`) because its argv is built inside the container;
    # the mode reaches it as the dispatch argv's `--security` pair.
    "gitleaks": ("gitleaks:allow", "--ignore-gitleaks-allow"),
    # gosec's own `-nosec` was not verified against the pinned 2.29.0 binary in
    # this round, so the `// #nosec` residual is disclosed, not invented.
    "gosec": ("// #nosec", None),
    # eslint's `--no-inline-config` likewise unverified at the pin, and the
    # adapter does not read the mode yet.
    "eslint-security": ("/* eslint-disable */", None),
    # trivy's inline `trivy:ignore` comments are read by its MISCONFIGURATION
    # scanner, which this argv does not select (`trivy fs` scans vuln+secret).
    # Its `.trivyignore` is a FILE and is neutralised in both modes above.
    "trivy": (None, None),
    # A dependency auditor reads lockfiles, not comments; its ignore file is
    # `osv-scanner.toml`, pinned by the adapter in both modes.
    "osv-scanner": (None, None),
}


# The tools whose suppression-comment answer is decided at the INGEST rather
# than on the argv (#1839 fix round 2, re-review finding 3). semgrep is the only
# one today: at the 1.177.0 pin it REPORTS a `# nosemgrep`'d result and marks it
# `suppressions: [{"kind": "inSource"}]` with and without `--disable-nosem`, so
# the flag above is belt and `tools/sarif_utils.sarif_to_findings` is the lever
# -- it drops such a result under `standard` and keeps it under `redteam`.
# `_record_suppression_posture` therefore reads THESE tools' manifest rows from
# the run's mode. Reading them off the argv was accidentally correct only while
# the belt was on: take `--disable-nosem` away and a redteam run would publish
# `honoured` while the ingest ignored every such comment, which is a false
# COVERAGE claim -- the one direction an observation ledger may not fail in.
SUPPRESSION_INGEST_LEVER = frozenset({"semgrep"})

# `tools-manifest.json`'s `suppression_comments` vocabulary (#1839, run-14
# SEC-284952751): what this run did with an inline suppression comment in the
# target's own source -- decided by the argv for a flag-lever tool (bandit,
# gitleaks) and by the run's mode for an ingest-lever one
# (`SUPPRESSION_INGEST_LEVER`: semgrep, whose flag is belt).
SUPPRESSION_IGNORED = "ignored"      # a verified knob was passed (redteam)
SUPPRESSION_HONOURED = "honoured"    # the comment stood, and is disclosed
SUPPRESSION_NA = "n/a"               # assessed: this argv honours no comment
# Filled where the argv is built and read back by `write_manifest`, like
# `run_tools._NETWORK_POSTURE`: "the operator's own suppression comments were
# honoured" is a coverage fact. For a flag-lever tool the row is read off the
# argv, so the claim cannot outlive the flag; for an ingest-lever tool
# (`SUPPRESSION_INGEST_LEVER`) no flag decides and the row says what the mode
# did at ingest.
_SUPPRESSION_POSTURE: dict[str, str] = {}

# `tools-manifest.json`'s `scanner_config` vocabulary (#1839): WHICH
# configuration file the scan a staged scanner ran under was pinned to. Only
# bandit has two answers, and only because the owner ruling of 2026-09-25 gives
# `standard` back to the operator scanning their own repository. That answer
# names the skips too, because honouring their ini means the scan's `tests` and
# `skips` are theirs -- the runner's own `-s` list comes off the argv with it
# (`_without_skip_list`), so a reader can tell which file chose the checks.
CONFIG_TARGET_BANDIT = "target .bandit (its skips and tests)"
CONFIG_SCANNER_OWNED = "scanner-owned"
_SCANNER_CONFIG_POSTURE: dict[str, str] = {}


def _insert_flags(tool, cmd, flags):
    """*flags* placed where this tool's parser reads them: BEFORE the `/src`
    positional, so the scan root stays the last token for every scanner that
    takes it there.

    bandit is the exception and keeps the position #1839's first increment gave
    its `--ini`, immediately after the program name: bandit's `/src` is NOT the
    last token (`-s B101,...` and `-f sarif` follow it), so "before the
    positional" and "after argv[0]" are different places here, argparse reads
    the flag at either, and moving it would rewrite a pinned argv for no gain.
    """
    if tool == "bandit":
        return cmd[:1] + list(flags) + cmd[1:]
    at = cmd.index("/src") if "/src" in cmd else len(cmd)
    return cmd[:at] + list(flags) + cmd[at:]


def _without_skip_list(cmd):
    """*cmd* with bandit's `-s <tests>` pair removed (#1839 fix round 1 §A).

    Measured in the pinned image: with the TARGET's ini pinned (`--ini
    /src/.bandit`) and the scanner's own `-s B101,B404,B110,B112` still on the
    argv, bandit 1.9.4 exits 2 -- "[main] ERROR Non-exclusive include/exclude
    test sets: {'B101'}" -- and writes no SARIF at all whenever that ini names
    an overlapping `tests`. A selected-but-unproduced scanner (#1452) is not
    what honouring the operator's file means, and the file governs skips and
    tests by definition once it is honoured, so the CLI list comes off with it.
    The `--exclude=` value stays: the same round measured a CLI `--exclude`
    merging cleanly with an ini (probe (c)).
    """
    if "-s" not in cmd:
        return cmd
    at = cmd.index("-s")
    return cmd[:at] + cmd[at + 2:]


def _with_suppression_flags(tool, cmd, security_mode):
    """`cmd` with the flag that stops *tool* honouring an inline suppression
    COMMENT in the target's own source -- under `--security redteam` only
    (#1839, run-14 SEC-284952751).

    The two kinds of in-tree suppression are not the same claim. An ignore FILE
    (`.trivyignore`, `osv-scanner.toml`, and bandit's `.bandit` under redteam)
    is target-authored scanner CONFIGURATION and is replaced with a
    scanner-owned one. A COMMENT is in the target's source, in the diff a
    reviewer reads, and under `standard` the operator is scanning their own
    repository, so it stands. It stands DISCLOSED, not silently:
    `write_manifest` publishes `suppression_comments` per tool.

    `standard` is an operator scanning their own repository; this repository's
    own CI (`security.yml` and the fork-PR `security-fork.yml`) scans in
    `redteam`, so nothing target-authored is honoured on either check (owner
    ruling of 2026-09-26; the workflows move in their own PR).

    Only knobs `SUPPRESSION_COMMENTS` names are passed, and only where that
    table records one as verified against the pinned image.
    """
    if security_mode != REDTEAM:
        return cmd
    flag = SUPPRESSION_COMMENTS.get(tool, (None, None))[1]
    if not flag:
        return cmd
    return _insert_flags(tool, cmd, [flag])


def _record_suppression_posture(tool, ignored, security_mode):
    """Publish what this launch really does with *tool*'s inline suppression
    comments (#1839), read off whatever DECIDES it for that tool.

    For a flag-lever tool (bandit, gitleaks) that is the argv: *ignored* is read
    back from the command this launch will run, so taking the flag away changes
    the claim instead of leaving an intention behind. For an ingest-lever tool
    (`SUPPRESSION_INGEST_LEVER`) the argv decides nothing and the run's MODE
    does, so the row follows the mode -- otherwise removing a belt flag would
    publish `honoured` for a run that ignores every such comment.

    Silent for a tool `SUPPRESSION_COMMENTS` has not assessed: an absent row
    says nobody looked, which is not the same claim as `n/a`.
    """
    entry = SUPPRESSION_COMMENTS.get(tool)
    if entry is None:
        return
    if entry[0] is None:
        _SUPPRESSION_POSTURE[tool] = SUPPRESSION_NA
        return
    if tool in SUPPRESSION_INGEST_LEVER:
        ignored = security_mode == REDTEAM
    _SUPPRESSION_POSTURE[tool] = (SUPPRESSION_IGNORED if ignored
                                  else SUPPRESSION_HONOURED)


def _suppression_flag_on(tool, cmd):
    """True when the flag that neutralises *tool*'s suppression comments is on
    the argv this launch will really run -- read back, not assumed. Only
    meaningful for a flag-lever tool; `SUPPRESSION_INGEST_LEVER` names the
    others, whose row `_record_suppression_posture` takes from the mode."""
    flag = SUPPRESSION_COMMENTS.get(tool, (None, None))[1]
    return bool(flag) and flag in cmd


def _record_scanner_config(tool, cmd):
    """Publish which configuration file this launch actually pinned (#1839),
    read off the argv rather than from the branch that built it. Silent for a
    tool that is pinned to no configuration of ours."""
    if tool not in SCANNER_OWNED_CONFIG:
        return
    _SCANNER_CONFIG_POSTURE[tool] = (CONFIG_TARGET_BANDIT
                                     if TARGET_BANDIT_INI in cmd
                                     else CONFIG_SCANNER_OWNED)


def _adapter_security_mode(docker_argv):
    """The security mode actually named on an adapter dispatch argv (#1839).

    `--security-opt=no-new-privileges` is one attached token, so it cannot be
    mistaken for this flag.
    """
    try:
        return docker_argv[docker_argv.index(SECURITY_FLAG) + 1]
    except (ValueError, IndexError):
        return "standard"


@contextlib.contextmanager
def _staged_scanner_file(prefix, name, contents):
    """Stage one public scanner-owned file in a private temporary directory."""
    scratch = path = error = None
    try:
        scratch = tempfile.mkdtemp(prefix=prefix)
        path = os.path.join(scratch, name)
        if isinstance(contents, bytes):
            with open(path, "wb") as fh:
                fh.write(contents)
        else:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(contents)
        os.chmod(path, 0o644)
    except OSError as exc:
        error = exc
        path = None
    try:
        yield path, error
    finally:
        if scratch is not None:
            shutil.rmtree(scratch, ignore_errors=True)


def _ignore_path_identity(path):
    """Device, inode, and file type of the mountpoint; None means absent."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


@contextlib.contextmanager
def _gitleaks_ignore_overlay(target, security_mode):
    """Stage an empty source-root ignore file only for a safe redteam mountpoint.

    Docker cannot mount a file over an absent path in the read-only /src bind.
    A symlink is worse: Docker follows it and hides its referent in the scan.
    Keep the scratch file alive until the capture finishes. The caller checks
    the mountpoint identity again after capture. This detects lasting changes,
    but a transient swap and restore can still escape both observations.
    """
    mountpoint = os.path.join(target, ".gitleaksignore")
    if security_mode != REDTEAM:
        try:
            identity = _ignore_path_identity(mountpoint)
        except OSError as exc:
            print("tool gitleaks: cannot inspect .gitleaksignore (%s); "
                  "left in place under standard" % exc, file=sys.stderr)
            identity = "unreadable"
        yield [], "absent" if identity is None else "honoured", None
        return
    try:
        identity = _ignore_path_identity(mountpoint)
    except OSError as exc:
        print("tool gitleaks skipped: cannot inspect .gitleaksignore (%s)" % exc,
              file=sys.stderr)
        yield None, None, None
        return
    if identity is None:
        yield [], "absent", None
        return
    if identity[2] != stat.S_IFREG:
        print("tool gitleaks skipped: unsafe .gitleaksignore mountpoint; "
              "recording as missing", file=sys.stderr)
        yield None, None, None
        return
    with _staged_scanner_file("pano-gitleaks-ignore-", "gitleaksignore", b"") as (
            host_file, error):
        if error is not None:
            print("tool gitleaks skipped: empty ignore file could not be staged "
                  "(%s); recording as missing" % error, file=sys.stderr)
            yield None, None, None
        else:
            yield ["-v", "%s:%s/.gitleaksignore:ro" % (host_file, TARGET_MOUNT)], \
                "neutralised", identity


@contextlib.contextmanager
def _adapter_ignore_overlay(tool, target, security_mode):
    if tool == "gitleaks":
        with _gitleaks_ignore_overlay(target, security_mode) as observation:
            yield observation
    else:
        yield [], None, None


@contextlib.contextmanager
def _scanner_owned_config(tool, cmd, security_mode="standard", target=None):
    """`(cmd, docker mount flags)` with *tool* pinned to a configuration file WE
    wrote, or `(None, None)` when that file could not be staged.

    Two tools are pinned this way (`SCANNER_OWNED_CONFIG`), for the same reason
    and by the same shape: bandit's `--ini`, and trivy's `--ignorefile`, which
    #1839 added when run-14 found the reviewed repository's `.trivyignore`
    choosing which advisories trivy reported.

    ONE exception, by the owner ruling of 2026-09-25 on #1924, and it is the
    same standard/redteam split the gate already uses: under `standard` a
    `.bandit` the target committed is the OPERATOR's file -- they are scanning
    their own repository, and the exclusions, `tests` and `skips` in it are
    their reviewed choice -- so it is pinned with `--ini /src/.bandit` and
    nothing of ours is staged. Under `--security redteam` the tree is untrusted
    and bandit never honours a target-authored suppression: the scanner-owned
    ini always, plus `--ignore-nosec` from `_with_suppression_flags`. Either way
    the `--ini` is EXPLICIT, which is what pre-empts #run7's discovery walk (a
    nested checkout's second `.bandit` made bandit ERROR and emit nothing), so
    a target with no `.bandit` of its own still gets ours in both modes.
    `write_manifest` publishes which of the two the scan ran under
    (`scanner_config`), so "bandit reported little" can be read against it.

    #run7 is real: bandit AUTO-DISCOVERS `.bandit` files by walking the scanned
    tree, and a nested checkout (a git worktree, a vendored repo) carrying a
    second one makes it ERROR ("Multiple .bandit files found -- ... choose one
    with --ini") and emit EMPTY output -- a selected-but-unproduced tool that
    silently blocked coverage certification on a worktree-heavy checkout.
    `--ini` is the escape hatch bandit itself names, and it is passed on every
    run -- ours here, or the operator's own under `standard` per the ruling
    above -- so the discovery walk never runs whether or not the target ships a
    `.bandit`. Pinning the TARGET's copy in EVERY mode is what handed the
    reviewed repository the scan's scope (#1839), and that is what redteam no
    longer does. The generated file has the same shape as `tools/brakeman.py`
    and `tools/bundler_audit.py`, which answer the same problem with a config
    they generate themselves.

    The file exists to pre-empt bandit's `.bandit` discovery by the `--ini`
    FLAG (bandit 1.9.4 reads `pyproject.toml`/`setup.cfg` only via `-c`, which
    nothing sets) and to keep bandit's stderr free of a config warning that
    `phases/tools.py` would otherwise surface -- so the mount stays even though
    its contents are pure belt.
    The contents are `BANDIT_INI_TEXT`, a module constant, so no directory name
    can reach them (review round 1 C1).

    ONE FILE is mounted, not the directory holding it (review Q4-bis): the
    scratch keeps `mkdtemp`'s own 0700 and is never chmodded, because the
    container reads the bind TARGET and its parent's mode on the host is
    nothing to it. The file itself is 0644 -- the tools image runs as
    `USER scanner`, and its contents are a generated exclusion list with
    nothing private in them. An ini that does not arrive is
    fail-OPEN, not fail-closed -- bandit 1.9.4's `utils.parse_ini_file` CATCHES a
    parse failure or a missing `[bandit]` section, warns
    ("Unable to parse config file ... or missing [bandit] section") and runs on
    the CLI args alone (review round 1 N1; round 0's docstring claimed exit 2,
    which is wrong). That is why the exclusions are on the argv unconditionally
    and this file is belt: what it still guarantees is that bandit's DISCOVERY
    walk never runs, which is #run7's failure.

    A staging failure -- a full or read-only `$TMPDIR`, an `EACCES` on `chmod` --
    yields `(None, None)` instead of raising through the dispatch loop, so it
    costs the ONE tool whose config it was (which lands in the manifest's
    `missing`, fail-closed for that tool) and not the eight scanners queued
    behind it (review round 1 N3).
    """
    if tool not in SCANNER_OWNED_CONFIG:
        yield cmd, []
        return
    if (tool == "bandit" and security_mode != REDTEAM and target is not None
            and os.path.isfile(os.path.join(target, ".bandit"))):
        yield _insert_flags(tool, _without_skip_list(cmd),
                            ["--ini", TARGET_BANDIT_INI]), []
        return
    flag, name, text, attached = SCANNER_OWNED_CONFIG[tool]
    with _staged_scanner_file("pano-scanner-config-", name, text) as (
            config_path, staging_error):
        if staging_error is not None:
            print("tool %s skipped: the scanner-owned config could not be "
                  "staged (%s); recording as missing (fail-closed, #1839)"
                  % (tool, staging_error), file=sys.stderr)
            yield None, None
        else:
            inside = "%s/%s" % (SCANNER_CONFIG_MOUNT, name)
            yield (_insert_flags(tool, cmd,
                                 ["%s=%s" % (flag, inside)] if attached
                                 else [flag, inside]),
                   ["-v", "%s:%s:ro" % (config_path, inside)])
