"""Phase 0 -- readiness: the environment checkpoint that runs BEFORE any paid
scouting (#1637 P08, owner ruling D7).

Run-13 is the case this phase exists for. Twelve scouts were dispatched and
paid for; then `tools` found the `panopticon-tools` image absent (Docker itself
was up), wrote a `skipped: true` marker, and 85 review panels went out with no
scanner evidence at all -- and the marker made that skip permanent, so
installing the image afterwards would not have retried the scan. The scanner
posture was discovered halfway down a run that had already spent money on the
strength of it.

So it is a STEP, with a pre-requisite and a post-requisite, in the thin
deterministic layer -- not a flag, and not a warning:

* pre-requisite: the run manifest exists (it always does by the time the engine
  runs -- `driver.run` writes it before `run_engine`).
* post-requisite: `runs/<tag>/readiness.json`, the artifact the done predicate
  reads back.
* it fails CLOSED. Any gating check that answers `false` raises
  `runio.DriverError` -- before `discovery`, before `coverage`, and therefore
  before a single dispatch entry is written -- with every failed check's remedy
  in the message, verbatim and copy-pasteable.

`--no-tools` is the documented way past it: the docker rows become `ok: null`
("not applicable"), readiness passes, and the run reviews without scanner
evidence. That is a disclosed choice, not a silent one -- it is recorded in
`tools-ran.json`, in the report's tool coverage, and in
`meta.tools.panels_with_scanner_context`.

`DOCKER_RUNNER` below is a TEST-ONLY injection point. Its production value is
`None` -- meaning "use `setup_flow.DEFAULT_RUNNER`" -- and no module outside
`tests/` may assign it: a non-`None` value left in shipped code makes this
checkpoint answer "ok" off a fake without probing Docker at all, which is the
one check gating every paid dispatch. See DEVELOPMENT.md, "Test-only injection
seams"; `tests/phases/test_readiness.py` asserts both halves.

NO host binary and NO paid dispatch runs here (ruling 2). The capability
posture is already established by `driver._establish_host_posture` on every
invocation, so `setup_flow._check_host_shells` -- which starts a host CLI -- is
deliberately not among the checks reused below; the artifact it writes is
recorded here as one INFORMATIONAL row and nothing more.
"""
import glob as _glob
import importlib.util
import json
import os
import shutil
import sys

import scripts.discovery as discovery
import scripts.grouping_engine as grouping_engine
import scripts.host_disclosure as host_disclosure
import scripts.hosts as hosts
import scripts.run_manifest as run_manifest
import scripts.setup_flow as setup_flow
from . import engine
from . import runio


READINESS = "readiness.json"
SCHEMA_VERSION = 1

# The repo root, resolved from `skill/`'s own location rather than from cwd:
# the remedy below names a `docker build` path, and the driver runs with cwd at
# the TARGET repo, which is emphatically not where the Dockerfile lives. Under
# the installed-flow substitution (#495) this resolves to whatever directory
# the skill was installed into, which is the correct answer there too.
_SKILL_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_REPO_ROOT = os.path.dirname(_SKILL_DIR)

TOOLS_IMAGE = "ghcr.io/panopticon-scanner/panopticon-tools:latest"

# Exact and paste-able, all three ways out in one line. `setup_flow`'s own
# tools-image detail points at DEVELOPMENT.md, which is the right register for
# a preflight report an operator reads at leisure and the wrong one for a
# refusal that just stopped a run: the remedy has to be runnable from the line
# it is printed on.
IMAGE_REMEDY = (
    "the panopticon-tools image is absent, so every scanner would produce "
    "nothing and every review panel would run without scanner evidence. "
    "Pull it: `docker pull %s && docker tag %s panopticon-tools:latest` -- "
    "or build it: `docker build -t panopticon-tools %s` -- or re-run with "
    "--no-tools to review without scanner evidence, which is disclosed in the "
    "report (meta.tools.panels_with_scanner_context and the tool coverage "
    "line)." % (TOOLS_IMAGE, TOOLS_IMAGE, _REPO_ROOT))

_NOT_APPLICABLE = "not applicable (--no-tools)"

# TEST-ONLY injection point; production value is None (see the module
# docstring). `None` means "use setup_flow's", which is `subprocess.run` in
# production and the suite's refusal under tests/conftest.py's autouse guard --
# so a test that wants a docker answer has to say so, and one that says nothing
# reaches nothing. Same construction, and the same reason, as the host-CLI
# launch seams in tests/test_host_launch_guard.py; this one is not a host CLI,
# so it is not spelled DEFAULT_RUNNER and does not belong in LAUNCH_SEAMS.
DOCKER_RUNNER = None


def _docker_checks(tools_flag):
    """The daemon + image rows, or two `ok: null` rows under `--no-tools`.

    Not merely skipped when tools are off: a row that vanishes is
    indistinguishable from a row that passed, and the artifact has to say which
    of the two happened on this run.
    """
    if tools_flag is False:
        return [("docker", None, _NOT_APPLICABLE),
                ("tools-image", None, _NOT_APPLICABLE)]
    runner = DOCKER_RUNNER if DOCKER_RUNNER is not None else setup_flow.DEFAULT_RUNNER
    rows = []
    for name, ok, detail in setup_flow._check_docker(runner):
        if name == "tools-image" and ok is False:
            detail = IMAGE_REMEDY
        rows.append((name, ok, detail))
    return rows


def _host_row(review_root):
    """`host-capabilities.json`, INFORMATIONAL (`ok: null`) and never gating.

    Readiness does not probe: `driver._establish_host_posture` has already run
    by the time the engine reaches this phase, and re-deriving a posture here
    would either duplicate that work or -- via `setup_flow._check_host_shells`
    -- launch a host CLI, which ruling 2 forbids. So this reads the artifact
    back and says what it says.

    The operational facts come from `host_disclosure.notes`, NOT from
    `lines()`: three consumers read that list as "capabilities this run does
    not verify", and a CLI-flag fact appended there would report as an
    unproven capability (D10 N2).
    """
    envelope = runio._load_json(runio._pano(review_root, runio.HOST_CAPABILITIES))
    if not isinstance(envelope, dict):
        return ("host-capabilities", None,
                "not recorded for this run yet -- the posture is established "
                "on every driver invocation, before any phase runs")
    return ("host-capabilities", None,
            "; ".join([host_disclosure.headline(envelope)]
                      + host_disclosure.notes(envelope)))


def _git_root_row(review_root):
    """`setup_flow._check_git_root`, recorded but NOT gating.

    `runio.resolve_review_root` supports a non-git target BY DESIGN -- it falls
    back to reviewing the directory itself, and what degrades is delta scoping
    (`-c`/`--pr`/`--base`) and the clean-tree baseline, not the review. A
    readiness step that refused one would invent a restriction the engine does
    not have, which is a product change rather than a preflight. `driver
    setup`'s own readiness keeps it gating, and should: setup is where an
    operator is still choosing the root.
    """
    name, ok, detail = setup_flow._check_git_root(review_root)
    if ok:
        return (name, True, detail)
    return (name, None,
            "not a git repo root -- the run proceeds over the directory "
            "itself; delta scoping (-c/--pr/--base) and the clean-tree "
            "baseline are what degrade")


def _checks(review_root, manifest):
    tools_flag = (manifest.get("flags") or {}).get("tools")
    checks = list(_docker_checks(tools_flag))
    checks.append(_git_root_row(review_root))
    checks.append(setup_flow._check_groups_manifest(review_root))
    checks.append(_host_row(review_root))
    return checks


def _refusal(failed):
    """The message the refusal carries: every failed row's remedy, verbatim.

    Verbatim because the remedy IS the check's output -- paraphrasing it here
    would give the operator two texts to reconcile, and the one printed by the
    thing that actually stopped the run is the one they will paste.
    """
    return ("readiness: refusing to start -- %d check(s) failed, and the first "
            "dispatch after this point is paid work done on an environment "
            "that cannot support it. %s"
            % (len(failed), " ".join("[%s] %s" % (name, detail)
                                     for name, detail in failed)))


def readiness_done(review_root, manifest):
    """The artifact parses, `ready` is true, it belongs to THIS run, and it was
    written under the tools flag this invocation is carrying.

    That last clause is what keeps a pass from becoming a cached one: a
    `--no-tools` run passes readiness without looking at Docker at all, and
    trusting that record after the operator switched tools back on would walk
    straight past the only check the switch made relevant.
    """
    body = runio._load_json(runio._pano(review_root, READINESS))
    if not isinstance(body, dict) or body.get("ready") is not True:
        return False
    if body.get("run_id") != manifest.get("run_id"):
        return False
    flags = body.get("flags")
    if not isinstance(flags, dict):
        return False
    return flags.get("tools") == (manifest.get("flags") or {}).get("tools")


def readiness_execute(review_root, manifest):
    checks = _checks(review_root, manifest)
    failed = [(name, detail) for name, ok, detail in checks if ok is False]
    # Written BEFORE the refusal, deliberately: the operator's next question
    # after a one-line refusal is "what else did it look at", and an artifact
    # that exists only on the happy path cannot answer it. `ready: false` also
    # keeps the done predicate honest -- the next invocation re-evaluates.
    runio._write_json(
        runio._pano(review_root, READINESS),
        {"schema_version": SCHEMA_VERSION,
         "run_id": manifest.get("run_id"),
         "checked_at": run_manifest._now_iso(),
         "ready": not failed,
         "flags": {"tools": (manifest.get("flags") or {}).get("tools")},
         "checks": [{"name": name, "ok": ok, "detail": detail}
                    for name, ok, detail in checks]})
    if failed:
        raise runio.DriverError(_refusal(failed))
    return engine.PhaseResult(
        kind="advanced",
        message="readiness: %d check(s), none failing" % len(checks))


# --- `driver readiness`: the preflight verb (#1637 P10) ---------------------
#
# The PHASE above answers one question inside a run that is already paying for
# itself. This answers the question a host has BEFORE it launches anything, and
# run-13 is again the case: its controller had no way to ask "can this machine
# run a review", so it answered by reading long documents and searching another
# host's plugin trees, and then started a run whose scanner image was absent.
#
# Three properties, each pinned by tests/phases/test_readiness_verb.py:
#
# * it LAUNCHES NOTHING. `shutil.which` is the only thing that looks at a host
#   binary, the docker probe goes through the phase's own seam, and the module
#   does not import `subprocess` -- so tests/test_host_launch_guard.py's walk
#   does not find a seam here, which is the structural half of the promise.
# * it WRITES NOTHING under the target. A preflight that leaves artifacts is a
#   run, and the operator asked for neither.
# * the EXIT CODE is the product. `driver readiness && driver loop` is the
#   whole point, so a gating row that fails takes it to 1 and an informational
#   one must never move it.

PREFLIGHT_SCHEMA_VERSION = 1

# Named in SKILL.md's "Required sub-skills" and searched for here.
REQUIRED_SUB_SKILLS = ("superpowers:writing-plans",
                       "superpowers:subagent-driven-development",
                       "superpowers:verification-before-completion")

# Where hosts TYPICALLY install them -- read-only, and never written. The same
# four roots SKILL.md's Dependencies section tells a host about (P02); the test
# pins the two lists together, because a doc that sends an operator to one
# directory while the verb searches another is worse than saying nothing.
SUB_SKILL_ROOTS = ("~/.claude/plugins", "~/.codex/skills",
                   "~/.agents/skills", "~/.kimi/skills")

# Bounded globs rather than a walk: a plugin cache can be enormous, this runs
# before every loop, and an unbounded `os.walk` over four roots is exactly the
# cost P10 exists to remove.
#
# Anchored on `skills/<leaf>` for everything below the top two levels, which is
# what makes the bound affordable: a host that nests plugins puts them under a
# `skills/` directory, so the measured layout on this workstation --
# `~/.claude/plugins/cache/<marketplace>/superpowers/<version>/skills/
# writing-plans/` -- is reached in one pattern rather than by growing the star
# ladder until it happens to be long enough. The two unanchored forms cover a
# flat root (`~/.codex/skills/<leaf>/`) and one directory of nesting.
_SUB_SKILL_GLOBS = ("%s", "*/%s", "skills/%s", "*/skills/%s", "*/*/skills/%s",
                    "*/*/*/skills/%s", "*/*/*/*/skills/%s")

NOT_MEASURED = "not measured — first `driver run` probes"

# Fix round 1, F4: `tools_image`'s remedy names `--no-tools`, and this one has
# to name its own way out for the same reason. `-f`/`-d`/`-g`/`--pr` reviews run
# fine with no committed matrix (`discovery._declares_groups`' adopt-all
# fallback); only the whole-repo scope degrades to `._N` chunking. The verb
# shares no scope flag -- deliberately -- so it reports the whole-repo answer
# and says which scopes that answer does not apply to.
NO_GROUPS = ("no groups.yml — run `driver setup`; a whole-repo review needs it, "
             "the -f / -d / -g / --pr scopes do not (this verb takes no scope "
             "flag, so it reports the whole-repo answer)")

# Fix round 1, F2. `--host H` is a statement about how the run will be DRIVEN,
# and `orchestrate._resolve_mode` resolves it to headless whenever
# `skill/scripts/runners/<H>.py` exists -- a fact about this repo, never about
# this machine. So `driver readiness --host claude && driver loop --host claude`
# on a box with no `claude` used to greenlight a loop that resolves to headless
# and then has nothing to launch: the failure class P10 exists to remove.
# Both ways out, and the session invocation is `orchestrate`'s real one.
# How the resolved host was chosen, spelled for someone reading a table.
# `runio.HOST_SOURCES` owns the tokens; this only says what each one MEANS.
HOST_SOURCE_NOTES = {
    "--host": "--host",
    "manifest": "from this run's manifest, which is what a resumed "
                "`driver loop` uses",
    "default": "the driver's default; a bare `driver loop` would assume the "
               "same here, so pass --host to check a different one",
}

SESSION_REMEDY = (
    "not on PATH — install `%(binary)s`, or drive this host in session mode: "
    "`driver loop --host %(host)s --mode session`. `driver loop` picks headless "
    "whenever skill/scripts/runners/%(host)s.py exists, which is a fact about "
    "this repo and not about this machine, so it would resolve to headless here "
    "and find no binary")

# Rendered width of the row label column, so the human form is a table and not
# a ragged list.
_LABEL = 13


def _find_sub_skill(leaf):
    """The first `SKILL.md` for `leaf` under any documented root, or None."""
    for root in SUB_SKILL_ROOTS:
        base = os.path.expanduser(root)
        if not os.path.isdir(base):
            continue
        for pattern in _SUB_SKILL_GLOBS:
            hits = sorted(_glob.glob(
                os.path.join(base, pattern % leaf, "SKILL.md")))
            if hits:
                return hits[0]
    return None


# #1639 P15 I2: the Python packages a RUN needs, as (import name, pip name).
# Both are declared in `pyproject.toml`'s `[project] dependencies` and
# `tests/phases/test_readiness_verb.py` holds this tuple to that list, so the
# two cannot drift. Checked HERE, before the first paid dispatch, because
# neither failure is cheap where it actually lands: `jsonschema` is imported by
# the completion path's artifact validation, which is deliberately fail-closed,
# so an install without it does not quietly stop validating -- it exits
# `artifact invalid` after the whole review has been paid for. PyYAML is a hard
# import in discovery and takes the run down with a traceback.
RUNTIME_PACKAGES = (("yaml", "pyyaml"), ("jsonschema", "jsonschema"))

PACKAGES_REMEDY = "pip install %s (or `pip install -e .` in a checkout)"


def _installed(module):
    """Is `module` importable? A seam, so a test can state the machine.

    `find_spec` rather than `import`: this is a preflight, and importing a
    package for its side effects is not a read. It can raise on a broken
    parent package, which is itself a "not usable" answer.
    """
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _dependencies_row():
    """Gating: every package the run itself imports, by pip name."""
    missing = [pip for module, pip in RUNTIME_PACKAGES if not _installed(module)]
    checked = ", ".join(pip for _module, pip in RUNTIME_PACKAGES)
    return {"missing": missing, "ok": not missing,
            "detail": (PACKAGES_REMEDY % " ".join(missing)) if missing
                      else "%s installed" % checked}


def _sub_skill_rows():
    """[{name, found_at}] -- never gating (SKILL.md ruling: a missing sub-skill
    is a documented default plus a disclosure, not a stop)."""
    return [{"name": name,
             "found_at": _find_sub_skill(name.split(":", 1)[-1])}
            for name in REQUIRED_SUB_SKILLS]


def _guide_row():
    """Gating: SKILL.md's first instruction is to read this file, and a host
    that cannot has no contract at all (#1637 P01)."""
    path = hosts.guide_path()
    exists = os.path.isfile(path)
    return {"path": path, "exists": exists, "ok": exists,
            "detail": path if exists else
                      "the guide is missing from this install -- reinstall the "
                      "skill; it ships at skill/docs/%s and %s is a symlink "
                      "onto it" % (hosts.GUIDE, os.path.join("docs", hosts.GUIDE))}


def _matrix_row(review_root):
    """The committed matrix and what it has to review. Gating: without a
    committed `groups.yml` every file falls back to `._N` chunks, which is a
    different review from the one the operator thinks they asked for."""
    counts = {"groups": 0, "code_files": 0, "tests_files": 0}
    if not os.path.isfile(os.path.join(review_root, ".panopticon", "groups.yml")):
        return dict(counts, ok=False, detail=NO_GROUPS)
    try:
        catalog = discovery._matrix_catalog(review_root) or {}
    except ValueError as exc:
        return dict(counts, ok=False,
                    detail="%s -- fix it or re-run `driver setup`" % exc)
    code_files, _commons, tests_files = grouping_engine.count_code_files(
        discovery.discover_repo_files(review_root))
    counts = {"groups": len(catalog), "code_files": code_files,
              "tests_files": tests_files}
    if not catalog:
        return dict(counts, ok=False,
                    detail="groups.yml declares no groups — run `driver setup`")
    unmatched = sorted(name for name, group in catalog.items()
                       if not (group or {}).get("match"))
    if unmatched:
        return dict(counts, ok=False,
                    detail="group(s) with no match patterns: %s — run "
                           "`driver setup`" % ", ".join(map(str, unmatched)))
    return dict(counts, ok=True,
                detail="%d group(s), %d code file(s), %d test file(s)"
                       % (len(catalog), code_files, tests_files))


def _entry_pending(entry):
    """A floor, deliberately: the ENGINE additionally applies each role's
    acceptance to the parsed reply, and reaching that here would mean importing
    half of `phases/` (and, through `persist`, the probe machinery this module
    is forbidden) into a preflight. An out_file that is absent or does not
    parse is pending on anybody's reading."""
    out_file = entry.get("out_file") if isinstance(entry, dict) else None
    if not out_file or not os.path.isfile(out_file):
        return True
    return runio._load_return_json(out_file) is None


def _existing_run_row(review_root):
    """What a bare `driver loop` here would resume, from `runs/latest`.

    `status` is the last state RECORDED for that run: `complete` (a durable
    report exists), `error` (the run stopped at the readiness checkpoint, which
    wrote its verdict), `checkpoint` (a dispatch request with entries still
    pending), and `started` for a run folder that exists but has recorded none
    of those yet.

    `none` means exactly one thing -- there is no run in this tree -- and that
    is fix round 1's F3: it used to cover both that and "a run in progress with
    nothing pending", so a `--json` consumer keying on `status` alone could not
    tell them apart while the row's own `detail` said which. A non-null `tag`
    with `none` was the contradiction.
    """
    runs = os.path.join(review_root, ".panopticon", "runs")
    try:
        tag = os.path.basename(os.readlink(os.path.join(runs, "latest")))
    except OSError:
        # No symlink (a platform without them, or a run that never got that
        # far): the manifest anchors the same tag.
        tag = run_manifest.run_tag(run_manifest.load_manifest(review_root))
    if not tag or not os.path.isdir(os.path.join(runs, tag)):
        return {"tag": None, "status": "none", "pending": 0,
                "detail": "none -- no previous run in this tree"}
    folder = os.path.join(runs, tag)
    report = os.path.join(review_root, ".panopticon", "%s-report.json" % tag)
    if os.path.isfile(report):
        return {"tag": tag, "status": "complete", "pending": 0,
                "detail": "complete: %s (`--reset` starts a new run)" % report}
    verdict = runio._load_json(os.path.join(folder, READINESS))
    if isinstance(verdict, dict) and verdict.get("ready") is False:
        failed = [row.get("name") for row in (verdict.get("checks") or [])
                  if isinstance(row, dict) and row.get("ok") is False]
        return {"tag": tag, "status": "error", "pending": 0,
                "detail": "%s stopped at readiness (%s)"
                          % (tag, ", ".join(map(str, failed)) or "no row named")}
    pending = 0
    request = runio._load_json(os.path.join(folder, "dispatch-request.json"))
    entries = request.get("entries") if isinstance(request, dict) else None
    if isinstance(entries, list):
        pending = sum(1 for entry in entries if _entry_pending(entry))
    if pending:
        return {"tag": tag, "status": "checkpoint", "pending": pending,
                "detail": "%s: %d entry(ies) pending -- `driver loop` resumes it"
                          % (tag, pending)}
    return {"tag": tag, "status": "started", "pending": 0,
            "detail": "%s: started, nothing pending -- `driver loop` carries it "
                      "on" % tag}


def _cli_rows(host):
    """`shutil.which` and nothing else, for every host whose registry row names
    a headless CLI -- plus the SELECTED host always, even when it names none,
    because an operator who passed `--host generic` must not read three rows
    about hosts they did not ask about and none about the one they did.

    `host` is the RESOLVED host, never the raw flag: fix round 2's whole point
    is that a bare invocation still has one (`runio.resolve_host`), so there is
    always a selected row and this check is never vacuous.

    `binary` and `on_path` are null for a host that launches no CLI of ours:
    there is nothing to look for, which is a different answer from "looked and
    did not find it".

    Only the selected row can gate (F2), and only when it names a binary that
    is absent -- see SESSION_REMEDY. The others are informational: `driver
    loop` will not pick them, so their absence costs this run nothing."""
    names = set(hosts.driver_hosts())
    if hosts.spec(host) is not None:
        # A manifest may name a registered-but-unselectable host (`gemini`);
        # `orchestrate.loop` refuses that separately, and a row saying nothing
        # about the host this document is ABOUT would be worse than either.
        names.add(host)
    rows = []
    for name in sorted(names):
        binary = hosts.spec(name).cli_binary
        selected = name == host
        if not binary and not selected:
            continue                  # session-only, and not the one asked about
        found = shutil.which(binary) if binary else None
        rows.append({"host": name, "binary": binary or None,
                     "on_path": bool(found) if binary else None,
                     "path": found, "selected": selected,
                     "remedy": (SESSION_REMEDY % {"binary": binary, "host": name}
                                if selected and binary and not found else None)})
    rows.sort(key=lambda row: (not row["selected"], row["host"]))
    return rows


def _cli_gate(rows):
    """`False` when the selected host cannot be launched the way `driver loop`
    would launch it, else `True`.

    Never `None` (fix round 2, item 2): this row CAN fail, so when it does not
    it says `ok`, like every other gating row -- `--` is reserved for the three
    rows nothing is checked against, and a passing check wearing the token for
    "not checked" understates what was verified. Derived from the rows rather
    than stored beside them, so the JSON contract stays the list the brief
    specified."""
    return not any(row["remedy"] for row in rows)


def _tools_image_row():
    """The phase's own two docker rows and the phase's own remedy text, through
    the phase's own seam -- so the preflight and the checkpoint cannot tell an
    operator two different stories about one machine."""
    rows = {name: (ok, detail) for name, ok, detail in _docker_checks(None)}
    docker_ok, docker_detail = rows.get("docker", (False, "docker was not probed"))
    if not docker_ok:
        return {"docker": False, "image": False, "ok": False,
                "remedy": docker_detail}
    image_ok, image_detail = rows.get("tools-image", (False, IMAGE_REMEDY))
    # F7: `null`, not the string "ok". A field called `remedy` holding "ok"
    # rendered as `tools-image   ok   ok`, and read as a contract it claimed
    # there was a remedy to apply. The two booleans beside it already say what
    # was probed, so there is nothing for the healthy case to add.
    return {"docker": True, "image": bool(image_ok), "ok": bool(image_ok),
            "remedy": None if image_ok else image_detail}


def _capabilities_row(review_root, tag):
    """The LAST run's measurement, read back. Never re-probed and never gating:
    probing is `driver._establish_host_posture`'s job on a real invocation, and
    doing it here would start a host CLI."""
    envelope = None
    if tag:
        envelope = runio._load_json(os.path.join(
            review_root, ".panopticon", "runs", tag, runio.HOST_CAPABILITIES))
    caps = envelope.get("capabilities") if isinstance(envelope, dict) else None
    who = envelope.get("host") if isinstance(envelope, dict) else None
    if not isinstance(caps, dict) or not who:
        return {"measured": False, "host": None, "states": {}, "unproven": [],
                "detail": NOT_MEASURED}
    states = hosts.posture(who, caps)
    return {"measured": True, "host": who, "states": states,
            "unproven": hosts.unproven(states),
            "detail": "; ".join([host_disclosure.headline(envelope)]
                                + host_disclosure.notes(envelope))}


def preflight(target=".", host=None):
    """The whole document. Reads; never writes, never launches.

    `host` is the raw `--host`, which is usually absent. The host this document
    is ABOUT is `runio.resolve_host`'s answer -- the same function
    `orchestrate.loop` asks, so the preflight cannot gate on a different host
    from the one the loop would drive (fix round 2, item 1). Without it a bare
    `driver readiness` had no selected row at all and passed a machine with no
    host CLI on it, while the equally bare `driver loop` resolved a host
    perfectly well and went looking for its binary.

    `selected_from` records WHICH rule answered, because "readiness said this
    machine was fine" is only useful if the operator can see which host it
    meant.
    """
    review_root = runio.resolve_review_root(target)[0]
    host, selected_from = runio.resolve_host(host, review_root)
    guide = _guide_row()
    matrix = _matrix_row(review_root)
    existing = _existing_run_row(review_root)
    tools_image = _tools_image_row()
    cli = _cli_rows(host)
    # Tri-state: True passes, False gates, None is INFORMATIONAL and passes.
    # `all(...)` would have read None as a failure, which is why this is a
    # `is False` filter and not a truthiness test.
    dependencies = _dependencies_row()
    gating = (("guide", guide["ok"]), ("dependencies", dependencies["ok"]),
              ("matrix", matrix["ok"]),
              ("cli", _cli_gate(cli)), ("tools-image", tools_image["ok"]))
    failed = [name for name, ok in gating if ok is False]
    return {"schema_version": PREFLIGHT_SCHEMA_VERSION,
            "target": os.path.abspath(target),
            "review_root": review_root,
            "host": host,
            "selected_from": selected_from,
            "ready": not failed,
            "failed": failed,
            "guide": guide,
            "dependencies": dependencies,
            "sub_skills": _sub_skill_rows(),
            "matrix": matrix,
            "existing_run": existing,
            "cli": cli,
            "tools_image": tools_image,
            "capabilities": _capabilities_row(review_root, existing["tag"])}


def _row_lines(document):
    """(label, state, detail) per row. `--` is informational: it never moves
    the exit code, and rendering it as `ok` would tell an operator that a
    sub-skill they do not have is fine AND that it was checked for pass/fail."""
    sub_skills = "; ".join(
        "%s: %s" % (row["name"].split(":", 1)[-1], row["found_at"] or "not found")
        for row in document["sub_skills"])
    return (("guide", document["guide"]["ok"], document["guide"]["detail"]),
            ("dependencies", document["dependencies"]["ok"],
             document["dependencies"]["detail"]),
            ("sub-skills", None, sub_skills),
            ("matrix", document["matrix"]["ok"], document["matrix"]["detail"]),
            ("existing-run", None, document["existing_run"]["detail"]),
            ("cli", _cli_gate(document["cli"]), _cli_cell(document["cli"])),
            ("tools-image", document["tools_image"]["ok"],
             document["tools_image"]["remedy"] or ""),
            ("capabilities", None, document["capabilities"]["detail"]))


def _cli_cell(rows):
    """`→ ` marks the host this invocation named (F2): without it the table was
    a flat list and the operator could not see which row `driver loop` would
    act on."""
    parts = []
    for row in rows:
        if row["remedy"]:
            what = row["remedy"]
        elif row["binary"] is None:
            what = "no CLI of ours — session mode only"
        else:
            what = row["path"] or "not on PATH"
        parts.append("%s%s: %s" % ("→ " if row["selected"] else "",
                                   row["host"], what))
    return "; ".join(parts)


def render(document):
    """One compact table: a header, one line per row, one verdict. No prose --
    a failing row's remedy IS its line."""
    lines = ["panopticon readiness — %s · host %s (%s)"
             % (document["review_root"], document["host"],
                HOST_SOURCE_NOTES.get(document["selected_from"],
                                      document["selected_from"]))]
    for label, ok, detail in _row_lines(document):
        state = "--" if ok is None else ("ok" if ok else "FAIL")
        # rstrip: a row with nothing to remedy ends at its verdict (F7), and a
        # line of trailing spaces is not a blank cell, it is invisible noise.
        lines.append(("  %-*s %-4s %s" % (_LABEL, label, state, detail)).rstrip())
    lines.append("READY" if document["ready"] else
                 "NOT READY — %d gating check(s) failed: %s"
                 % (len(document["failed"]), ", ".join(document["failed"])))
    return "\n".join(lines) + "\n"


def emit_preflight(target=".", host=None, as_json=False, stream=None):
    """Print the document and return the process exit code (0 ready, 1 not),
    so `driver readiness && driver loop` is a correct thing for a host to
    write. `sys.stdout` is read at CALL time, not bound at import, so a caller
    that redirects it gets the output."""
    document = preflight(target, host)
    out = stream if stream is not None else sys.stdout
    out.write(json.dumps(document, indent=2, sort_keys=True) + "\n"
              if as_json else render(document))
    return 0 if document["ready"] else 1
