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

The environment checks themselves -- Docker and the tools image, the Python
packages, the host CLIs on PATH -- are `phases/readiness_checks.py`, and the
`DOCKER_RUNNER` test-only injection seam moved there with the check that
reads it. What is decided about those rows, and the artifact and the table
built out of them, stay here.

NO host binary and NO paid dispatch runs here (ruling 2). The capability
posture is already established by `driver._establish_host_posture` on every
invocation, so `setup_flow._check_host_shells` -- which starts a host CLI -- is
deliberately not among the checks reused below; the artifact it writes is
recorded here as one INFORMATIONAL row and nothing more.
"""
import glob as _glob
import json
import os
import sys

import scripts.discovery as discovery
import scripts.grouping_engine as grouping_engine
import scripts.host_disclosure as host_disclosure
import scripts.hosts as hosts
import scripts.run_manifest as run_manifest
import scripts.setup_flow as setup_flow
from . import engine
from . import readiness_checks
from . import runio


READINESS = "readiness.json"
SCHEMA_VERSION = 1


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
    checks = list(readiness_checks._docker_checks(tools_flag))
    checks.append(_git_root_row(review_root))
    checks.append(setup_flow._check_groups_manifest(review_root))
    checks.append(_host_row(review_root))
    # #1639 P15 fix round 2, F7. GATING, and here rather than only in the
    # `preflight` verb: this phase is the pre-spend checkpoint `driver loop`
    # actually runs, and an operator who never types `driver readiness` gets
    # every check from it. A missing `jsonschema` does not surface until
    # synthesize refuses to publish an unvalidated artifact -- after the whole
    # review has been paid for -- so it belongs before the first dispatch.
    dependencies = readiness_checks._dependencies_row()
    checks.append(("dependencies", dependencies["ok"], dependencies["detail"]))
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


def _capabilities_row(review_root, tag):
    """The LAST run's measurement, read back. Never re-probed and never gating:
    probing is `driver._establish_host_posture`'s job on a real invocation, and
    doing it here would start a host CLI."""
    envelope = None
    if tag:
        envelope = runio._load_json(os.path.join(
            review_root, ".panopticon", "runs", tag, runio.HOST_CAPABILITIES))
    caps = envelope.get("capabilities") if isinstance(envelope, dict) else None
    who = host_disclosure.host_of(envelope)      # str or None, as headline() reads it
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
    tools_image = readiness_checks._tools_image_row()
    cli = readiness_checks._cli_rows(host)
    # Tri-state: True passes, False gates, None is INFORMATIONAL and passes.
    # `all(...)` would have read None as a failure, which is why this is a
    # `is False` filter and not a truthiness test.
    dependencies = readiness_checks._dependencies_row()
    gating = (("guide", guide["ok"]), ("dependencies", dependencies["ok"]),
              ("matrix", matrix["ok"]),
              ("cli", readiness_checks._cli_gate(cli)),
              ("tools-image", tools_image["ok"]))
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
            ("cli", readiness_checks._cli_gate(document["cli"]),
             _cli_cell(document["cli"])),
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
