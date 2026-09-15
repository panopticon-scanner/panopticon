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

NO host binary and NO paid dispatch runs here (ruling 2). The capability
posture is already established by `driver._establish_host_posture` on every
invocation, so `setup_flow._check_host_shells` -- which starts a host CLI -- is
deliberately not among the checks reused below; the artifact it writes is
recorded here as one INFORMATIONAL row and nothing more.
"""
import os

import scripts.host_disclosure as host_disclosure
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

# The docker probe's launcher, as a module attribute so one patch can reach it.
# `None` means "use setup_flow's", which is `subprocess.run` in production and
# the suite's refusal under tests/conftest.py's autouse guard -- so a test that
# wants a docker answer has to say so, and one that says nothing reaches
# nothing. Same construction, and the same reason, as the host-CLI launch seams
# in tests/test_host_launch_guard.py; this one is not a host CLI, so it is not
# spelled DEFAULT_RUNNER and does not belong in LAUNCH_SEAMS.
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
