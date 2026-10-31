"""#3233: what `driver readiness` can say about the run its flags describe, without starting it.

Every row here is informational and none moves the exit code. Each one says what it measured, or
that it cannot say and why; none of them guesses. Nothing is written under the target: discovery
and the shell render each write into a temp directory of their own, removed on every exit path, and
nothing here launches a host CLI.
"""
import contextlib
import io
import json
import os
import re
import shutil
import tempfile

import scripts.discovery as discovery
import scripts.dispatch as dispatch
import scripts.probes.common as probes_common
import scripts.redact as redact
import scripts.safe_write as safe_write
from scripts import hosts
from scripts.tools import ONLINE_ONLY
from . import runio

_DETAIL_MAX = 300
_SHELL_MAX = 1024 * 1024
_CHUNK = re.compile(r"_[0-9]+\Z")
SKILL_ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           os.pardir, os.pardir))
INSTALLED_SKILL = "~/.claude/skills/panopticon"


def _said(exc):
    return redact.redact_diagnostic("%s: %s" % (type(exc).__name__, exc), _DETAIL_MAX)


def flags_row(plan):
    flags = plan.get("flags") or {}
    scope = plan.get("scope") or {"mode": "repo"}
    parts = ["security %s" % (plan.get("security") or "standard"),
             "scope %s%s" % (scope.get("mode"), " %s" % scope["target"] if scope.get("target")
                             and isinstance(scope["target"], str) else ""),
             "tools %s" % ("off" if flags.get("tools") is False else "on"),
             "online %s" % ("on" if flags.get("online") else "off"),
             "max-verify %s" % (flags.get("max_verify") or "uncapped")]
    if plan.get("reset"):
        parts.append("--reset: the run would discard this target's run folder; readiness does not")
    return {"ok": None, "detail": " · ".join(parts)}


def gate_row(plan):
    fail_on = (plan.get("flags") or {}).get("fail_on")
    if not fail_on:
        return {"ok": "warn", "fail_on": None,
                "detail": "no --fail-on and none committed: the run ends `gate: OFF`, which fails "
                          "nothing. Pass --fail-on to gate on findings"}
    return {"ok": None, "fail_on": fail_on, "detail": "fails on %s and above" % fail_on}


def _discovery_argv(review_root, plan, out):
    argv = ["--repo-scan", "--security", plan.get("security") or "standard", review_root,
            "--out", out]
    scope = plan.get("scope") or {"mode": "repo"}
    if scope.get("mode") == "files":
        argv += ["--scope-files"] + list(scope.get("target") or [])
    elif scope.get("target"):
        argv += [{"file": "--scope-file", "directory": "--scope-dir",
                  "group": "--scope-group"}[scope["mode"]], scope["target"]]
    if (plan.get("flags") or {}).get("max_per_group") is not None:
        argv += ["--max-per-group", str(plan["flags"]["max_per_group"])]
    return argv


def groups_row(review_root, plan):
    """What discovery will dispatch, by running discovery: the committed leaves (and their `_N`
    chunks) and what it derives beside them. A delta scope depends on a diff, so it is not counted."""
    scope = plan.get("scope") or {"mode": "repo"}
    if scope.get("mode") == "changed" or plan.get("pr") is not None or plan.get("base"):
        return {"ok": None, "committed": None, "derived": None,
                "detail": "not counted for a delta scope: it depends on the diff"}
    tmp = tempfile.mkdtemp(prefix="panopticon-readiness-")
    err = io.StringIO()
    try:
        out = os.path.join(tmp, "groups.json")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = discovery.main(_discovery_argv(review_root, plan, out))
        if code != 0:
            lines = [line for line in err.getvalue().splitlines() if line.strip()]
            raise ValueError(lines[-1] if lines else "exit %s" % code)
        with open(out, encoding="utf-8") as fh:
            names = [group["name"] for group in json.load(fh)["groups"]]
        catalog = discovery._matrix_catalog(review_root) or {}
    except (Exception, SystemExit) as exc:          # noqa: BLE001 -- a row, never a traceback
        return {"ok": None, "committed": None, "derived": None,
                "detail": "discovery could not count them: %s" % _said(exc)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    derived = [name for name in names if _CHUNK.sub("", name) not in catalog]
    committed = len(names) - len(derived)
    return {"ok": None, "committed": committed, "derived": derived,
            "detail": "%d group(s): %d committed + %d derived%s"
                      % (len(names), committed, len(derived),
                         " (%s)" % ", ".join(derived) if derived else "")}


def shells_row(host):
    """Whether the registered enforcement shells are the ones this install would emit, compared
    under their registered names. The render goes to a temp directory; the real one is only read."""
    row = hosts.spec(host)
    if not row or not row.shell_format:
        return {"ok": None, "stale": [], "missing": [],
                "detail": "n/a: host %s registers no shells" % host}
    directory = row.registration_dir
    if not directory:
        return {"ok": None, "stale": [], "missing": [],
                "detail": row.registration_refusal or "host %s has no registration directory"
                % host}
    remedy = "`python3 skill/scripts/dispatch.py --emit-host-agents %s`" % host
    tmp = tempfile.mkdtemp(prefix="panopticon-shells-")
    stale, missing = [], []
    try:
        for rendered in sorted(dispatch.emit_host_agents(host, tmp)):
            name = os.path.basename(rendered)
            with open(rendered, "rb") as fh:
                want = fh.read()
            try:
                have = safe_write.read_regular_bytes(os.path.join(directory, name), _SHELL_MAX)
            except FileNotFoundError:
                missing.append(name)
                continue
            if have != want:
                stale.append(name)
    except Exception as exc:                     # noqa: BLE001 -- a row, never a traceback
        return {"ok": None, "stale": [], "missing": [],
                "detail": "could not compare with %s: %s" % (directory, _said(exc))}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if not (stale or missing):
        return {"ok": None, "stale": [], "missing": [], "detail": "current in %s" % directory}
    return {"ok": "warn", "stale": stale, "missing": missing,
            "detail": "%s%s in %s: run %s"
                      % ("stale: %s" % ", ".join(stale) if stale else "",
                         "%smissing: %s" % ("; " if stale else "", ", ".join(missing))
                         if missing else "", directory, remedy)}


def enforcement_row(host, plan):
    """The half of the `--allow-unenforced` question that needs no launch. `artifact_write_guard`
    is measured by one real launch on the first run, and the loop's stop depends on it, so whether
    the loop will stop is never answered here."""
    row = hosts.spec(host)
    if row and (row.probes or {}).get(hosts.TOOL_POLICY_ENFORCED) == "registered-shell-tools":
        state, _by, why = probes_common.probe_registered_shell_tools(host)
        policy = "%s from the registered shells (%s)" % (state, why)
    else:
        state, policy = None, "needs a launch on host %s" % host
    if (plan.get("flags") or {}).get("allow_unenforced"):
        verdict = "--allow-unenforced is given: an unproven boundary is recorded, not refused"
    else:
        verdict = ("can't say whether the loop will stop for --allow-unenforced: "
                   "artifact_write_guard is measured by one launch on the first run")
    return {"ok": None, "tool_policy_enforced": state,
            "detail": "tool_policy_enforced %s; %s" % (policy, verdict)}


def tool_findings_row(review_root, manifest):
    """How many tool findings will each get an advisor, which is only known after the tools phase.
    On a resume whose scan already ran, counted by the verify phase's own function; tool output is
    target-writable, so a file it cannot read is a row that says so."""
    flags = (manifest or {}).get("flags") or {}
    cap = flags.get("max_verify")
    capped = "capped at %d by --max-verify" % cap if cap else "uncapped unless --max-verify"
    ran = (runio._load_json(runio._pano(review_root, "tools-ran.json")) or {}).get("ran") \
        if manifest else None
    if not ran:
        return {"ok": None, "count": None,
                "detail": "not known until the tools phase runs: it depends on what the scanners "
                          "find, and each tool finding gets an advisor (%s)" % capped}
    try:
        from . import verify_tools               # lazy: it imports `tools`, which imports this
        count = len(verify_tools._tool_verify_queue(review_root, manifest))
    except Exception as exc:                     # noqa: BLE001 -- target-writable input
        return {"ok": None, "count": None,
                "detail": "this run's tool output could not be read: %s" % _said(exc)}
    return {"ok": None, "count": count,
            "detail": "%d tool finding(s) from this run's scan, before review merges; each gets "
                      "an advisor (%s)" % (count, capped)}


def online_tools_row(plan):
    flags = plan.get("flags") or {}
    if flags.get("tools") is False:
        return {"ok": None, "withheld": [], "detail": "tool scan off (--no-tools)"}
    if flags.get("online"):
        return {"ok": None, "withheld": [], "detail": "--online: dependency auditors may run"}
    withheld = sorted(ONLINE_ONLY)
    return {"ok": None, "withheld": withheld,
            "detail": "withheld without --online: %s. A scout that asks for one gets "
                      "`requested_unavailable`" % ", ".join(withheld)}


def install_row(review_root):
    """Which copy of the skill this driver is, beside the two others an operator may mean."""
    others = {"the target's skill/": os.path.join(review_root, "skill"),
              INSTALLED_SKILL: os.path.expanduser(INSTALLED_SKILL)}
    elsewhere = sorted("%s is %s" % (label, os.path.realpath(path))
                       for label, path in others.items()
                       if os.path.isfile(os.path.join(path, "scripts", "driver.py"))
                       and os.path.realpath(path) != SKILL_ROOT)
    detail = "running %s" % SKILL_ROOT
    if not elsewhere:
        return {"ok": None, "skill": SKILL_ROOT, "elsewhere": [], "detail": detail}
    return {"ok": "warn", "skill": SKILL_ROOT, "elsewhere": elsewhere,
            "detail": "%s; a different copy: %s. The copy you run decides the rules and prompts"
                      % (detail, "; ".join(elsewhere))}


ROWS = ("flags", "gate", "groups", "shells", "enforcement", "tool-findings", "online-tools",
        "install")


def rows(review_root, host, plan, manifest):
    """Every row, in `ROWS` order. `plan` is what the run flags describe; `manifest` the run this
    tree already holds, or None."""
    plan = plan or {}
    return dict(zip(ROWS, (flags_row(plan), gate_row(plan), groups_row(review_root, plan),
                           shells_row(host), enforcement_row(host, plan),
                           tool_findings_row(review_root, manifest), online_tools_row(plan),
                           install_row(review_root)), strict=True))

