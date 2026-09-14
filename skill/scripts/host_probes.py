#!/usr/bin/env python3
"""Establish what a host actually delivers, as opposed to what it claims.

`hosts.py` is the table of claims and stays I/O-free. This module is where the
filesystem and subprocess live, so it is imported only by the driver's
pre-phase step and by setup -- never by `phases/*` on the hot path, and never
by `hosts.py` (that import would break the purity guard).

Every probe returns `(state, by, detail)`:

  state   one of hosts.PROVEN / hosts.REFUTED / hosts.UNKNOWN
  by      the probe id that produced it, or None when nothing ran
  detail  a sentence a human can act on, naming paths where paths matter

A probe that CANNOT RUN returns UNKNOWN with the reason -- never a guess, and
never `proven` by default. UNKNOWN and REFUTED are different answers: unknown
means nobody looked, refuted means we looked and the control is not there.
Confusing the two is the failure this whole spec exists to prevent.

No probe may touch live state. Anything that needs to arm, install or write
does it inside a `tempfile.TemporaryDirectory()`.
"""
import glob
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib

from scripts import (collect_usage, dispatch, hosts, model_resolver,
                    read_guard_hook, run_manifest, write_guard_hook)

# The roles the DRIVER dispatches and therefore needs registered shells for:
# every template in dispatch.ROLE_FILES. #1606: this used to be a hand-kept
# three-tuple that excluded `advisor` on the claim the host dispatched it, not
# the driver -- false since the 5.1 tool-verify round, whose
# phases/verify.py::_tool_verify_entry dispatches panopticon-advisor ENFORCED
# on the strength of the other three shells' proof. Derived, so no role the
# driver dispatches can be left unchecked by an edit to one tuple.
DRIVER_ROLES = tuple(sorted(dispatch.ROLE_FILES))

REGISTERED_SHELL_TOOLS = "registered-shell-tools"


def _frontmatter_tools(path):
    """The `tools:` grant of a registered shell as a list, or None.

    Understands BOTH shapes this repo emits: the inline form claude's
    registration writes (`tools: Read, Grep, Glob`, dispatch.py:187) and the
    YAML block list kimi's writes (`tools:` then `  - Read`, dispatch.py:196).
    A line scan rather than a YAML parse: stdlib has no YAML, and a dependency
    here would break the plan's stdlib-only constraint.

    Returns None when the file cannot be read or carries no grant at all.
    `ValueError` is caught alongside `OSError` because a non-UTF-8 file raises
    UnicodeDecodeError, and a probe that raises is worse than one that guesses.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except (OSError, ValueError):
        return None
    for index, line in enumerate(lines):
        if not line.startswith("tools:"):
            continue
        inline = line.split(":", 1)[1].strip()
        if inline:
            return [t.strip() for t in inline.split(",") if t.strip()]
        block = []
        for follow in lines[index + 1:]:
            stripped = follow.strip()
            if not stripped.startswith("- "):
                break
            block.append(stripped[2:].strip())
        return block or None
    return None


def probe_registered_shell_tools(host, registration_dir=None):
    """Every driver role has a shell whose tools match its template exactly.

    `registration_dir` overrides the host's own, for fixtures only.
    """
    row = hosts.spec(host)
    if not row or not row.shell_format:
        return (hosts.UNKNOWN, None,
                "host %r registers no enforcement shells" % host)
    directory = registration_dir or row.registration_dir
    if not directory:
        return (hosts.UNKNOWN, None,
                "host %r has no registration directory" % host)
    if not os.path.isdir(directory):
        return (hosts.REFUTED, REGISTERED_SHELL_TOOLS,
                "no registration directory at %s: this host's enforcement "
                "shells were never emitted" % directory)
    if not os.access(directory, os.R_OK):
        return (hosts.UNKNOWN, REGISTERED_SHELL_TOOLS,
                "cannot read %s, so nothing could be checked" % directory)
    faults, checked = [], 0
    for role in DRIVER_ROLES:
        role_file = dispatch.ROLE_FILES[role]
        path = os.path.join(directory,
                            dispatch.registered_agent_filename(host, role_file))
        if not os.path.isfile(path):
            faults.append("%s: no shell at %s" % (role, path))
            continue
        checked += 1
        policy = dispatch.load_template(role_file)[0]["tool_policy"]
        granted = _frontmatter_tools(path)
        forbidden = sorted(set(granted or []) & set(policy["forbidden"] or []))
        if granted is None:
            faults.append("%s: shell has no readable `tools:` grant" % role)
        elif forbidden:
            faults.append("%s: shell grants forbidden tool(s) %s"
                          % (role, ", ".join(forbidden)))
        elif sorted(granted) != sorted(policy["allowed"]):
            faults.append("%s: shell grants %s, template allows %s"
                          % (role, sorted(granted), sorted(policy["allowed"])))
    if faults:
        return (hosts.REFUTED, REGISTERED_SHELL_TOOLS, "; ".join(faults))
    return (hosts.PROVEN, REGISTERED_SHELL_TOOLS,
            "%d/%d driver roles registered in %s; tools match their templates"
            % (checked, len(DRIVER_ROLES), directory))


ENTRY_MODEL_BOUND = "entry-model-bound"


def _frontmatter_model(path):
    """The `model:` binding inside a registered shell's frontmatter, or None.

    Frontmatter ONLY: the charter body is prose and may contain the word.
    Stops at the closing fence rather than scanning the whole file, which is
    the one way this differs from `_frontmatter_tools`. That stop is
    load-bearing, not an optimisation -- the match below tests `fences >= 1`
    rather than `fences == 1`: the latter would double as its own implicit
    "still inside the frontmatter" guard (it goes false the moment the second
    fence is seen, whether or not the early return exists) and make the early
    return provably dead code, so a mutant that deletes it would change
    nothing this file's tests could observe. With `fences >= 1`, the early
    return is the ONLY thing standing between a shell that binds no model and
    a body `model:` line rescuing it as if it had.

    None for an absent line, an empty value, or an unreadable file
    (`ValueError` covers a non-UTF-8 shell) -- a probe that raises is worse
    than one that reports.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except (OSError, ValueError):
        return None
    fences = 0
    for line in lines:
        if line.strip() == "---":
            fences += 1
            if fences == 2:
                return None
            continue
        if fences >= 1 and line.startswith("model:"):
            return line.split(":", 1)[1].strip() or None
    return None


def probe_entry_model_bound(host, registration_dir=None):
    """Every REGISTERED shell binds the model dispatch will request (F4).

    The entry's model comes from model_resolver.resolve_model, which honours
    PANOPTICON_MODEL_* overrides. The shell's `model:` comes from
    registration_model, which is override-free BY DESIGN so a persisted file
    never carries one run's ambient override. On an enforced dispatch the
    host binds the SHELL's model, so wherever the two differ the entry is a
    claim the run does not keep -- registration silently wins. That is the
    refutation; a shell binding NO model is the same refutation (the session's
    model wins instead). A role with no shell dispatches general-purpose and
    carries its model on the entry itself, so it is named in the detail and
    not counted against the proof. No shell at all is UNKNOWN: nothing here
    can prove the host honours the entry's model, and a vacuous PROVEN is the
    fail-open this epic exists to remove.

    A missing REGISTRATION DIRECTORY is also UNKNOWN, not REFUTED, even
    though the sibling `probe_registered_shell_tools` refutes on the same
    condition: that probe's question is "did the host register its shells at
    all", where an absent directory IS the answer (never registered, REFUTE).
    This probe's question is narrower -- "does what WAS registered bind the
    right model" -- and an absent directory means there is nothing to compare
    against, which is unmeasured rather than measured-and-broken. Harmonising
    the two would turn "nobody has run --emit-host-agents yet" into a claim
    that model binding specifically is broken, which is not what was found.

    Compares SOURCES rather than dispatch entries because this runs pre-phase
    (spec 5.2), before any entry exists. requests.bound_model is what makes
    the two equivalent, and its tests pin that every builder calls it.
    """
    row = hosts.spec(host)
    if not row or not row.shell_format:
        return (hosts.UNKNOWN, None,
                "host %r registers no enforcement shells, so no shell binds a model"
                % host)
    directory = registration_dir or row.registration_dir
    if not directory or not os.path.isdir(directory):
        return (hosts.UNKNOWN, ENTRY_MODEL_BOUND,
                "no registration directory at %s: nothing registered binds a model, "
                "and nothing here proves the host honours the entry's model"
                % directory)
    faults, matched, absent = [], [], []
    for role, role_file in sorted(dispatch.ROLE_FILES.items()):
        path = os.path.join(directory,
                            dispatch.registered_agent_filename(host, role_file))
        if not os.path.isfile(path):
            absent.append(role)
            continue
        resolved = model_resolver.resolve_model(host, role).get("model")
        bound = _frontmatter_model(path)
        if bound is None:
            faults.append("%s: shell at %s binds no model, so the session's model "
                          "silently wins over the entry's %r" % (role, path, resolved))
        elif bound != resolved:
            faults.append("%s: shell binds %r but dispatch resolves %r -- "
                          "registration silently wins" % (role, bound, resolved))
        else:
            matched.append(role)
    if faults:
        return (hosts.REFUTED, ENTRY_MODEL_BOUND, "; ".join(faults))
    if not matched:
        return (hosts.UNKNOWN, ENTRY_MODEL_BOUND,
                "no role is registered in %s, so nothing binds a model" % directory)
    detail = ("%d/%d roles registered in %s bind the model dispatch resolves"
              % (len(matched), len(dispatch.ROLE_FILES), directory))
    if absent:
        detail += ("; unregistered, model bound on the entry itself: %s"
                   % ", ".join(absent))
    return (hosts.PROVEN, ENTRY_MODEL_BOUND, detail)


WRITE_GUARD_ARMED = "write-guard-armed"


def headless_settings_path(review_root, namespace=None):
    """The settings file the headless runner will arm: runs/<tag>/host-settings.json
    once a manifest exists, flat top-level for `namespace == "setup"` (R-P6-5;
    namespace-aware since Task 6 fix round 1, item 2).

    Setup keeps its OWN manifest (setup-manifest.json), never
    run-manifest.json -- so if this review_root already holds a run-manifest.json
    from an EARLIER review run (a realistic sequence: review first, refresh
    groups.yml with `driver loop --setup` later), routing setup's settings
    path through `runio._pano`'s manifest-tag lookup would resolve it into
    that PRIOR run's `runs/<tag>/` folder and clobber its host-settings.json/
    dispatch-ledger.jsonl/usage.json. `namespace == "setup"` bypasses the tag
    lookup entirely and resolves directly to the flat top-level path, so
    setup never depends on -- or disturbs -- whatever other run's manifest
    happens to be lying around. Every other namespace (a review run) still
    resolves through `runio._pano`, so the probe and the runner name the
    same file."""
    import scripts.phases.runio as runio
    import scripts.runners.base as runners_base
    if namespace == "setup":
        return os.path.abspath(os.path.join(review_root, ".panopticon", runners_base.SETTINGS_FILE))
    return os.path.abspath(runio._pano(review_root, runners_base.SETTINGS_FILE))


def _headless_subject_ok(settings_path):
    """(ok, detail): the runner creates the file itself, so demand only that
    its directory exists or can be created, and is writable."""
    settings_dir = os.path.dirname(os.path.abspath(settings_path)) or "."
    probe_dir = settings_dir
    while not os.path.isdir(probe_dir):
        parent = os.path.dirname(probe_dir)
        if parent == probe_dir:
            break
        probe_dir = parent
    if not os.access(probe_dir, os.W_OK):
        return False, "the runner cannot arm its guards: %s is not writable" % probe_dir
    return True, ""


def _round_trip_denies_an_outside_write():
    """Arm the guard in a throwaway sandbox and confirm it actually denies.

    Never touches the session's real settings or allowlist: install/uninstall
    run entirely against paths inside a TemporaryDirectory. Returns
    (ok, detail).
    """
    # Minor 6: the `try` opens BEFORE TemporaryDirectory(), not inside it. This
    # runs inside driver.run() on EVERY invocation now, and an OSError from the
    # constructor itself (no space on the temp filesystem, TMPDIR gone, the
    # process out of file descriptors) would otherwise escape as a traceback and
    # abort the whole run -- violating this module's contract that a probe which
    # cannot run resolves to a STATE rather than raising.
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            settings = os.path.join(sandbox, "settings.json")
            allowlist = os.path.join(sandbox, "allowlist.json")
            declared = os.path.join(sandbox, "findings-probe.json")
            with open(declared, "w", encoding="utf-8") as fh:
                fh.write("{}")
            write_guard_hook.install([{"out_file": declared}],
                                     settings_path=settings,
                                     allowlist_path=allowlist)
            state = write_guard_hook.guard_state(settings_path=settings,
                                                 allowlist_path=allowlist)
            if not state["armed"]:
                return False, "install() did not register the PreToolUse hook"
            granted = write_guard_hook._read_allowlist(allowlist)
            allowed, _why = write_guard_hook.decide("Write", declared, granted)
            denied, _why = write_guard_hook.decide(
                "Write", os.path.join(sandbox, "not-declared.json"), granted)
            if not allowed:
                return False, "the guard denied a write to a DECLARED out_file"
            if denied:
                return False, "the guard ALLOWED a write outside the allowlist"
            write_guard_hook.uninstall(settings_path=settings,
                                       allowlist_path=allowlist)
    except OSError as exc:
        return False, "sandbox round-trip could not run: %s" % exc
    return True, "arm/deny round-trip ok"


def probe_write_guard_armed(host, session_root=None, settings_path=None):
    """This host CAN mediate a reviewer's Write when it fans out.

    COUPLING, and it is load-bearing: the subject of this probe is whatever
    `write_guard_hook._resolve(None, None, session_root)` names -- the SAME
    resolver `write_guard_hook.install()` calls when the host arms the guard
    during fan-out. Re-deriving `.claude/settings.local.json` here instead
    would be a second definition free to drift from the one that arms, and a
    probe that proves a file nothing arms proves nothing. `install()` applies
    its #1493 existence check only when `used_defaults` is set; this probe
    applies it unconditionally, which is the fail-CLOSED direction (stricter
    than install(), never laxer). Both halves are pinned by
    TestWriteGuardArmedProbe's resolve-the-same-settings-file tests.

    NOT "the guard is armed right now". The host arms it during fan-out --
    `write_guard_hook.install` writes the PreToolUse entry and `uninstall`
    removes it -- so at run start, which is when 5.2 probes, it is legitimately
    absent. A probe that gated on live arming was measured returning REFUTED on
    a correctly configured machine, which would have made require_unenforced_ack
    refuse every Claude run.

    So: prove the mechanism mediates (in a sandbox), and prove the place the
    host will arm is writable. #1493 -- a guard armed at a path nothing reads is
    worse than no guard -- so the resolved path is named either way.

    With `settings_path` (headless), the subject is that file; the runner
    creates it, so only its directory is checked (spec 5.4).
    """
    if not hosts.declares(host, hosts.ARTIFACT_WRITE_GUARD):
        return (hosts.UNKNOWN, None,
                "host %r claims no artifact write guard" % host)
    if settings_path is not None:
        ok, detail = _headless_subject_ok(settings_path)
        if not ok:
            return (hosts.REFUTED, WRITE_GUARD_ARMED, detail)
        ok, detail = _round_trip_denies_an_outside_write()
        if not ok:
            return (hosts.REFUTED, WRITE_GUARD_ARMED, detail)
        return (hosts.PROVEN, WRITE_GUARD_ARMED,
                "%s; the runner will arm at %s" % (detail, os.path.abspath(settings_path)))
    settings_path, _allowlist_path, _defaults = write_guard_hook._resolve(
        None, None, session_root)
    settings_dir = os.path.dirname(os.path.abspath(settings_path)) or "."
    if not os.path.isfile(settings_path):
        # install()'s OWN fail-closed rule (#1493): a settings file that does
        # not exist means the caller is in the wrong directory, so arming would
        # write a file nothing reads. Proving the capability here would prove
        # something install() is about to refuse.
        return (hosts.REFUTED, WRITE_GUARD_ARMED,
                "the host would arm its guard at %s, which does not exist -- "
                "install() refuses that (#1493), so no Write would be mediated"
                % os.path.abspath(settings_path))
    if not os.access(settings_dir, os.W_OK):
        return (hosts.REFUTED, WRITE_GUARD_ARMED,
                "the host cannot arm its guard: %s is not writable" % settings_dir)
    ok, detail = _round_trip_denies_an_outside_write()
    if not ok:
        return (hosts.REFUTED, WRITE_GUARD_ARMED, detail)
    return (hosts.PROVEN, WRITE_GUARD_ARMED,
            "%s; the host will arm at %s" % (detail, settings_path))


READ_GUARD_ARMED = "read-guard-armed"


def _fake_subagent(parent_transcript, agent_id, entry_id):
    """A subagent transcript in the Agent-tool layout the spike measured: the
    first user record is the dispatch prompt, marker on line 1."""
    stem = parent_transcript[:-len(".jsonl")]
    directory = os.path.join(stem, "subagents")
    os.makedirs(directory, exist_ok=True)
    record = {"type": "user", "isSidechain": True, "agentId": agent_id,
              "message": {"role": "user", "content": [
                  {"type": "text", "text": read_guard_hook.marker_line(entry_id) + "\nDo the work."}]}}
    with open(os.path.join(directory, "agent-%s.jsonl" % agent_id), "w", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def _round_trip_confines_reads():
    """Arm the read guard in a throwaway sandbox, bind two fake subagents
    through fake transcripts, and drive the ten payloads of design spec 5,
    plus four env-binding payloads of spec 5.3 (plan 6), through
    adjudicate(). Never touches the session's real settings, scope file or
    transcripts. Returns (ok, detail)."""
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            settings = os.path.join(sandbox, "settings.json")
            scope_file = os.path.join(sandbox, "read-scope.json")
            inside = os.path.join(sandbox, "cell", "a.py")
            outside = os.path.join(sandbox, "elsewhere", "b.py")
            root = os.path.join(sandbox, "root")
            for p in (inside, outside, os.path.join(root, "c.py")):
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("")
            parent = os.path.join(sandbox, "session.jsonl")
            with open(parent, "w", encoding="utf-8") as fh:
                fh.write("")
            _fake_subagent(parent, "agent-x", "probe-cell")
            _fake_subagent(parent, "agent-z", "probe-scan")
            read_guard_hook.install(
                [{"id": "probe-cell", "scope": {"files": [inside], "dirs": [], "reads": []}},
                 {"id": "probe-scan", "scope": {"files": [], "dirs": [root], "reads": []}}],
                settings_path=settings, scope_path=scope_file)
            if not read_guard_hook.guard_state(settings_path=settings, scope_path=scope_file)["armed"]:
                return False, "install() did not register the PreToolUse hook"

            def call(tool, agent, **tool_input):
                payload = {"tool_name": tool, "tool_input": tool_input,
                           "transcript_path": parent, "cwd": sandbox}
                if agent:
                    payload["agent_id"] = agent
                # A stray PANOPTICON_ENTRY_ID in the operator's shell must
                # never change this probe's verdict -- env is explicit here.
                return read_guard_hook.adjudicate(payload, scope_file, env={})[0]

            cell_dir = os.path.dirname(inside)
            rows = (
                ("bound Read inside scope", call("Read", "agent-x", file_path=inside), True),
                ("bound Read outside scope", call("Read", "agent-x", file_path=outside), False),
                ("bound Grep of an in-scope file", call("Grep", "agent-x", pattern="x", path=inside), True),
                ("bound Grep over a directory", call("Grep", "agent-x", pattern="x", path=cell_dir), False),
                ("bound Glob", call("Glob", "agent-x", pattern="*.py", path=cell_dir), False),
                ("unbound subagent Read", call("Read", "agent-y", file_path=inside), False),
                ("orchestrator Read outside any scope", call("Read", None, file_path=outside), True),
                ("directory-scoped Grep inside its dir", call("Grep", "agent-z", pattern="x", path=root), True),
                ("directory-scoped Glob inside its dir", call("Glob", "agent-z", pattern="*.py", path=root), True),
                ("directory-scoped Read outside its dir", call("Read", "agent-z", file_path=outside), False),
            )
            for name, got, want in rows:
                if got != want:
                    return False, "the guard %s: %s" % ("ALLOWED" if got else "DENIED", name)

            # Spec 5.3 (plan 6): the env binding the headless runner relies on.
            env_rows = (
                ("env-bound read inside its entry",
                 {"tool_name": "Read", "tool_input": {"file_path": inside}},
                 {read_guard_hook.ENV_ENTRY_ID: "probe-cell"}, True),
                ("env-bound read outside its entry",
                 {"tool_name": "Read", "tool_input": {"file_path": outside}},
                 {read_guard_hook.ENV_ENTRY_ID: "probe-cell"}, False),
                ("agent_type with no binding",
                 {"tool_name": "Read", "tool_input": {"file_path": inside},
                  "agent_type": "panopticon-scout"}, {}, False),
                # The real headless payload shape: agent_type AND the env id
                # both present. The env binding governs either way (#1344
                # plan 6 review finding 1).
                ("env-bound read inside its entry despite agent_type",
                 {"tool_name": "Read", "tool_input": {"file_path": inside},
                  "agent_type": "panopticon-domain-panel"},
                 {read_guard_hook.ENV_ENTRY_ID: "probe-cell"}, True),
            )
            for name, env_payload, env, want in env_rows:
                got = read_guard_hook.adjudicate(env_payload, scope_file, env=env)[0]
                if got != want:
                    return False, "env binding: the guard %s: %s" % (
                        "ALLOWED" if got else "DENIED", name)
            read_guard_hook.uninstall(settings_path=settings, scope_path=scope_file)
    except OSError as exc:
        return False, "sandbox round-trip could not run: %s" % exc
    return True, "arm/bind/deny round-trip ok (%d rows)" % (len(rows) + len(env_rows))


def probe_read_guard_armed(host, session_root=None, settings_path=None):
    """This host CAN confine a dispatched subagent's reads to its entry.

    Same coupling as probe_write_guard_armed, for the same reason: the
    subject is whatever read_guard_hook._resolve(None, None, session_root)
    names -- the file install() will arm -- and the #1493 existence check is
    applied unconditionally (fail-closed). NOT "armed right now": the host
    arms it per fan-out, so at run start it is legitimately absent.

    With `settings_path` (headless), the subject is that file; the runner
    creates it, so only its directory is checked (spec 5.4).
    """
    if not hosts.declares(host, hosts.READ_SCOPE_CONFINED):
        return (hosts.UNKNOWN, None,
                "host %r claims no read-scope confinement" % host)
    if settings_path is not None:
        ok, detail = _headless_subject_ok(settings_path)
        if not ok:
            return (hosts.REFUTED, READ_GUARD_ARMED, detail)
        ok, detail = _round_trip_confines_reads()
        if not ok:
            return (hosts.REFUTED, READ_GUARD_ARMED, detail)
        return (hosts.PROVEN, READ_GUARD_ARMED,
                "%s; the runner will arm at %s" % (detail, os.path.abspath(settings_path)))
    settings_path, _scope_path, _defaults = read_guard_hook._resolve(None, None, session_root)
    settings_dir = os.path.dirname(os.path.abspath(settings_path)) or "."
    if not os.path.isfile(settings_path):
        return (hosts.REFUTED, READ_GUARD_ARMED,
                "the host would arm its read guard at %s, which does not exist -- "
                "install() refuses that (#1493), so no read would be confined"
                % os.path.abspath(settings_path))
    if not os.access(settings_dir, os.W_OK):
        return (hosts.REFUTED, READ_GUARD_ARMED,
                "the host cannot arm its read guard: %s is not writable" % settings_dir)
    ok, detail = _round_trip_confines_reads()
    if not ok:
        return (hosts.REFUTED, READ_GUARD_ARMED, detail)
    return (hosts.PROVEN, READ_GUARD_ARMED,
            "%s; the host will arm at %s" % (detail, settings_path))


# --- kimi family probes (#1344) ---------------------------------------------
# The kimi runner confines reviewers through a per-run KIMI_CODE_HOME whose
# config registers kimi_guard_hook.py (see runners/kimi.py's docstring for the
# whole design). These probes prove the pieces: the shells' tool surface, the
# two guard round-trips through the REAL hook protocol (a subprocess, exactly
# as the CLI invokes it), the model-alias binding, and the wire-file usage
# channel.

# I3 (gate review): every spawn of a REAL host binary in this module resolves
# its launcher from this ONE module attribute, inside the call, so
# tests/conftest.py's autouse guard can swap it for a refusal.
#
# N1 (re-review): module-scoped, not family-scoped. #1619's launch guard finds
# seams by AST walk and then asserts `hasattr(module, "DEFAULT_RUNNER")` and
# refuses through it, so the name is per MODULE -- and this module holds every
# family's probe spawns, which is still one module. A `DEFAULT_RUNNER`
# would fail that guard twice on the rebase; the later families' probe spawns
# read this same attribute rather than adding siblings.
#
# The guard-hook round-trip below is NOT routed through it: that subprocess is
# `sys.executable`, the hook's own protocol, and refusing it would delete the
# proof rather than protect it.
DEFAULT_RUNNER = subprocess.run

KIMI_SHELL_SURFACE = "kimi-shell-surface"
KIMI_READ_GUARD = "kimi-read-guard-armed"
KIMI_WRITE_GUARD = "kimi-write-guard-armed"
KIMI_MODEL_ALIAS = "kimi-model-alias-bound"
KIMI_USAGE_WIRE = "kimi-usage-wire"

# The CLI's builtin tool vocabulary lives with the RUNNER
# (runners.kimi.TOOL_VOCABULARY), because the runner is what has to deny it:
# Kimi's config offers a deny-list and no allow-list, so the per-run
# `tools.disabled` is derived from that table minus the templates' grants (I1).
# The probe reads the same table back. A version it does not cover resolves
# UNKNOWN, never a guess: a tool name that matches nothing in the installed CLI
# is warned about and restricts NOTHING (FAMILY-PR-GUARDRAILS, the recorded
# kimi finding), so a stale table must not wave the shells through.


def _kimi_version(runner=None):
    """The installed CLI's major.minor ("0.42"), or None."""
    import scripts.runners.kimi as kimi_runner
    runner = DEFAULT_RUNNER if runner is None else runner
    try:
        proc = runner(["kimi", "--version"], capture_output=True, text=True, timeout=15)
    except kimi_runner.LaunchRefused:  # I3: the suite's guard propagates --
        raise                          # never reported as "version unknown"
    except Exception:  # noqa: BLE001 -- a probe reports, never raises
        return None
    text = (proc.stdout or "") + (proc.stderr or "")
    match = re.search(r"(\d+)\.(\d+)\.\d+", text)
    return "%s.%s" % (match.group(1), match.group(2)) if match else None


_TOOLS_SNAPSHOT = "llm.tools_snapshot"


def _kimi_wire_snapshot(run_home):
    """(tools, agent, wire) from the most recent child's `llm.tools_snapshot`
    under THIS run's per-run home, or (None, None, why).

    I5: the effective tool surface of a child that really ran, which is the
    only thing that answers "did the shell restrict it". `run_home` is handed
    in by the loop, off the live runner instance (N2). It is deliberately NOT
    read back from the run folder's pointer file: that file sits in the
    reviewed tree, and a target that could rewrite it could point this probe
    at a directory it had planted -- turning `host-capabilities.json` into a
    record of a child that never ran.

    The record's shape is read tolerantly: `tools` as names or as objects with
    a `name`, and the agent under any of the spellings a snapshot has been
    seen to use. A record this cannot read is "no snapshot", never a
    refutation -- an unrecognised shape is unknown data, not evidence.
    """
    home = run_home
    if not home or not os.path.isdir(home):
        return None, None, "this run has no per-run kimi home yet"
    pattern = os.path.join(glob.escape(home), "sessions", "*", "*", "agents", "*", "wire.jsonl")
    try:
        wires = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    except OSError as exc:        # a file that vanished between glob and stat
        return None, None, "the per-run home's wire files could not be listed: %s" % exc
    for wire in wires:
        tools, agent = None, None
        try:
            with open(wire, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(record, dict) or record.get("type") != _TOOLS_SNAPSHOT:
                        continue
                    names = record.get("tools")
                    if not isinstance(names, list):
                        continue
                    tools = {n if isinstance(n, str) else n.get("name")
                             for n in names if isinstance(n, (str, dict))}
                    tools.discard(None)
                    for key in ("agent", "agentName", "agent_file", "agentFile"):
                        value = record.get(key)
                        if isinstance(value, str) and value:
                            agent = os.path.basename(value)
                            agent = agent[:-3] if agent.endswith(".md") else agent
                            break
        except OSError:
            continue
        if tools is not None and agent:
            return tools, agent, wire
    return None, None, ("no child wire file under %s carries an %s record yet"
                        % (home, _TOOLS_SNAPSHOT))


def probe_kimi_shell_surface(host, registration_dir=None, version=None, runner=None,
                             run_home=None):
    """The registered shells restrict tools on the EFFECTIVE surface.

    Two halves, both required. First the template check the shipped
    `probe_registered_shell_tools` already performs (it understands kimi's
    block-list frontmatter): every driver role's shell exists and grants
    exactly its template's tools. Then the kimi-specific half the guardrails
    demand: every tool name those shells ALLOW or FORBID must exist in the
    installed CLI's vocabulary, because a name that matches nothing is warned
    about and restricts nothing. The vocabulary is the measured per-version
    table above; the live run's wire `llm.tools_snapshot` is the effective-
    surface confirmation (a writer-role child measured carrying exactly
    ['Read', 'Write']).
    """
    import scripts.runners.kimi as kimi_runner
    registration_dir = registration_dir or (hosts.spec(host).registration_dir
                                            if hosts.spec(host) else "")
    base_state, base_by, base_detail = probe_registered_shell_tools(host, registration_dir)
    if base_state != hosts.PROVEN:
        # A host that registers no shells at all gets the base probe's own
        # (UNKNOWN, None, ...) untouched: nothing ran that can be named.
        return (base_state, base_by if base_by is None else KIMI_SHELL_SURFACE, base_detail)
    if version is None:
        version = _kimi_version(runner)
    if version is None:
        return (hosts.UNKNOWN, KIMI_SHELL_SURFACE,
                "shells match their templates, but the installed kimi version "
                "could not be determined, so its tool vocabulary is unverified")
    vocabulary = kimi_runner.TOOL_VOCABULARY.get(version)
    if vocabulary is None:
        return (hosts.UNKNOWN, KIMI_SHELL_SURFACE,
                "shells match their templates, but the probe's vocabulary table "
                "does not cover kimi %s -- upgrade the table before trusting "
                "the shells' tool surface" % version)
    faults = []
    for role in DRIVER_ROLES:
        policy = dispatch.load_template(dispatch.ROLE_FILES[role])[0]["tool_policy"]
        for direction in ("allowed", "forbidden"):
            unknown = sorted(set(policy[direction] or []) - vocabulary)
            if unknown:
                faults.append("%s: %s tool name(s) match nothing in kimi %s: %s"
                              % (role, direction, version, ", ".join(unknown)))
    # I1: the default-agent surface is an ALLOW-LIST, so every name in the
    # CLI's vocabulary must be either granted by a template or disabled by the
    # per-run config. Anything in neither set is live for every UNENFORCED
    # entry -- and the setup scan is always unenforced.
    #
    # N3: the disabled half is read out of a config.toml the RUNNER GENERATES,
    # not recomputed from `disabled_tools()`. Recomputing subtracted the
    # templates' union from a vocabulary it had just subtracted the same union
    # from: empty by construction, an identity wearing a measurement's clothes.
    allowed = kimi_runner.allowed_tool_union()
    disabled, where = _kimi_generated_disabled()
    if disabled is None:
        surface = "the per-run config's disabled set could not be read: %s" % where
    else:
        unaccounted = sorted(set(vocabulary) - allowed - disabled)
        if unaccounted:
            faults.append("neither granted by a template nor disabled by %s, so "
                          "live for every unenforced entry: %s"
                          % (where, ", ".join(unaccounted)))
        surface = ("all %d of kimi %s's tools are accounted for (%d granted by a "
                   "template, %d disabled by %s)"
                   % (len(vocabulary), version, len(allowed & set(vocabulary)),
                      len(disabled), where))
    # I5: the EFFECTIVE surface, when a child has already run in this run's
    # home. The table above says what the CLI ships; the snapshot says what a
    # launched child was actually given.
    snapshot, agent, where = _kimi_wire_snapshot(run_home)
    if snapshot is not None:
        grant = _frontmatter_tools(os.path.join(registration_dir, "%s.md" % agent))
        if grant is None:
            measured = ("%s reports %s for %r, which is not a shell registered in "
                        "%s, so the table above is what this rests on"
                        % (where, sorted(snapshot), agent, registration_dir))
        elif set(grant) != snapshot:
            faults.append("the last child's %s for %r carries %s, its registered "
                          "shell grants %s" % (_TOOLS_SNAPSHOT, agent,
                                               sorted(snapshot), sorted(grant)))
            measured = ""
        else:
            measured = ("the last child's %s for %r carries exactly its shell's "
                        "grant %s (%s)" % (_TOOLS_SNAPSHOT, agent, sorted(grant), where))
    else:
        measured = ("%s, so the effective surface rests on the version table"
                    % where)
    if faults:
        return (hosts.REFUTED, KIMI_SHELL_SURFACE, "; ".join(faults))
    return (hosts.PROVEN, KIMI_SHELL_SURFACE,
            "%s; every tool name exists in kimi %s's builtin vocabulary; %s; %s"
            % (base_detail, version, surface, measured))


def _guard_round_trip(mode, data_path, rows, guard_path=None, runner=None):
    """Drive payloads through the guard as a subprocess -- the real hook
    protocol, not an import. `rows` is (name, payload, env_id, want_allow).
    Returns (ok, detail); the detail names what was driven through what, and
    the probes compose theirs out of it rather than restating a count of their
    own (M1: a literal "(8 rows)" beside this function's own answer drifts the
    moment a row is added). Everything happens inside the caller's tempdir."""
    import scripts.kimi_guard_hook as kimi_guard_hook
    # Plain `subprocess.run`, NOT DEFAULT_RUNNER: what this spawns is
    # `sys.executable <the hook> <mode> <data>`, the hook protocol itself.
    runner = subprocess.run if runner is None else runner
    guard_path = guard_path or os.path.abspath(kimi_guard_hook.__file__)
    for name, payload, env_id, want_allow in rows:
        env = {"PATH": os.environ.get("PATH", "")}
        if env_id:
            env[kimi_guard_hook.ENV_ENTRY_ID] = env_id
        try:
            proc = runner([sys.executable, guard_path, mode, data_path],
                          input=json.dumps(payload), capture_output=True,
                          text=True, timeout=30, env=env)
        except Exception as exc:  # noqa: BLE001 -- report, never raise
            return False, "guard subprocess could not run: %s" % exc
        out = (proc.stdout or "").strip()
        denied = '"permissionDecision": "deny"' in out
        if denied == want_allow:
            return False, ("the guard %s: %s" % ("DENIED" if denied else "ALLOWED", name)
                           + (" (stdout: %s)" % out[:160] if out and not denied else ""))
    return True, ("%s round-trip: %d/%d payloads adjudicated as expected through %s"
                  % (mode, len(rows), len(rows), os.path.basename(guard_path)))


def _kimi_armed_home(sandbox):
    """Build the per-run home the RUNNER builds, inside `sandbox`, from a
    minimal fixture operator config. Returns (home, scope_path, allowlist_path).

    The real `build_kimi_home` -- not a re-implementation -- so the file this
    inspects is the file a run arms. C1 puts the runner's own home under the
    temp root; the probe passes a home inside its sandbox instead, so nothing
    survives the probe. The operator's real home is never read.
    """
    import scripts.runners.kimi as kimi_runner
    fixture_home = os.path.join(sandbox, "fixture-home")
    os.makedirs(fixture_home, exist_ok=True)
    with open(os.path.join(fixture_home, "config.toml"), "w", encoding="utf-8") as fh:
        fh.write('default_model = "kimi-code/k3"\n')
    run_dir = os.path.join(sandbox, "run")
    os.makedirs(run_dir, exist_ok=True)
    scope_path = os.path.join(run_dir, "read-scope.json")
    allowlist_path = os.path.join(run_dir, "write-allowlist.json")
    home = kimi_runner.build_kimi_home(os.path.join(sandbox, "kimi-home"),
                                       scope_path, allowlist_path,
                                       real_home=fixture_home)
    return home, scope_path, allowlist_path


def _kimi_generated_disabled():
    """(tools.disabled, where) read out of a config.toml the runner generates,
    or (None, why). The file is built and read inside a sandbox and nothing
    survives the call."""
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            home, _scope, _allowlist = _kimi_armed_home(sandbox)
            with open(os.path.join(home, "config.toml"), "rb") as fh:
                config = tomllib.load(fh)
    except OSError as exc:
        return None, "the per-run config could not be generated (%s)" % exc
    except tomllib.TOMLDecodeError as exc:
        return None, "the generated config.toml is not valid TOML (%s)" % exc
    tools = config.get("tools") if isinstance(config.get("tools"), dict) else {}
    names = {t for t in (tools.get("disabled") or []) if isinstance(t, str)}
    return names, "the config.toml the runner generates"


def _kimi_hooks_are_armed(sandbox):
    """(ok, detail): does the config.toml the runner generates REGISTER the
    guards? `ok` is None when the home could not be built at all.

    C3: both guard probes are named "...-armed", and both used to prove only
    the adjudication -- payloads through the hook script -- while nothing
    looked at whether the hook was registered anywhere. With
    `build_merged_config` replaced by one that arms no hooks, both still
    returned `proven`. This is the half C2 could break by accident and a
    refactor could break with no test going red, so it is measured here:
    the generated file is parsed with `tomllib` and must carry exactly one
    PreToolUse hook per matcher, each command naming this repo's guard script,
    its own mode and its own data file, with the runner's disabled-tool set
    present in `tools.disabled`.
    """
    import scripts.kimi_guard_hook as kimi_guard_hook
    import scripts.runners.kimi as kimi_runner
    try:
        home, scope_path, allowlist_path = _kimi_armed_home(sandbox)
        with open(os.path.join(home, "config.toml"), "rb") as fh:
            config = tomllib.load(fh)
    except OSError as exc:
        return None, "the per-run home could not be built: %s" % exc
    except tomllib.TOMLDecodeError as exc:
        return False, ("the config.toml the runner generates is not valid TOML "
                       "(%s), so the run would start with its guard hooks "
                       "unregistered" % exc)
    guard = os.path.abspath(kimi_guard_hook.__file__)
    hooks = [h for h in (config.get("hooks") or []) if isinstance(h, dict)]
    tools = config.get("tools") if isinstance(config.get("tools"), dict) else {}
    disabled = set(tools.get("disabled") or [])
    faults, armed_matchers = [], []
    for matcher, mode, data_path in ((kimi_runner.READ_MATCHER, "read", scope_path),
                                     (kimi_runner.WRITE_MATCHER, "write", allowlist_path)):
        matching = [h for h in hooks
                    if h.get("event") == "PreToolUse" and h.get("matcher") == matcher]
        if len(matching) != 1:
            faults.append("%d PreToolUse hooks match %r, expected exactly 1"
                          % (len(matching), matcher))
            continue
        command = matching[0].get("command") or ""
        for needle, what in ((guard, "the guard script %s" % guard),
                             (" %s " % mode, "its %s mode argument" % mode),
                             (os.path.abspath(data_path), "its %s data file" % mode)):
            if needle not in command:
                faults.append("the %r hook's command does not name %s: %r"
                              % (matcher, what, command[:160]))
        armed_matchers.append(matcher)
    missing = sorted(set(kimi_runner.disabled_tools()) - disabled)
    if missing:
        faults.append("tools.disabled omits %s" % ", ".join(missing))
    if faults:
        return False, ("the config.toml the runner generates does not arm the "
                       "guards: %s" % "; ".join(faults))
    return True, ("the config.toml the runner generates registers %s on %s and "
                  "disables %d tool(s)"
                  % (os.path.basename(guard), " and ".join(repr(m) for m in armed_matchers),
                     len(disabled)))


def _kimi_home_arms_and_validates(runner=None):
    """(ok, detail): the generated per-run config arms both guards AND
    `kimi doctor` accepts it. `ok` None means nothing could be measured."""
    runner = DEFAULT_RUNNER if runner is None else runner
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            ok, detail = _kimi_hooks_are_armed(sandbox)
            if ok is not True:
                return ok, detail
            env = dict(os.environ, KIMI_CODE_HOME=os.path.join(sandbox, "kimi-home"))
            proc = runner(["kimi", "doctor"], capture_output=True, text=True,
                          timeout=60, env=env)
    except OSError as exc:
        return None, "kimi doctor could not run: %s" % exc
    if proc.returncode != 0 or "OK config.toml" not in (proc.stdout or ""):
        return False, ("kimi doctor rejected the generated per-run config: %s%s"
                       % (proc.stdout or "", proc.stderr or ""))[:300]
    return True, "%s, and kimi doctor validates it" % detail


def probe_kimi_read_guard(host, runner=None, doctor_runner=None):
    """Kimi can confine a dispatched reviewer's reads to its entry's scope.

    Two halves, both required. ADJUDICATION: the guard subprocess allows an
    in-scope read and denies outside reads, unbound sessions, unknown entries
    and a malformed scope file. ARMING (C3): the config.toml the runner
    generates really registers that script as a PreToolUse hook, with this
    run's scope file bound into its command, in a file `kimi doctor` accepts.
    NOT "armed right now" -- the loop arms the scope file per batch, so at run
    start it is legitimately absent.

    `runner` drives the guard subprocess (plain python; tests use the real
    one). `doctor_runner` drives `kimi doctor` and is resolved separately,
    from DEFAULT_RUNNER, so the suite never launches the real host
    binary (FAMILY-PR-GUARDRAILS, Suite rules; I3): the two spawns are
    different binaries and must not share one default.
    """
    if not hosts.declares(host, hosts.READ_SCOPE_CONFINED):
        return (hosts.UNKNOWN, None,
                "host %r claims no read-scope confinement" % host)
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            inside = os.path.realpath(os.path.join(sandbox, "cell", "a.py"))
            outside = os.path.realpath(os.path.join(sandbox, "elsewhere", "b.py"))
            for p in (inside, outside):
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("")
            scope_path = os.path.join(sandbox, "read-scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({"probe-cell": {"files": [inside], "dirs": [], "reads": []}}, fh)
            rows = (
                ("bound Read inside scope",
                 {"tool_name": "Read", "tool_input": {"path": inside}}, "probe-cell", True),
                ("bound Read outside scope",
                 {"tool_name": "Read", "tool_input": {"path": outside}}, "probe-cell", False),
                ("bound Grep of an in-scope file",
                 {"tool_name": "Grep", "tool_input": {"pattern": "x", "path": inside}}, "probe-cell", True),
                ("bound Grep over a directory",
                 {"tool_name": "Grep", "tool_input": {"pattern": "x", "path": os.path.dirname(inside)}}, "probe-cell", False),
                ("bound Glob",
                 {"tool_name": "Glob", "tool_input": {"pattern": "*.py", "path": os.path.dirname(inside)}}, "probe-cell", False),
                ("unbound session Read",
                 {"tool_name": "Read", "tool_input": {"path": inside}}, None, False),
                ("unknown entry Read",
                 {"tool_name": "Read", "tool_input": {"path": inside}}, "not-armed", False),
            )
            ok, detail = _guard_round_trip("read", scope_path, rows, runner=runner)
            if not ok:
                return (hosts.REFUTED, KIMI_READ_GUARD, detail)
            round_trip_detail = detail
            with open(scope_path, "w", encoding="utf-8") as fh:
                fh.write("not json")
            ok, detail = _guard_round_trip(
                "read", scope_path,
                (("malformed scope file",
                  {"tool_name": "Read", "tool_input": {"path": inside}}, "probe-cell", False),),
                runner=runner)
            if not ok:
                return (hosts.REFUTED, KIMI_READ_GUARD, detail)
            round_trip_detail = "%s; and, with the data file corrupted, %s" % (
                round_trip_detail, detail)
    except OSError as exc:
        return (hosts.UNKNOWN, KIMI_READ_GUARD,
                "sandbox round-trip could not run: %s" % exc)
    armed, armed_detail = _kimi_home_arms_and_validates(doctor_runner)
    if armed is None:
        return (hosts.UNKNOWN, KIMI_READ_GUARD,
                "%s, but %s" % (round_trip_detail, armed_detail))
    if not armed:
        return (hosts.REFUTED, KIMI_READ_GUARD, armed_detail)
    # M1: composed from what the two halves REPORTED -- no hardcoded row count
    # (the old "(8 rows)" was a literal beside `_guard_round_trip`'s own
    # answer, and drifted the moment a row was added) and no surface this
    # probe did not open.
    return (hosts.PROVEN, KIMI_READ_GUARD, "%s; %s" % (round_trip_detail, armed_detail))


def probe_kimi_write_guard(host, runner=None):
    """Kimi can mediate a self-writing reviewer's Write/Edit.

    Same shape as the read probe: declared out_file allowed, everything else
    denied, symlinks denied, malformed allowlist denied -- and then the arming
    half (C3), which parses the config.toml the runner generates and requires
    the write hook to be registered there. The allowlist is the file the loop
    arms per batch (orchestrate.Guards), so it is legitimately absent at probe
    time.
    """
    if not hosts.declares(host, hosts.ARTIFACT_WRITE_GUARD):
        return (hosts.UNKNOWN, None,
                "host %r claims no artifact write guard" % host)
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            declared = os.path.realpath(os.path.join(sandbox, "findings-probe.json"))
            other = os.path.realpath(os.path.join(sandbox, "not-declared.json"))
            with open(declared, "w", encoding="utf-8") as fh:
                fh.write("{}")
            allowlist_path = os.path.join(sandbox, "write-allowlist.json")
            with open(allowlist_path, "w", encoding="utf-8") as fh:
                json.dump([declared], fh)
            rows = (
                ("Write to the declared out_file",
                 {"tool_name": "Write", "tool_input": {"path": declared, "content": "{}"}}, "probe-cell", True),
                ("Write outside the allowlist",
                 {"tool_name": "Write", "tool_input": {"path": other, "content": "{}"}}, "probe-cell", False),
                ("Edit outside the allowlist",
                 {"tool_name": "Edit", "tool_input": {"path": other}}, "probe-cell", False),
                ("unbound session Write",
                 {"tool_name": "Write", "tool_input": {"path": declared, "content": "{}"}}, None, False),
            )
            ok, detail = _guard_round_trip("write", allowlist_path, rows, runner=runner)
            if not ok:
                return (hosts.REFUTED, KIMI_WRITE_GUARD, detail)
            round_trip_detail = detail
            with open(allowlist_path, "w", encoding="utf-8") as fh:
                fh.write("not json")
            ok, detail = _guard_round_trip(
                "write", allowlist_path,
                (("malformed allowlist",
                  {"tool_name": "Write", "tool_input": {"path": declared, "content": "{}"}}, "probe-cell", False),),
                runner=runner)
            if not ok:
                return (hosts.REFUTED, KIMI_WRITE_GUARD, detail)
            round_trip_detail = "%s; and, with the data file corrupted, %s" % (
                round_trip_detail, detail)
            # C3: the ARMING half, in the same sandbox -- the write probe used
            # to build no home at all, so its detail ("the runner arms the hook
            # in the per-run home's config.toml") named a file it never opened.
            armed, armed_detail = _kimi_hooks_are_armed(sandbox)
    except OSError as exc:
        return (hosts.UNKNOWN, KIMI_WRITE_GUARD,
                "sandbox round-trip could not run: %s" % exc)
    if armed is None:
        return (hosts.UNKNOWN, KIMI_WRITE_GUARD,
                "%s, but %s" % (round_trip_detail, armed_detail))
    if not armed:
        return (hosts.REFUTED, KIMI_WRITE_GUARD, armed_detail)
    return (hosts.PROVEN, KIMI_WRITE_GUARD, "%s; %s" % (round_trip_detail, armed_detail))


def probe_kimi_model_alias(host, configured=None):
    """Every role's entry model resolves to an alias the installed CLI has.

    The runner binds `-m <alias>` on every entry (Kimi agent files cannot
    bind a model), so the question is exactly the runner's: does the tier the
    entry carries resolve through model-profiles.yml to an alias present in
    the installed config's [models] table. An unresolvable role is a
    refutation -- that entry would fail at launch rather than silently run
    the session's default model.
    """
    import scripts.runners.kimi as kimi_runner
    if not hosts.declares(host, hosts.MODEL_BINDING):
        return (hosts.UNKNOWN, None, "host %r claims no model binding" % host)
    if configured is None:
        configured = kimi_runner.configured_models()
    if not configured:
        return (hosts.REFUTED, KIMI_MODEL_ALIAS,
                "no [models] table is readable in the installed kimi config, "
                "so no entry model can bind")
    faults, bound = [], []
    for role in DRIVER_ROLES:
        tier = model_resolver.resolve_model(host, role).get("model")
        alias = kimi_runner.resolve_cli_alias(tier, configured)
        if alias is None:
            faults.append("%s: entry model %r resolves to no configured alias" % (role, tier))
        else:
            bound.append("%s->%s" % (role, alias))
    if faults:
        return (hosts.REFUTED, KIMI_MODEL_ALIAS, "; ".join(faults))
    return (hosts.PROVEN, KIMI_MODEL_ALIAS,
            "%d/%d roles bind a configured alias: %s"
            % (len(bound), len(DRIVER_ROLES), ", ".join(bound)))


def probe_kimi_usage_wire(host):
    """The usage ledger's channel, end to end on the layout the runner globs.

    I4: the runner reads `wire_path(self.kimi_home, session_id)` -- a file the
    CHILD writes under the PER-RUN home, which its own `KIMI_CODE_HOME`
    override guarantees is not `~/.kimi-code`. The probe therefore builds a
    per-run home, writes a synthetic session at exactly that layout, and
    proves `wire_path` + `parse_wire` together: resolution and summation, the
    two steps a real launch takes between a child finishing and a ledger row
    existing. It refutes when `wire_path` cannot resolve the layout (the
    ledger would report null rather than a figure) and when the parser returns
    anything but the figures the synthetic records carry.

    Everything it writes lives in the tempdir it owns (N4). It deliberately
    takes no `home` parameter: `run_probes`' `home=` means "a stand-in for ~"
    to the transcript probe, and taking the same argument here meant one name
    with two meanings -- and a fixture session left behind in whatever
    directory the caller had in mind.
    """
    import scripts.runners.kimi as kimi_runner
    if not hosts.declares(host, hosts.USAGE_LEDGER):
        return (hosts.UNKNOWN, None, "host %r claims no usage ledger" % host)
    session_id = "session_probe"
    records = [
        {"type": "llm.request", "modelAlias": "kimi-code/k3"},
        {"type": "usage.record", "model": "kimi-code/k3", "usageScope": "turn",
         "usage": {"inputOther": 10, "output": 3, "inputCacheRead": 5, "inputCacheCreation": 2}},
        {"type": "usage.record", "model": "kimi-code/k3", "usageScope": "turn",
         "usage": {"inputOther": 7, "output": 1, "inputCacheRead": 0, "inputCacheCreation": 0}},
        {"type": "usage.record", "model": "kimi-code/k3", "usageScope": "session",
         "usage": {"inputOther": 999, "output": 999, "inputCacheRead": 999, "inputCacheCreation": 999}},
    ]
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            run_home = os.path.join(sandbox, "kimi-home")
            # The layout `wire_path` globs: <home>/sessions/*/<sid>/agents/main/
            wire = os.path.join(run_home, "sessions", "wd_probe", session_id,
                                "agents", "main", "wire.jsonl")
            os.makedirs(os.path.dirname(wire), exist_ok=True)
            with open(wire, "w", encoding="utf-8") as fh:
                for record in records:
                    fh.write(json.dumps(record) + "\n")
            resolved = kimi_runner.wire_path(run_home, session_id)
            usage, model = kimi_runner.parse_wire(resolved) if resolved else ({}, None)
    except OSError as exc:
        return (hosts.UNKNOWN, KIMI_USAGE_WIRE,
                "the per-run wire round-trip could not run: %s" % exc)
    if resolved is None:
        return (hosts.REFUTED, KIMI_USAGE_WIRE,
                "a child's wire.jsonl written at the per-run home's own layout "
                "(%s) does not resolve through wire_path, so the cost ledger "
                "would report null rather than a figure" % wire)
    expected = {"input_tokens": 17, "output_tokens": 4,
                "cache_read_input_tokens": 5, "cache_creation_input_tokens": 2}
    if usage != expected or model != "kimi-code/k3":
        return (hosts.REFUTED, KIMI_USAGE_WIRE,
                "wire_path resolved %s but parse_wire returned %r (model %r), "
                "expected %r" % (resolved, usage, model, expected))
    return (hosts.PROVEN, KIMI_USAGE_WIRE,
            "a synthetic session under the run home %s resolves through "
            "wire_path to %s and sums to %d input / %d output tokens, the "
            "turn-scoped records only" % (run_home, resolved,
                                          expected["input_tokens"], expected["output_tokens"]))


TRANSCRIPT_DIR = "transcript-dir"

# Every probe id a registry row may map to and get a runner for; the
# shadow-shell scan runs unconditionally and is not a mappable probe. The
# retirement bar (tests/test_generic_retirement_bar.py) reads this as "the
# shipped probes" (spec 8.1), so it must not drift from the runner table:
# run_probes refuses to build a table that disagrees with it.
PROBE_IDS = (REGISTERED_SHELL_TOOLS, WRITE_GUARD_ARMED, TRANSCRIPT_DIR,
            ENTRY_MODEL_BOUND, READ_GUARD_ARMED,
            KIMI_SHELL_SURFACE, KIMI_READ_GUARD, KIMI_WRITE_GUARD,
            KIMI_MODEL_ALIAS, KIMI_USAGE_WIRE)

# Which capability each shipped probe MEASURES. The retirement bar reads this
# so a row cannot satisfy spec 8.1 by mapping a security capability to a
# shipped probe that proves something else (READ_SCOPE_CONFINED ->
# "registered-shell-tools" would otherwise pass both the bar and, because
# run_probes is row-driven, the live posture).
PROBE_CAPABILITY = {REGISTERED_SHELL_TOOLS: hosts.TOOL_POLICY_ENFORCED,
                    WRITE_GUARD_ARMED: hosts.ARTIFACT_WRITE_GUARD,
                    TRANSCRIPT_DIR: hosts.USAGE_LEDGER,
                    ENTRY_MODEL_BOUND: hosts.MODEL_BINDING,
                    READ_GUARD_ARMED: hosts.READ_SCOPE_CONFINED,
                    KIMI_SHELL_SURFACE: hosts.TOOL_POLICY_ENFORCED,
                    KIMI_READ_GUARD: hosts.READ_SCOPE_CONFINED,
                    KIMI_WRITE_GUARD: hosts.ARTIFACT_WRITE_GUARD,
                    KIMI_MODEL_ALIAS: hosts.MODEL_BINDING,
                    KIMI_USAGE_WIRE: hosts.USAGE_LEDGER}


def probe_transcript_dir(host, session_dir, home=None):
    """The host's own transcript directory for this SESSION exists and reads.

    Operational rather than security -- 8.1 excludes usage_ledger from F5's
    bar, and it gates nothing directly. But it DOES gate
    `synthesize._collect_host_usage`, so the directory it asks about has to be
    the one that collector will read.

    `session_dir` is where the HOST SESSION runs -- NOT the review root, and
    NOT the target. synthesize.py:52-66 spends fourteen lines
    (#calibration-2, #calibration-4) establishing that these are deliberately
    different directories on every external-target run; passing the target
    here resolved a slug with no transcripts, refuted, and took
    `meta.cost.tokens` to null on every calibration run while a self-scan
    (session dir == target) hid it. `phases.runio.session_dir` is the single
    source both this probe and the collector read, so the gate and the
    collector cannot disagree about which transcript they mean.

    The path mangling belongs to collect_usage.project_slug; re-deriving it
    here would be a second definition that could drift from the reader's.
    """
    if not hosts.declares(host, hosts.USAGE_LEDGER):
        return (hosts.UNKNOWN, None, "host %r claims no usage ledger" % host)
    root = home or os.path.expanduser("~")
    directory = os.path.join(root, ".claude", "projects",
                             collect_usage.project_slug(session_dir))
    if not os.path.isdir(directory):
        return (hosts.REFUTED, TRANSCRIPT_DIR,
                "no transcript directory at %s; the cost ledger will report "
                "null rather than a figure" % directory)
    if not os.access(directory, os.R_OK):
        return (hosts.REFUTED, TRANSCRIPT_DIR,
                "%s is not readable" % directory)
    return (hosts.PROVEN, TRANSCRIPT_DIR, "%s is readable" % directory)


SHADOW_SHELL_SCAN = "shadow-shell-scan"

# The prefix `dispatch.registered_agent_name` gives every emitted shell. A
# TARGET file with this prefix in a project-scoped agent directory replaces the
# user-level shell rather than adding to it.
_SHELL_PREFIX = "panopticon-"


def _declares_a_shell_name(path):
    """True when this file CLAIMS one of our shell names in its frontmatter.

    Identity is the `name` field, not the filename: `registered_agent_name`
    writes `panopticon-<role>` into `name:` for markdown hosts and
    `name = "panopticon-<role>"` for codex's TOML, and that is the string a
    host resolves an agent type against. A target shipping `innocuous.md`
    whose frontmatter declares `name: panopticon-scout` shadows the registered
    shell exactly as a same-named file would, so a filename-only scan is
    evaded by `mv`.
    """
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            # Not a regular file. The case that matters is a FIFO: open() on a
            # named pipe BLOCKS until a writer attaches, so a hostile target can
            # plant one here and hang this scan forever -- a denial of service
            # against the control that is supposed to detect its attack.
            # os.stat, NOT os.lstat, deliberately: a symlink pointing at a real
            # .md file is a genuine shadow candidate and must be scanned, while
            # a symlink pointing at a FIFO resolves to S_ISFIFO and is skipped.
            return False
        with open(path, encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return False                   # unreadable, vanished, or a broken symlink
    for line in head.splitlines()[:40]:
        stripped = line.strip()
        if not stripped.lower().startswith("name"):
            continue
        if ":" in stripped:
            value = stripped.split(":", 1)[1]
        elif "=" in stripped:
            value = stripped.split("=", 1)[1]
        else:
            continue
        if value.strip().strip("\"'").lower().startswith(_SHELL_PREFIX):
            return True
    return False


def probe_shadow_shells(host, review_root):
    """The REVIEWED tree ships nothing that shadows our enforcement shells.

    `review_root` is the tree under review -- `runio.resolve_review_root`'s
    answer, which for `--pr` is the PR WORKTREE and from a subdirectory is the
    git toplevel. It is emphatically not `args.target`: scanning that scanned
    the operator's own checkout, the one tree guaranteed clean, while the
    hostile `.claude/agents/panopticon-scout.md` sat unread in the worktree.

    Spec 7.3. Kimi's agent discovery precedence is Explicit > Project > Extra >
    User, so a target repo's `.agents/agents/panopticon-scout.md` silently
    replaces the registered shell -- an attack on the enforcement mechanism
    itself, aimed at a tool whose stated purpose is reviewing possibly-hostile
    repositories. Several hosts discover project-scoped agents, so this is a
    registry-driven check rather than a per-family one: a host with no
    `project_scope_dirs` is a no-op and costs nothing.

    Can only REFUTE. A clean scan is UNKNOWN, not PROVEN -- finding no
    shadowing file says nothing about whether the host enforces anything, which
    is `registered-shell-tools`' question. `hosts.resolve_state` combines the
    two, and refuted beats proven.
    """
    row = hosts.spec(host)
    if not row or not row.project_scope_dirs:
        return (hosts.UNKNOWN, SHADOW_SHELL_SCAN,
                "host %r discovers no project-scoped agents" % host)
    hits, unreadable = [], []
    for relative in row.project_scope_dirs:
        directory = os.path.join(review_root, relative)
        try:
            names = sorted(os.listdir(directory))
        except (FileNotFoundError, NotADirectoryError):
            continue                   # the target has no such directory: nothing to shadow
        except OSError as exc:
            # We could not LOOK, which is not the same as looking and finding
            # nothing. It has to REFUTE rather than resolve UNKNOWN: resolve_state
            # lets UNKNOWN lose to PROVEN, so an unknown here would combine with
            # the shell probe's proof into PROVEN and hide a shadow we never saw.
            unreadable.append("%s (%s)" % (relative, exc.strerror or exc))
            continue
        for name in names:
            path = os.path.join(directory, name)
            if name.lower().startswith(_SHELL_PREFIX):
                hits.append(os.path.join(relative, name))
            elif _declares_a_shell_name(path):
                hits.append("%s (declares a panopticon shell name)"
                            % os.path.join(relative, name))
    if hits:
        return (hosts.REFUTED, SHADOW_SHELL_SCAN,
                "the reviewed tree (%s) ships agent file(s) that shadow this "
                "host's enforcement shells: %s"
                % (review_root, ", ".join(hits)))
    if unreadable:
        return (hosts.REFUTED, SHADOW_SHELL_SCAN,
                "could not read the reviewed tree's %s, so shadowing could not "
                "be ruled out" % ", ".join(unreadable))
    return (hosts.UNKNOWN, SHADOW_SHELL_SCAN,
            "no shadowing agent files in the reviewed tree's %s"
            % ", ".join(row.project_scope_dirs))


SCHEMA_VERSION = 1

# Capabilities with no probe at all. Empty since plan 5 shipped
# read-guard-armed; kept so a future capability that genuinely has no probe
# yet is written down here rather than inferred from an absent key (5.1). A
# host that does not CLAIM a capability goes through `_no_probe_reason`.
_NO_PROBE = {}


def _row(state, by, detail):
    return {"state": state, "by": by, "detail": detail}


def _no_probe_reason(row, capability, host):
    """Why a capability got no probe -- split on whether it is even CLAIMED.

    Minor 1: one sentence used to cover both, and it said the host "claims
    this capability's proof is not shipped yet". For gemini -- which claims
    NOTHING -- that was simply false, in the one artifact whose entire purpose
    is separating claims from proof. A host that does not claim a capability
    is not waiting on a probe; there is nothing to prove.
    """
    if row and capability in row.claims:
        return ("no probe: host %r claims this capability's proof is not "
                "shipped yet" % host)
    return ("no probe: host %r does not claim this capability, so there is "
            "nothing to prove" % host)


def run_probes(host, review_root, session_root=None, registration_dir=None,
               home=None, shadow=None, settings_path=None, run_home=None):
    """Establish this host's posture now, and return the artifact body.

    THREE DIFFERENT TREES, and collapsing them is what produced both of this
    branch's Criticals. One `target` argument used to answer all three:

      * `review_root`  -- the REVIEWED tree. What the shadow-shell scan reads:
        the PR worktree under `--pr`, the git toplevel from a subdirectory.
        Never `args.target`, which under `--pr` is the operator's own checkout
        -- the one tree guaranteed clean (C1).
      * `session_root` -- where the HOST SESSION runs. What the write-guard
        probe and the transcript probe read. On every external-target run this
        is a DIFFERENT directory from the reviewed tree, which is the whole
        subject of synthesize.py's #calibration-2/#calibration-4 comment (C2).
        Defaults to cwd, exactly as `runio.session_dir` does; note that
        `write_guard_hook._resolve(None, None, os.getcwd())` and
        `_resolve(None, None, None)` name the same settings file (one
        absolute, one cwd-relative), so defaulting it here does not move the
        write-guard probe's subject -- measured, not assumed.
      * `registration_dir` -- where the USER's shells are registered. Defaults
        to the host row's own.

    Runs every probe the registry's `HostSpec.probes` maps for `host`, plus
    the shadow-shell scan which runs for any host with project scope. Where
    two probes bear on one capability, `hosts.resolve_state` ranks them:
    refuted beats proven beats unknown.

    `shadow` lets a caller that must ALSO decide from the shadow scan's own
    `(state, by, detail)` -- driver._shadow_refusal, which may not read it
    back off the artifact's `by` field -- hand in the single result it already
    computed. Without it the scan ran twice per invocation: duplicate work,
    and a TOCTOU window in which the artifact and the refusal could disagree
    about the same tree. `home` exists for fixtures.

    `settings_path` (plan 6, spec 5.4) names the file a HEADLESS runner will
    arm; when given, it is the two guard probes' subject INSTEAD of
    `session_root`. `None` (session mode, or plain `driver run`) leaves them
    probing the session root exactly as before.

    `run_home` is the live runner's scratch directory outside the reviewed
    tree (`HostRunner.run_home`), threaded down from the loop so a probe can
    measure THIS run's children -- the effective tool surface a launch really
    had. It is passed in process, never re-derived from a path recorded inside
    the target (N2). `None` until the loop's `prepare` has run.
    """
    findings = {}          # capability -> list of (state, by, detail)
    session_root = session_root or os.getcwd()

    def record(capability, result):
        findings.setdefault(capability, []).append(result)

    row = hosts.spec(host)
    # The registry's capability -> probe-id mapping DRIVES this, rather than
    # being consulted for membership while the capability is hard-coded here.
    # A row that maps a probe to a different capability must record it there;
    # otherwise `HostSpec.probes` is decorative and a mis-mapped row fails
    # silently -- the defect this epic exists to remove.
    runners = {
        REGISTERED_SHELL_TOOLS:
            lambda: probe_registered_shell_tools(host, registration_dir),
        WRITE_GUARD_ARMED:
            lambda: probe_write_guard_armed(host, session_root=session_root,
                                            settings_path=settings_path),
        TRANSCRIPT_DIR:
            lambda: probe_transcript_dir(host, session_root, home=home),
        ENTRY_MODEL_BOUND:
            lambda: probe_entry_model_bound(host, registration_dir),
        READ_GUARD_ARMED:
            lambda: probe_read_guard_armed(host, session_root=session_root,
                                           settings_path=settings_path),
        KIMI_SHELL_SURFACE:
            # `run_home` is the live runner's scratch home, handed down by the
            # loop (N2) -- never a path read out of the reviewed tree. None
            # before the first `prepare`, in session mode and under plain
            # `driver run`, where I5 falls back to the version table and says
            # so in its detail.
            lambda: probe_kimi_shell_surface(host, registration_dir,
                                             run_home=run_home),
        KIMI_READ_GUARD:
            lambda: probe_kimi_read_guard(host),
        KIMI_WRITE_GUARD:
            lambda: probe_kimi_write_guard(host),
        KIMI_MODEL_ALIAS:
            lambda: probe_kimi_model_alias(host),
        KIMI_USAGE_WIRE:
            lambda: probe_kimi_usage_wire(host),
    }
    if set(runners) != set(PROBE_IDS):
        raise RuntimeError("host_probes.PROBE_IDS is out of step with run_probes' runner "
                           "table: %s" % sorted(set(runners) ^ set(PROBE_IDS)))
    for capability, probe_id in ((row.probes if row else None) or {}).items():
        runner = runners.get(probe_id)
        if runner is None:
            record(capability, (hosts.UNKNOWN, None,
                                "no implementation for probe %r" % probe_id))
            continue
        record(capability, runner())
    # Not in any row's `probes`: it runs for any host with project scope, claim
    # or no claim, and it can only refute. Minor 4: run ONCE per invocation --
    # the caller that also needs the raw tuple passes its own result in rather
    # than making us scan the tree a second time.
    record(hosts.TOOL_POLICY_ENFORCED,
           shadow if shadow is not None
           else probe_shadow_shells(host, review_root))

    capabilities = {}
    for capability in hosts.CAPABILITIES:
        results = findings.get(capability) or []
        if not results:
            capabilities[capability] = _row(
                hosts.UNKNOWN, None,
                _NO_PROBE.get(capability, _no_probe_reason(row, capability, host)))
            continue
        state = hosts.resolve_state([r[0] for r in results])
        agreeing = [r for r in results if r[0] == state] or results[:1]
        # `by` names the probe that decided, so it stays the FIRST agreeing
        # result -- for tool_policy_enforced that means a registry-mapped
        # probe (walked above) is reported ahead of the unconditional
        # shadow-shell-scan call that follows it, exactly as before. `detail`
        # now carries EVERY probe that reached that verdict, joined: reporting
        # only the first silently DROPPED the shadow-shell finding whenever
        # the shell probe also refuted (an empty/absent registration
        # directory) -- which is every machine that has not run `driver
        # setup`, i.e. exactly where a hostile target is most likely to be
        # reviewed. A caller that must decide from the shadow probe alone
        # (driver._shadow_refusal) calls it directly rather than trusting
        # this join order; this field is disclosure, not a decision input.
        capabilities[capability] = _row(
            state, agreeing[0][1], "; ".join(r[2] for r in agreeing))
    return {"schema_version": SCHEMA_VERSION, "host": host,
            "probed_at": run_manifest._now_iso(), "capabilities": capabilities}


def capabilities_of(artifact):
    """The capability -> state map, for comparing two probe runs.

    Deliberately drops `probed_at`: it changes on every probe by design, and
    comparing it would make 5.2's resume check fire merely because time passed.

    FAIL-CLOSED on a truthy non-mapping `artifact`, AND on a truthy
    non-mapping per-capability entry. `(artifact or {})` / `(body or {})` only
    catch the FALSY case -- `[]`, `0`, `""`, `False` -- by falling through to
    `{}` before `.get` is ever called; a truthy non-dict (a non-empty list, a
    string, a nonzero number) sailed past that `or` unchanged and `.get(...)`
    on it raised AttributeError, at BOTH levels: `capabilities_of(["x"])` and
    `capabilities_of({"capabilities": {"tool_policy_enforced": "pwned"}})`
    both crashed before this fix (fix round 1 caught the second: the first
    fix pass hardened only the outer level and left `(body or {})` on its
    original guard). The caller here is `driver._establish_host_posture`,
    feeding this `stored` -- the parsed contents of `host-capabilities.json`,
    a file a hostile target can plant or truncate -- so a corrupt artifact
    produced a mid-run traceback instead of a refusal, and that caller reads
    this function DIRECTLY rather than through `hosts.posture()` (which
    already guards malformed per-capability entries) -- `posture()`'s
    hardening does not cover this call site. `hosts.posture()` and
    `runio.host_evidence()` were both hardened against exactly this shape
    already ("a crash mid-run is not failing closed -- it is failing"); this
    was the spot still missed, at both levels.
    """
    if not isinstance(artifact, dict):
        artifact = {}
    caps = artifact.get("capabilities")
    if not isinstance(caps, dict):
        caps = {}
    return {name: (body.get("state") if isinstance(body, dict) else None)
            for name, body in caps.items()}
