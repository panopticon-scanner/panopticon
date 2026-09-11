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
import os
import stat
import tempfile

from scripts import collect_usage, dispatch, hosts, run_manifest, write_guard_hook

# The roles the DRIVER dispatches and therefore needs registered shells for.
# `advisor` is deliberately absent -- it is dispatched by the host, not the
# driver. Protected by test_the_driver_roles_match_setup_flows.
DRIVER_ROLES = ("scout", "domain_panel", "domain_advisor")

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


WRITE_GUARD_ARMED = "write-guard-armed"


def _round_trip_denies_an_outside_write():
    """Arm the guard in a throwaway sandbox and confirm it actually denies.

    Never touches the session's real settings or allowlist: install/uninstall
    run entirely against paths inside a TemporaryDirectory. Returns
    (ok, detail).
    """
    with tempfile.TemporaryDirectory() as sandbox:
        settings = os.path.join(sandbox, "settings.json")
        allowlist = os.path.join(sandbox, "allowlist.json")
        declared = os.path.join(sandbox, "findings-probe.json")
        with open(declared, "w", encoding="utf-8") as fh:
            fh.write("{}")
        try:
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


def probe_write_guard_armed(host, session_root=None):
    """This host CAN mediate a reviewer's Write when it fans out.

    NOT "the guard is armed right now". The host arms it during fan-out --
    `write_guard_hook.install` writes the PreToolUse entry and `uninstall`
    removes it -- so at run start, which is when 5.2 probes, it is legitimately
    absent. A probe that gated on live arming was measured returning REFUTED on
    a correctly configured machine, which would have made require_unenforced_ack
    refuse every Claude run.

    So: prove the mechanism mediates (in a sandbox), and prove the place the
    host will arm is writable. #1493 -- a guard armed at a path nothing reads is
    worse than no guard -- so the resolved path is named either way.
    """
    if not hosts.declares(host, hosts.ARTIFACT_WRITE_GUARD):
        return (hosts.UNKNOWN, None,
                "host %r claims no artifact write guard" % host)
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


TRANSCRIPT_DIR = "transcript-dir"


def probe_transcript_dir(host, project_dir, home=None):
    """The host's own transcript directory for this project exists and reads.

    Operational rather than security -- 8.1 excludes usage_ledger from F5's
    bar, and it gates nothing. It is probed so the posture is COMPLETE: 5.1
    requires that absence of a warning mean "measured and proven", never
    "nobody looked", and that only works if every claimed capability answers.

    The path mangling belongs to collect_usage.project_slug; re-deriving it
    here would be a second definition that could drift from the reader's.
    """
    if not hosts.declares(host, hosts.USAGE_LEDGER):
        return (hosts.UNKNOWN, None, "host %r claims no usage ledger" % host)
    root = home or os.path.expanduser("~")
    directory = os.path.join(root, ".claude", "projects",
                             collect_usage.project_slug(project_dir))
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


def probe_shadow_shells(host, target):
    """The target repository ships nothing that shadows our enforcement shells.

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
        directory = os.path.join(target, relative)
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
                "target ships agent file(s) that shadow this host's "
                "enforcement shells: %s" % ", ".join(hits))
    if unreadable:
        return (hosts.REFUTED, SHADOW_SHELL_SCAN,
                "could not read the target's %s, so shadowing could not be "
                "ruled out" % ", ".join(unreadable))
    return (hosts.UNKNOWN, SHADOW_SHELL_SCAN,
            "no shadowing agent files in the target's %s"
            % ", ".join(row.project_scope_dirs))


SCHEMA_VERSION = 1

# Capabilities with no probe in F3a, and the reason each says so. 5.1 requires
# "nobody looked" to be written down rather than inferred from an absent key.
_NO_PROBE = {
    hosts.READ_SCOPE_CONFINED:
        "no probe: no host implements a read-confinement control (spec 7.2)",
    hosts.MODEL_BINDING:
        "no probe in F3a: dispatch entries still carry model=None (spec 8, F4)",
}


def _row(state, by, detail):
    return {"state": state, "by": by, "detail": detail}


def run_probes(host, target, session_root=None, home=None,
               registration_dir=None):
    """Establish this host's posture now, and return the artifact body.

    Runs every probe the registry's `HostSpec.probes` maps for `host`, plus
    the shadow-shell scan which runs for any host with project scope. Where
    two probes bear on one capability, `hosts.resolve_state` ranks them:
    refuted beats proven beats unknown.

    `session_root`, `home` and `registration_dir` exist for fixtures; production
    callers pass `target` and, when the operator supplied --session-dir,
    `session_root`.
    """
    findings = {}          # capability -> list of (state, by, detail)

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
            lambda: probe_write_guard_armed(host, session_root=session_root),
        TRANSCRIPT_DIR:
            lambda: probe_transcript_dir(host, target, home=home),
    }
    for capability, probe_id in ((row.probes if row else None) or {}).items():
        runner = runners.get(probe_id)
        if runner is None:
            record(capability, (hosts.UNKNOWN, None,
                                "no implementation for probe %r" % probe_id))
            continue
        record(capability, runner())
    # Not in any row's `probes`: it runs for any host with project scope, claim
    # or no claim, and it can only refute.
    record(hosts.TOOL_POLICY_ENFORCED, probe_shadow_shells(host, target))

    capabilities = {}
    for capability in hosts.CAPABILITIES:
        results = findings.get(capability) or []
        if not results:
            capabilities[capability] = _row(
                hosts.UNKNOWN, None,
                _NO_PROBE.get(capability,
                              "no probe: host %r claims this capability's "
                              "proof is not shipped yet" % host))
            continue
        state = hosts.resolve_state([r[0] for r in results])
        # Report the probe that DECIDED, so `by` and `detail` always agree with
        # `state` -- naming a probe that lost the precedence would be worse
        # than naming none. When two results TIE on the decided state (e.g.
        # both REFUTED), the FIRST recorded wins: for tool_policy_enforced
        # that means a registry-mapped probe (walked above) is reported ahead
        # of the unconditional shadow-shell-scan call that follows it. Both
        # facts stay true in the resolved STATE either way; only which
        # `detail` string surfaces is decided by this order, and it is
        # pinned deliberately here rather than left to accident.
        deciding = next((r for r in results if r[0] == state), results[0])
        capabilities[capability] = _row(state, deciding[1], deciding[2])
    return {"schema_version": SCHEMA_VERSION, "host": host,
            "probed_at": run_manifest._now_iso(), "capabilities": capabilities}


def capabilities_of(artifact):
    """The capability -> state map, for comparing two probe runs.

    Deliberately drops `probed_at`: it changes on every probe by design, and
    comparing it would make 5.2's resume check fire merely because time passed.
    """
    return {name: (body or {}).get("state")
            for name, body in ((artifact or {}).get("capabilities") or {}).items()}
