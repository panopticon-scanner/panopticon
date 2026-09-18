"""Host-agnostic probe machinery: the pieces every family's probes share.

Split out of `host_probes.py` (#1627), which had grown past the package
ceiling holding three families' probes plus the shared tables. What lives
here is what is true of ANY host: the driver's role list, the registered-shell
readers, the `--help` interrogation every family runs through its OWN
launcher, the headless settings path, and the shadow-shell scan that runs for
every host with project scope, claim or no claim.

A family's own probes live beside this, in `probes/<family>.py`, and reach it
by module attribute (`from . import common`; `common.DRIVER_ROLES`) so a name
still has exactly one definition and one patch target. The registry that maps
probe ids to those functions stays in `host_probes.py`.
"""
import errno
import os
import re
import shutil
import stat
from collections import namedtuple

from scripts import dispatch, hosts

from . import surface


# The roles the DRIVER dispatches and therefore needs registered shells for:
# every template in dispatch.ROLE_FILES. #1606: this used to be a hand-kept
# three-tuple that excluded `advisor` on the claim the host dispatched it, not
# the driver -- false since the 5.1 tool-verify round, whose
# phases/verify.py::_tool_verify_entry dispatches panopticon-advisor ENFORCED
# on the strength of the other three shells' proof. Derived, so no role the
# driver dispatches can be left unchecked by an edit to one tuple.
DRIVER_ROLES = tuple(sorted(dispatch.ROLE_FILES))

REGISTERED_SHELL_TOOLS = "registered-shell-tools"


def failure_detail(exc, operation):
    """What a probe says when it could not measure at all (#1637 P05).

    Run-13's Codex probes reported `unknown` with a bare
    `PermissionError: [Errno 1] Operation not permitted`. That string is the
    ENTIRE answer an operator gets -- it is what lands in
    `host-capabilities.json`, on all four disclosure surfaces and in the
    report -- and it names neither what was attempted nor what the OS refused.
    EPERM on a `fork` inside a seatbelt sandbox, EPERM opening a settings file,
    and EPERM on a socket are the same sentence and three different remedies.

    So an `OSError` carries the errno NAME (`EPERM`, not the bare `1` -- the
    number is the thing an operator has to go look up), the OS's own
    `strerror`, the `filename` when the exception has one, and the operation
    the probe was attempting. Anything else carries its type, its message and
    the operation; the shape is the same so a reader does not have to learn
    two.

    This changes the DETAIL only. The verdict stays whatever the caller
    decided -- a probe that could not measure still answers `unknown`, never a
    guess, and `LaunchRefused` still escapes every one of these handlers
    untouched.
    """
    name = type(exc).__name__
    if isinstance(exc, OSError):
        code = (errno.errorcode.get(exc.errno) if exc.errno is not None
                else None) or "no errno"
        where = " (%s)" % exc.filename if exc.filename else ""
        return "%s [%s] %s%s: %s" % (name, code, exc.strerror or exc, where,
                                     operation)
    return "%s: %s: %s" % (name, exc, operation)


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


def headless_settings_path(review_root, namespace=None):
    """The settings file the headless runner will arm: runs/<tag>/host-settings.json
    once a manifest exists, flat top-level for `namespace == "setup"` (R-P6-5;
    namespace-aware since Task 6 fix round 1, item 2).

    Setup keeps its OWN manifest (setup-manifest.json), never
    run-manifest.json -- so if this review_root already holds a run-manifest.json
    from an EARLIER review run (a realistic sequence: review first, refresh
    the config with `driver loop --setup` later), routing setup's settings
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


CLI_HELP_TIMEOUT = 30    # seconds; a CLI that cannot print --help inside this is unmeasurable


def _flag_advertised(flag, text):
    """Is `flag` a standalone token of `text`? `-p` must not match inside
    `--print` or `--permission-mode`; `--output-format=stream-json` still
    advertises `--output-format`."""
    return re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(flag), text) is not None


def _cli_help(launch, found, env=None, cwd=None, help_argv=("--help",)):
    """(text, verdict, why): what `<found> <help_argv>` printed.

    `text` is None when the read could not be made at all, and `verdict` then
    carries the answer a probe must give for that failure -- None when nothing
    ran (unmeasurable) and False when the CLI ran and refused (measured, and
    not a CLI the headless runner can drive). The two are different answers
    and this is the one place that decides which is which.

    `help_argv` is the runner's own (`HostRunner.HELP_ARGV`): codex documents
    `--output-schema` under `codex exec --help`, and a top-level read would
    record "not advertised" for a CLI that takes the flag (D10 N1).

    Going through the runner's launcher rather than subprocess.run is
    deliberate: it is the one seam the suite refuses real launches at
    (tests/conftest.py), so a test that reaches this without a fake fails
    loudly instead of running the real binary.
    """
    import scripts.runners.base as runners_base
    argv = [found] + list(help_argv)
    try:
        proc = launch(argv, capture_output=True, text=True,
                      env=env, cwd=cwd, timeout=CLI_HELP_TIMEOUT)
    except runners_base.LaunchRefused:
        # The suite's structural guard, and the ONE exception that must not
        # become a verdict: `LaunchRefused` has its own type precisely so the
        # probes' fail-closed mapping cannot swallow it (see its docstring in
        # runners/base.py). Swallowed, a test that actually reached a live
        # `claude`/`codex`/`kimi` would read as a green "runtime unavailable".
        # First, so the widened clause below cannot absorb it -- it is a
        # RuntimeError subclass. Every other seam re-raises it the same way.
        raise
    except Exception as exc:          # noqa: BLE001 -- a probe reports, never raises
        # #1626 I2. `launch` is FAMILY-supplied (`Runner.runner`): a launcher
        # with a different signature raises TypeError, one that refuses raises
        # whatever it likes, and neither was in the old
        # (OSError, SubprocessError, ValueError) triple. The exception then
        # escaped run_probes -> _establish_host_posture -> driver.run, which
        # does not wrap it, so `driver run` printed a traceback instead of a
        # status. The sibling block in _headless_usage_source has caught bare
        # Exception for exactly this reason since it was written.
        return None, None, failure_detail(
            exc, "`%s` could not run" % " ".join(argv))
    if proc.returncode != 0:
        return None, False, ("`%s` exited %s: not a CLI the headless runner can drive"
                             % (" ".join(argv), proc.returncode))
    return "%s\n%s" % (proc.stdout or "", proc.stderr or ""), True, ""


def _cli_advertises(launch, found, flags, env=None, cwd=None):
    """(verdict, why): does `<found> --help`, run through the RUNNER's own
    launcher and under the RUNNER's own environment, exit 0 and advertise
    every flag in `flags`? None means it could not be run at all -- a probe
    that cannot measure says UNKNOWN, never guesses.

    `env` and `cwd` come from the runner too (#1626 I2). `env` is
    `HostRunner.launch_env()`, the same preparation `run_entry` uses for a
    real launch -- claude's pops CLAUDECODE because a nested `claude -p`
    refuses to start inside a Claude Code session, and interrogating the CLI
    under an environment the runner never uses measures the wrong thing. It
    works today only because `--help` is answered at argparse level; the day
    that refusal moves earlier in start-up, every self-scan run from inside a
    session would refute usage_ledger."""
    text, verdict, why = _cli_help(launch, found, env=env, cwd=cwd)
    if text is None:
        return verdict, why
    missing = [f for f in flags if not _flag_advertised(f, text)]
    if missing:
        return False, ("`%s --help` does not advertise %s, so a launch would print no "
                       "JSON envelope to read usage from" % (found, ", ".join(missing)))
    return True, "`%s --help` advertises %s" % (found, ", ".join(flags))


CLI_FLAGS_PROBE = "cli-flags"


def probe_cli_flags(host):
    """What this host's headless CLI can be ASKED to do: `{fact: row}` for
    every operational fact its registry row declares (D10 N1).

    NOT a capability probe, and deliberately not in `PROBE_IDS`: it returns no
    `(state, by, detail)` triple, maps to no capability, and gates nothing.
    `run_probes` writes what it returns BESIDE `capabilities`, so a CLI
    upgraded between two turns of a resumable loop is not posture drift.

    F1 answered this question inside the usage-source probe, from the `--help`
    read that probe already made. That tied an operational fact to an
    unrelated CLAIM: codex's row maps no usage-source probe and codex declares
    no usage ledger, so on codex -- the other host whose runner takes an
    output-schema flag -- the question could never be asked at all, and ruling
    3's codex half was unreachable for the life of the row rather than dormant
    until a CLI upgrade. It runs off `HostSpec.cli_flag_facts` now, which is
    pinned to the runners' own `OUTPUT_SCHEMA_FLAG` by test.

    One `--help` launch per declaring host, and only on a HEADLESS run (the
    caller decides): session mode launches no CLI of ours, so there is nothing
    to ask about. `advertised` is a tri-state -- True, False, and None for
    "the read could not be made" -- and every consumer treats None exactly as
    it treats False: no schema on the argv.
    """
    row = hosts.spec(host)
    facts = tuple(getattr(row, "cli_flag_facts", ()) or ()) if row else ()
    if hosts.OUTPUT_SCHEMA not in facts:
        return {}
    import scripts.runners.base as runners_base
    try:
        runner = runners_base.runner_for(host, "headless")
        cli, flag = runner.CLI, tuple(runner.OUTPUT_SCHEMA_FLAG or ())
        launch, help_argv = runner.runner, tuple(runner.HELP_ARGV or ("--help",))
        launch_env = runner.launch_env()
    except Exception as exc:          # noqa: BLE001 -- a probe reports, never raises
        return {hosts.OUTPUT_SCHEMA: {
            "flag": None, "advertised": None,
            "detail": failure_detail(
                exc, "host %r has no usable headless runner to interrogate" % host)}}
    if not cli or not flag:
        # The registry row and the runner disagree; the pin test exists to
        # stop that reaching a release, and the fail-safe answer is "unknown".
        return {hosts.OUTPUT_SCHEMA: {
            "flag": flag[0] if flag else None, "advertised": None,
            "detail": "host %r declares the fact but its runner names no CLI or no flag"
                      % host}}
    found = shutil.which(cli)
    if not found:
        return {hosts.OUTPUT_SCHEMA: {
            "flag": flag[0], "advertised": None,
            "detail": "no `%s` on PATH: nothing to interrogate, so no reply will be "
                      "schema-constrained" % cli}}
    text, _verdict, why = _cli_help(
        launch, found, env=launch_env,
        cwd=getattr(runner, "review_root", None), help_argv=help_argv)
    if text is None:
        return {hosts.OUTPUT_SCHEMA: {"flag": flag[0], "advertised": None, "detail": why}}
    advertised = _flag_advertised(flag[0], text)
    return {hosts.OUTPUT_SCHEMA: {
        "flag": flag[0], "advertised": advertised,
        "detail": "`%s %s` %s advertise %s"
                  % (found, " ".join(help_argv), "does" if advertised else "does not",
                     flag[0])}}


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


# --- the target's discovery surface (#1657 step 3) --------------------------
DISCOVERY_SURFACE = "target-discovery-surface"

# What CLOSES a surface the registry marks CONTROLLED, and how a test proves
# it is still there (spec §4). Written here, beside the scan that reports the
# hit, and pinned by tests/probes/test_discovery_surface.py against the
# runners' own `command()` argv: a control that stops being passed must fail
# the suite, because the table would otherwise go on calling its surface
# closed. `argv` is the token(s) the launch carries -- a token spelled with a
# trailing `=` matches a `--flag=<value>` argv entry by prefix -- and is empty
# for a control that is not a flag at all, whose `mechanism` names what a test
# must assert instead.
Control = namedtuple("Control", "host argv mechanism")
CONTROLS = {
    "claude:setting-sources-user": Control(
        "claude", ("--setting-sources", "user"),
        "the launch reads the USER's settings only, so a target-shipped "
        "`.claude/settings.json` / `settings.local.json` -- and every hook it "
        "declares -- is never read"),
    "claude:strict-mcp-config": Control(
        "claude", ("--strict-mcp-config",),
        "the loop passes no `--mcp-config`, so the reviewer gets no MCP "
        "servers at all rather than the target's"),
    "claude:disable-slash-commands": Control(
        "claude", ("--disable-slash-commands",),
        '"Disable all skills" (`claude --help`), which closes a planted '
        "`.claude/skills/*/SKILL.md` as well as `.claude/commands/**`"),
    "codex:cwd-outside-target": Control(
        "codex", (),
        "`codex_host.launch_cwd` runs the child in the empty, run-owned "
        "scratch `--cd` names, outside the review root, so whichever root the "
        "CLI keys discovery off it is not the target's"),
    "codex:ignore-user-config-and-rules": Control(
        "codex", ("--ignore-user-config", "--ignore-rules"),
        "the launch reads neither the user's config nor a `.rules` file"),
    "kimi:workspace-trust-gate": Control(
        "kimi", (),
        "the per-run `$KIMI_CODE_HOME` links only `kimi_home._CREDENTIAL_ITEMS`, "
        "so it holds no `workspace-trust` record and the CLI never reads the "
        "target's project MCP files"),
    "kimi:skills-dir": Control(
        "kimi", ("--skills-dir=",),
        "`--skills-dir=<run-owned empty dir>` replaces BOTH auto-discovered "
        "skill roots, the operator's and the target's"),
}


def control_is_on(control, argv):
    """Does this launch's argv carry the control's token(s)?

    The matcher the liveness test uses, defined beside the table rather than
    in the test, so "what counts as carrying this control" has one spelling:
    an exact token, or -- for a token written with a trailing `=` -- an argv
    entry starting with it, which is the equals form kimi's 0.42.0 parser
    requires. A control with no `argv` at all is not a flag and answers False:
    its `mechanism` is what a test must assert.
    """
    row = CONTROLS.get(control)
    if not row or not row.argv:
        return False
    return all(any(a == token or (token.endswith("=") and a.startswith(token))
                   for a in argv)
               for token in row.argv)


def _already_shadow_reported(row, review_root, path):
    """§5.3: `probe_shadow_shells` has already refused on this file.

    Only inside the host's OWN `project_scope_dirs`, and only for the two
    shapes that scan reports: the `panopticon-` filename prefix and a declared
    shell name. Registry-driven, so no cell id appears here -- CL-5, KM-2 and
    CX-6 are simply the rows whose patterns reach those directories.

    A symlink is never opened for the second check (R3); the cheap name check
    still applies to it, which is the same order `probe_shadow_shells` uses.
    """
    directory, name = os.path.split(path)
    inside = any(os.path.abspath(directory) == os.path.abspath(
        os.path.join(review_root, relative)) for relative in row.project_scope_dirs)
    if not inside:
        return False
    if name.lower().startswith(_SHELL_PREFIX):
        return True
    try:
        if stat.S_ISLNK(os.lstat(path).st_mode):
            return False
    except OSError:
        return False
    return _declares_a_shell_name(path)


_OPEN_HIT = "the reviewed tree ships %s (%s: no launch control closes it)"
_CONTROLLED_HIT = "target ships %s; closed by %s (%s)"
# §6: the CONTROLLED disclosure on the run's stderr, one line per CELL rather
# than per file -- this shares the operator's stderr with the run's own
# progress output, and a target with a hundred planted commands must not
# crowd out the thing they are watching (the rule `kimi_toml.MCP_DISCLOSURE`
# is written under). The artifact's `detail` keeps the per-file sentences.
SURFACE_DISCLOSURE = "driver: target ships %s; closed by %s (%s)"


def probe_discovery_surface(host, review_root, disclose=None):
    """What the REVIEWED tree ships that this host's CLI would DISCOVER.

    The shadow-shell scan's generalisation (spec §7.3 / D8 covers one class of
    file, `panopticon-*` agent shells; this covers the whole surface the #1657
    spike mapped and #1717 narrowed). Same shape, same reasoning, same tree:
    `review_root` is `runio.resolve_review_root`'s answer -- the PR WORKTREE
    under `--pr` -- and never `args.target`, the one checkout guaranteed clean.

    Registry-driven: every path comes from `HostSpec.discovery_surface`, so a
    host with an empty tuple is a no-op and this module holds no host
    knowledge. A hit on an OPEN row REFUTES `tool_policy_enforced`: a target
    that can put text into the reviewer's system prompt, or start a process
    beside it, controls the reviewer's policy as surely as one that replaces
    its shell. A hit on a CONTROLLED row is DISCLOSED and changes nothing --
    the launch already closed that channel, and saying what was there is how
    an operator learns the control earned its keep.

    Can only REFUTE, for the shadow scan's reason: finding nothing says
    nothing about whether the host enforces anything. Not being able to LOOK
    -- an unreadable directory, or a tree so deep or so wide that a cap
    stopped the walk -- refutes too, because UNKNOWN loses to PROVEN in
    `hosts.resolve_state` and the miss would be invisible.

    `disclose` is the run's stderr (§6); given, the CONTROLLED hits are
    written to it once per run, the same channel and the same discipline as
    `kimi_toml.MCP_DISCLOSURE`. Nothing is written for a clean tree.
    """
    row = hosts.spec(host)
    if not row or not row.discovery_surface:
        return (hosts.UNKNOWN, DISCOVERY_SURFACE,
                "host %r discovers no target-authored configuration" % host)
    open_hits, controlled, problems, seen = [], [], [], set()
    patterns = 0
    for entry in row.discovery_surface:
        found = []
        for pattern in entry.pattern:
            patterns += 1
            walk = surface.Walk(pattern)
            for path in surface.candidates(review_root,
                                           pattern.split("/"), walk):
                identity = surface.hit_identity(path)
                if identity is None or identity in seen:
                    continue
                if (entry.kind == hosts.OPEN
                        and _already_shadow_reported(row, review_root, path)):
                    continue           # the shadow scan already refused on it
                seen.add(identity)
                found.append(os.path.relpath(path, review_root))
            problems.extend(walk.unreadable)
            if walk.capped:
                problems.append("%s was not scanned past the cap (%s)"
                                % (pattern, walk.capped))
        if not found:
            continue
        if entry.kind == hosts.OPEN:
            open_hits.extend(_OPEN_HIT % (hit, entry.cell) for hit in found)
        else:
            controlled.extend(_CONTROLLED_HIT % (hit, entry.control, entry.cell)
                              for hit in found)
            if disclose is not None:
                print(SURFACE_DISCLOSURE % (", ".join(found), entry.control,
                                            entry.cell),
                      file=disclose, flush=True)
    if open_hits or problems:
        # OPEN hits first: they are what an operator has to act on. Then what
        # could not be scanned, then the disclosure.
        return (hosts.REFUTED, DISCOVERY_SURFACE,
                "; ".join(open_hits + problems + controlled))
    if controlled:
        return (hosts.UNKNOWN, DISCOVERY_SURFACE, "; ".join(controlled))
    return (hosts.UNKNOWN, DISCOVERY_SURFACE,
            "no target-authored discovery files in %d patterns" % patterns)
