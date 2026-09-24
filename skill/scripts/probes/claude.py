"""The claude family's probes: what a Claude Code host proves about itself.

Split out of `host_probes.py` (#1627). Four of the five capabilities the
`claude` row claims are measured here -- the `model:` binding on the
registered shells, the two guard round-trips (the real `write_guard_hook` /
`read_guard_hook` protocols, armed and exercised inside a throwaway sandbox),
and the usage ledger. The fifth, `registered-shell-tools`, is host-agnostic
and lives in `common` beside the shadow-shell scan.

What every family shares is reached by module attribute (`common.<name>`), so
each of those names still has exactly one definition and one patch target.
The probe-id -> function registry stays in `host_probes.py`.
"""
import json
import os
import tempfile

from scripts import (collect_usage, dispatch, executable, hosts, model_resolver,
                    read_guard_hook, write_guard_hook)

from . import common, claude_read_guard


ENTRY_MODEL_BOUND = "entry-model-bound"


def _frontmatter_model(path):
    """The `model:` binding inside a registered shell's frontmatter, or None.

    Frontmatter ONLY: the charter body is prose and may contain the word.
    Stops at the closing fence rather than scanning the whole file, which is
    the one way this differs from `common._frontmatter_tools`. That stop is
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

    A REGISTRATION DIRECTORY the probe cannot use is also UNKNOWN, not REFUTED, even
    though `common.probe_registered_shell_tools` refutes on the same
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
    # #1610: the same three cases `common.probe_registered_shell_tools` splits,
    # in the same words. They used to be two, and the first rendered as "no
    # registration directory at None"; the third did not exist at all, so an
    # unreadable directory reported "no role is registered in <dir>" -- the one
    # reading the operator could act on wrongly. The STATE is `unknown` in all
    # three (see above on why an absent directory is not THIS probe's
    # refutation), and `by` stays this probe's id throughout: it ran, it looked
    # at the registry, and what it reports is what it found there.
    if not directory:
        return (hosts.UNKNOWN, ENTRY_MODEL_BOUND,
                "host %r has no registration directory, so nothing registered "
                "binds a model" % host)
    if not os.path.isdir(directory):
        return (hosts.UNKNOWN, ENTRY_MODEL_BOUND,
                "no registration directory at %s: nothing registered binds a model, "
                "and nothing here proves the host honours the entry's model"
                % directory)
    if not os.access(directory, os.R_OK):
        return (hosts.UNKNOWN, ENTRY_MODEL_BOUND,
                "cannot read %s, so nothing could be checked" % directory)
    faults, matched, absent, unbound = [], [], [], []
    for role, role_file in sorted(dispatch.ROLE_FILES.items()):
        path = os.path.join(directory,
                            dispatch.registered_agent_filename(host, role_file))
        if not os.path.isfile(path):
            absent.append(role)
            continue
        resolved = model_resolver.resolve_model(host, role).get("model")
        bound = _frontmatter_model(path)
        if bound is None and resolved is None:
            # #1737: the two AGREE. None is the explicit "inherit the session's
            # model" policy (R-F4-2, `setup_scan`) and a shell that binds
            # nothing is how a claude agent file states it -- nothing silently
            # wins, because the entry asks for nothing either. Named in the
            # detail, not hidden in the count.
            unbound.append(role)
        elif bound is None:
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
        # #1737: the unbound roles are deliberately NOT counted here. A registry
        # holding only those proves nothing -- no entry in it asks for a model
        # -- and a vacuous PROVEN is the fail-open this probe removes.
        return (hosts.UNKNOWN, ENTRY_MODEL_BOUND,
                "no role is registered in %s that binds a model, so nothing "
                "here proves the host honours the entry's" % directory)
    detail = ("%d/%d roles registered in %s bind the model dispatch resolves"
              % (len(matched), len(dispatch.ROLE_FILES), directory))
    if unbound:
        detail += ("; deliberately unbound, shell and entry both inherit the "
                   "session's model: %s" % ", ".join(unbound))
    if absent:
        detail += ("; unregistered, model bound on the entry itself: %s"
                   % ", ".join(absent))
    return (hosts.PROVEN, ENTRY_MODEL_BOUND, detail)


WRITE_GUARD_ARMED = "write-guard-armed"


def _headless_subject_dir(settings_path):
    """(writable, probe_dir): the run folder the headless loop writes into.

    `settings_path` is created by the ARMING (`orchestrate.Guards.arm`, per
    batch, through the two hooks' own installers), not by this probe and not
    by the runner's `prepare` -- so the question here is only whether its
    directory exists or can be created, and is writable, answered off the
    nearest existing ancestor. Shared by the two guard probes and the usage
    probe, which word the failure differently."""
    settings_dir = os.path.dirname(os.path.abspath(settings_path)) or "."
    probe_dir = settings_dir
    while not os.path.isdir(probe_dir):
        parent = os.path.dirname(probe_dir)
        if parent == probe_dir:
            break
        probe_dir = parent
    return os.access(probe_dir, os.W_OK), probe_dir


def _headless_subject_ok(settings_path):
    """(ok, detail) for the guard probes, off `_headless_subject_dir`."""
    writable, probe_dir = _headless_subject_dir(settings_path)
    if not writable:
        return False, "the runner cannot arm its guards: %s is not writable" % probe_dir
    return True, ""


def _write_row(allowlist_path, path, entry_id):
    """One Write payload through the real `adjudicate`, bound as `entry_id`
    (None = the orchestrator, which nothing binds)."""
    env = {write_guard_hook.ENV_ENTRY_ID: entry_id} if entry_id else {}
    allowed, _why = write_guard_hook.adjudicate(
        {"tool_name": "Write", "tool_input": {"file_path": path}},
        allowlist_path, env=env)
    return allowed


def _round_trip_denies_an_outside_write():
    """Arm the guard in a throwaway sandbox and confirm it actually denies.

    Never touches the session's real settings or allowlist: install/uninstall
    run entirely against paths inside a TemporaryDirectory. Returns
    (ok, detail).

    #1571: the plan has TWO entries and the rows are driven through
    `adjudicate` (the function the hook itself calls), because the capability
    being claimed is "confine a reviewer's Write to the declared out_file" --
    singular -- and a one-entry flat-membership round-trip cannot tell that
    apart from "confine it to the batch". The armed file is read and required
    to be version 2, and a version-1 flat list dropped in its place must be
    REFUSED: proving a guard that still honours one would prove the batch-wide
    grant this issue is about.
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
            peer = os.path.join(sandbox, "findings-peer.json")
            for path in (declared, peer):
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("{}")
            write_guard_hook.install([{"id": "probe-cell", "out_file": declared},
                                      {"id": "peer-cell", "out_file": peer}],
                                     settings_path=settings,
                                     allowlist_path=allowlist)
            state = write_guard_hook.guard_state(settings_path=settings,
                                                 allowlist_path=allowlist)
            if not state["armed"]:
                return False, "install() did not register the PreToolUse hook"
            with open(allowlist, encoding="utf-8") as fh:
                document = json.load(fh)
            if (not isinstance(document, dict)
                    or document.get("version") != write_guard_hook.ALLOWLIST_VERSION
                    or not isinstance(document.get("entries"), dict)):
                return False, ("the armed allowlist is not a version-%d document "
                               "(per-entry grants), so nothing records whose grant "
                               "a path is"
                               % write_guard_hook.ALLOWLIST_VERSION)
            rows = (
                ("Write to its own declared out_file", declared, "probe-cell", True),
                ("Write to a PEER entry's declared out_file", peer, "probe-cell", False),
                ("Write outside the allowlist",
                 os.path.join(sandbox, "not-declared.json"), "probe-cell", False),
                ("Write bound to an entry the allowlist does not name",
                 declared, "ghost-cell", False),
                ("the orchestrator's own write", declared, None, True),
            )
            for name, path, entry_id, want in rows:
                if _write_row(allowlist, path, entry_id) != want:
                    return False, ("the guard %s: %s"
                                   % ("DENIED" if want else "ALLOWED", name))
            with open(allowlist, "w", encoding="utf-8") as fh:
                json.dump(sorted(document["paths"]), fh)
            if _write_row(allowlist, declared, "probe-cell"):
                return False, ("the guard ALLOWED a write against a version-1 flat "
                               "allowlist: a stale file must deny, never widen")
            write_guard_hook.uninstall(settings_path=settings,
                                       allowlist_path=allowlist)
    except OSError as exc:
        return False, common.failure_detail(
            exc, "the write-guard sandbox round-trip could not run")
    return True, ("arm/deny round-trip ok: %d payloads adjudicated per entry "
                  "against a version-%d allowlist, and a version-1 flat list "
                  "refused" % (len(rows), write_guard_hook.ALLOWLIST_VERSION))


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

# Keep the historical probe/test call surfaces without re-exporting a sibling.
def _fake_subagent(parent_transcript, agent_id, entry_id, layout="direct"):
    return claude_read_guard._fake_subagent(parent_transcript, agent_id, entry_id, layout)


def _round_trip_confines_reads():
    return claude_read_guard._round_trip_confines_reads()


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
    # M-11: the claim alone stopped being enough the moment a second host
    # claimed read confinement through a different primitive. Everything below
    # measures CLAUDE's read guard -- the settings file it would arm, the
    # hook's round-trip -- so a row that maps this capability to some other
    # probe (codex -> codex-read-scope) would get a refutation about a file it
    # never arms. Unreachable while run_probes dispatches by the row's own
    # probe id; latent until someone calls this directly.
    if (hosts.spec(host).probes if hosts.spec(host) else {}).get(
            hosts.READ_SCOPE_CONFINED) != READ_GUARD_ARMED:
        return (hosts.UNKNOWN, None,
                "host %r does not measure read-scope confinement with %s"
                % (host, READ_GUARD_ARMED))
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


USAGE_SOURCE = "usage-source"


def _ledger_carries_usage(ledger):
    """(verdict, how) from the rows the loop has ALREADY written to `ledger`
    for this run -- the surface this probe names as its evidence, read back
    on every re-probe. None: no ledger yet, or no successful launch in it
    (nothing to measure). False: successful launches, and not one envelope
    carried a usage figure -- the capability, measured and absent. True
    otherwise. A single odd row never refutes; systematic absence does.

    `how` is worded for the REFUTATION. The proven detail must not carry a
    running count: `driver._establish_host_posture` rewrites the evidence
    artifact whenever any capability's detail changes, and a count that
    grows with every batch would make that an "always write" on every turn
    of the loop -- the very hazard its comment says it avoids -- and move
    `probed_at` to the last iteration rather than the run's start."""
    try:
        with open(ledger, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None, "no launch ledgered yet"
    ok_rows = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("ok"):
            ok_rows.append(row)
    if not ok_rows:
        return None, "no successful launch ledgered yet"

    def carried(row):
        usage = row.get("usage")
        return isinstance(usage, dict) and any(
            isinstance(v, (int, float)) and v > 0 for v in usage.values())
    with_usage = sum(1 for r in ok_rows if carried(r))
    if not with_usage:
        return False, ("%d successful launch(es) ledgered at %s and not one envelope "
                       "carried a usage figure: this CLI's envelope reports none"
                       % (len(ok_rows), ledger))
    return True, "%d of %d successful launches ledgered so far carried usage" % (with_usage, len(ok_rows))


def _headless_usage_source(host, settings_path, review_root):
    """The headless half of `probe_usage_source`: can the loop ledger what
    the runner's envelope reports?

    Each measurement can refute. The run folder must be able to hold the
    ledger the loop appends after every launch (`runners.base.LEDGER_FILE`,
    beside `settings_path`). The CLI the host's headless runner launches
    must be on PATH -- no launch, no envelope, no figure -- and must be the
    thing the runner drives: its `--help` runs and advertises the runner's
    own `ENVELOPE_FLAGS`, the tokens that make a launch print the envelope.
    Existence alone was this branch's review objection: any executable
    named `claude` proved the ledger. And once the loop has ledgered
    successful launches, their envelopes are the evidence: if not one of
    them carried usage, the capability is refuted on what was measured, not
    on what a launch might do. Name, flags and launcher are all the runner's
    own (`Runner.CLI`, `Runner.ENVELOPE_FLAGS`, `Runner.runner`), never
    re-spelled here, so a family that renames its binary or a flag moves
    this probe with it -- and the launcher is the seam the suite refuses
    real launches at.

    A claiming host with no usable headless runner is UNKNOWN whatever makes
    it unusable (no module, a module that fails to import, a Runner without
    the three attributes): nothing here can name a CLI to look for, a
    vacuous PROVEN is the fail-open this epic exists to remove, and a probe
    reports rather than raises.

    It measures the ENVELOPE flags and nothing else. D10 F1 also answered the
    optional output-schema flag from this same read; N1 moved that to
    `common.probe_cli_flags`, because hanging an operational fact off this
    probe meant no host that fails to CLAIM a usage ledger could ever be asked
    -- codex being exactly that host, and one of the two whose runner takes
    the flag. The cost is one extra `--help` launch on claude; the fact no
    longer depends on an unrelated claim."""
    import scripts.runners.base as runners_base
    writable, probe_dir = _headless_subject_dir(settings_path)
    ledger = os.path.join(os.path.dirname(os.path.abspath(settings_path)),
                         runners_base.LEDGER_FILE)
    if not writable:
        return (hosts.REFUTED, USAGE_SOURCE,
                "the loop cannot write its dispatch ledger at %s: %s is not writable"
                % (ledger, probe_dir))
    # Three distinct failures, three distinct sentences (#1626 I3). One
    # message covered all of them -- "has no usable headless runner naming a
    # CLI, its envelope flags and a launcher" -- which is wrong for a family
    # that shipped a perfectly good runner and simply left one attribute
    # empty, and sends them looking for a missing module.
    try:
        runner = runners_base.runner_for(host, "headless")
        runner.review_root = os.path.abspath(review_root)
        cli, flags, launch = runner.CLI, tuple(runner.ENVELOPE_FLAGS), runner.runner
        launch_env = runner.launch_env()
    except Exception as exc:          # noqa: BLE001 -- a probe reports, never raises
        return (hosts.UNKNOWN, USAGE_SOURCE,
                "%s. Ship skill/scripts/runners/%s.py exposing a Runner, so "
                "nothing here proves a launch envelope will carry usage"
                % (common.failure_detail(
                    exc, "host %r has no usable headless runner" % host), host))
    if not cli:
        return (hosts.UNKNOWN, USAGE_SOURCE,
                "host %r ships a headless runner that names no CLI (its `CLI` is empty, "
                "the seam's default in runners/base.py): there is no binary to look for "
                "on PATH, so nothing here proves a launch envelope will carry usage" % host)
    if not flags:
        return (hosts.UNKNOWN, USAGE_SOURCE,
                "host %r ships a headless runner naming `%s` but no envelope flags (its "
                "`ENVELOPE_FLAGS` is empty, the seam's default in runners/base.py): "
                "nothing here proves a launch of it prints an envelope to read usage "
                "from, and an empty flag list would otherwise be advertised vacuously"
                % (host, cli))
    try:
        resolved = executable.resolve(cli, runner.review_root,
                                      launch_env.get("PATH", ""))
    except executable.ExecutableResolutionError:
        return (hosts.REFUTED, USAGE_SOURCE,
                "no trusted `%s` on PATH outside review root %s: the headless runner "
                "cannot launch, so no envelope will ever carry usage and the ledger at "
                "%s stays empty"
                % (cli, runner.review_root, ledger))
    found = resolved.path
    launch_env["PATH"] = resolved.path_env
    # Use the runner's OWN env and cwd (#1626 I2). It did not run `prepare`,
    # so run_probes supplies its actual review root before resolution/launch.
    advertised, why = common._cli_advertises(
        launch, found, flags, env=launch_env,
        cwd=runner.review_root)
    if advertised is None:
        return (hosts.UNKNOWN, USAGE_SOURCE, why)
    if not advertised:
        return (hosts.REFUTED, USAGE_SOURCE, why)
    ledgered, how = _ledger_carries_usage(ledger)
    if ledgered is False:
        return (hosts.REFUTED, USAGE_SOURCE, how)
    # One detail for the whole run, before the first launch and after the
    # last: see _ledger_carries_usage on why no count appears here.
    return (hosts.PROVEN, USAGE_SOURCE,
            "headless: usage is read from the JSON envelope of every `%s` launch "
            "(%s; %s) and ledgered at %s, every successful launch ledgered there "
            "carrying its figure; the session's transcripts are not consulted"
            % (cli, found, why, ledger))


def probe_usage_source(host, session_dir, home=None, settings_path=None, review_root=None):
    """Where this host's usage figures come from, and that the source is
    reachable. The probe follows the MODE, exactly as the two guard probes do
    (spec 5.4 applied to spec 5.5): `settings_path` names the file a headless
    runner will arm, and with it the subject is the launch envelope plus the
    run-folder ledger (`_headless_usage_source`); without it -- session mode,
    or plain `driver run` -- the subject is the host's own transcript
    directory for this SESSION, which is what `collect_usage` reads.

    Before the Claude family PR this was `transcript-dir` and knew only the
    session surface, so a headless run launched from any directory without
    transcripts (every fresh target) REFUTED a ledger that was exact.

    Operational rather than security -- 8.1 excludes usage_ledger from F5's
    bar, and it gates nothing directly. But it DOES gate
    `synthesize._collect_host_usage`, so in session mode the directory it
    asks about has to be the one that collector will read.

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
    if settings_path is not None:
        return _headless_usage_source(host, settings_path,
                                      review_root or session_dir)
    root = home or os.path.expanduser("~")
    directory = os.path.join(root, ".claude", "projects",
                             collect_usage.project_slug(session_dir))
    if not os.path.isdir(directory):
        return (hosts.REFUTED, USAGE_SOURCE,
                "no transcript directory at %s; the cost ledger will report "
                "null rather than a figure" % directory)
    if not os.access(directory, os.R_OK):
        return (hosts.REFUTED, USAGE_SOURCE,
                "%s is not readable" % directory)
    return (hosts.PROVEN, USAGE_SOURCE, "session: %s is readable" % directory)
