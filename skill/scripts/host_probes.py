#!/usr/bin/env python3
"""Establish what a host actually delivers, as opposed to what it claims.

`hosts.py` is the table of claims and stays I/O-free. The probes are where
the filesystem and subprocess live, so this module is imported only by the
driver's pre-phase step and by setup -- never by `phases/*` on the hot path,
and never by `hosts.py` (that import would break the purity guard).

This module is the REGISTRY, not the probes: `PROBE_IDS`, `PROBE_CAPABILITY`,
the id -> runner table `run_probes` walks, and `capabilities_of`. The probes
themselves live in `scripts/probes/` -- `common` for what every host shares,
`claude` / `codex` / `kimi` for what each family proves about itself (#1627,
which split a 1900-line module into four under the package ceiling). They are
reached by module attribute and never re-exported from here: a name lives in
exactly one module, so `mock.patch` has exactly one target to aim at.

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

from scripts import hosts, run_manifest
import scripts.probes.claude as claude_probes
import scripts.probes.codex as codex_probes
import scripts.probes.common as probes_common
import scripts.probes.kimi as kimi_probes


# Every probe id a registry row may map to and get a runner for; the
# shadow-shell scan runs unconditionally and is not a mappable probe. The
# retirement bar (tests/test_generic_retirement_bar.py) reads this as "the
# shipped probes" (spec 8.1), so it must not drift from the runner table:
# run_probes refuses to build a table that disagrees with it.
PROBE_IDS = (probes_common.REGISTERED_SHELL_TOOLS,
            claude_probes.WRITE_GUARD_ARMED, claude_probes.USAGE_SOURCE,
            claude_probes.ENTRY_MODEL_BOUND, claude_probes.READ_GUARD_ARMED,
            codex_probes.CODEX_EFFECTIVE_TOOLS, codex_probes.CODEX_READ_SCOPE,
            kimi_probes.KIMI_SHELL_SURFACE, kimi_probes.KIMI_READ_GUARD,
            kimi_probes.KIMI_WRITE_GUARD, kimi_probes.KIMI_MODEL_ALIAS,
            kimi_probes.KIMI_USAGE_WIRE)

# Which capability each shipped probe MEASURES. The retirement bar reads this
# so a row cannot satisfy spec 8.1 by mapping a security capability to a
# shipped probe that proves something else (READ_SCOPE_CONFINED ->
# "registered-shell-tools" would otherwise pass both the bar and, because
# run_probes is row-driven, the live posture).
PROBE_CAPABILITY = {probes_common.REGISTERED_SHELL_TOOLS: hosts.TOOL_POLICY_ENFORCED,
                    claude_probes.WRITE_GUARD_ARMED: hosts.ARTIFACT_WRITE_GUARD,
                    claude_probes.USAGE_SOURCE: hosts.USAGE_LEDGER,
                    claude_probes.ENTRY_MODEL_BOUND: hosts.MODEL_BINDING,
                    claude_probes.READ_GUARD_ARMED: hosts.READ_SCOPE_CONFINED,
                    codex_probes.CODEX_EFFECTIVE_TOOLS: hosts.TOOL_POLICY_ENFORCED,
                    codex_probes.CODEX_READ_SCOPE: hosts.READ_SCOPE_CONFINED,
                    kimi_probes.KIMI_SHELL_SURFACE: hosts.TOOL_POLICY_ENFORCED,
                    kimi_probes.KIMI_READ_GUARD: hosts.READ_SCOPE_CONFINED,
                    kimi_probes.KIMI_WRITE_GUARD: hosts.ARTIFACT_WRITE_GUARD,
                    kimi_probes.KIMI_MODEL_ALIAS: hosts.MODEL_BINDING,
                    kimi_probes.KIMI_USAGE_WIRE: hosts.USAGE_LEDGER}


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
               home=None, shadow=None, settings_path=None, run_home=None,
               surface=None):
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
    about the same tree. `surface` is the same arrangement for
    `probes.common.probe_discovery_surface` (#1657 step 3), whose result
    `driver._surface_refusal` reads for the same reason and which also
    DISCLOSES on stderr -- so the caller owns the one call and this records
    what it already learned. `home` exists for fixtures.

    `settings_path` (plan 6, spec 5.4) names the file a HEADLESS runner will
    arm; when given, it is the two guard probes' subject INSTEAD of
    `session_root`, and the usage probe's cue to measure the launch envelope
    and run-folder ledger instead of the session's transcripts (spec 5.5).
    `None` (session mode, or plain `driver run`) leaves all three probing the
    session root exactly as before.

    `run_home` is the live runner's scratch directory outside the reviewed
    tree (`HostRunner.run_home`), threaded down from the loop so a probe can
    measure THIS run's children -- the effective tool surface a launch really
    had. It is passed in process, never re-derived from a path recorded inside
    the target (N2). `None` until the loop's `prepare` has run.
    """
    findings = {}          # capability -> list of (state, by, detail)
    # D10 F1/N1: operational CLI facts, measured by `probes.common` and
    # written BESIDE `capabilities` (see hosts.CLI_FLAGS): inside it, a CLI
    # upgraded between two turns of a resumable loop would read as posture
    # drift and discard everything already dispatched. Filled below, after the
    # capability probes, and only on a headless run.
    cli_flags = {}
    session_root = session_root or os.getcwd()

    def record(capability, result):
        findings.setdefault(capability, []).append(result)

    row = hosts.spec(host)
    # The registry's capability -> probe-id mapping DRIVES this, rather than
    # being consulted for membership while the capability is hard-coded here.
    # A row that maps a probe to a different capability must record it there;
    # otherwise `HostSpec.probes` is decorative and a mis-mapped row fails
    # silently -- the defect this epic exists to remove.
    codex_measurement = []

    def codex_measure():
        if not codex_measurement:
            codex_measurement.append(codex_probes._codex_surfaces(registration_dir))
        return codex_measurement[0]

    runners = {
        probes_common.REGISTERED_SHELL_TOOLS:
            lambda: probes_common.probe_registered_shell_tools(host, registration_dir),
        claude_probes.WRITE_GUARD_ARMED:
            lambda: claude_probes.probe_write_guard_armed(
                host, session_root=session_root, settings_path=settings_path),
        claude_probes.USAGE_SOURCE:
            lambda: claude_probes.probe_usage_source(
                host, session_root, home=home, settings_path=settings_path),
        claude_probes.ENTRY_MODEL_BOUND:
            lambda: claude_probes.probe_entry_model_bound(host, registration_dir),
        claude_probes.READ_GUARD_ARMED:
            lambda: claude_probes.probe_read_guard_armed(
                host, session_root=session_root, settings_path=settings_path),
        codex_probes.CODEX_EFFECTIVE_TOOLS:
            lambda: codex_probes.probe_codex_tool_policy(
                host, registration_dir, settings_path, codex_measure),
        codex_probes.CODEX_READ_SCOPE:
            lambda: codex_probes.probe_codex_read_scope(
                host, registration_dir, settings_path, codex_measure),
        kimi_probes.KIMI_SHELL_SURFACE:
            # `run_home` is the live runner's scratch home, handed down by the
            # loop (N2) -- never a path read out of the reviewed tree. None
            # before the first `prepare`, in session mode and under plain
            # `driver run`, where I5 falls back to the version table and says
            # so in its detail.
            lambda: kimi_probes.probe_kimi_shell_surface(
                host, registration_dir, run_home=run_home),
        kimi_probes.KIMI_READ_GUARD:
            lambda: kimi_probes.probe_kimi_read_guard(host),
        kimi_probes.KIMI_WRITE_GUARD:
            lambda: kimi_probes.probe_kimi_write_guard(host),
        kimi_probes.KIMI_MODEL_ALIAS:
            lambda: kimi_probes.probe_kimi_model_alias(host),
        kimi_probes.KIMI_USAGE_WIRE:
            lambda: kimi_probes.probe_kimi_usage_wire(host),
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
           else probes_common.probe_shadow_shells(host, review_root))
    # Its generalisation (#1657 step 3), on the SAME capability and for the
    # same reason: a target that gets text into the reviewer's system prompt,
    # or a process started beside it, controls the reviewer's tool policy as
    # surely as one that replaces its shell. Run for every host whose registry
    # row declares a discovery surface -- a row with none has nothing to scan
    # for, and recording its no-op sentence would put a line about a table
    # that does not exist into every `generic` run's disclosure.
    if row and row.discovery_surface:
        record(hosts.TOOL_POLICY_ENFORCED,
               surface if surface is not None
               else probes_common.probe_discovery_surface(host, review_root))
    # Also not in any row's `probes`, and for a stronger reason than the
    # shadow scan's: it measures no capability at all, so there is no
    # capability to map it to and PROBE_CAPABILITY would have to lie. It runs
    # for every host whose row declares an operational CLI fact
    # (`HostSpec.cli_flag_facts`), on a HEADLESS run only -- session mode
    # launches none of our CLIs, so there is nothing to interrogate and
    # nothing to disclose (D10 N1).
    if settings_path is not None:
        cli_flags.update(probes_common.probe_cli_flags(host))

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
            "probed_at": run_manifest._now_iso(), "capabilities": capabilities,
            hosts.CLI_FLAGS: cli_flags}


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
