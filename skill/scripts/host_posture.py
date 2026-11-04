"""Host capability posture assessment and disclosure for the driver (#3402)."""
import os
import sys

from scripts import hosts
import scripts.host_disclosure as host_disclosure
import scripts.host_probes as host_probes
import scripts.probes.common as probes_common
import scripts.run_manifest as run_manifest
import scripts.phases.persist as persist
import scripts.phases.runio as runio


def _emit_posture_disclosure(envelope, since=None):
    """5.1 surface 1: stderr, before anything dispatches.

    Same channel and register as phases/tools.py's "driver: tool scan CRASHED
    (rc=...)" -- `driver: ` prefixed lines on stderr. `host_disclosure`
    composes the sentence; this picks the channel and writes it, once per
    call, and nothing else -- see host_disclosure.py's module docstring on
    why no caller is allowed to write its own wording. A named function
    (rather than the write inlined at the call site) so a cross-surface
    consistency test can call it directly with a hand-built envelope, without
    also having to fake a whole `_establish_host_posture` invocation.

    `since` (#1596) is the stamp at which this exact disclosure was already
    printed in full; passing it collapses the block to ONE line. The default
    is the full block, so the surface a caller gets by asking for nothing is
    the whole disclosure.

    `envelope` is a `run_probes()`-shaped dict; `host_disclosure.headline`/
    `lines` already degrade an unreadable envelope to NO_EVIDENCE / no lines
    rather than raising, so this function does not re-validate it.
    """
    sys.stderr.write("driver: host capabilities: %s\n"
                     % (host_disclosure.unchanged_headline(envelope, since) if since
                        else host_disclosure.headline(envelope)))
    for line in () if since else host_disclosure.lines(envelope) + host_disclosure.notes(envelope):
        sys.stderr.write("driver:   %s\n" % line)


def _disclose_posture(review_root, manifest, fresh, namespace=None):
    """Surface 1, in full once per posture and as a headline thereafter (#1596).

    `driver run` is a resumable loop and this runs on every invocation, so a
    self-scan printed the same 5-line block 100+ times -- roughly 120 KB of
    stderr that is byte-identical BY CONSTRUCTION, since F3a refuses the run
    outright if the posture moves. Full block when the posture has not been
    disclosed yet, or when what it SAYS has changed since it was (the digest
    covers the detail and the operational notes too, not just the states);
    one headline otherwise.

    Decided from the RUN MANIFEST's stamp, never from `host-capabilities.json`.
    That file lives on a `.panopticon` path a hostile target can pre-commit,
    so a target able to guess its own posture could suppress the first
    disclosure; the manifest is the one artifact first contact proves this
    machine wrote for this tree (its stamp, #3271).

    The stamp is only recorded when a manifest already exists on disk. Every
    production caller has one -- `driver.run` writes it before this runs --
    and MINTING one here would be worse than not recording: `runio._pano`
    resolves the per-run folder off the manifest, so creating one mid-flow
    would move `host-capabilities.json` out from under this very function.

    Setup stamps its own `setup-manifest.json` through the same namespace
    resolver. A prior review run's manifest and capability evidence remain
    associated with that review run.
    """
    digest = host_disclosure.disclosure_digest(fresh)
    since = run_manifest.posture_disclosed_at(manifest, digest)
    _emit_posture_disclosure(fresh, since=since)
    if (since is None
            and os.path.isfile(run_manifest.manifest_path(review_root, namespace))):
        try:
            run_manifest.record_posture_disclosure(review_root, manifest, digest,
                                                   fresh.get("probed_at"), namespace=namespace)
        except OSError as exc:
            # The stamp is EXPENDABLE, and a stamp that cannot be written must
            # not be the thing that kills an invocation. Losing it costs one
            # repeated block next time; raising costs the whole call -- and on
            # the shadow-refusal path below this is the only write in this
            # function (the artifact write is past the refusal), so an
            # unwrapped OSError turned a clean "refusing to run" status into a
            # traceback with no JSON behind it. Said on stderr rather than
            # swallowed: a run directory that has stopped accepting writes is
            # something the operator wants to know before synthesis tries.
            sys.stderr.write(
                "driver: could not record the posture disclosure stamp (%s: %s)"
                " -- the full block will print again next invocation\n"
                % (type(exc).__name__, exc))
        except ValueError as exc:
            # #1735: NOT the expendable case above. A ValueError here is the
            # whole-path confinement refusing a planted component -- the tree is
            # hostile, so the run must stop rather than shrug and continue. It
            # stops the way this verb stops: as its own error STATUS. Returned
            # rather than raised for exactly the reason the OSError comment
            # gives -- `driver run` speaks a status protocol, and a traceback is
            # not a status. The raise stays inside `_rewrite`, where fail-closed
            # and loud belongs; this is only where it becomes a sentence.
            return ("refusing to record the posture disclosure stamp: %s" % exc)


def _establish_host_posture(review_root, manifest, args, *, registration_dir=None,
                            namespace=None):
    """Assess this host now; write the evidence, or refuse if it moved.

    Spec 5.2. Runs on EVERY invocation, not once per run. #3272 caches each
    host/CLI measurement by external-app identity and its settings under
    operator state; target-tree surface scans still run here every time.

    First invocation writes `runs/<tag>/host-capabilities.json`; later calls
    reuse or refresh the keyed assessment, then COMPARE. Any difference refuses
    the run in both directions: a posture that degraded is alarming, and one that improved
    still leaves the entries already dispatched under the weaker posture, so
    the honest answer to both is a fresh run.

    `namespace` is the artifact namespace this invocation belongs to (#1616
    item 3): None for a review run, `"setup"` for `driver loop --setup`, which
    is the one caller that is not a run. `host-capabilities.json` resolves
    per-RUN, so on a repo that already holds a review run-manifest the flat
    `driver loop --setup` would otherwise probe and then overwrite THAT run's
    evidence -- the hazard `phases/persist.run_dir` exists to resolve, and the
    one `test_setup_never_writes_into_a_stale_review_runs_folder` already pins
    for setup's other artifacts.

    That artifact FEEDS A GATE (#1737). It used to be a record and nothing
    more, which is why both setup entrypoints could afford to differ about
    whether they ran this step at all; now `loop_batch.expected_enforced(...,
    namespace="setup")` reads it to decide whether the setup-scan dispatch
    gets its registered shell, and `phases/setup_ack.require_unenforced_scan_ack`
    reads it to decide whether the shell-less fallback needs the operator's
    acknowledgement. So EVERY caller of `run_setup_flow` passes this step --
    `driver setup` as much as `driver loop --setup`. A caller that skipped it
    would hand the gate a `.panopticon/host-capabilities.json` nothing in this
    invocation measured: absent on a fresh target (refusing the bootstrap with
    a remedy that cannot change the answer), or planted by the target and
    believed. Writing it here, before any phase runs, is what makes the
    evidence this invocation's own.

    `registration_dir` (#1609) is a TEST SEAM: None -- the default, and what
    every production caller passes -- keeps the registration probes reading the
    real registry row, which is what production must do. F4 pinned every direct
    `run_probes("claude", ...)` call in tests to a temp dir and could not pin
    the ones that come through here, because this argument did not exist.

    `args` is accepted and deliberately READ FOR NOTHING TREE-SHAPED. It is
    kept as a test seam: `args.target` is the operator's own checkout, which
    under `--pr` is emphatically not the tree being reviewed, and passing it
    to the shadow scan is C1. The regression test hands this function a
    `target` that DIFFERS from `review_root` and requires the refusal to fire
    off `review_root`, which is only a test that can fail while the parameter
    is still here to get wrong.

    Also prints the `--host generic` fallback notice (owner ruling D1, spec
    8.3 option 1) when the resolved host is the unenforced fallback -- this
    is the one place the manifest's host is resolved before any phase
    dispatches, so it is the only call site that can print it once per
    invocation regardless of entrypoint or resume state.

    Returns an error message when the run must stop, else None.
    """
    host = manifest.get("host", "claude")
    # #1624: refuse a run whose manifest names a host the registry still knows but the driver may no
    # longer pick -- BEFORE the fallback notice and before any probe, because nothing about this run
    # may proceed. On a resume the manifest is authoritative (`--host` is omitted; a contradicting
    # one is refused as flag drift), so the parser's `choices`/`type=` -- this file's only other
    # read of the selectable set -- never sees the name, and a run started under a row that has
    # since lost `driver_selectable` (gemini, #1621) probed to all-unknown and went on emitting
    # dispatch entries for a host `--host` refuses to name. `driver loop` has refused it since
    # #1621; this is the same refusal, in the same words, on the primitive the loop is built out of.
    #
    # Read off the registry, never a host-name literal, so a family PR that
    # flips its own row needs no edit here (`tests/test_host_posture_wiring.py`
    # bans the literal form under `phases/`; this file follows the same rule).
    # A host the registry has NEVER heard of is a different failure with a
    # different remedy and is deliberately not handled here.
    if host in hosts.known_hosts() and host not in hosts.driver_hosts():
        return hosts.unselectable_host_message(host, "run")
    if hosts.is_unenforced_fallback(host):
        # D1: printed from the RESOLVED host, not from argv, so a resumed run
        # (--host absent, the manifest authoritative) prints it too. Every
        # invocation reaches here before any phase dispatches (spec 10: a
        # notice, not a gate -- nothing about the run below this line changes).
        print(host_disclosure.GENERIC_FALLBACK_NOTICE, file=sys.stderr)
    # THREE trees, three arguments -- see run_probes' docstring. `review_root`
    # is the REVIEWED tree (the --pr worktree, or the git toplevel), which is
    # what the shadow scan must read; `args.target` is the operator's own
    # checkout and scanning it left a hostile PR's planted shell unread (C1).
    # The session root comes from runio.session_dir, the single expression
    # synthesize._collect_host_usage also reads, so the probe that GATES the
    # token ledger and the collector that BUILDS it cannot drift apart (C2).
    # session_dir is read off the MANIFEST rather than args because driver.run()
    # assigns it there (in memory, after write_manifest) -- but it is NOT
    # persisted, so a resume without the flag legitimately falls back to cwd.
    # `_posture_drift` names --session-dir when that is what moved.
    session_root = runio.session_dir(manifest)
    # Probed directly, and ONCE (Minor 4): _surface_refusal may not read the
    # verdict back off the artifact's `by` field (see its docstring), and
    # running the scan a second time inside run_probes was both duplicate work
    # and a window in which the artifact and the refusal could disagree about
    # the same tree.
    shadow = probes_common.probe_shadow_shells(host, review_root)
    # The same arrangement for #1657 step 3's generalisation of that scan, and
    # the same argument twice over: it also DISCLOSES its CONTROLLED hits on
    # stderr, and a second call would print them twice. `sys.stderr` is the
    # run's disclosure channel here exactly as it is for
    # `kimi_toml.MCP_DISCLOSURE`, and this runs once per invocation.
    surface = probes_common.probe_discovery_surface(host, review_root,
                                                    disclose=sys.stderr)
    # Plan 6 (spec 5.4): in headless mode the guards are armed into the run
    # folder's host-settings.json, never the session root -- so that file,
    # not the session's, is what the guard probes must prove. `mode` is a
    # `driver loop` flag; `driver run` has none and probes the session root.
    #
    # #1616 item 10: WITH the namespace. Without it this resolves through
    # whatever run-manifest.json is on the review root, so `driver loop
    # --setup` on a repo that already holds a review run's manifest measured
    # `runs/<tag>/host-settings.json` while `orchestrate.Guards` armed the flat
    # `.panopticon/host-settings.json`. Both are writable directories, so the
    # VERDICT was unaffected -- but the evidence's detail names the path ("the
    # runner will arm at %s"), F3b renders it on three disclosure surfaces, and
    # it named a file this invocation never touches.
    settings_path = (probes_common.headless_settings_path(review_root, namespace)
                     if getattr(args, "mode", None) == "headless" else None)
    # N2: the live runner's scratch home, when the loop has one. `driver run`
    # on its own never does, and neither does the first invocation of a loop
    # (posture is established before `prepare`), so a probe that measures this
    # run's children legitimately falls back until a child has run.
    fresh = host_probes.run_probes(host, review_root, session_root=session_root,
                                   registration_dir=registration_dir,
                                   shadow=shadow, surface=surface,
                                   settings_path=settings_path,
                                   run_home=getattr(args, "run_home", None))
    # 5.1 surface 1. Emitted here -- after `fresh` is computed, before the artifact is written or
    # compared, and before the shadow refusal below -- rather than at the dispatch sites, because
    # 5.2 already puts this step before `coverage` dispatches the scout (so it runs before anything
    # dispatches, satisfying the "at the first dispatch" half of spec 5.1), and because emitting
    # once per INVOCATION here (not once per dispatched cell) is what "once per run" rules out. A
    # resumed invocation re-announces deliberately: the operator resuming needs the posture they are
    # resuming under -- as a HEADLINE once it has already had the whole thing for this posture
    # (#1596). Emitted even when the shadow refusal below is about to stop the run, so the operator
    # sees the posture the refusal is about.
    # #1732: the artifact is READ before the disclosure now, because the
    # disclosure block says this run's output-schema shape and the shape is
    # recorded by the LOOP (under the armed guards), not here. Carrying it
    # into `fresh` is what makes it survive a re-probe -- see
    # `_carry_output_schema_shape`.
    path = os.path.join(persist.run_dir(review_root, namespace), runio.HOST_CAPABILITIES)
    stored = runio._load_json(path)
    _carry_output_schema_shape(fresh, manifest)
    disclosure_refusal = _disclose_posture(review_root, manifest, fresh, namespace)
    if disclosure_refusal:                         # #1735: a planted staging path
        return disclosure_refusal
    # I6 / spec 5.2: evaluated on EVERY invocation, not only the first. When
    # tool_policy_enforced is already REFUTED for an unrelated reason -- no
    # registration directory, i.e. every machine that has not run `driver
    # setup` -- a shadow file planted mid-run gives refuted -> refuted, no
    # mismatch, and a refusal evaluated only under `stored is None` would never
    # look at it again.
    refusal = _surface_refusal((shadow, surface), manifest)
    if refusal:
        return refusal
    # A namespace that is not a run is RECORDED, never compared (fix round 1,
    # F2). Everything the drift refusal says is about one run -- "entries
    # already dispatched were built under the previous posture", and the remedy
    # it names is `--reset`, which starts a fresh one. `driver loop --setup` is
    # not a run: its single `setup-scan` entry is dispatched and consumed inside
    # the invocation, while the flat host-capabilities.json outlives every one
    # of them. Comparing across invocations would therefore refuse the verb for
    # a difference that is not drift -- and the bootstrap sequence itself makes
    # one, since `tool_policy_enforced` is REFUTED before the operator emits the
    # host agents and PROVEN after, and it gates. The record is still written
    # every time, so the disclosure is this invocation's own.
    if stored is None or namespace is not None:
        runio._write_json(path, fresh)
        return None
    was, now = host_probes.capabilities_of(stored), host_probes.capabilities_of(fresh)
    gating_was, gating_now = _gating_states(was), _gating_states(now)
    if gating_was != gating_now:
        return _posture_drift(gating_was, gating_now, manifest)
    # The GATING states agree, so the run continues. An operational
    # capability may still have moved (#1626 I1) and the write below records
    # it -- state and reason both -- which is exactly the point: disclosure
    # stays current, the run does not stop. The REASON may also have moved -- a capability refuted for "no shell at X" on
    # invocation 1 and for "grants forbidden tool Bash" on invocation 5 is
    # refuted both times. F3b renders `detail` on three surfaces, so a stale
    # reason is now a wrong disclosure rather than a cosmetic one. Refresh the
    # record; do NOT refuse, because the operator can do nothing about a reason
    # that changed underneath an unchanged verdict.
    #
    # Gated on the CAPABILITIES map, not the whole artifact: `fresh["probed_at"]` is stamped fresh
    # on every call (run_manifest._now_iso(), second resolution), so comparing whole dicts
    # degenerates to "always write" on essentially every real invocation -- rewriting, on every turn
    # of a resumable loop, the very artifact the mid-run refusal above reads, which widens rather
    # than shrinks the window in which a killed process could leave it truncated. `was`/`now` above
    # are STATE-only and already equal by construction here, so gating on those instead would mean
    # `detail` never refreshes -- defeating this whole fix. `capabilities` carries the
    # per-capability state/by/detail triples and excludes probed_at/ schema_version/host, which is
    # exactly the "did anything an operator cares about change" question.
    #
    # `cli_flags` is on the REWRITE trigger and deliberately NOT on the drift
    # comparison above (D10 S1). The two ask different questions: drift asks
    # "may this run continue", and a CLI upgraded between two turns of a
    # resumable loop must never refuse a resume over a flag that gates
    # nothing; the rewrite asks "is the record still true", and a fact that
    # moved and was not written back is a stale fact the NEXT dispatch reads.
    # That was F1's failure class exactly: invocation 2 measured
    # `advertised: false`, disclosed it on stderr, and then
    # `requests._materialize_prompts` stamped `output_schema` off the stored
    # `true` -- putting the flag on the argv of a CLI just measured not to take
    # it, which exits non-zero and takes every entry's launch budget with it.
    if (stored.get("capabilities") != fresh.get("capabilities")
            or stored.get(hosts.CLI_FLAGS) != fresh.get(hosts.CLI_FLAGS)):
        # Write the FULL fresh payload (not just the capabilities key) so
        # `probed_at` on disk stays honest about when the record was last
        # actually written.
        runio._write_json(path, fresh)
    return None


def _carry_output_schema_shape(fresh, manifest):
    """Keep this run's recorded output-schema SHAPE across a re-probe (#1732).

    The shape is measured once per run by `loop_batch.prove_output_schema_shape`,
    inside the loop, after `Guards.arm` -- not here. This step runs before
    anything is armed and before the run folder holds a settings file, so a
    launch from here would be one unconfined turn in the reviewed tree per
    run, naming a file that does not exist yet.

    What this step owes the verdict is SURVIVAL. `fresh` is a new probe result
    on every invocation, and the artifact is rewritten whenever `cli_flags`
    differ from what is stored -- so a `fresh` that simply omitted the
    recorded shape would erase it on the next turn of a resumable loop, and
    the turn after that would spend another launch re-measuring it. The
    `--help` half (`flag`, `advertised`, `detail`) is this invocation's own
    and is left exactly as the probe found it; only the launch's verdict is
    carried -- off the run's stamp (#3280 S4), never the stored file, whose
    shape a replaced artifact could set.
    """
    fact = (fresh.get(hosts.CLI_FLAGS) or {}).get(hosts.OUTPUT_SCHEMA)
    prior = run_manifest.artifact_stamp(manifest, run_manifest.OUTPUT_SCHEMA_SHAPE)
    if not isinstance(fact, dict) or not isinstance(prior, dict):
        return
    if prior.get(hosts.SHAPE):
        fact[hosts.SHAPE] = prior[hosts.SHAPE]
        fact[hosts.SHAPE_DETAIL] = prior.get(hosts.SHAPE_DETAIL)


def _gating_states(states):
    """`states` minus the capabilities that are operational rather than
    security (#1626 I1, `hosts.OPERATIONAL_CAPABILITIES`).

    `_posture_drift` halts a run in flight, and the remedy it names discards
    everything already dispatched. That is the right answer when the thing
    that moved is enforcement -- the report would otherwise disagree with
    itself about what was confined -- and the wrong answer for `usage_ledger`
    and `model_binding`, which gate nothing.

    `usage_ledger` is the case that made this structural rather than
    theoretical. It is the only probe whose subject the run itself PRODUCES:
    `probe_usage_source` reads back `runs/<tag>/dispatch-ledger.jsonl`, which
    the loop appends to after every batch. Two failures followed. A `claude
    --help` that does not answer inside CLI_HELP_TIMEOUT under a full
    concurrency pool reads UNKNOWN for one invocation and aborted the loop.
    And a CLI release whose envelope stops carrying `usage` completes batch 1,
    refutes from invocation 2 on, and refuses EVERY re-invocation from then
    on -- permanently, since the stored artifact still says proven -- leaving
    `--reset` (throw the paid-for batches away) as the only exit. A token
    counter going quiet must not cost a run.

    Filtered rather than merely tolerated: `_posture_drift`'s message lists
    what moved, and naming a capability that did not cause the refusal next
    to a remedy about capabilities that did is a worse message, not a fuller
    one.
    """
    return {name: state for name, state in states.items()
            if name not in hosts.OPERATIONAL_CAPABILITIES}


def _posture_drift(was, now, manifest):
    """The mid-run posture-change refusal, naming the likeliest remedy first.

    I2: `session_dir` is deliberately NOT a manifest field (driver.run() sets
    it in memory after write_manifest), so a run started with `--session-dir /s`
    and resumed WITHOUT it re-resolves that host's session-root capability
    probes against cwd. Telling that operator to discard the run with
    --reset, while naming neither the flag nor the option of simply passing it
    again, is a worse answer than the mistake. So when a session-derived
    capability moved and this invocation carries no --session-dir, that remedy
    goes first. Otherwise --reset stands: an improved posture still leaves
    entries dispatched under the weaker one.
    """
    moved = ["%s: %s -> %s" % (name, was.get(name), now.get(name))
             for name in sorted(set(was) | set(now))
             if was.get(name) != now.get(name)]
    message = ("host posture changed mid-run (%s). Entries already dispatched "
               "were built under the previous posture, so this run's report "
               "would disagree with itself about what was enforced."
               % "; ".join(moved))
    row = hosts.spec((manifest or {}).get("host", runio._DEFAULTS["host"]))
    session_derived = row.session_root_capabilities if row else ()
    session_moved = sorted(name for name in session_derived
                           if was.get(name) != now.get(name))
    if session_moved and not (manifest or {}).get("session_dir"):
        return ("%s If the earlier invocation ran with --session-dir, pass the "
                "same --session-dir again: %s resolve off the session root, "
                "which defaults to the current directory (%s) when the flag is "
                "absent, and the flag is deliberately not stored in the "
                "manifest. Otherwise start a fresh run with --reset."
                % (message, ", ".join(session_moved), os.getcwd()))
    return "%s Start a fresh run with --reset." % message


# What each preflight probe's refusal MEANS, keyed by the probe's own id (R4).
# One sentence each, beside the other, because the two refusals are one
# decision for the operator -- "the tree you pointed me at supplies part of
# the reviewer" -- reached by two different routes.
_REFUSAL_REASON = {
    probes_common.SHADOW_SHELL_SCAN:
        "A project-scoped agent file takes precedence over the registered "
        "enforcement shell, so this target would be reviewing itself with "
        "reviewers it supplied.",
    probes_common.DISCOVERY_SURFACE:
        "A target-authored file the host would load reaches the reviewer "
        "through a channel no launch control closes.",
}
_REFUSAL_FALLBACK = "The reviewed tree supplies part of the reviewer."
_REFUSAL_REMEDY = ("Remove the file(s), or re-run with --allow-unenforced to "
                   "proceed with enforcement explicitly refuted.")


def _surface_refusal(results, manifest):
    """Spec 7.3 and #1657 step 3: what the TARGET supplies refuses the run.

    `results` are the preflight probes' OWN `(state, by, detail)` tuples --
    the shadow-shell scan's and the discovery-surface scan's -- never the
    artifact's `capabilities[tool_policy_enforced]` row.
    That row's `by` names whichever probe `run_probes` recorded FIRST among
    those that reached the resolved state, so on a host whose
    registered-shell-tools probe ALSO refutes (no registration directory at
    all -- every machine that has not run `driver setup`), `by` would read
    "registered-shell-tools" even though shadow-shell-scan is the one that
    found the hostile file. Keying this refusal off `by` silently dropped the
    shadow finding on exactly the machines a hostile target is most likely to
    be pointed at: an unregistered first run. Deciding from the probe's own
    result is immune to whatever else ties with it -- and with two probes on
    one capability it is now also the only way to say WHICH one refused.

    Any REFUTED refuses, and the message names EVERY probe that refused and
    repeats each one's detail: the two findings differ (an agent file that
    replaces a shell; a file the host would load beside one), and an operator
    told only about the first would delete it, re-run, and be refused again by
    a probe they were never told about. The remedy is one sentence at the end,
    because it is the same flag either way.

    `--allow-unenforced` downgrades rather than silences: the run proceeds with
    tool_policy_enforced REFUTED (resolve_state ranks refuted over proven), so
    the report says plainly it was not enforced. Every REFUTED reason either
    probe can return -- a file was found, or a directory could not be read and
    the tree could not be ruled out -- refuses the same way.
    """
    refuted = [r for r in results if r and r[0] == hosts.REFUTED]
    if not refuted:
        return None
    if (manifest.get("flags") or {}).get("allow_unenforced"):
        return None
    clauses = ["%s: %s. %s" % (by, detail,
                               _REFUSAL_REASON.get(by, _REFUSAL_FALLBACK))
               for _state, by, detail in refuted]
    return "refusing to run: %s %s" % (" ".join(clauses), _REFUSAL_REMEDY)
