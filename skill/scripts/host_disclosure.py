"""How the verified posture is SAID -- spec 5.1's four surfaces, one voice.

This module formats; it never reads. `hosts.py` is I/O-free because it is the
registry; this is I/O-free because four callers in three processes render the
same facts and the only way to keep them saying the same thing is to give them
one place to say it from. Four hand-written copies of the wording rule would
drift within a release, and each surface's own test would keep passing while
they did -- which is the failure mode 5.1 exists to prevent, reproduced inside
the fix for it.

5.1's wording rule, verbatim: "name the capability, the host, the probe, and
the remedy. 'unenforced' alone is not a disclosure; it is a mood."
"""
import hashlib

# This repo has two directories named `scripts` with no __init__.py (repo-root
# scripts/ and skill/scripts/). When imported flat (skill/scripts on
# sys.path -- the standalone-script shape), the try arm raises
# ModuleNotFoundError. When `scripts` resolves as a namespace package (pytest
# via conftest.py, or driver.py's own bootstrap), it succeeds and binds the
# SAME module object every other caller sees. A bare `import hosts` would
# still resolve (skill/scripts is on sys.path either way) but as a SECOND,
# non-identical module with its own HOSTS dict -- see model_resolver.py for
# the same fallback on the same seam.
try:
    from scripts import hosts
except ImportError:
    import hosts

# The probe that records the operational CLI facts (D10 F1/N1); named here
# because `_output_schema_line` must say WHICH measurement it is reporting and
# this module may not import the probes package (it is I/O-free by design, and
# imports only the registry).
CLI_FLAGS_PROBE = "cli-flags"

ALL_PROVEN = ("all measured and PROVEN -- "
              "every control this run relies on was verified, not assumed")
NO_EVIDENCE = ("NO EVIDENCE -- nobody looked. Nothing this "
               "run reports about enforcement is verified (spec 5.1)")

# Owner ruling D1 (2026-09-15, spec 8.3 option 1): keep --host generic as the
# permanent ack-gated fallback and retire F5 (its planned deletion). Printed
# once per `driver run` / `driver setup` under --host generic. It is a
# posture notice, not a gate (spec 10): the run proceeds, ack-gated and
# disclosed exactly as before.
#
# Spec D4 first shipped this notice and said it would end "once every
# remaining host clears the retirement bar". That stopped being true at
# #1621: with gemini out of the selectable set, claude is the only host the
# bar examines and it clears it -- so the bar is MET while generic is still
# the only path a Gemini operator has, and the only path for any host whose
# family has not shipped a runner. D1 settles it for good: this row is not
# going away, so the notice says what it is FOR rather than naming a trigger
# that already fired and changed nothing.
GENERIC_FALLBACK_NOTICE = (
    "driver: NOTICE: --host generic claims no capability, so every dispatch "
    "under it is unenforced and ack-gated. It is the permanent path for any "
    "host with no family runner, gemini among them (#1621); it is not going "
    "away (owner ruling D1, spec 8.3 option 1).")

# The remedy is the whole point of the line. A capability nobody can act on
# gets an honest "there is nothing to do yet" rather than an invented command.
_REMEDY = {
    hosts.TOOL_POLICY_ENFORCED:
        "run `python3 skill/scripts/dispatch.py --emit-host-agents %(host)s` "
        "and start a fresh session; if a reviewed tree ships its own "
        "panopticon-* agent files, remove them or re-run with --allow-unenforced",
    hosts.ARTIFACT_WRITE_GUARD:
        "ensure the host session's .claude/settings.local.json exists (pass "
        "--session-dir if the session runs outside the reviewed tree)",
    hosts.USAGE_LEDGER:
        "headless: put the %(host)s CLI on PATH and make the run folder writable "
        "so every launch's envelope can be ledgered; session: pass --session-dir "
        "naming the directory the %(host)s session runs in, so its transcript "
        "can be found",
    hosts.READ_SCOPE_CONFINED:
        "ensure the host session's .claude/settings.local.json exists and its "
        "transcript directory is readable (pass --session-dir if the session runs "
        "outside the reviewed tree): the read guard binds each subagent to its "
        "entry through the subagent's transcript, and arms in that settings file",
    hosts.MODEL_BINDING:
        "re-run `python3 skill/scripts/dispatch.py --emit-host-agents %(host)s` so "
        "every registered shell binds the model in skill/reference/model-profiles.yml, "
        "and unset any PANOPTICON_MODEL_* override -- an enforced dispatch binds the "
        "shell's model, never the override's",
}


# I-4: _REMEDY above is keyed by CAPABILITY, and its texts are Claude's --
# a settings file and a transcript directory. Rendered on a Codex run they
# named artefacts that host does not have, on one of 5.1's four mandatory
# surfaces, every time. A host whose answer differs records it here; anything
# absent falls through to the shared text, so a new host inherits the generic
# remedy rather than a silently wrong one.
_REMEDY_BY_HOST = {
    "codex": {
        hosts.ARTIFACT_WRITE_GUARD:
            "Codex has no write guard; every role is return_json and the loop "
            "writes the artifact -- expected, nothing to do",
        hosts.USAGE_LEDGER:
            "Codex reports tokens but no dollars or model identity; bound the "
            "run with --max-iterations / --entry-timeout",
        hosts.MODEL_BINDING:
            "Codex does not bind the model per entry; the registered shell's "
            "model is advisory -- set PANOPTICON_MODEL_<ROLE> to override",
        # Codex CLAIMS this one, so it is normally proven rather than
        # disclosed -- but when its probe answers unknown the generic text
        # would send the operator to Claude's settings file and transcript,
        # neither of which exists here. The primitive is the scope-bound MCP
        # read broker, and only a headless launch arms it.
        hosts.READ_SCOPE_CONFINED:
            "Codex confines reads through its scope-bound MCP read broker, "
            "which only a headless launch arms: register the shells with "
            "`python3 skill/scripts/dispatch.py --emit-host-agents codex` and "
            "run `driver loop --host codex --mode headless` -- a parent "
            "session can override a child's native permissions, so session "
            "mode cannot prove it",
    },
}


def host_of(envelope):
    """The host the artifact was written for, or None if it is unreadable."""
    if not isinstance(envelope, dict):
        return None
    host = envelope.get("host")
    return host if isinstance(host, str) and host else None


def _capabilities(envelope):
    if not isinstance(envelope, dict):
        return None
    caps = envelope.get("capabilities")
    return caps if isinstance(caps, dict) else None


def remedy(capability, host):
    override = _REMEDY_BY_HOST.get(host, {}).get(capability)
    text = override or _REMEDY.get(capability, "no remedy recorded for %s" % capability)
    return text % {"host": host or "this host"}


# What the line says INSTEAD of the probe and the detail when the row does not
# support the status being shown (#1597). It names the disagreement rather than
# the measurement: printing "probe write-guard-armed: round-trip denied" beside
# "is unknown" asserts two things that cannot both be true of one measurement,
# and the one the operator is entitled to is the masked state -- `hosts.posture`
# is the fail-closed answer every other surface renders.
_MASKED = ("the artifact's own state is %s, not the state this run reports; its "
           "probe and detail describe that other measurement and are not shown")
# The same suppression for a row that carries a measurement and NO state of its
# own. It is not a milder case: `posture()` answers `unknown` for it exactly as
# it does for a masked `proven`, so printing the measurement produced #1597's
# reported sentence verbatim -- and, on a row whose `by` is also absent, the
# worse "no probe ran: <what a probe found>".
_STATELESS = ("the artifact records %s but no state of its own, so nothing in "
              "it supports the state this run reports; it is not shown")
_SILENT = "no probe ran: no detail recorded"


def _recorded_state(recorded):
    """The row's own state, rendered for a disclosure line.

    NEVER the raw value. `state` is read off a file a hostile target can
    pre-commit and a foreign report can carry, so echoing it put an unbounded,
    attacker-chosen string on all four of 5.1's surfaces -- measured at 5408
    characters for a 5000-character state, the exact unreadability #1601 is
    fixing one commit away. Only this module's own three-token vocabulary is
    quoted; anything else is described, because the fact worth disclosing is
    that the artifact says something unreadable, not what it says.
    """
    return repr(recorded) if recorded in hosts.STATES else "unrecognised"


def _probe_clause(row, state):
    """What replaces `probe <by>: <detail>` for one capability's row.

    The rule is one-directional: the measurement prints ONLY when the row's own
    `state` is present AND equal to the status being shown. Everything else is
    a row that does not support the sentence it would be printed in.

    * Equal -> render it. A refuted row keeps `probe shadow-shell-scan: ...`,
      because REFUTED passes the claim mask untouched (hosts.posture, I5).
    * A DIFFERENT state -> `_MASKED`. The stale or `--compare`-fed artifact:
      `posture()` masks a PROVEN row for a capability the host does not claim,
      and normalises an unreadable state to UNKNOWN.
    * NO state but a probe or a detail -> `_STATELESS`. This was the hole the
      first pass left: `recorded is None` was read as silence and fell through
      to the measurement branch, so a row with `by`/`detail` and no `state`
      printed #1597's reported sentence unchanged. A fresh probe always writes
      `state` (`host_probes._row`), so this is the stale / foreign / truncated
      path -- which is the path this rule exists for.
    * NOTHING recorded at all -> `_SILENT`. An empty row claims nothing, and
      "nobody looked" is the honest reading of it rather than a contradiction.
    """
    recorded = row.get("state")
    if recorded == state:
        by = row.get("by")
        probe_clause = ("probe %s" % by) if by else "no probe ran"
        return "%s: %s" % (probe_clause, row.get("detail") or "no detail recorded")
    if recorded is None:
        held = [w for w, k in (("a probe", "by"), ("a detail", "detail")) if row.get(k)]
        return _STATELESS % (" and ".join(held),) if held else _SILENT
    return _MASKED % (_recorded_state(recorded),)


def unproven_rows(envelope):
    """THE selection: [(capability, masked state)] this envelope does not prove.

    Pure, and the ONLY place the `hosts.posture()` -> `hosts.unproven()` chain
    is written for disclosure (#1600). `lines()` renders it and
    `setup_flow._check_host_shells` (5.1 surface 4) consumes it; before this
    existed, readiness wrote the same chain itself and then pulled each row's
    TEXT out of `lines()` by prefix match. Two derivations of one fact, and
    only one of them observable from the other: mutating `lines()` to emit a
    row per capability broke the cross-surface guard on the stderr and body
    surfaces and NOT on readiness -- 2 of 3, from a test written to catch
    exactly that.

    It returns the STATE beside the name rather than the bare name
    `hosts.unproven` gives, because that is the other half readiness was
    re-deriving: `refuted` is a fault an operator can clear and `unknown` is
    NOT APPLICABLE, and the two must be told apart by the same answer that
    chose the row. Sorted by `hosts.unproven`, because a reader diffs these
    across runs.

    An unreadable envelope selects nothing -- `headline()` is where that case
    is SAID (NO_EVIDENCE); an empty list here would read as all-proven, which
    is the inversion its docstring forbids, so no caller may take [] from this
    as an answer on its own.
    """
    caps = _capabilities(envelope)
    host = host_of(envelope)
    if caps is None or host is None:
        return []
    posture = hosts.posture(host, caps)
    return [(capability, posture[capability])
            for capability in hosts.unproven(posture)]


def lines(envelope):
    """One line per capability that is not PROVEN, in a stable order.

    Stable because a reader diffs these across runs; `hosts.unproven` sorts for
    exactly that reason. One line per `unproven_rows` entry, in that order, so
    the two surfaces that consume this can be zipped rather than prefix-matched.
    """
    caps = _capabilities(envelope) or {}
    host = host_of(envelope)
    out = []
    for capability, state in unproven_rows(envelope):
        row = caps.get(capability)
        row = row if isinstance(row, dict) else {}
        out.append("%s is %s on host %r -- %s. fix: %s"
                   % (capability, state, host, _probe_clause(row, state),
                      remedy(capability, host)))
    return out


def notes(envelope):
    """The OPERATIONAL lines: measured facts that gate nothing (D10 N2).

    Separate from `lines()` because three consumers read that list as "the
    capabilities this run does not verify" -- `headline` counts it,
    `setup_flow._readiness` passes only when the headline is ALL_PROVEN, and
    both report renderers print it under "Host capabilities". A fact appended
    there made a fully proven host announce "1 of 5 NOT PROVEN on host
    'claude' ()", naming an empty set in the same sentence, and downgraded
    setup readiness from PASS to WARN over a flag nothing depends on.

    Said in this module, and by every surface, for the reason the module
    exists: it is a measured fact about this host on this machine, and one
    voice is the only way four renderings keep agreeing.
    """
    host = host_of(envelope)
    if host is None:
        return []
    return _output_schema_line(envelope, host)


def _output_schema_line(envelope, host):
    """The one line that says a reply will NOT be schema-constrained (D10 F1).

    Not a capability line: this gates nothing and refuses nothing, so it
    carries no state and no remedy in `remedy()`'s sense -- the run is correct
    either way, because the driver validates every returned reply itself.

    Silent when the flag IS advertised. Silent, too, when the whole `cli_flags`
    block is absent: nothing was interrogated at all, which is session mode
    (the loop launches no CLI) or an artifact written before this probe
    shipped, and inventing a line about a binary nobody interrogated is the
    "mood" 5.1 rules out. A block that exists but is MISSING a fact this host's
    registry row says should be in it is the third case, and it gets a line of
    its own (D10 N1): that combination means the probe did not answer for a
    host whose runner declares the flag, and the flag will not be passed.
    """
    fact = (envelope.get(hosts.CLI_FLAGS) if isinstance(envelope, dict) else None) or {}
    if not isinstance(fact, dict) or not fact:
        return []
    row = fact.get(hosts.OUTPUT_SCHEMA)
    if not isinstance(row, dict):
        if hosts.OUTPUT_SCHEMA not in (getattr(hosts.spec(host), "cli_flag_facts", ()) or ()):
            return []
        return ["the output schema was not interrogated on host %r -- probe %s recorded "
                "nothing, so the flag will not be passed. fix: re-run so the probe can "
                "read `<cli> --help`; the driver validates every reply either way"
                % (host, CLI_FLAGS_PROBE)]
    if row.get("advertised") is True:
        return _shape_line(row, host)
    return ["replies are not schema-constrained this run on host %r -- probe %s: %s. "
            "fix: upgrade the CLI if you want %s enforced output; the driver validates "
            "every reply either way"
            % (host, CLI_FLAGS_PROBE, row.get("detail") or "no detail recorded",
               row.get("flag") or "its")]


def _shape_line(row, host):
    """What one real launch found out about an ADVERTISED flag (#1732).

    `advertised` is a read of the flag's NAME out of `<cli> --help`. Run 14
    proved a name is not a contract: `claude --help` advertises
    `--json-schema`, the driver handed it the schema's PATH where the CLI
    wants its TEXT, and 309 launches went to that gap under a posture line
    saying "5 of 5 capabilities proven". So an advertised flag is no longer
    silent -- it says which of the three answers this run's own probe got.

    No `shape` recorded yet is its OWN answer, not silence. The proof happens
    inside the loop, on the first batch that carries a schema-stamped entry,
    under the guards that batch armed -- so the first invocation of a run
    discloses honestly that the measurement has not been made yet rather than
    implying it passed. (Session mode reaches none of this: it carries no
    `cli_flags` block at all, because the loop launches none of our CLIs, and
    `_output_schema_line` returns above.)

    Still a NOTE and never a capability line: the flag gates nothing, the
    headline counts five capabilities whatever this says, and the driver
    validates every reply either way.
    """
    shape, flag = row.get(hosts.SHAPE), row.get("flag") or "its output-schema flag"
    detail = row.get(hosts.SHAPE_DETAIL) or "no detail recorded"
    if shape == hosts.SHAPE_PROVEN:
        return ["replies are schema-constrained this run on host %r -- %s advertised, "
                "shape proven by one launch (%s)" % (host, flag, detail)]
    if shape == hosts.SHAPE_REFUTED:
        return ["replies are not schema-constrained this run on host %r -- %s "
                "advertised, shape REFUTED by one launch (%s) -- entries launch "
                "without the flag and reply in fenced JSON, which the driver "
                "validates against the same schema on receipt" % (host, flag, detail)]
    if shape == hosts.SHAPE_UNMEASURED:
        return ["replies may be schema-constrained this run on host %r -- %s "
                "advertised (shape unmeasured: %s); entries carry the flag as "
                "before, and the driver validates every reply either way"
                % (host, flag, detail)]
    return ["replies may be schema-constrained this run on host %r -- %s "
            "advertised (shape unmeasured until the first batch launches); the "
            "loop proves it once, under that batch's own guards, and says so here "
            "from then on" % (host, flag)]


def disclosure_digest(envelope):
    """A stable fingerprint of everything the full block would SAY (#1596).

    Over the rendered TEXT, not over the posture map, because the question a
    caller asks it is "has the operator already been told this?" -- and the
    `detail`, the remedies and the operational notes are all part of the
    answer. A capability that stayed refuted for a NEW reason is a changed
    disclosure even though its state did not move, and `driver` already
    refreshes the artifact for exactly that case.

    `probed_at` is excluded by construction: it is stamped fresh on every
    probe and appears in no line, so an unchanged posture digests identically
    on every invocation of a resumable loop.
    """
    body = "\n".join([headline(envelope)] + lines(envelope) + notes(envelope))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def unchanged_headline(envelope, since):
    """The ONE line an invocation prints when it has said all this already.

    Spec 5.1 says the posture is disclosed once per run; `driver run` is a
    resumable loop, so the full block ran on every invocation -- ~120 KB of
    byte-identical stderr across a self-scan (#1596). It is deliberately not
    silence: a resumer must see the posture they are resuming under, and
    "absence of warnings must mean measured and proven" forbids saying
    nothing. So it names the host, BOTH counts (a headline that reported only
    the unproven could go quiet by counting nothing), and when the full block
    was printed.

    Falls back to NO_EVIDENCE on an unreadable envelope for the same reason
    `headline` does: a count of nothing must never render as the all-proven
    case.
    """
    caps = _capabilities(envelope)
    host = host_of(envelope)
    if caps is None or host is None:
        return NO_EVIDENCE
    unproven_count = len(unproven_rows(envelope))
    return ("host %r: %d of %d capabilities proven, %d not -- unchanged since "
            "%s, when the full disclosure was printed (spec 5.1)"
            % (host, len(hosts.CAPABILITIES) - unproven_count,
               len(hosts.CAPABILITIES), unproven_count, since))


def headline(envelope):
    """The single line surfaces 1 and 3 lead with.

    Three outcomes, never two: proven, unproven, and "no artifact at all". The
    third is why this is not `if lines(): warn()` -- an empty result from a
    missing artifact would render as the all-proven case and turn 5.1's
    guarantee inside out.
    """
    caps = _capabilities(envelope)
    host = host_of(envelope)
    if caps is None or host is None:
        return NO_EVIDENCE
    # R1 Minor 2: the COUNT and the NAMES come off one call. This counted
    # `len(lines(...))` and separately named `hosts.unproven(hosts.posture(...))`
    # -- a second derivation of one fact, surviving inside the module #1600
    # designated as the single place for it, and producing a sentence whose
    # count and name-list can disagree with each other.
    rows = unproven_rows(envelope)
    if not rows:
        return ALL_PROVEN
    return ("%d of %d NOT PROVEN on host %r (%s) -- this run "
            "does not verify them; see the lines below"
            % (len(rows), len(hosts.CAPABILITIES), host,
               ", ".join(name for name, _state in rows)))
