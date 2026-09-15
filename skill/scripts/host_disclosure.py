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

# The probe that records the operational CLI facts (D10 F1); named here
# because `_output_schema_line` must say WHICH measurement it is reporting and
# this module may not import the probes package (it is I/O-free by design, and
# imports only the registry).
USAGE_SOURCE_PROBE = "usage-source"

ALL_PROVEN = ("all measured and PROVEN -- "
              "every control this run relies on was verified, not assumed")
NO_EVIDENCE = ("NO EVIDENCE -- nobody looked. Nothing this "
               "run reports about enforcement is verified (spec 5.1)")

# Spec D4: "deprecate now, remove when the families land". Printed once per
# `driver run` / `driver setup` under --host generic. It is a notice, not a
# gate (spec 10): the run proceeds, ack-gated and disclosed exactly as before.
#
# It used to end "removed once every remaining host clears the retirement bar".
# That promise stopped being true at #1621: with gemini out of the selectable
# set, claude is the only host the bar examines and it clears it -- so the bar
# is MET while generic is still the only path a Gemini operator has, and the
# only path for any host whose family has not shipped a runner. A notice that
# names a trigger which has already fired and changed nothing teaches the
# operator to ignore the notice. It says what generic is still FOR instead.
GENERIC_DEPRECATION = (
    "driver: NOTICE: --host generic is deprecated -- it claims no capability, so every "
    "dispatch under it is unenforced and ack-gated. It remains the path for any host "
    "with no family runner, gemini among them (#1621), so removing it is an owner "
    "decision, not something the retirement bar triggers on its own (spec 8.1).")

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


def lines(envelope):
    """One line per capability that is not PROVEN, in a stable order.

    Stable because a reader diffs these across runs; `hosts.unproven` sorts for
    exactly that reason.
    """
    caps = _capabilities(envelope)
    host = host_of(envelope)
    if caps is None or host is None:
        return []
    posture = hosts.posture(host, caps)
    out = []
    for capability in hosts.unproven(posture):
        row = caps.get(capability)
        row = row if isinstance(row, dict) else {}
        by = row.get("by")
        probe_clause = ("probe %s" % by) if by else "no probe ran"
        detail = row.get("detail") or "no detail recorded"
        out.append("%s is %s on host %r -- %s: %s. fix: %s"
                   % (capability, posture[capability], host, probe_clause,
                      detail, remedy(capability, host)))
    out += _output_schema_line(envelope, host)
    return out


def _output_schema_line(envelope, host):
    """The one line that says a reply will NOT be schema-constrained (D10 F1).

    Not a capability line: this gates nothing and refuses nothing, so it
    carries no state and no remedy in `remedy()`'s sense -- the run is correct
    either way, because the driver validates every returned reply itself. It is
    here because it is a MEASURED fact about this host on this machine, and
    spec 5.1's rule ("name the capability, the host, the probe, and the
    remedy") is the reason all such facts are said in one voice.

    Silent when the flag IS advertised, and silent when nothing asked: a host
    whose row maps no `--help` read has no measurement to report, and inventing
    a line about a binary nobody interrogated is the "mood" 5.1 rules out.
    """
    fact = (envelope.get(hosts.CLI_FLAGS) if isinstance(envelope, dict) else None) or {}
    row = fact.get(hosts.OUTPUT_SCHEMA) if isinstance(fact, dict) else None
    if not isinstance(row, dict) or row.get("advertised") is True:
        return []
    return ["replies are not schema-constrained this run on host %r -- probe %s: %s. "
            "fix: upgrade the CLI if you want %s enforced output; the driver validates "
            "every reply either way"
            % (host, USAGE_SOURCE_PROBE, row.get("detail") or "no detail recorded",
               row.get("flag") or "its")]


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
    gaps = lines(envelope)
    if not gaps:
        return ALL_PROVEN
    posture = hosts.posture(host, caps)
    return ("%d of %d NOT PROVEN on host %r (%s) -- this run "
            "does not verify them; see the lines below"
            % (len(gaps), len(hosts.CAPABILITIES), host,
               ", ".join(hosts.unproven(posture))))
