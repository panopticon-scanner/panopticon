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

ALL_PROVEN = ("all measured and PROVEN -- "
              "every control this run relies on was verified, not assumed")
NO_EVIDENCE = ("NO EVIDENCE -- nobody looked. Nothing this "
               "run reports about enforcement is verified (spec 5.1)")

# Spec D4: "deprecate now, remove when the families land". Printed once per
# `driver run` / `driver setup` under --host generic. It is a notice, not a
# gate (spec 10): the run proceeds, ack-gated and disclosed exactly as before.
GENERIC_DEPRECATION = (
    "driver: NOTICE: --host generic is deprecated -- it claims no capability, so every "
    "dispatch under it is unenforced. It is removed once every remaining host "
    "clears the retirement bar (spec 8.1, test_generic_retirement_bar).")

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
        "pass --session-dir naming the directory the %(host)s session runs in, "
        "so its transcript can be found",
    hosts.READ_SCOPE_CONFINED:
        "nothing to do: no host implements a read-confinement control yet "
        "(spec 7.2), so this stays unknown by design",
    hosts.MODEL_BINDING:
        "re-run `python3 skill/scripts/dispatch.py --emit-host-agents %(host)s` so "
        "every registered shell binds the model in skill/reference/model-profiles.yml, "
        "and unset any PANOPTICON_MODEL_* override -- an enforced dispatch binds the "
        "shell's model, never the override's",
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
    return _REMEDY.get(capability, "no remedy recorded for %s" % capability) % {
        "host": host or "this host"}


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
    return out


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
