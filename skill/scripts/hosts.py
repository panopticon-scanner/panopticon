#!/usr/bin/env python3
"""#1344: the one table that knows what a host is.

Before this module, four separate places disagreed about which hosts exist:
the driver's `--host` choices (claude|generic|gemini), `emit_host_agents`
(claude|kimi|codex), `_detect_host`'s return values, and `model_resolver`'s
fallback branches. A host could therefore be first-class in one and absent from
another -- `gemini` was selectable by the driver while `emit_host_agents`
raised `ValueError` for it, and setup told operators to run that exact command.

This module is DATA and PURE FUNCTIONS ONLY. It is imported by `phases/*`,
which must not pay for templates, model resolution or a subprocess to ask
whether a host enforces its tool policy. Anything needing the filesystem or a
subprocess belongs in `host_probes.py` (F3); `tests/test_hosts.py` pins that
separation.

CLAIMS ARE NOT EVIDENCE. `claims` records what a host's platform can provide,
never what a given machine actually delivers. `declares()` reads the claim and
is what F1/F2 consumers use, preserving today's behavior exactly. F3 adds
`posture()`, which reads probe evidence, and the consumers move to it; that swap
is the single intended behavior change and it is tested on its own. A capability
that is claimed but unproven is `UNKNOWN`, and `UNKNOWN` gates as `REFUTED`.
"""
import os
from dataclasses import dataclass

# --- capabilities ----------------------------------------------------------
TOOL_POLICY_ENFORCED = "tool_policy_enforced"
READ_SCOPE_CONFINED = "read_scope_confined"
ARTIFACT_WRITE_GUARD = "artifact_write_guard"
MODEL_BINDING = "model_binding"
USAGE_LEDGER = "usage_ledger"

CAPABILITIES = (TOOL_POLICY_ENFORCED, READ_SCOPE_CONFINED,
                ARTIFACT_WRITE_GUARD, MODEL_BINDING, USAGE_LEDGER)

# --- capability states (F3 consumes these; defined here so one module owns
# the vocabulary) ----------------------------------------------------------
PROVEN, REFUTED, UNKNOWN = "proven", "refuted", "unknown"
STATES = (PROVEN, REFUTED, UNKNOWN)

# --- registration directories ---------------------------------------------
# Moved here from dispatch.py so the table is the single source; dispatch.py
# re-exports them for its existing importers.
CLAUDE_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".claude", "agents")
KIMI_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".kimi-code", "agents")
CODEX_HOME = os.path.expanduser(os.environ.get("CODEX_HOME", "~/.codex"))
CODEX_AGENTS_DIR = os.path.join(CODEX_HOME, "agents")


@dataclass(frozen=True)
class HostSpec:
    """One host's static facts.

    `claims` is the platform's advertised capability set, not a measurement.
    `driver_selectable` is deliberately separate from membership in HOSTS: a
    host can be registrable (its shells emit) long before the driver may pick
    it, which is exactly kimi's and codex's position today. A family PR flips
    its own row to True as part of proving its capabilities -- never before.
    `project_scope_dirs` are directories a TARGET repository could use to
    shadow a registered shell; F3's preflight scans them (spec §7.3).
    """

    name: str
    claims: frozenset
    registration_dir: str = ""      # "" when the host registers no shells
    shell_format: str = ""          # "md" | "toml" | ""
    project_scope_dirs: tuple = ()
    detect_env: tuple = ()          # env vars that identify an active session
    driver_selectable: bool = False


HOSTS = {
    "claude": HostSpec(
        name="claude",
        claims=frozenset({TOOL_POLICY_ENFORCED, ARTIFACT_WRITE_GUARD,
                          MODEL_BINDING, USAGE_LEDGER}),
        registration_dir=CLAUDE_AGENTS_DIR,
        shell_format="md",
        project_scope_dirs=(os.path.join(".claude", "agents"),),
        detect_env=("CLAUDECODE",),
        driver_selectable=True),
    "kimi": HostSpec(
        name="kimi",
        claims=frozenset({TOOL_POLICY_ENFORCED, MODEL_BINDING}),
        registration_dir=KIMI_AGENTS_DIR,
        shell_format="md",
        project_scope_dirs=(os.path.join(".agents", "agents"),
                            os.path.join(".kimi-code", "agents")),
        detect_env=("KIMI_CODE_VERSION", "KIMI_SESSION_ID"),
        driver_selectable=False),
    "codex": HostSpec(
        name="codex",
        claims=frozenset({TOOL_POLICY_ENFORCED}),
        registration_dir=CODEX_AGENTS_DIR,
        shell_format="toml",
        project_scope_dirs=(os.path.join(".codex", "agents"),),
        detect_env=("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED"),
        driver_selectable=False),
    # Selectable today with NO enforcement support of any kind -- the state
    # this epic exists to end. It claims nothing, so every consumer that reads
    # the registry treats it as unenforced, which is what already happens.
    "gemini": HostSpec(name="gemini", claims=frozenset(),
                       driver_selectable=True),
    # The deprecated fallback (spec D4). Deleted in F5 once every remaining
    # driver-selectable host clears the bar in spec §8.1.
    "generic": HostSpec(name="generic", claims=frozenset(),
                        driver_selectable=True),
}


def known_hosts():
    """Every host the registry knows, selectable or not."""
    return tuple(sorted(HOSTS))


def driver_hosts():
    """Hosts `driver.py --host` accepts."""
    return tuple(sorted(n for n, h in HOSTS.items() if h.driver_selectable))


def spec(host):
    """The HostSpec, or None for a host the registry does not know."""
    return HOSTS.get(host)


def declares(host, capability):
    """Does this host CLAIM the capability?

    Not "does it deliver it" -- that is F3's `posture()`. Consumers use this
    only until probe evidence exists; the swap is the behavior change spec
    §7.1 describes.
    """
    row = HOSTS.get(host)
    return bool(row) and capability in row.claims


def posture(host, evidence):
    """Every capability's state for this run. FAIL-CLOSED.

    `evidence` is the `capabilities` block of
    `.panopticon/runs/<tag>/host-capabilities.json`, or None when no probe has
    run. Three rules, each of which is a defect this repo has already shipped
    once in another form:

    * No evidence for a capability -> UNKNOWN. An absent artifact is not
      benign (A1's `_owes_a_snapshot`).
    * Evidence for a capability the host does not CLAIM -> UNKNOWN. A stale
      artifact from another host's run must not grant anything.
    * A state string this module does not recognise -> UNKNOWN. Never trust an
      unparseable value; that is how `noscan` became `empty` in #1335.
    * An unreadable SHAPE -> UNKNOWN. `evidence` that is not a mapping, or a
      per-capability entry that is not a mapping, resolves to UNKNOWN for every
      capability rather than raising. This function's input is a FILE ON DISK
      (`host-capabilities.json`) and therefore untrusted: truncated,
      half-written, or tampered. "Unparseable value" and "unparseable
      container" are the same defect, and a crash mid-run is not failing
      closed -- it is failing.

    UNKNOWN gates exactly as REFUTED. The two are kept distinct because
    "we did not measure" and "we measured and it is off" have different
    remedies, and the run says which (spec §5.1).
    """
    if not isinstance(evidence, dict):
        evidence = {}
    row = HOSTS.get(host)
    result = {}
    for capability in CAPABILITIES:
        if not row or capability not in row.claims:
            result[capability] = UNKNOWN
            continue
        entry = evidence.get(capability)
        state = entry.get("state") if isinstance(entry, dict) else None
        result[capability] = state if state in STATES else UNKNOWN
    return result


def unproven(posture_map):
    """Capabilities that are not PROVEN, sorted so the disclosure line a
    reader sees is stable across runs (spec §5.1)."""
    return sorted(name for name, state in posture_map.items()
                  if state != PROVEN)
