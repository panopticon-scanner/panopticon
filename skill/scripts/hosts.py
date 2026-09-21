#!/usr/bin/env python3
"""#1344: the one table that knows what a host is.

Before this module, four separate places disagreed about which hosts exist:
the driver's `--host` choices, `emit_host_agents` (claude|kimi|codex),
`_detect_host`'s return values, and `model_resolver`'s fallback branches. A
host could therefore be first-class in one and absent from another -- `gemini`
was selectable by the driver while `emit_host_agents` raised `ValueError` for
it, and setup told operators to run that exact command. That disagreement is
what this table ends; `driver_selectable` is now one field on one row, and
gemini's reads False (#1621).

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
from collections import namedtuple
from dataclasses import dataclass, field

# --- capabilities ----------------------------------------------------------
TOOL_POLICY_ENFORCED = "tool_policy_enforced"
READ_SCOPE_CONFINED = "read_scope_confined"
ARTIFACT_WRITE_GUARD = "artifact_write_guard"
MODEL_BINDING = "model_binding"
USAGE_LEDGER = "usage_ledger"

CAPABILITIES = (TOOL_POLICY_ENFORCED, READ_SCOPE_CONFINED,
                ARTIFACT_WRITE_GUARD, MODEL_BINDING, USAGE_LEDGER)

# The two capabilities that are OPERATIONAL rather than security (#1626 I1).
# Spec 8.1's retirement bar excludes exactly these (D5), and
# docs/PANOPTICON.md says of usage_ledger that it "gates nothing directly":
# a run whose token counter went quiet is a run with a worse cost report, not
# a run whose reviewers were unconfined. The other three ARE the enforcement
# story, and every consumer that refuses on a posture change must refuse on
# those alone.
#
# Written down here, on the table that owns the vocabulary, rather than
# spelled out at the one call site that needs it today
# (`driver._establish_host_posture`): the same split already exists in
# `tests/test_generic_retirement_bar.py` as a hand-listed SECURITY_BAR, and a
# second, independent list of "which capabilities are security" is how two
# consumers come to disagree about it.
#
# It is emphatically NOT an exemption from measurement or disclosure: both are
# probed on every invocation, both are written into host-capabilities.json
# with their fresh state and reason, and both appear on all four disclosure
# surfaces. What they do not do is halt a run in flight.
OPERATIONAL_CAPABILITIES = (MODEL_BINDING, USAGE_LEDGER)

# --- operational CLI facts (D10 F1) ----------------------------------------
# Not capabilities: these are things the host's CLI turned out to accept, not
# controls the run relies on. They live in their OWN block of the evidence
# artifact, beside `capabilities` rather than inside it, for one reason --
# `driver._establish_host_posture` refuses a run whose capabilities moved, and
# a CLI upgraded between two turns of a resumable loop must not discard
# everything already dispatched over a flag that gates nothing.
#
# Named here, in the registry, because four modules in three processes read
# the same two strings: the probe that records the fact, the entry builder
# that consumes it, the artifact accessor, and the disclosure surface.
CLI_FLAGS = "cli_flags"
# The fact itself: {"flag": "--json-schema", "advertised": True|False|None,
# "detail": "<what the --help read saw>"}. `advertised` is a tri-state and
# only True means yes -- absent, null and False are all "do not pass one".
OUTPUT_SCHEMA = "output_schema"
# #1732: the second half of that fact, and the one a `--help` read cannot
# reach. `advertised` is the flag's NAME appearing in the help text; `shape`
# is whether the CLI accepts what this driver actually puts AFTER it,
# established by one real launch per run (`probes/shape.py`).
#
# Run 14 is why the two are separate facts: `claude --help` advertises
# `--json-schema`, the driver handed it the schema's PATH, the CLI wants its
# TEXT, and every return_json entry of every checkpoint exited 1 in ~120 ms
# with no envelope -- 309 launches for one wrong token, under a posture line
# reading "5 of 5 capabilities proven".
#
# Three values, and `unmeasured` is deliberately not `UNKNOWN`: the capability
# states below are about CONTROLS, and reusing their vocabulary for an
# operational fact that gates nothing is how a reader starts treating it as
# one. `unmeasured` never blocks and never changes what is stamped on an
# entry; only `refuted` does.
SHAPE = "shape"
SHAPE_DETAIL = "shape_detail"
SHAPE_PROVEN, SHAPE_REFUTED, SHAPE_UNMEASURED = "proven", "refuted", "unmeasured"

# --- capability states (F3 consumes these; defined here so one module owns
# the vocabulary) ----------------------------------------------------------
PROVEN, REFUTED, UNKNOWN = "proven", "refuted", "unknown"
STATES = (PROVEN, REFUTED, UNKNOWN)

# --- registration directories ---------------------------------------------
# Defined here and nowhere else. dispatch.py briefly re-exported them; nothing
# ever imported the copies, and a second name for a fact this table owns is
# exactly what #1344 removes. Consumers read the row instead:
# `spec(host).registration_dir`.
CLAUDE_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".claude", "agents")
KIMI_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".kimi-code", "agents")
CODEX_HOME = os.path.expanduser(os.environ.get("CODEX_HOME", "~/.codex"))
CODEX_AGENTS_DIR = os.path.join(CODEX_HOME, "agents")


# --- where the guide is (#1637 P01) ----------------------------------------
# SKILL.md's links are relative to SKILL.md's own directory, and `skill/` is
# what gets symlinked or copied into `~/.claude/skills/`, `~/.kimi/skills/`
# and `~/.agents/skills/` -- so the guide has to live INSIDE the skill or the
# first read the skill instructs fails in every installed layout. It does now
# (`skill/docs/PANOPTICON.md`); the repo-root path is a symlink onto it, so
# every root-level reference still resolves.
#
# Here rather than in a module of its own because this is the same KIND of
# fact as the registration directories above -- a path this repo's layout
# fixes, computed from `__file__` and never from cwd (the driver runs with cwd
# at the TARGET repo). PURE, like everything else in this module: it computes
# the path and does not stat it. `driver readiness` reports whether it exists,
# which is the one caller that has an answer to give when it does not.
GUIDE = "PANOPTICON.md"
_SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def guide_path():
    """The absolute path of the user guide inside THIS skill install."""
    return os.path.join(_SKILL_DIR, "docs", GUIDE)


# --- the target's discovery surface (#1657 step 3) -------------------------
# What the REVIEWED tree can ship that this host's CLI would DISCOVER from it
# -- as configuration, as instructions, or as a process beside the reviewer --
# and whether anything the launch passes closes that channel.
#
# The table lives HERE, on the registry that already owns `project_scope_dirs`
# and the registration directories, for the reason the module docstring gives:
# `probes/common.probe_discovery_surface` is the scan, and a scan that carried
# per-host paths would be a second place a host is defined. A host with an
# empty tuple is a no-op that costs nothing.
Surface = namedtuple("Surface", "pattern kind control cell")
# pattern: a TUPLE of paths relative to the review root -- the spec's row,
#          which lists one or several (`CLAUDE.md`, `**/CLAUDE.md`) under ONE
#          cell id. One `*` segment means "any single directory name"; `**`,
#          at the head or at the tail, means "at any depth" (bounded by
#          probes/common's DEPTH_CAP / ENTRY_CAP).
# kind:    OPEN       -- nothing in the launch closes it; a hit REFUTES
#          CONTROLLED -- a launch control closes it; a hit is DISCLOSED
# control: for CONTROLLED, the id of the control (probes/common.CONTROLS);
#          None for OPEN
# cell:    the #1657 spike's cell id (CL-n / CX-n / KM-n), for the report and
#          the tests. Unique per host.
OPEN, CONTROLLED = "open", "controlled"
SURFACE_KINDS = (OPEN, CONTROLLED)


def supported_surface_pattern(pattern):
    """Is this one of the three shapes the scan resolves (R2)?

    A plain path is one `stat`; a `*` SEGMENT is one `listdir` on its parent;
    `**` -- at the head or at the tail, never in the middle, never twice -- is
    the bounded walk. Anything else is rejected here, by the registry test,
    rather than silently resolving to nothing on the one tree it matters for.

    Pure and on the registry because it describes what a ROW may say. The
    resolver in `probes/common` reads the same three shapes and nothing else.
    """
    if not isinstance(pattern, str) or not pattern or pattern.startswith("/"):
        return False
    segments = pattern.split("/")
    if any(s in ("", ".", "..") for s in segments):
        return False
    stars = [i for i, s in enumerate(segments) if s == "**"]
    if len(stars) > 1 or (stars and stars[0] not in (0, len(segments) - 1)):
        return False
    # `*` is a whole segment or nothing: `pre*fix.md` would need a glob match
    # this scan deliberately does not do (one listdir, exact names).
    return not any("*" in s and s not in ("*", "**") for s in segments)


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
    # The `Surface` rows above: what a TARGET can ship that this host's CLI
    # discovers from the reviewed tree (#1657). Empty for a host no runner of
    # ours launches at a target, which makes the probe a no-op for it.
    discovery_surface: tuple = ()
    detect_env: tuple = ()          # env vars that identify an active session
    driver_selectable: bool = False
    probes: dict = field(default_factory=dict)
    # Which OPERATIONAL CLI facts (CLI_FLAGS, below) this host's headless
    # runner takes, and therefore which ones the cli-flags probe interrogates
    # on a headless run (D10 N1). Not capabilities and not claims: nothing
    # here gates a dispatch, and a fact that goes unmeasured only means the
    # driver passes the flag to nobody. The flag TOKEN stays the runner's
    # (`OUTPUT_SCHEMA_FLAG`); this says only that the row expects an answer,
    # so a disclosure surface can tell "no answer" from "no question" --
    # tests/probes/test_common.py pins the two together.
    cli_flag_facts: tuple = ()
    # The binary this host's HEADLESS runner launches (`HostRunner.CLI`), named
    # here so a consumer can ask "is it on PATH" without importing
    # `scripts.runners`. `""` means the host launches no CLI of ours (session
    # mode, `generic`), and then there is nothing to look for.
    #
    # `driver readiness` is that consumer, and the reason is not a layout rule:
    # test_layout pins the REVERSE edge (`runners/* -> phases`), so a
    # `phases -> runners` import would pass it today. The reason is what the
    # runners package IS -- host launch machinery -- and what the verb promises:
    # that it starts nothing. A preflight that imports the launcher to learn a
    # binary's NAME has taken on the launcher's import graph, its module-level
    # state and its seams to say one string. This registry is the single pure
    # source of static host facts (it sits with the registration directories
    # above for the same reason), so the fact lives here.
    #
    # It is still a second name for something the runner owns, so it is PINNED
    # to the runner by test (tests/test_hosts.py), exactly as `cli_flag_facts`
    # is pinned to `OUTPUT_SCHEMA_FLAG`. Duplication a test forbids drifting is
    # the price of keeping this registry importable from everywhere.
    cli_binary: str = ""


HOSTS = {
    "claude": HostSpec(
        name="claude",
        claims=frozenset({TOOL_POLICY_ENFORCED, READ_SCOPE_CONFINED,
                          ARTIFACT_WRITE_GUARD, MODEL_BINDING, USAGE_LEDGER}),
        registration_dir=CLAUDE_AGENTS_DIR,
        shell_format="md",
        project_scope_dirs=(os.path.join(".claude", "agents"),),
        # #1657 spike cells CL-1..CL-8, as #1717 narrowed them. CL-5 and CL-8
        # are the OPEN residual the step-2 launch fixes could not close: the
        # only flag that removes project agents, plugins, hooks and workflows
        # is `--safe-mode`, which also disables hooks and would un-arm both
        # guards -- hardening that reads like hardening and is not.
        discovery_surface=(
            Surface(("CLAUDE.md", "**/CLAUDE.md"), OPEN, None, "CL-1"),
            Surface((".claude/settings.json", ".claude/settings.local.json"),
                    CONTROLLED, "claude:setting-sources-user", "CL-2/CL-4"),
            Surface((".mcp.json",), CONTROLLED, "claude:strict-mcp-config", "CL-3"),
            Surface((".claude/agents/*",), OPEN, None, "CL-5"),
            Surface((".claude/skills/*/SKILL.md", ".claude/commands/**"),
                    CONTROLLED, "claude:disable-slash-commands", "CL-6/CL-7"),
            Surface((".claude/hooks/**", ".claude/workflows/**",
                     ".claude/plugins/**"), OPEN, None, "CL-8"),
        ),
        detect_env=("CLAUDECODE",),
        driver_selectable=True,
        probes={TOOL_POLICY_ENFORCED: "registered-shell-tools",
                ARTIFACT_WRITE_GUARD: "write-guard-armed",
                MODEL_BINDING: "entry-model-bound",
                USAGE_LEDGER: "usage-source",
                READ_SCOPE_CONFINED: "read-guard-armed"},
        cli_flag_facts=(OUTPUT_SCHEMA,),
        cli_binary="claude"),
    "kimi": HostSpec(
        name="kimi",
        claims=frozenset({TOOL_POLICY_ENFORCED, READ_SCOPE_CONFINED,
                          ARTIFACT_WRITE_GUARD, MODEL_BINDING, USAGE_LEDGER}),
        registration_dir=KIMI_AGENTS_DIR,
        shell_format="md",
        project_scope_dirs=(os.path.join(".agents", "agents"),
                            os.path.join(".kimi-code", "agents")),
        # KM-1..KM-4. KM-3 is the largest OPEN residual on any host: the
        # binary loads `AGENTS.md` root-to-leaf into the reviewer's system
        # prompt, no flag disables it, and the kimi child's cwd is still the
        # review root. Refusing on it is the point of this probe.
        discovery_surface=(
            Surface((".mcp.json", ".kimi-code/mcp.json"), CONTROLLED,
                    "kimi:workspace-trust-gate", "KM-4"),
            Surface(("AGENTS.md", "agents.md", "**/AGENTS.md",
                     "**/.kimi-code/AGENTS.md"), OPEN, None, "KM-3"),
            Surface((".kimi-code/skills/*/SKILL.md", ".agents/skills/*/SKILL.md"),
                    CONTROLLED, "kimi:skills-dir", "KM-1"),
            Surface((".kimi-code/agents/*", ".agents/agents/*"), OPEN, None,
                    "KM-2"),
        ),
        detect_env=("KIMI_CODE_VERSION", "KIMI_SESSION_ID"),
        driver_selectable=True,
        probes={TOOL_POLICY_ENFORCED: "kimi-shell-surface",
                READ_SCOPE_CONFINED: "kimi-read-guard-armed",
                ARTIFACT_WRITE_GUARD: "kimi-write-guard-armed",
                MODEL_BINDING: "kimi-model-alias-bound",
                USAGE_LEDGER: "kimi-usage-wire"},
        cli_binary="kimi"),
    "codex": HostSpec(
        name="codex",
        claims=frozenset({TOOL_POLICY_ENFORCED, READ_SCOPE_CONFINED}),
        registration_dir=CODEX_AGENTS_DIR,
        shell_format="toml",
        project_scope_dirs=(os.path.join(".codex", "agents"),),
        # CX-1..CX-6. CX-1..CX-3 are CONTROLLED by the cwd move (#1717), a
        # control with no positive post-run evidence -- the scratch dirs are
        # removed -- so this probe's DISCLOSURE is that evidence's substitute
        # until a measurement exists. The row's `kind` moves to OPEN the day
        # one refutes it.
        discovery_surface=(
            Surface(("AGENTS.md", "**/AGENTS.md"), CONTROLLED,
                    "codex:cwd-outside-target", "CX-1"),
            Surface((".codex/skills/*/SKILL.md", ".agents/skills/*/SKILL.md"),
                    CONTROLLED, "codex:cwd-outside-target", "CX-2/CX-3"),
            Surface((".codex/agents/*", ".agents/agents/*"), OPEN, None, "CX-6"),
            Surface((".codex/config.toml", ".rules"), CONTROLLED,
                    "codex:ignore-user-config-and-rules", "CX-4/CX-5"),
        ),
        detect_env=("CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED"),
        driver_selectable=True,
        probes={TOOL_POLICY_ENFORCED: "codex-effective-tools",
                READ_SCOPE_CONFINED: "codex-read-scope"},
        cli_flag_facts=(OUTPUT_SCHEMA,),
        cli_binary="codex"),
    # Registered, not selectable: its family PR did not clear the gate (#1621,
    # retired 2026-09-13). The row STAYS so the registry still knows the name
    # -- `known_hosts()` lists it, `spec("gemini")` resolves, it still claims
    # nothing, and every consumer that reads the registry keeps answering for
    # it honestly. Operators use `--host generic` (session mode, unenforced,
    # ack-gated), the same path as any host without a family runner. A future
    # Gemini PR flips this back as part of proving its capabilities, exactly
    # as kimi's and codex's rows did above.
    "gemini": HostSpec(name="gemini", claims=frozenset(),
                       driver_selectable=False),
    # The permanent, unenforced fallback (owner ruling D1, spec 8.3 option 1,
    # superseding D4's planned F5 deletion). It stays because the spec 8.1
    # bar is a floor, not a trigger (see `test_generic_retirement_bar`), and
    # generic is the only path left for gemini and for any other host
    # without a family runner.
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


def unselectable_host_message(host, verb):
    """The refusal for a run whose MANIFEST names a registered-but-unselectable
    host, spelled once because two entrypoints have to say it.

    `driver loop` has refused this since #1621 and `driver run` since #1624,
    and they reach it down the same path: a resume passes no `--host` (a
    contradicting one is refused as flag drift), so the manifest is
    authoritative and `driver.py`'s only other read of the selectable set --
    the parser's `choices`/`type=` -- never sees the name. The remedy is the
    same for both, because it is the MANIFEST that has to change.

    A second copy of this paragraph is a thing that drifts; an operator who
    moves between the two entrypoints would then be told two different stories
    about one registry fact. `verb` is all a call site supplies -- everything
    after the colon is a property of the `driver_selectable` field above, so
    it belongs in the table that owns that field.
    """
    return ("driver %s: this run's manifest names host %r, which is "
            "registered but no longer driver-selectable (it proves no "
            "enforcement capability). Start over with `--host generic "
            "--reset` (session mode, unenforced, ack-gated); resuming "
            "would dispatch for a host --host refuses to name." % (verb, host))


def is_unenforced_fallback(host):
    """Owner ruling D1 (spec 8.3 option 1): `--host generic` is the permanent,
    unenforced fallback for any host without a family runner. D4's "deprecate
    now, remove when the families land" is superseded: D1 retired F5 (the
    deletion it planned), so there is no longer anything for spec 8.1's bar
    to trigger -- that bar asks whether a remaining SELECTABLE host falls
    short (it does not, on this base -- see `test_generic_retirement_bar`),
    and it never spoke to whether this row itself goes away.

    A named predicate rather than a bare `host == "generic"` at each call
    site: `tests/test_host_posture_wiring.py`'s AST guard exists precisely so
    nothing under `phases/` decides behaviour from a host's NAME, and this
    registry -- "the one table that knows what a host is" -- is where that
    one comparison belongs. `gemini` also claims nothing, and since #1621 is
    not selectable either, but it is still not this: this predicate gates the
    fallback NOTICE, which describes the fallback specifically.
    """
    return host == "generic"


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
    * PROVEN evidence for a capability the host does not CLAIM -> UNKNOWN. A
      stale artifact from another host's run must not GRANT anything. REFUTED
      passes the mask untouched (I5): the rule is written for the granting
      direction but applied symmetrically it discarded refutations, and §7.3
      makes refuted the STRONGER answer. A refutation grants nothing, so
      letting it through is strictly non-permissive. It was latent only
      while every selectable host had empty `project_scope_dirs` -- generic
      still does, and so does gemini, which #1621 left registered but
      unselectable. It went LIVE when the family PRs flipped codex (#1619)
      and kimi (#1620) to driver_selectable with scope dirs of their own, and
      F5's entry-criterion test reads `posture()` -- so a genuinely refuted
      host would have read `unknown` and failed the bar for the wrong stated
      reason.
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
        entry = evidence.get(capability)
        state = entry.get("state") if isinstance(entry, dict) else None
        state = state if state in STATES else UNKNOWN
        # The claim mask applies to GRANTS only -- see the REFUTED rule in the
        # docstring. (The normalisation above runs first, but the two orders
        # are equivalent: an unrecognised state becomes UNKNOWN either way,
        # and a mutation check confirmed swapping them changes nothing. Said
        # here because a comment claiming the order is load-bearing would be
        # exactly the kind of false note this fix round is cleaning up.)
        if state != REFUTED and (not row or capability not in row.claims):
            state = UNKNOWN
        result[capability] = state
    return result


def resolve_state(states):
    """One capability's answer when several probes touched it.

    refuted > proven > unknown. Two probes can now bear on
    `tool_policy_enforced` -- `registered-shell-tools`, which can prove it, and
    `shadow-shell-scan`, which can only refute it -- so the precedence has to
    be written down rather than left to whichever ran last. A proof of
    registration does not survive evidence that the target is shadowing it.
    Anything unrecognised is ignored rather than believed.
    """
    seen = [s for s in states if s in STATES]
    if REFUTED in seen:
        return REFUTED
    if PROVEN in seen:
        return PROVEN
    return UNKNOWN


def unproven(posture_map):
    """Capabilities that are not PROVEN, sorted so the disclosure line a
    reader sees is stable across runs (spec §5.1)."""
    return sorted(name for name, state in posture_map.items()
                  if state != PROVEN)
