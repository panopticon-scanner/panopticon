"""The `setup-scan` unenforced-dispatch acknowledgement (#1737, AGT-B1D).

Split out of `phases/setup.py` under the 700-line ceiling (`tests/test_layout.py`
rule 5). One cohesive block with one subject: whether `driver setup` may dispatch
the setup classifier SHELL-LESS, the acceptance file that records the operator
saying yes, the remedy phrasing the refusal offers, and the discard that happens
once the posture no longer needs an acceptance. Nothing here reads a setup PHASE,
which is why it moved rather than the predicates around it -- `phases/setup.py`
reaches in by module attribute (`setup_ack.require_unenforced_scan_ack`) at its
two call sites and nothing here reaches back, so there is no cycle to route
around.
"""
import os
import sys

from scripts import hosts
import scripts.loop_batch as loop_batch
import scripts.synth.integrity as integrity_mod
import scripts.runners.base as runners_base
from . import requests
from . import runio


SETUP_UNENFORCED_ACK = "setup-unenforced-ack.json"

# The operator's fix, not just an escape hatch: the refusal below names the
# command that makes the refusal go away for good -- when there is one.
_EMIT_REMEDY = "python3 skill/scripts/dispatch.py --emit-host-agents %s"
# ...and when what is missing is a MEASUREMENT rather than a registration, the
# invocation that takes it. `driver loop` resolves `--mode` to headless for any
# host with a runner and writes it back onto `args` before the posture step, so
# this is the one entry point that hands the probes a settings path (fix round
# 2; verified against `orchestrate._resolve_mode` and
# `driver._establish_host_posture`). `--mode headless` is spelled out even
# though it is the default for these hosts: a remedy an operator pastes should
# not depend on a resolution rule to be correct.
_MEASURE_REMEDY = "driver loop --setup --host %s --mode headless"


def require_unenforced_scan_ack(review_root, manifest, entries):
    """Refuse to dispatch `setup-scan` SHELL-LESS unless the operator accepted
    it explicitly (#1737, AGT-B1D) -- the setup analogue of
    `requests.require_unenforced_ack`, sharing its never-overwrite writer.

    The capability is TOOL_POLICY_ENFORCED, not ARTIFACT_WRITE_GUARD: this
    dispatch writes nothing (it is return-persist by construction) and the risk
    is the other one. It reads the WHOLE reviewed tree as untrusted content,
    and without a registered shell nothing bounds the tool set the host hands
    it -- the template's Read/Grep/Glob travels as the advisory line
    `dispatch._tool_policy_line` appends to the brief, and that is all. This is
    the acknowledgement every OTHER unenforced dispatch has required since
    #1519 and this one never passed through.

    A refusal is the normal outcome on a machine that has not emitted its
    shells, and the remedy it names FIRST is to emit them -- `--allow-unenforced`
    accepts the residual risk instead, and is recorded in
    `setup-unenforced-ack.json`.

    That record describes THIS invocation and nothing else. Every field is
    refreshed on every write, and once the posture proves enforcement the file
    is DISCARDED: an acceptance that outlives the posture it was about is a
    tree saying `acknowledged: true` over a dispatch that runs in a registered
    shell, which is worse than no record at all. The bootstrap sequence makes
    exactly that transition -- accept once, emit the shells, re-run.

    Its OWN file, beside setup's other artifacts, never the review run's
    `unenforced-ack.json`: that one's `plan_sha256` binds a review plan (#493
    R2) and is never-overwrite, so stamping setup's hash into it would make the
    next review run's ack read as stale -- and `runio._pano` would resolve the
    shared name into an unrelated run's folder besides (#1507).

    Returns the ack path when one was written, else None.
    """
    host = manifest.get("host", "claude")
    path = runio._pano(review_root, SETUP_UNENFORCED_ACK)
    if loop_batch.expected_enforced(review_root, host,
                                    namespace=loop_batch.SETUP_NAMESPACE):
        _discard_scan_ack(path)        # the shell is registered and proven
        return None
    evidence = loop_batch.evidence_for(review_root, loop_batch.SETUP_NAMESPACE)
    posture = hosts.posture(host, evidence)
    row = evidence.get(hosts.TOOL_POLICY_ENFORCED) or {}
    if not (manifest.get("flags") or {}).get("allow_unenforced"):
        # declares(), NOT posture(), for the hint -- the same reason
        # `requests.require_unenforced_ack` gives: we have no evidence for a
        # host we are not running, so posture() would answer unknown for all
        # of them and the hint would go empty.
        enforcing = [n for n in hosts.driver_hosts()
                     if hosts.declares(n, hosts.TOOL_POLICY_ENFORCED)]
        emit = _remedy_clause(host, posture[hosts.TOOL_POLICY_ENFORCED])
        raise runio.DriverError(
            "%s is %s on host %r -- probe %s: %s. The setup-scan agent reads "
            "the whole reviewed tree as untrusted content, and with no "
            "registered shell nothing confines its tools to Read, Grep, Glob "
            "-- the brief's tool policy is advisory prose. %s-run with "
            "--allow-unenforced to accept that explicitly (it is recorded in "
            "%s), or use one of: %s."
            % (hosts.TOOL_POLICY_ENFORCED, posture[hosts.TOOL_POLICY_ENFORCED],
               host, row.get("by") or "none ran", row.get("detail") or "no evidence",
               emit, SETUP_UNENFORCED_ACK,
               ", ".join("--host " + n for n in enforcing)))
    body = {
        "acknowledged": True, "host": host,
        # The launch SHAPE the operator accepted (id, shell, posture,
        # destination), not the brief: that text carries the repository spine
        # and moves with the tree, so hashing it would bind the acceptance to
        # a file listing rather than to the thing being acknowledged.
        "plan_sha256": integrity_mod._plan_hash(
            [{key: entry.get(key) for key in ("id", "agent", "enforced", "out_file")}
             for entry in entries if isinstance(entry, dict)]),
        "roles": ["setup_scan"],
        "note": ("The setup classifier reads the whole reviewed tree with no "
                 "registered shell: its tool grant is whatever this host gives "
                 "a general-purpose agent. The operator accepted this with "
                 "--allow-unenforced."),
        hosts.TOOL_POLICY_ENFORCED: posture[hosts.TOOL_POLICY_ENFORCED],
        "tool_policy_detail": row.get("detail") or "no evidence"}
    # Every key refreshed: see the docstring. Nothing downstream binds to this
    # file, so there is no earlier write to preserve -- only an older set of
    # facts to correct.
    return requests._merge_ack(path, body, refresh=tuple(body))


def _remedy_clause(host, state):
    """The fixing remedy this refusal may honestly name, as a sentence opener
    ending in "re" for the `--allow-unenforced` clause that follows.

    Three answers, and the rule is the capability's STATE, which is what says
    whether a fix EXISTS and which one (fix round 2):

    * REFUTED -- the host measured and said no. Every capability that gates
      here maps to a registration probe, so re-emitting is the fix for its
      ordinary cause, and the refusal quotes the probe's own detail for the
      rest. Name the emit command -- unless the row itself carries a
      registration refusal (`hosts.HostSpec.registration_refusal`, #2214): a
      relative CODEX_HOME refuses that exact emit command with the same
      message (`hosts.codex_home`), so naming the refusal is the fix that
      remains. Read it off the row PR #2232 already recorded it on, never
      re-derived from the environment here.
    * UNKNOWN -- NOTHING measured it. No amount of registering changes what
      was never read, and naming the emit command there is the round-1
      Critical one host over: `driver setup --host codex` cannot reach PROVEN
      on any machine, because codex maps `tool_policy_enforced` to
      `codex-effective-tools` and that probe answers UNKNOWN unless it is
      handed a headless settings path, which only `driver loop` produces.
      Name the invocation that can measure.
    * A host that registers no shells at all (`--host generic`, owner ruling
      D1, the permanent unenforced fallback) gets NEITHER: emitting refuses
      and measuring finds nothing to measure, so the acceptance and the host
      switch are the whole truthful list.

    `headless_available` is the one owner of "does this family ship a runner",
    and it is asked rather than assumed -- a host that registers shells and
    ships no runner would otherwise be handed a `--mode headless` that
    `runner_for` refuses, which is the same defect in a third place. Reached
    through the module-level import, which #1603 fix round 2 needed anyway for
    `LaunchRefused`: `phases` may import `runners` (only the reverse is
    banned), and there is no cycle to route around -- `runners.base` reaches
    `dispatch`, which imports only `model_resolver`, `codex_read_tools` and
    `hosts`, none of which comes back here.
    """
    row = hosts.spec(host)
    if row is None or not row.shell_format:
        return "Re"
    if state == hosts.REFUTED:
        if row.registration_refusal:
            return "%s -- re" % row.registration_refusal
        return "Run %s and re-run `driver setup`, or re" % (_EMIT_REMEDY % host)
    if runners_base.headless_available(host):
        return ("Nothing measured it here -- re-run as `%s`, the invocation "
                "that can, or re" % (_MEASURE_REMEDY % host))
    return "Re"


def _discard_scan_ack(path):
    """Drop a standing acceptance the posture has superseded, and say so.

    Announced rather than silent: the operator passed `--allow-unenforced` at
    some point, and the file going away is the run telling them they no longer
    need to. Never fatal -- the ack lives under `.panopticon`, which the target
    owns, so a read-only directory or a directory planted at the name must not
    take down the ENFORCED path, which needs no acknowledgement anyway.
    """
    try:
        os.remove(path)
    except OSError:
        return None
    print("driver setup: %s discarded -- this host now enforces the setup-scan "
          "shell, so there is nothing left to acknowledge" % SETUP_UNENFORCED_ACK,
          file=sys.stderr)
    return path
