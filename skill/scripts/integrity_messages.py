"""Shared integrity-key membership and operator-facing sentences."""
from dataclasses import dataclass


# Mirrors tools.base.INERT_TEXT_MAX. This module must also import flat when
# skill/scripts itself is on sys.path, where the `scripts.tools.base` package
# path does not exist; keep the HTML boundary local and pin equality in tests.
HTML_DETAIL_MAX = 2000
HTML_DETAIL_CUT = "…"


@dataclass(frozen=True)
class IntegrityKey:
    """One `meta.integrity` key's two published facts.

    `sinks` says whether a TRUTHY value sinks `integrity_ok`, the single bool
    `tool_axis.reconcile` hands certification. `sentence` is the shared body
    both human renderers print; the terminal prefixes `**Integrity:**` or
    `**Note:**`, while HTML nests sinking reasons below `NOT CERTIFIED`. One
    optional `%s` slot carries evidence. `None` means the key has no line.
    """
    sinks: bool
    sentence: str | None = None


# ARC-3284703909 (#1761): the certification-sinking rule, in ONE place.
#
# It used to live in three, with three memberships: `integrity_section` below
# published ~20 keys, `tool_axis.reconcile` re-spelled 14 of them in a
# hand-written `or` chain, and `render.render_summary` named four -- one of
# which deliberately does not gate. So ten of the fourteen sinking keys had no
# line of their own on the TERMINAL SUMMARY `render_summary` prints -- nine of
# them named nowhere on it, the tenth (`delta_scope_suppressed_git_drivers`)
# only inside `coverage_note` -- and it said the bare word "incomplete" instead.
# That is the exact hole #1644 closed for `tools_manifest_invalid` alone. The
# reasons went to stderr; the summary an operator reads did not have them.
# (`report.json` carries the whole section; the terminal and HTML renderers
# both consume this table.)
#
# The terminal inserts each line at one index, so it renders this order in
# reverse. Non-gating notes therefore remain below failures. HTML renders only
# sinking keys, directly under its verdict, in this table's order. The sinking
# block follows `integrity_section`'s published key order.
INTEGRITY_KEYS: dict[str, IntegrityKey] = {
    # --- reported, never gating (rendered BELOW the failures) -----------------
    # #calibration-4: a reviewer filing outside its lane is a fact about the
    # REVIEW, not about whether the artifacts on disk can be trusted. Its
    # evidence slot carries the count and the domain pairs.
    "cross_domain_findings": IntegrityKey(
        False, "%s. Reviewers filed outside their cell's domain; often a "
               "catalog gap (X0X). Does NOT affect certification."),
    # #2271: discovery's two DEGRADATION disclosures, which the driver path
    # dropped -- `discovery.py` printed them on its own stderr and wrote them
    # into `groups.json`, and nothing downstream read either. NON-GATING, on
    # the same precedence as the truncation disclosure that already did not
    # gate: the reviewed surface is a SUPERSET (the git listing failed, so the
    # raw walk ignored the target's `.gitignore`) or a PREFIX (the cap cut it)
    # of the intended one, and the artifacts on disk are still what they claim
    # to be, which is what this section gates on. The DISSENT, kept so the
    # owner can flip either `sinks` in one line: a surface "far larger than the
    # target's own" is arguably not a run that should certify at all.
    #
    # Listed truncation-first so the LOUDER of the two renders above it (this
    # table's order is render order, reversed), and both below the failures.
    "discovery_files_truncated": IntegrityKey(
        False, "DISCOVERY TRUNCATED — %s files beyond the cap were not "
               "reviewed"),
    "discovery_git_failure": IntegrityKey(
        False, "DISCOVERY FELL BACK TO A RAW WALK — %s (the target's Git "
               "listing failed, so the surface does not honour its .gitignore "
               "and may be far larger than the target's own)"),
    # Counters and disclosures with no line of their own: a planned file that
    # never arrived is not evidence of tampering (`reconcile_findings_files`
    # reports it and no gate reads it), and the rest are measurements --
    # how many plans were seen, how many hashes were checked, whether an
    # unenforced-write ack was recorded, whether it was stale, and what that
    # ack said about Bash coverage.
    "missing_planned_files": IntegrityKey(False),
    "unenforced_acknowledged": IntegrityKey(False),
    "ack_stale": IntegrityKey(False),
    "content_hashes_checked": IntegrityKey(False),
    "plans_seen": IntegrityKey(False),
    "write_guard_covers_bash": IntegrityKey(False),
    # --- sinks `integrity_ok` -------------------------------------------------
    "unexpected_findings_files": IntegrityKey(
        True, "UNEXPECTED FILES — %s (not declared by the dispatch plan; run "
              "not certified)"),
    "malformed_findings_files": IntegrityKey(
        True, "MALFORMED FILES — %s (violate the findings contract, so source "
              "evidence was dropped from this report; run not certified)"),
    "duplicate_out_files": IntegrityKey(
        True, "DUPLICATE out_file — %s (two reviewers share a write target; one "
              "overwrote the other; run not certified)"),
    "mislabeled_findings_files": IntegrityKey(
        True, "MISLABELED FILES — %s (the `_panopticon` cell stamp disagrees "
              "with the filename; possible mis-targeted write; run not "
              "certified)"),
    # The #493 R4 tamper check: the triage probe's own example of a sink that
    # reached the terminal summary as "incomplete".
    "content_mismatched_files": IntegrityKey(
        True, "CONTENT CHANGED — %s (the bytes no longer match the fan-out "
              "snapshot, or could not be re-read; run not certified)"),
    "content_snapshot_unreadable": IntegrityKey(
        True, "CONTENT SNAPSHOT UNREADABLE — the fan-out out-file-hashes.json "
              "exists and cannot be read as a non-empty object, so no findings "
              "file could be verified against it (tamper, not an unmeasured "
              "run; run not certified)"),
    "content_snapshot_missing": IntegrityKey(
        True, "CONTENT SNAPSHOT MISSING — this run's dispatch plan declares "
              "review cells, so a fan-out out-file-hashes.json was owed and "
              "none is present (a deleted baseline; run not certified)"),
    "empty_dispatch_plans": IntegrityKey(
        True, "EMPTY DISPATCH PLAN — %s plan file(s) declare no reviewer entry, "
              "so there is nothing to reconcile the ingested files against; run "
              "not certified"),
    # Three reasons, and the third is a plan rejected on its NAME -- a stray
    # `dispatch-plan-*.json` that may parse and may meet the cell contract. The
    # filename alone cannot say which fired, so this key's rows render their
    # reason too (`_row_evidence`).
    "invalid_dispatch_plans": IntegrityKey(
        True, "INVALID DISPATCH PLAN — %s (a plan file on disk that does not "
              "parse, does not meet the review-cell contract, or is not the "
              "dispatch plan the driver writes; run not certified)"),
    # UNUSABLE, not unreadable: one of `load_verify_queue`'s two reasons is a
    # queue that read perfectly and has no `entries` list.
    "invalid_verify_queue": IntegrityKey(
        True, "VERIFY QUEUE UNUSABLE — %s (the queue recording what the advisor "
              "round was asked to verify could not be read as a queue; run not "
              "certified)"),
    # SEC-377944137 (#1832): `plans_seen` was the only key that noticed a
    # deleted driver plan and it was not in the chain, so the `rm` that erased
    # #1208's snapshot obligation certified a substitution the run had already
    # detected.
    "dispatch_plan_missing": IntegrityKey(
        True, "DISPATCH PLAN MISSING — this run's driver dispatched review "
              "cells and no dispatch-plan file is present, so every plan-keyed "
              "check went quiet (deleted evidence; run not certified)"),
    # ...and a plan that is PRESENT but is not the one this run wrote: a
    # narrower plan declares fewer cells, so replacing it is a cheaper `rm`.
    "dispatch_plan_mismatched": IntegrityKey(
        True, "DISPATCH PLAN SUBSTITUTED — the plan on disk does not hash to "
              "the content the run manifest stamped, so it is not the plan this "
              "run wrote; run not certified"),
    # #1644, and the one key that already had a name on the surface -- in
    # `coverage_note`, not here. It keeps both: the note says what could not be
    # measured, this says the run cannot be certified.
    "tools_manifest_invalid": IntegrityKey(
        True, "TOOLS MANIFEST UNREADABLE — %s (the runner's selected scanner "
              "set is unknown, so tool coverage could not be computed; run not "
              "certified)"),
    # #2013 fix round 1: a delta whose scope was chosen by a suppressed
    # comparison -- raw worktree bytes against a filtered index blob.
    "delta_scope_suppressed_git_drivers": IntegrityKey(
        True, "DELTA SCOPE INFLATED — %s (git driver(s) this scan emptied, so "
              "the diff that chose the reviewed files and the gate's scope "
              "compared raw bytes against a filtered blob; run not certified)"),
}


def _row_evidence(key, row):
    """One row of a list-valued integrity key, as the summary names it.

    The file, plus -- for `invalid_dispatch_plans` -- the loader's reason: that
    key's three reasons include a plan rejected on its NAME, which a filename
    alone cannot be told apart from one that does not parse.

    `file: reason`, not `file (reason)`: that third reason ends in a
    parenthetical of its own ("(expected dispatch-plan-driver.json)"), so the
    parenthesised form collided with the sentence's own in the COMMON case. A
    row carrying no reason -- which only a foreign report can produce -- says so
    rather than rendering `None`.
    """
    if not isinstance(row, dict):
        return str(row)
    if key == "invalid_dispatch_plans":
        return "%s: %s" % (row.get("file"),
                           row.get("reason") or "no reason recorded")
    return str(row.get("file"))


def raw_evidence_text(key, value):
    """Unescaped text for a sentence's `%s` slot, in the published shape.

    Each renderer applies its own output encoding: the terminal wrapper uses
    `tools.base.inert_text`, while the HTML renderer escapes the whole sentence.
    """
    if key == "cross_domain_findings":
        by: dict[tuple, int] = {}
        for row in value:
            if isinstance(row, dict):
                pair = (row.get("cell_domain"), row.get("finding_domain"))
                by[pair] = by.get(pair, 0) + 1
        text = "%d cross-domain finding(s) — %s" % (len(value), ", ".join(
            "%s→%s ×%d" % (a, b, n) for (a, b), n in sorted(
                by.items(), key=lambda item: (item[0][0] or "", item[0][1] or ""))))
    elif isinstance(value, list):
        text = ", ".join(_row_evidence(key, row) for row in value)
    else:
        text = str(value)
    return text


def _marked_prefix(text, limit):
    """Return at most `limit` characters, marking any truncation."""
    if len(text) <= limit:
        return text
    if limit <= 0:
        return ""
    marker = HTML_DETAIL_CUT[:limit]
    return text[:limit - len(marker)] + marker


def sentence_text(key, value, *, limit=None):
    """Render one table sentence, optionally bounding its complete length."""
    sentence = INTEGRITY_KEYS[key].sentence
    if sentence is None:
        return None
    if "%s" not in sentence:
        return sentence if limit is None else _marked_prefix(sentence, limit)
    evidence = raw_evidence_text(key, value)
    if limit is None:
        return sentence % evidence
    prefix, suffix = sentence.split("%s", 1)
    evidence_limit = limit - len(prefix) - len(suffix)
    if evidence_limit <= 0:
        return _marked_prefix(sentence % "", limit)
    return prefix + _marked_prefix(evidence, evidence_limit) + suffix


def sinking_sentences(section):
    """The shared sentences for truthy facts that sink certification."""
    if not isinstance(section, dict):
        return []
    rendered = []
    for key, spec in INTEGRITY_KEYS.items():
        value = section.get(key)
        if value and spec.sinks:
            sentence = sentence_text(key, value, limit=HTML_DETAIL_MAX)
            if sentence is not None:
                rendered.append(sentence)
    return rendered
