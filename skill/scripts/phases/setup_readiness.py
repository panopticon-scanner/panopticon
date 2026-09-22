"""What `driver setup` DOES with a readiness answer: record it, render it.

`setup_flow.readiness` takes the measurement. This module owns what either
setup path then does with the rows it returns -- the keys the setup artifacts
carry, the verdict line the operator reads, and the clause that declares the
checks which gate nothing.

It is a module of its own rather than a section of `phases/setup.py` because
5.1's surface 4 is a promise about what an operator READS, and this rendering
now has more than one caller. Two copies of it are two things that drift while
each path's own test keeps passing -- the failure the four-surface rule exists
to prevent, reproduced inside the fix for it.

Formatting and shaping only: nothing here reads or writes a file. What is
measured belongs to `setup_flow`; where the rows are written belongs to
`phases/setup.py`.
"""
import scripts.grouping_engine as grouping_engine


# #1601. Every limitation carried a full remedy and they were all joined into
# ONE line: on gemini that line measured 1847 characters, up ~17x from ~110,
# because a host that claims nothing legitimately has seven of them. Nothing
# gating moved (shell-less hosts produce 7 rows and 0 gaps), which is the
# reason it needed fixing rather than a reason to leave it -- §5.1's "LOUDLY
# declare them" is about being READ, and a 1847-character line is a disclosure
# in the letter and not in the fact.
#
# One remedy per line, under the column bar, and a bounded list: the full,
# untruncated text of every limitation is in `setup-complete.json`'s
# `limitations` array either way, so the message is an index into it rather
# than a second copy of it.
#
# The artifact the "and N more" tail points at. A PARAMETER because the two
# setup paths write their rows to different files -- the fallback's
# `setup-complete.json` and the normal path's `setup-report.json` (#1603) --
# and a tail naming the wrong one sends the operator to a file that does not
# hold the text it promises.
_FALLBACK_ARTIFACT = "setup-complete.json"
REPORT_ARTIFACT = "setup-report.json"

_LIMITATION_LINE = 119          # strictly under the 120-column bar
_LIMITATION_MAX = 12            # remedies shown before the "and N more" tail
_TRUNCATED = "..."

# The word each `ok` renders as in the report section. `None` is NOT
# APPLICABLE -- the third answer, never collapsed into either of the other
# two: a check nobody could measure must not read as one that passed (§5.1).
_VERDICT = {True: "ok", False: "gap", None: "not applicable"}


def _limitation_line(name, detail):
    """One limitation on one line, no longer than `_LIMITATION_LINE` -- unless
    the NAME alone is longer than that, in which case the name wins.

    The name is never what gets cut: it is the key `setup-complete.json`
    stores the untruncated detail under, and the string an operator greps the
    readiness rows for. A line whose name has been sliced in half identifies
    nothing and points at nothing. Only the detail is trimmed, and it says so.

    R1 Minor 4: this used to slice the whole rendered line, so the docstring
    above asserted a guarantee the code did not make -- measured, a 156-char
    name came back cut mid-name. Every check name this repo emits is
    code-controlled and far under the bar (the longest,
    `host-capability:tool_policy_enforced`, is 36 characters), so the
    name-wins branch is a promise kept rather than a trade-off anyone meets.
    """
    detail = str(detail)     # read off setup-complete.json: any JSON shape
    line = "  - %s (%s)" % (name, detail)
    if len(line) <= _LIMITATION_LINE:
        return line
    head = "  - %s (" % name
    room = _LIMITATION_LINE - len(head) - len(_TRUNCATED) - 1   # the ")"
    return head + (detail[:room] if room > 0 else "") + _TRUNCATED + ")"


def _limitations_clause(limitations, artifact=_FALLBACK_ARTIFACT):
    """Render the readiness checks that gate nothing (`ok is None`).

    Spec §5.1: "If there are limitations by host then we should LOUDLY declare
    them", and "absence of warnings must mean 'measured and proven', never
    'nobody looked'". A check whose `ok` is None was never measured against a
    pass/fail bar -- gemini registering no enforcement shells is a FACT, not a
    fault. So it must not join `gaps` (those gate READY and carry a remedy),
    and it must not be swallowed either: `readiness OK` on a host that cannot
    enforce is exactly the ambiguity §5.1 forbids. Its own clause, carrying the
    check's own detail, which already names the capability and the host.
    """
    rows = list(limitations)
    shown = rows[:_LIMITATION_MAX]
    out = ["limitations:"]
    out.extend(_limitation_line(name, detail) for name, detail in shown)
    if len(rows) > len(shown):
        out.append("  - and %d more -- full text in .panopticon/%s `limitations`"
                   % (len(rows) - len(shown), artifact))
    return "\n".join(out)


def _stored_limitations(marker):
    """The `limitations` pairs from a setup-complete.json, or []. Tolerates a
    marker written before the key existed, and any row that is not a pair."""
    return [(row[0], row[1]) for row in ((marker or {}).get("limitations") or [])
            if isinstance(row, (list, tuple)) and len(row) == 2]


def _readiness_suffix(record):
    """readiness's verdict as ONE clause, for whichever setup line carries it.

    #1603: both setup paths print this now, so it is written once. The
    fallback has said `readiness gaps: ... (fix before running a review)`
    since Task 3 and the normal path says the same thing in the same words --
    two spellings of one verdict are two things to keep in step, and the one
    that falls behind is still green in its own test.

    THREE outcomes, not two (fix round 1). The clean case is a SENTENCE, not
    silence: §5.1's "absence of warnings must mean 'measured and proven',
    never 'nobody looked'" only holds if the passing case is stated out loud,
    the same rule surface 3 renders on every all-proven report. But that cuts
    both ways, so "nobody looked" gets a sentence of its own: a verdict read
    off `gaps` alone answered `readiness OK` for a record in which NOTHING
    was measured against a pass/fail bar -- the single degraded row a failed
    measurement leaves, or an empty list off a stale artifact -- which is the
    inversion the rule exists to forbid, printed in the rule's own words.
    """
    if record["gaps"]:
        return ("readiness gaps: %s (fix before running a review)"
                % ", ".join(record["gaps"]))
    if not any(row[1] is not None for row in record["readiness"]):
        return "readiness NOT TAKEN -- nothing was measured"
    return "readiness OK"


def _readiness_record(checks):
    """The three keys a setup artifact carries, off one `readiness()` answer.

    ONE shape for both artifacts (#1603): the fallback's
    `setup-complete.json` and the normal path's `setup-report.json` describe
    readiness with the same three keys, so a consumer reads either without
    knowing which path wrote it.

    `ok is None` is NOT-APPLICABLE, a third answer the renderer used to
    collapse into "fine". It is kept under its own key so a consumer can tell
    "not applicable" from "measured and passed" (§5.1), and out of `gaps`,
    which gate READY and carry a remedy.
    """
    return {"readiness": [[c[0], c[1], c[2]] for c in checks],
            "gaps": [c[0] for c in checks if c[1] is False],
            "limitations": [[c[0], c[2]] for c in checks if c[1] is None]}


def _readiness_section(record):
    """The readiness section of `setup-report.md` -- surface 4 in the artifact
    an operator is told to read (#1603), rather than only in a line that
    scrolls past.

    The verdict, then every row that was measured, then the gate-nothing rows
    through the SAME clause the fallback prints, so a limitation looks the
    same wherever it is met. Every row is listed and not just the failures:
    a disclosure surface has to say what was looked at, or a short section
    cannot be told from a short list of checks.

    Details are put through the report's own hygiene (#1120) because some of
    them quote the reviewed repository -- a refused config's errors name its
    groups -- and this text is written to a file rather than to a terminal.
    """
    out = ["## Readiness", "", _readiness_suffix(record), ""]
    out += ["- %s: %s -- %s" % (grouping_engine._clean(name, token=True),
                                _VERDICT.get(ok, ok), grouping_engine._clean(detail))
            for name, ok, detail in record["readiness"]]
    if record["limitations"]:
        out += ["", _limitations_clause(
            [(grouping_engine._clean(name, token=True), grouping_engine._clean(detail))
             for name, detail in record["limitations"]], artifact=REPORT_ARTIFACT)]
    return "\n".join(out) + "\n"


def _stored_record(document):
    """A readiness record read back off a setup artifact, SANITIZED.

    `runio._load_json` returns whatever parses and `.panopticon` is the
    reviewed tree's own directory, so a planted or hand-edited artifact
    arrives here as a list, a string, a number, or an object whose `gaps` is
    a string -- which `", ".join` would then render one character per "gap"
    (fix round 1, I3). Every shape that is not what this module writes
    degrades to "nothing recorded", because both call sites sit OUTSIDE
    `run_setup_flow`'s status protocol: a traceback there is a setup that
    succeeded, reported as a crash.

    Row tolerance is `_stored_limitations`' own -- any row that is not a
    triple is dropped rather than unpacked.
    """
    document = document if isinstance(document, dict) else {}
    rows = document.get("readiness")
    gaps = document.get("gaps")
    return {"readiness": [list(row) for row in rows
                          if isinstance(row, (list, tuple)) and len(row) == 3]
            if isinstance(rows, list) else [],
            "gaps": [gap for gap in gaps if isinstance(gap, str)]
            if isinstance(gaps, list) else [],
            "limitations": _stored_limitations(document)}


def _readiness_tail(document, artifact=REPORT_ARTIFACT):
    """The readiness tail for a COMPLETED setup, read back off the artifact
    that path wrote -- `setup-report.json`, whose name the overflow tail
    carries, since the normal path is this helper's caller. The vocab-absent
    fallback assembles its own two lines from the same two helpers: its
    completion line is unchanged by #1603, which means it still says nothing
    when readiness is clean.

    It is read back rather than passed down because the completion message is
    assembled after the engine returns -- and on a re-invocation that finds
    the work already done, no phase ran at all and the artifact is the only
    thing that remembers.

    An artifact carrying no readiness rows gets NO tail -- absent, empty, or
    rows of a shape this module never wrote. `readiness OK` over a setup that
    never measured is the exact inversion §5.1 forbids, and a version that
    predates this record, or a target-supplied file, is precisely the case
    where nobody looked. (An empty LIST used to satisfy the old
    `isinstance(..., list)` guard and render `readiness OK`, which is the
    docstring promising what the code did not do -- fix round 1, M1.)
    """
    record = _stored_record(document)
    if not record["readiness"]:
        return ""
    tail = " — " + _readiness_suffix(record)
    if record["limitations"]:
        tail += "\n" + _limitations_clause(record["limitations"], artifact=artifact)
    return tail
