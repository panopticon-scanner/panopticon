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
_LIMITATION_LINE = 119          # strictly under the 120-column bar
_LIMITATION_MAX = 12            # remedies shown before the "and N more" tail
_TRUNCATED = "..."


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


def _limitations_clause(limitations):
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
        out.append("  - and %d more -- full text in "
                   ".panopticon/setup-complete.json `limitations`"
                   % (len(rows) - len(shown)))
    return "\n".join(out)


def _stored_limitations(marker):
    """The `limitations` pairs from a setup-complete.json, or []. Tolerates a
    marker written before the key existed, and any row that is not a pair."""
    return [(row[0], row[1]) for row in ((marker or {}).get("limitations") or [])
            if isinstance(row, (list, tuple)) and len(row) == 2]
