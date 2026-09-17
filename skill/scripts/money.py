"""Exact dollars for the dispatch ledger and the `--max-budget-usd` gate (#1648).

Two defects with one fix site, both in `orchestrate.Ledger`:

* the ledger summed `float(cost)` and the gate compared it with `float(budget)`,
  so the boundary was only as exact as binary floating point -- eight ledgered
  dimes come to 0.7999999999999999 and miss a $0.80 budget by one ulp; and
* Python's JSON encoder EMITS `NaN`/`Infinity` and its decoder ACCEPTS them, so
  one non-finite cost poisoned the sum -- and `NaN >= budget` is False, which
  made a control whose entire purpose is to stop spending fail OPEN and keep
  launching paid entries.

So: money is read as `decimal.Decimal` and never as `float`; nothing non-finite
is written to the ledger (`allow_nan=False` is the backstop, not the guard); and
a line that cannot be read back as money raises `LedgerCorrupt` rather than
being summed past. The gate fails CLOSED -- a run that cannot see what it has
spent stops, because the alternative is spending on in the dark.

It lives in its own module rather than in `orchestrate.py` because the ledger's
entry script is at the top of its size ratchet and this is a self-contained
vocabulary: no imports from this package, nothing but stdlib, and every function
pure except the two that take a file handle or raise.
"""
import argparse
import decimal
import json
import math

ZERO = decimal.Decimal(0)
# What `_money` will look at. bool is excluded deliberately (see `_money`);
# Decimal is here so a caller may pass a value that has already been read.
_NUMERIC = (int, float, str, decimal.Decimal)


class LedgerCorrupt(Exception):
    """A dispatch-ledger line whose cost cannot be read as money.

    Carries the 1-based line number so the operator is told WHICH line to look
    at: the remedy is to inspect (or delete) that row, and a message that only
    said "the ledger is unreadable" would send them through the whole file.

    `line_no` 0 is the file-level fault -- the ledger is there and could not be
    opened at all -- and says so instead of naming a line nobody can go and
    look at (fix round 1, M2)."""

    def __init__(self, line_no, reason):
        self.line_no = line_no
        self.reason = reason
        where = "ledger corrupt at line %s" % line_no if line_no else "ledger corrupt"
        super().__init__("%s: %s" % (where, reason))


def _money(value):
    """`value` as an exact, finite `Decimal` -- or None when it is not money.

    Accepts int, float, str and Decimal. `Decimal(str(v))` rather than
    `Decimal(v)` on purpose: the ledger's floats came from JSON text, so the
    shortest repr that round-trips (`0.1`) is the number the host reported,
    while `Decimal(0.1)` would faithfully preserve the binary error this
    function exists to remove.

    bool is refused explicitly even though `Decimal("True")` would refuse it
    anyway: `isinstance(True, int)` is True, and a numeric reader that counts a
    flag as a dollar is the kind of thing that is only ever found afterwards."""
    if isinstance(value, bool) or not isinstance(value, _NUMERIC):
        return None
    try:
        parsed = decimal.Decimal(str(value).strip())
    except (ArithmeticError, ValueError):       # decimal.InvalidOperation is an ArithmeticError
        return None
    return parsed if parsed.is_finite() else None


def is_non_finite(value):
    """True when `value` IS a number -- or the text of one -- that is not finite.

    Deliberately narrower than `_money(value) is None`: something that is not a
    number at all (a dict, `"abc"`, a bool) is not this guard's business. The
    guard drops a non-finite cost silently-but-loudly at the moment of writing;
    an unreadable one is left in the row for `sum_costs` to refuse, where the
    operator sees the value that confused it."""
    if value is None:
        return False
    try:
        parsed = decimal.Decimal(str(value).strip())
    except (ArithmeticError, ValueError, TypeError):
        return False
    return not parsed.is_finite()


def note_error(error, note):
    """`error` extended with `note` -- the note alone when there was no error.

    A dropped cost must never overwrite the launch failure the row was written
    with: the error field is the only place either fact is recorded."""
    return note if not error else "%s; %s" % (error, note)


def scrub_non_finite(value):
    """`value` with every non-finite float replaced by None, recursively.

    The last resort behind `allow_nan=False`: a row is evidence of a launch
    that really happened, so a non-finite in some field that is not money must
    not cost the whole line. Containers are rebuilt, never mutated."""
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {k: scrub_non_finite(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_non_finite(v) for v in value]
    return value


def dumps(obj, default=None):
    """The ledger's serializer. `allow_nan=False` is the point: the default
    emits bare `NaN`/`Infinity` tokens, which are not JSON, which every other
    reader of this file would either reject or silently accept as a number.

    `default` is for `ledger_text`'s last resort only (fix round 1, L3): a row
    is evidence of a launch that was paid for, and a field json cannot encode
    must not be what loses it."""
    return json.dumps(obj, sort_keys=True, allow_nan=False, default=default)


def _reject_constant(name):
    raise ValueError("non-finite JSON constant %s" % name)


def loads(text):
    """The ledger's parser: the three non-finite constants raise instead of
    decoding. `json.loads` accepts all three by default, and that acceptance is
    how a NaN cost reached the budget comparison and made it false."""
    return json.loads(text, parse_constant=_reject_constant)


def ledger_text(line):
    """`(text, note)`: the JSON line to append for one ledger row, and what had
    to be dropped to make it writable (None when nothing was).

    `line` is mutated in place -- the caller's row IS the row that gets written,
    and the note belongs in its `error` field as well as on stderr."""
    note = None
    cost = line.get("cost_usd")
    if is_non_finite(cost):
        note = "cost_usd non-finite (%r) dropped" % (cost,)
        line["cost_usd"] = None
        line["error"] = note_error(line.get("error"), note)
    try:
        return dumps(line), note
    except (ValueError, TypeError) as exc:
        # The backstop fired. ValueError is `allow_nan=False` -- something that
        # is not money is non-finite; TypeError is a field json cannot encode at
        # all (a set, an object, whatever a host envelope puts in `denials`).
        # Neither may cost the row: it is evidence of a launch already paid for,
        # so the value is repaired, the row says which, and the line is written.
        extra = ("non-finite value dropped (%s)" % exc if isinstance(exc, ValueError)
                 else "unserializable value stored as text (%s)" % exc)
        scrubbed = scrub_non_finite(line)
        scrubbed["error"] = note_error(scrubbed.get("error"), extra)
        return dumps(scrubbed, default=repr), note_error(note, extra)


def read_rows(handle):
    """Yield `(line_no, row, reason)` for every non-blank line of a ledger.

    `row` is the parsed object and `reason` None, or `row` is None and `reason`
    says why the line could not be read. Blank lines are skipped without
    consuming a number, so a reported line number is the one an editor shows."""
    for line_no, text in enumerate(handle, 1):
        if not text.strip():
            continue
        try:
            row = loads(text)
        except ValueError as exc:
            yield line_no, None, str(exc)
            continue
        if not isinstance(row, dict):
            yield line_no, None, "line is not a JSON object"
            continue
        yield line_no, row, None


def cost_fault(row, reason):
    """Why this ledger row's money cannot be read, or None when it can.

    One definition for both readers: `sum_costs` refuses the run on the first
    fault, `usage_document` counts them and goes on (tokens are not dollars --
    they were really spent, and under-reporting them is its own dishonesty)."""
    if row is None:
        return reason or "unreadable line"
    value = row.get("cost_usd")
    if value is None:
        return None
    amount = _money(value)
    # Negative is a fault, not a credit (fix round 1, M1): a ledger row saying
    # -1000 subtracts a thousand dollars the run never got back, putting the
    # total below every budget for the rest of the run -- the #1648 fail-open
    # reached by arithmetic instead of by NaN. No host reports a refund.
    if amount is None or amount < 0:
        return "cost_usd is not a non-negative finite amount: %r" % (value,)
    return None


def sum_costs(rows):
    """The exact total of `cost_usd` over `(line_no, row, reason)` triples.

    Raises `LedgerCorrupt` on the first line that cannot be read: a budget gate
    that cannot see what was spent must stop the run, not spend past it. A row
    with no cost (`null` -- a host that reports no dollars) contributes zero, as
    it always did."""
    total = ZERO
    for line_no, row, reason in rows:
        fault = cost_fault(row, reason)
        if fault:
            raise LedgerCorrupt(line_no, fault)
        value = row.get("cost_usd")
        if value is None:
            continue
        try:
            total += _money(value)
        except decimal.DecimalException:
            # `Decimal("1E+999999999")` is finite, so it passes `_money` and
            # overflows on the `+` (fix round 1, L2). Reported as the ledger
            # fault it is, so the run ends with the gate's own refusal rather
            # than with the loop catch-all's `Overflow` (spend past an
            # unreadable cost is the thing being refused either way).
            raise LedgerCorrupt(line_no, "cost_usd out of range: %r" % (value,)) from None
    return total


def budget_arg(text):
    """argparse `type` for `--max-budget-usd`: an exact, finite, non-negative
    Decimal, refused at parse time rather than at the gate.

    `type=float` accepted `nan` (every `spent >= budget` comparison False -- the
    gate silently off, which is the #1648 failure spelled on the command line),
    `inf` and `-1`. None of the three is an amount of money, which is the whole
    of the reason: a huge budget is refused by nothing here (`1e400` parses, and
    is just as unreachable), because a number IS what the flag takes. All three
    are a typo or a shell variable that did not expand."""
    value = _money(text)
    if value is None or value < 0:
        raise argparse.ArgumentTypeError(
            "expected a finite, non-negative dollar amount, got %r" % text)
    return value
