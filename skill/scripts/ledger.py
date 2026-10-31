"""scripts.ledger: the dispatch ledger (spec 4.3), split out of `orchestrate.py`
so the entry script stays under its own size instruction rather than the
package ratchet (item 21 took it to 729 lines; this is a pure move, no
behaviour change -- see #1648 and `scripts.money` for why the money itself
already lived in its own module).

`Ledger` is `orchestrate.loop`'s only writer and reader of
`runs/<tag>/dispatch-ledger.jsonl`: `record` appends one line per runner call,
and `_rows`/`lines`/`total_cost`/`usage_document` are its readers -- the last
two go through `scripts.money` for the exact-decimal cost arithmetic and the
`LedgerCorrupt` fault a line that cannot be read back as money raises.
"""
import json
import math
import os
import sys
import time
from decimal import Decimal

import scripts.guard_rules as guard_rules
import scripts.money as money
import scripts.phases.persist as persist
import scripts.phases.runio as runio
import scripts.redact as redact
import scripts.runners.base as runners_base
from scripts.collect_usage import PHASES, USAGE_FIELDS

PHASE_OF_CHECKPOINT = {"scout": "scout", "review": "review", "verify": "verify",
                       "scan": "unattributed"}          # R-P6-9: collect_usage.PHASES keys
MODEL_USAGE_FIELDS = {"inputTokens": "input_tokens", "outputTokens": "output_tokens",
                      "cacheCreationInputTokens": "cache_creation_input_tokens",
                      "cacheReadInputTokens": "cache_read_input_tokens"}


def _measured_model_fields(details):
    """Only figures the host actually reported can enter a model roll-up."""
    if not isinstance(details, dict):
        return {}
    fields: dict[str, int | float] = {
        target: value for source, target in MODEL_USAGE_FIELDS.items()
        if isinstance((value := details.get(source)), int)
        and not isinstance(value, bool) and value >= 0}
    cost = details.get("costUSD")
    if (isinstance(cost, (int, float)) and not isinstance(cost, bool)
            and cost >= 0 and (not isinstance(cost, float) or math.isfinite(cost))):
        fields["cost_usd"] = cost
    return fields
# #1662: the two `status` values the interrupt's own rows carry -- `CANCELLED`
# for an entry it cut before it completed, `ROLLED_BACK` for the marker beside
# an entry that HAD completed and whose artifacts were then taken back. One
# owner, because `orchestrate.loop` writes them and the run's history is read
# back through them.
CANCELLED = "cancelled"
ROLLED_BACK = "rolled_back"


def _guard_reasons(path, wanted):
    """{tool_use_id: the hook's reason} from the hooks' sidecar (#3234), for `wanted` ids only.

    The join can only annotate a denial the HOST reported: a sidecar row matching none is ignored,
    so nothing written there can add a denial or move an `ok`, a tally or a retry. Bounded by
    `DENIALS_CAP`, and a damaged line (a full disk's short write) is skipped. A missing file is the
    ordinary case: nothing the hook denied, or a host with no such hook."""
    out: dict = {}
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as fh:
            lines = fh.read(guard_rules.DENIALS_CAP + guard_rules.DENIAL_REASON_CAP).splitlines()
    except OSError:
        return out
    for raw in lines:
        try:
            row = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        key, reason = row.get("tool_use_id"), row.get("reason")
        if isinstance(key, str) and key in wanted and key not in out and isinstance(reason, str):
            out[key] = reason
    return out


def _with_reasons(path, rows):
    """A copy of the host's denial rows, each carrying the hook's own `reason` where it left one.
    Redacted and bounded here, the single writer. `tool_input` beside it stays as the host wrote it.
    `RunResult.denials` is never touched: `phases.denials` reads the host's report, not this."""
    wanted = {row.get("tool_use_id") for row in rows if isinstance(row, dict)
              and isinstance(row.get("tool_use_id"), str)} if isinstance(rows, list) else None
    if not wanted:
        return rows
    reasons = _guard_reasons(path, wanted)
    return [dict(row, reason=redact.redact(reasons[row["tool_use_id"]])[:guard_rules.DENIAL_REASON_CAP])
            if isinstance(row, dict) and row.get("tool_use_id") in reasons else row for row in rows]


def _self_write_failed(entry, result, refusal):
    """A self-writing entry whose launch came back fine and left no good artifact. Its `result` is
    the only sentence naming the cause. `ok` does not change: the tally and the retries read it."""
    if (not result.ok or refusal is not None or entry.get("delivery") == "return_json"
            or not entry.get("out_file")):
        return False
    try:
        return not persist.is_done(entry)
    except Exception:  # noqa: BLE001 -- this row is evidence of a launch already paid for
        return False


class Ledger:
    """runs/<tag>/dispatch-ledger.jsonl: one line per runner call (spec 4.3)."""

    def __init__(self, run_dir):
        self.path = os.path.join(run_dir, runners_base.LEDGER_FILE)
        # #3349: entry id -> `(result, refusal)` for every REAL row this process appended since
        # `mark_batch`, or None outside a batch. The graceful interrupt's settlement authority:
        # held in memory, so nothing the reviewed tree can edit decides what an interrupt keeps.
        self.settled = None

    def mark_batch(self):
        """Start this batch's settlement record (#3349); called as the batch opens."""
        self.settled = {}

    def record(self, entry, checkpoint, result, mode, host, duration_ms=None,
               refusal=None, timing=None, rejected_file=None,
               status=None, rolled_back=False):
        """One line per runner call.

        `refusal` (fix round 2) overrides the LAUNCH's own verdict. A return-persist
        reply that persist refused came back from a runner that reported success --
        `result.ok` is True -- but the entry did not advance, so a row saying `ok: true`
        would both overstate the run and disagree with the per-entry failure cap that is
        about to count it. The usage and cost stay the real launch's: those tokens were
        spent whatever the reply turned out to be (M2).

        `timing` (P07, #1636) is the runner's `{started_at, finished_at, duration_ms}`
        for this entry, measured around `run_entry` itself. The row GAINS two keys and
        loses none: every reader of the older shape -- `usage_document`'s
        `phase`/`usage`, `total_cost`'s `cost_usd` -- reads exactly what it always did.
        `duration_ms` defaults from it too, rather than being spelled twice at the call
        site, where the two could drift apart (F5).

        `ts` comes from that SAME dict (#1685). It used to be its own
        `time.gmtime()` read, and all three stamps are second-resolution ISO strings,
        so two reads straddling a second boundary truncate to different seconds: CI
        produced a row whose write time was one second EARLIER than the start of the
        entry it records. Reading the loop's persist moment off a second clock bought
        nothing -- the loop persists each entry as it arrives, so the entry's own
        finish IS when the row is written, to the resolution the row carries -- and it
        made an ordering the code never guaranteed look like one it did. A row with NO
        timing (the interrupt's, from `rollback_rows`) still stamps the clock: there
        the write time is the interrupt's own moment, which is the fact wanted.

        `status` and `rolled_back` (#1662) are the interrupt's. A Ctrl-C writes one
        row per entry of the batch it CUT -- `status: CANCELLED`, `rolled_back: true`,
        and a `ts` that is the interrupt's own moment -- so the run's history says what
        was stopped instead of leaving a silent gap. They are written ONLY when set, so
        a completed row's shape is byte-for-byte what it was (ruling 5) and every
        existing reader of it is untouched. And they come through `record` rather than
        through a second writer for the same reason the money does: this method is the
        only thing that appends to dispatch-ledger.jsonl, and a second appender is how
        two spellings of one row begin.

        A cancelled entry never completed, so it has no cost: `result.cost_usd` is None,
        which `money.cost_fault` reads as "no cost" rather than as an unreadable one --
        the budget gate fails CLOSED, so a row it could not read would end every
        interrupted run with a money complaint instead of the interrupt's own
        message."""
        timing = timing or {}
        duration_ms = timing.get("duration_ms") if duration_ms is None else duration_ms
        line = {"ts": (timing.get("finished_at")
                       or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
                "entry_id": entry.get("id"), "checkpoint": checkpoint,
                "phase": PHASE_OF_CHECKPOINT.get(checkpoint, "unattributed"),
                "mode": mode, "host": host, "model": result.model,
                "ok": result.ok and refusal is None,
                "usage": {k: int(result.usage.get(k, 0) or 0) for k in USAGE_FIELDS} if result.usage else {},
                "cost_usd": result.cost_usd, "duration_ms": duration_ms,
                "started_at": timing.get("started_at"), "finished_at": timing.get("finished_at"),
                "session_id": result.session_id,
                "denials": _with_reasons(os.path.join(os.path.dirname(self.path),
                                                      guard_rules.DENIALS_FILE), result.denials),
                "rejected_file": rejected_file,
                "error": refusal if refusal is not None else result.error}
        models = getattr(result, "models", None)
        if models:
            line["models"] = models
        # Host errors and persistence refusals can quote credentials. Redact at
        # the single writer, preserving null when the row has no error (#1709).
        if line["error"] is not None:
            line["error"] = redact.redact(line["error"])
        # #1732: what the CLI printed on stderr, on a FAILED row only. Written
        # ONLY when the launch produced something, so a completed row's shape
        # is byte-for-byte what it was (the same rule `status`/`rolled_back`
        # follow) and no success row carries a stream nobody asked about.
        #
        # Redacted AGAIN here even though every family redacts on the way out:
        # this method is the single appender to dispatch-ledger.jsonl, so it
        # is where the guarantee can be made once instead of trusted from six
        # call sites -- and bounded again at the same seam constant, because a
        # family that grew its own idea of "the head" must not widen a row.
        stderr = getattr(result, "stderr", None)
        if stderr and not line["ok"]:
            line["stderr"] = redact.redact(str(stderr))[:runners_base.STDERR_HEAD]
        # #3234: written only when set, so every other row's shape is what it was. Neither is read
        # by a done predicate: they answer an auditor's question, not the loop's.
        if entry.get("delivery") == "return_json" and getattr(result, "reply_via", None):
            line["reply_via"] = result.reply_via
        if _self_write_failed(entry, result, refusal) and result.text:
            line["result_head"] = redact.redact(str(result.text))[:runners_base.STDERR_HEAD]
        if status is not None:
            line["status"] = status
        if rolled_back:
            line["rolled_back"] = True
        # #1648: `money.ledger_text` is this file's only writer. A non-finite cost
        # is dropped to null INTO THE ROW (its `error` says so) and never reaches
        # disk: `json.dumps` emits a bare `NaN` token that the decoder then
        # accepts, which is how a poisoned cost reached the budget comparison.
        text, note = money.ledger_text(line)
        if note:
            print("driver loop: %s: %s" % (line.get("entry_id"), note),
                  file=sys.stderr, flush=True)
        # #1095, plan 6 review round 1: the ledger path is a `.panopticon`
        # artifact like any other; a plain `open(path, "a")` bypasses the
        # symlink confinement every other run-folder write goes through.
        with runio._open_a_nofollow(self.path) as fh:
            fh.write(text + "\n")
        # AFTER the append, never before: an entry is settled once its real row is on disk, and
        # an interrupt's own rows (`status`) settle nothing.
        if status is None and self.settled is not None:
            self.settled[line["entry_id"]] = (result, refusal)

    def rollback_rows(self, entries, completed, checkpoint, mode, host, reason="Ctrl-C"):
        """Write the interrupt's rows for one rolled-back batch (#1662): one
        per entry, through `record`, which is still the ledger's only writer.

        Two kinds, because an interrupted batch leaves two kinds of entry
        behind and a reader has to be able to tell them apart:

        * an entry that never completed is `CANCELLED` -- it was cut, and
          nothing was spent on it that the host reported;
        * an entry that HAD completed gets a `ROLLED_BACK` marker BESIDE its
          real row. The real row is untouched: it carries the spend, and spend
          is a fact. But without the marker nothing in the file says that the
          artifact that row paid for was then deleted, so a reader totting up
          what the run produced would count a findings file that is not there.

        Appended, never retro-edited: `dispatch-ledger.jsonl` is append-only,
        and rewriting a line that is already evidence is how a ledger stops
        being one. Both kinds carry no cost and `ok: false`, so `total_cost`,
        `usage_document` (`corrupt_rows` included) and the usage probe's own
        `ok`-filtered read all answer exactly what they did before.
        """
        completed = set(completed or ())
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            eid = entry.get("id")
            cut = eid not in completed
            self.record(entry, checkpoint,
                        runners_base.RunResult.failed(
                            eid, ("cancelled (%s) before it completed" % reason) if cut
                            else ("rolled back (%s): this entry's artifacts were removed" % reason)),
                        mode, host,
                        status=CANCELLED if cut else ROLLED_BACK, rolled_back=True)

    def _rows(self):
        """`(line_no, row, reason)` per ledger line (money.read_rows).

        An ABSENT ledger is not an error: a run that launched nothing spent
        nothing. A ledger that is THERE and cannot be opened is the opposite --
        "nothing spent" is the one answer that is certainly wrong -- so it
        becomes a file-level fault at line 0 (fix round 1, M2): `total_cost`
        refuses the run over it, `lines()` still answers `[]`, and
        `usage_document` counts it as the one corrupt row it is."""
        try:
            with open(self.path, encoding="utf-8") as fh:
                return list(money.read_rows(fh))
        except FileNotFoundError:
            return []
        except OSError as exc:
            return [(0, None, "ledger unreadable: %s" % exc)]

    def lines(self):
        """Every row that could be read, SILENTLY DROPPING the rest -- for the
        readers that want the launches, not the money. Any reader of the cost
        must go through `_rows()` (via `total_cost`/`money.cost_fault`), which
        reports what this one discards.

        #1648: the old whole-file `except ValueError` was intolerant instead --
        ONE unreadable line returned `[]` and blanked the ledger for everyone."""
        return [row for _line_no, row, _reason in self._rows() if row is not None]

    def total_cost(self):
        """The cumulative reported cost, exactly (#1648): `Decimal`, never `float`
        -- three ledgered $0.15 rows are $0.45, and the float sum of them is
        0.44999999999999996, one paid entry short of a $0.45 budget. Raises
        `money.LedgerCorrupt` rather than summing past a line it cannot read."""
        return money.sum_costs(self._rows())

    def usage_document(self):
        by_phase = {p: 0 for p in PHASES}
        by_field = {k: 0 for k in USAGE_FIELDS}
        by_model_tokens: dict[str, dict[str, int]] = {}
        by_model_costs: dict[str, Decimal] = {}
        corrupt = 0
        for _line_no, row, reason in self._rows():
            # #1648: tokens are not dollars. A row whose MONEY is unreadable still
            # records tokens that were really spent, so they are counted and the
            # document says how many such rows it read -- where `total_cost`, over
            # those very same rows, refuses the run.
            corrupt += 1 if money.cost_fault(row, reason) else 0
            if row is None:
                continue
            # M2: a FAILED launch counts too. `claude -p` reports usage on an is_error envelope
            # exactly as it does on success, and those tokens were really spent -- a timed-out or
            # errored entry is often the most expensive one in a run. Skipping them made
            # usage.json (and meta.cost.tokens, which is read straight off it) under-report what
            # the run cost, which is the one thing an honest ledger must never do.
            usage = row.get("usage") or {}
            n = sum(int(usage.get(k, 0) or 0) for k in USAGE_FIELDS)
            by_phase[row.get("phase") or "unattributed"] = by_phase.get(row.get("phase") or "unattributed", 0) + n
            for k in USAGE_FIELDS:
                by_field[k] += int(usage.get(k, 0) or 0)
            models = row.get("models")
            if isinstance(models, dict):
                for name, details in models.items():
                    measured = _measured_model_fields(details)
                    if not measured:
                        continue
                    totals = by_model_tokens.setdefault(name, {})
                    for field, value in measured.items():
                        if field == "cost_usd":
                            by_model_costs[name] = (by_model_costs.get(name, Decimal(0))
                                                    + Decimal(str(value)))
                        else:
                            totals[field] = totals.get(field, 0) + int(value)
        by_model: dict[str, dict[str, int | float]] = {
            name: dict(fields) for name, fields in by_model_tokens.items()}
        for name, cost in by_model_costs.items():
            by_model[name]["cost_usd"] = float(cost)
        return {"schema_version": 1, "total": sum(by_phase.values()), "by_phase": by_phase,
                "by_field": by_field, "by_model": by_model,
                "source": runners_base.LEDGER_FILE,
                "corrupt_rows": corrupt,
                "definition": "every token the host's envelope reported for each entry "
                              "launch, failed launches included, summed over the four "
                              "usage fields"}
