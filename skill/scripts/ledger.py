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
import os
import sys
import time

import scripts.money as money
import scripts.phases.runio as runio
import scripts.redact as redact
import scripts.runners.base as runners_base

PHASE_OF_CHECKPOINT = {"scout": "scout", "review": "review", "verify": "verify",
                       "scan": "unattributed"}          # R-P6-9: collect_usage.PHASES keys
USAGE_FIELDS = ("input_tokens", "output_tokens",
                "cache_creation_input_tokens", "cache_read_input_tokens")
# #1662: the two `status` values the interrupt's own rows carry -- `CANCELLED`
# for an entry it cut before it completed, `ROLLED_BACK` for the marker beside
# an entry that HAD completed and whose artifacts were then taken back. One
# owner, because `orchestrate.loop` writes them and the run's history is read
# back through them.
CANCELLED = "cancelled"
ROLLED_BACK = "rolled_back"


class Ledger:
    """runs/<tag>/dispatch-ledger.jsonl: one line per runner call (spec 4.3)."""

    def __init__(self, run_dir):
        self.path = os.path.join(run_dir, runners_base.LEDGER_FILE)

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
                "session_id": result.session_id, "denials": result.denials,
                "rejected_file": rejected_file,
                "error": refusal if refusal is not None else result.error}
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
        by_phase = {p: 0 for p in ("scout", "review", "verify", "unattributed")}
        by_field = {k: 0 for k in USAGE_FIELDS}
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
        return {"schema_version": 1, "total": sum(by_phase.values()), "by_phase": by_phase,
                "by_field": by_field, "source": runners_base.LEDGER_FILE,
                "corrupt_rows": corrupt,
                "definition": "every token the host's envelope reported for each entry "
                              "launch, failed launches included, summed over the four "
                              "usage fields"}
