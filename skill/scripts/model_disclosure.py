"""Cross-run disclosure of model fallbacks and strict state (#3626).

#3582 records, per run, whether model fallbacks were off (`meta.model_strict`)
and every dispatch that ran on a fallback rung (`meta.model_substitutions`).
Two runs compared as if they ran the same models when one fell back, or ran
non-strict, would hide an instrument change, so every cross-run view
(`devtools/compare_runs.py`, the HTML `--compare` view) discloses it.

Disclosure only: nothing here refuses or alters a comparison.

A report from before #3582 records neither fact. It reads as NOT RECORDED --
never as strict, and never as "no fallbacks". A report that recorded
`model_strict` and carries no `model_substitutions` is read as having run every
dispatch as requested: the key is present only when non-empty. That reading
rests on the run's ledger, which is where the substitutions come from. A
session-mode run has no ledger, so for it "as requested" means "no fallback was
recorded", not "proven to have run as requested".

A `model_substitutions` that is not a list is UNREADABLE (its fallbacks are
unknown), and records that fail the shape check are counted and disclosed, never
silently dropped into "none ran on a fallback".

Reports are untrusted input (`--compare` is the documented route for a foreign
report.json), so only well-formed records are read and the callers escape
every string they print.
"""

NOT_RECORDED = None          # a run's strict state or substitutions when it recorded neither
AS_REQUESTED = "as requested"
# A run that recorded fallbacks but dropped some unreadable records: an entry missing from
# it may have run as requested, or its record may be one of the dropped ones.
MAYBE_UNREADABLE = "as requested or unreadable"
_TEXT = ("entry", "role", "requested", "bound", "route", "reason")


def _record(value):
    """A substitution record with every field well-formed, else None."""
    if not isinstance(value, dict):
        return None
    if not all(isinstance(value.get(k), str) and value.get(k) for k in _TEXT):
        return None
    rung = value.get("rung")
    if not isinstance(rung, int) or isinstance(rung, bool) or rung < 1:
        return None
    return {k: value[k] for k in _TEXT + ("rung",)}


def run_models(meta):
    """One run's model facts.

    `strict`: True, False, or None (not recorded). `substitutions`: the readable
    records, first record per entry winning as the producer's does, or None when
    the run recorded nothing or its list is unreadable. `dropped`: records that
    failed the shape check. `malformed`: the
    key is present but not a list."""
    meta = meta if isinstance(meta, dict) else {}
    strict = meta.get("model_strict")
    strict = strict if isinstance(strict, bool) else NOT_RECORDED
    raw = meta.get("model_substitutions")
    subs: list | None
    dropped, malformed = 0, False
    if isinstance(raw, list):
        subs, seen = [], set()
        for record in map(_record, raw):
            if record is None:
                dropped += 1
                continue
            if record["entry"] in seen:          # first write wins, as the producer's
                continue
            seen.add(record["entry"])
            subs.append(record)
    elif raw is not None:
        subs, malformed = NOT_RECORDED, True
    else:
        subs = [] if strict is not NOT_RECORDED else NOT_RECORDED
    return {"strict": strict, "substitutions": subs, "dropped": dropped, "malformed": malformed}


def compare_models(metas):
    """What a cross-run view must disclose about the runs' models.

    `strict`: each run's strict state (None: not recorded).
    `entries`: one row per entry that ran on a fallback in ANY run. Per run, what
    that run did: a fallback (its own role, requested, bound, rung, route and
    reason), "as requested", "as requested or unreadable" when that run dropped
    unreadable records, or None when that run's fallbacks are unknown.
    `requested` is the one requested model every falling-back run agrees on, else
    None (print it per run). `same`: every run recorded the entry and did the same
    thing (requested, bound and route). `routes_differ`: the falling-back runs used
    different routes.
    `unreadable`: per run, how many fallback records could not be read, or "all"
    when its list is malformed.
    `disclose`: the strict states differ (not recorded counts as its own state),
    any run fell back, or any run had unreadable records. `recorded`: whether any
    run recorded anything. `partial`: some run's fallbacks are unknown, wholly or
    because it dropped unreadable records."""
    runs = [run_models(m) for m in metas]
    strict = [r["strict"] for r in runs]
    by_entry: dict = {}
    for i, run in enumerate(runs):
        for sub in run["substitutions"] or ():
            row = by_entry.setdefault(sub["entry"], {"entry": sub["entry"],
                                                     "runs": [None] * len(runs)})
            row["runs"][i] = {k: sub[k] for k in ("role", "requested", "bound", "rung",
                                                  "route", "reason")}
    entries = []
    for entry in sorted(by_entry):
        row = by_entry[entry]
        for i, run in enumerate(runs):
            if row["runs"][i] is None and run["substitutions"] is not NOT_RECORDED:
                row["runs"][i] = MAYBE_UNREADABLE if run["dropped"] else AS_REQUESTED
        fell_back = [r for r in row["runs"] if isinstance(r, dict)]
        requested = {r["requested"] for r in fell_back}
        roles = {r["role"] for r in fell_back}
        did = {(r["requested"], r["bound"], r["route"]) if isinstance(r, dict) else r
               for r in row["runs"]}
        row["requested"] = requested.pop() if len(requested) == 1 else None
        row["role"] = roles.pop() if len(roles) == 1 else None
        row["routes_differ"] = len({r["route"] for r in fell_back}) > 1
        row["same"] = (None not in row["runs"] and MAYBE_UNREADABLE not in row["runs"]
                       and len(did) == 1)
        entries.append(row)
    unreadable = ["all" if r["malformed"] else r["dropped"] for r in runs]
    return {"strict": strict,
            "strict_differs": len(set(strict)) > 1,
            "entries": entries,
            "unreadable": unreadable,
            "disclose": len(set(strict)) > 1 or bool(entries) or any(unreadable),
            "recorded": any(s is not NOT_RECORDED for s in strict)
                        or any(r["substitutions"] or r["malformed"] or r["dropped"]
                               for r in runs),
            "partial": any(r["substitutions"] is NOT_RECORDED or r["dropped"] for r in runs)}


def strict_word(value):
    """How a run's strict state reads to an operator."""
    return {True: "fallbacks off (strict)", False: "fallbacks on"}.get(value, "not recorded")


def ran_word(value, *, with_requested=False, with_route=False, with_role=False):
    """How one run's model for an entry reads to an operator. `with_requested` names
    the run's own requested model (the runs disagree on it); `with_route` names the
    route, and `with_role` the role (the runs used different ones)."""
    if isinstance(value, dict):
        return "%s%sran %s%s (fallback rung %d: %s)" % (
            "as %s, " % value["role"] if with_role else "",
            "requested %s, " % value["requested"] if with_requested else "",
            value["bound"], " via route %s" % value["route"] if with_route else "",
            value["rung"], value["reason"])
    if value == MAYBE_UNREADABLE:
        return "ran as requested, or its record is unreadable"
    return "ran as requested" if value == AS_REQUESTED else "not recorded"


def unreadable_word(value):
    """How a run's unreadable fallback records read to an operator, or "" for none."""
    if value == "all":
        return "fallback records unreadable (not a list)"
    return "%d fallback record%s unreadable" % (value, "" if value == 1 else "s") if value else ""
