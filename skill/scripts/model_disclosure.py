"""Cross-run disclosure of model fallbacks and strict state (#3626).

#3582 records, per run, whether model fallbacks were off (`meta.model_strict`)
and every dispatch that ran on a fallback rung (`meta.model_substitutions`).
Two runs compared as if they ran the same models when one fell back, or ran
non-strict, would hide an instrument change, so every cross-run view
(`devtools/compare_runs.py`, the HTML `--compare` view) discloses it.

Disclosure only: nothing here refuses or alters a comparison.

A report from before #3582 records neither fact. It reads as NOT RECORDED --
never as strict, and never as "no fallbacks". A report from #3582 on that
recorded `model_strict` and carries no `model_substitutions` ran every dispatch
as requested (the key is present only when non-empty).

Reports are untrusted input (`--compare` is the documented route for a foreign
report.json), so only well-formed records are read and the callers escape
every string they print.
"""

NOT_RECORDED = None          # a run's strict state or substitutions when it recorded neither
AS_REQUESTED = "as requested"
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
    """{"strict": True|False|None, "substitutions": [records]|None} for one run.

    None means not recorded (a report from before #3582)."""
    meta = meta if isinstance(meta, dict) else {}
    strict = meta.get("model_strict")
    strict = strict if isinstance(strict, bool) else NOT_RECORDED
    raw = meta.get("model_substitutions")
    subs: list | None
    if isinstance(raw, list):
        subs = [r for r in map(_record, raw) if r is not None]
    else:
        subs = [] if strict is not NOT_RECORDED else NOT_RECORDED
    return {"strict": strict, "substitutions": subs}


def compare_models(metas):
    """What a cross-run view must disclose about the runs' models.

    `strict`: each run's strict state (None: not recorded).
    `entries`: one row per entry that ran on a fallback in ANY run -- its role, the
    requested model, and per run the model it ran (`bound`, with the rung), "as
    requested", or None when that run recorded nothing. `same` says whether every
    run that recorded the entry ran the same model.
    `disclose`: the strict states differ (not recorded counts as its own state), or
    any run fell back. `recorded`: whether any run recorded anything at all."""
    runs = [run_models(m) for m in metas]
    strict = [r["strict"] for r in runs]
    by_entry: dict = {}
    for i, run in enumerate(runs):
        for sub in run["substitutions"] or ():
            row = by_entry.setdefault(sub["entry"], {
                "entry": sub["entry"], "role": sub["role"], "requested": sub["requested"],
                "runs": [None] * len(runs)})
            row["runs"][i] = {"bound": sub["bound"], "rung": sub["rung"],
                              "route": sub["route"], "reason": sub["reason"]}
    entries = []
    for entry in sorted(by_entry):
        row = by_entry[entry]
        for i, run in enumerate(runs):
            if row["runs"][i] is None and run["substitutions"] is not NOT_RECORDED:
                row["runs"][i] = AS_REQUESTED
        seen = [r["bound"] if isinstance(r, dict) else r for r in row["runs"] if r is not None]
        row["same"] = len(set(seen)) <= 1 and None not in row["runs"]
        entries.append(row)
    return {"strict": strict,
            "strict_differs": len(set(strict)) > 1,
            "entries": entries,
            "disclose": len(set(strict)) > 1 or bool(entries),
            "recorded": any(s is not NOT_RECORDED for s in strict)
                        or any(r["substitutions"] for r in runs)}


def strict_word(value):
    """How a run's strict state reads to an operator."""
    return {True: "fallbacks off (strict)", False: "fallbacks on"}.get(value, "not recorded")


def ran_word(value):
    """How one run's model for an entry reads to an operator."""
    if isinstance(value, dict):
        return "ran %s (fallback rung %d: %s)" % (value["bound"], value["rung"], value["reason"])
    return "ran as requested" if value == AS_REQUESTED else "not recorded"
