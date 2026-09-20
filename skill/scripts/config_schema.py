"""The `settings:` trust classes and the ratchet (#1681 Plan 2, spec §4).

The root config is TARGET-AUTHORED and read before dispatch, so a key under
`settings:` is worth exactly what its CLASS says it is worth:

  grain     -- how the review is CUT (sizes, fixtures). Honoured when
               well-typed; the two size knobs are clamped to a band, because
               `max_per_group: 100000` collapses the whole matrix into one
               unreadable cell and `max_groups: 1` collapses it the other way.
  gate      -- how the review JUDGES (security mode, gate threshold, report
               severity floor, gate scope, scanners, verify cap). Honoured
               only when the value is at least as strict as panopticon's own
               default: a target may tighten its own review, never loosen it.
  operator  -- per-invocation choices belonging to the person RUNNING the
               review (allow_unenforced, egress/online, diff_context, host,
               base, pr, the scope selectors, the loop's bounds). Refused on
               sight: disclosed, ignored, counted.

The command line wins in both directions and is never clamped. A refused
line changes nothing about posture -- `tool_policy_enforced` is not refuted
by a config key -- but the refusal is visible in `meta.config`, in the run
manifest and on the terminal summary.

Pure: three stdlib imports, nothing from the tree, no file I/O except the
run-artifact reader at the bottom, so any module may import it. The config
FILENAMES live in `repo_config.py` and are never spelled here
(tests/test_repo_config_literals.py).
"""
import json
import math
import os
from collections import namedtuple

GRAIN_KEYS = ("include_fixtures", "max_groups", "max_per_group")
GATE_KEYS = ("fail_on", "gate_scope", "max_verify", "security", "severity", "tools")
# Every per-invocation flag of `driver run` / `driver loop`, plus the two
# egress names a future spec may introduce. Enumerated rather than inferred:
# tests/test_config_schema.py walks the real parser and fails on a dest that
# is in neither this tuple nor the two above, so a new flag cannot land
# unclassified (spec §4).
OPERATOR_ONLY_KEYS = (
    "allow_unenforced", "base", "concurrency", "diff_context", "egress",
    "entry_timeout", "host", "max_budget_usd", "max_iterations", "max_turns",
    "mode", "no_tools", "online", "pr", "reset", "scope_changed", "scope_dir",
    "scope_file", "scope_files", "scope_group", "session_dir", "setup", "target",
)
CLASS_OF = dict([(k, "grain") for k in GRAIN_KEYS]
                + [(k, "gate") for k in GATE_KEYS]
                + [(k, "operator") for k in OPERATOR_ONLY_KEYS])

# Grain, but TOP-LEVEL rather than under `settings:` (groups_schema.
# parse_exclude_paths owns it). Named so the refusal for `settings:
# exclude_paths:` can say where the key really goes.
TOP_LEVEL_GRAIN = ("exclude_paths",)

INT_KEYS = ("max_groups", "max_per_group", "max_verify")
BOOL_KEYS = ("include_fixtures", "tools")
ENUM_KEYS = {"fail_on": ("critical", "high", "medium", "low"),
             "gate_scope": ("on-diff", "all"),
             "security": ("standard", "redteam"),
             "severity": ("all", "critical", "high", "medium")}

# Ruling 6b: the bands. 48 is `discovery.DEFAULT_MAX_PER_GROUP`, the engine's
# own cap; 8 / 4 / 64 are the owner's other three bounds. A CLI value is NOT
# clamped -- the operator may cut the matrix however they like.
CLAMPS = {"max_per_group": (8, 48), "max_groups": (4, 64)}

# The ratchet's DIRECTION, weakest first. Written down rather than inferred,
# because "stricter" points a different way for each key: a LOWER `fail_on`
# threshold fails on more findings, a HIGHER `severity` floor reports fewer,
# `gate_scope: all` judges more than `on-diff`, and `tools: false` removes an
# input from every panel.
STRICTNESS = {
    "fail_on": (None, "critical", "high", "medium", "low"),
    "gate_scope": ("on-diff", "all"),
    "security": ("standard", "redteam"),
    "severity": ("critical", "high", "medium", "all"),
    "tools": (False, True),
}

# What the ratchet measures against: panopticon's OWN default for each gate
# key, verified in the tree at Plan 2's baseline.
#   fail_on     None  -- driver/synthesize `--fail-on` default; grading reads
#                        a falsy fail_on as gate OFF, the weakest state.
#   gate_scope  on-diff, severity all  -- synthesize.build_parser defaults.
#   security    standard -- phases/runio._DEFAULTS.
#   tools       True  -- the parser's default is None, but only
#                        `flags["tools"] is False` skips the scan
#                        (phases/tools.py), so "tools run" IS the default.
#   max_verify  None = UNCAPPED, i.e. verify every queued finding
#                        (evidence.build_verify_queue cuts nothing on None).
#                        Uncapped is the strictest setting there is, which is
#                        why a committed max_verify is refused: see the spec's
#                        2026-09-18 Amendments note, finding 1.
DEFAULTS = {"fail_on": None, "gate_scope": "on-diff", "max_verify": None,
            "security": "standard", "severity": "all", "tools": True}

_SCALARS = (str, int, float, bool, type(None))

# What a RECORD of a target-authored value may cost. `settings:` is written by
# the repository under review, and every string in it is copied into
# run-manifest.json (`config_requested` / `config_refused` /
# `config_disclosures`), into `meta.config` and onto the terminal. YAML
# anchors amplify past repo_config's source cap -- one 50 KB scalar aliased
# 2000 times is a 73 KB file that expands to a 300 MB record -- so the parse
# boundary, the one place that decides what is worth recording, bounds it:
#   MAX_RECORDED_CHARS  every recorded string (a key name, a scalar value, and
#                       the disclosure line that quotes either) is cut to this
#                       many characters, with a trailing ellipsis when it was
#                       cut. A bound, not a validator: the value is still
#                       classified and type-checked in full.
#   MAX_SETTINGS_KEYS   how many keys of the mapping are looked at AT ALL, in
#                       DOCUMENT order -- a target's real settings sit at the
#                       top of its file, so a sorted cut would be the one that
#                       drops them. The rest are one disclosure line, not one
#                       refusal each: the whole point is to stop counting.
# A non-string scalar needs no bound -- an int or a bool records as itself --
# except the one float shape that is not JSON at all; see parse_settings.
MAX_RECORDED_CHARS = 200
MAX_SETTINGS_KEYS = 32
_ELLIPSIS = "\u2026"

Parsed = namedtuple("Parsed", "requested typed refused disclosures")
EMPTY_PARSED = Parsed({}, {}, [], [])


def _bounded(text):
    """`text` cut to MAX_RECORDED_CHARS, with an ellipsis when it was cut."""
    return (text if len(text) <= MAX_RECORDED_CHARS
            else text[:MAX_RECORDED_CHARS] + _ELLIPSIS)


def _recorded(value):
    """A value on its way into `requested` or a refusal: bounded if it is a
    string, unchanged otherwise (an int or a bool is its own bound)."""
    return _bounded(value) if isinstance(value, str) else value


def _refusal(key, value, reason):
    return {"key": _bounded(str(key)), "value": _recorded(value), "reason": reason}


def _fmt(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return "null" if value is None else _bounded(str(value))


def _line(key, value, tail):
    """The one disclosure sentence shape (spec §4): the target asked for X,
    and here is what happened to it. Bounds both halves it quotes, so a line
    is safe to print and to record however long the file's own spelling was."""
    return "target config asked for `%s: %s`; %s" % (_bounded(str(key)), _fmt(value), tail)


def _typed(key, value):
    """(ok, normalised, why) for a value of a KNOWN key.

    A bool is not an int here and an int is not a bool: `max_verify: true`
    is a typo, not a 1, and `tools: 1` is a typo, not True. Enum values are
    matched case-insensitively and normalised to lower case, the same
    `type=str.lower` synthesize's own parser applies.
    """
    if key in INT_KEYS:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
            return True, value, ""
        return False, None, "expected a positive integer"
    if key in BOOL_KEYS:
        if isinstance(value, bool):
            return True, value, ""
        return False, None, "expected true or false"
    allowed = ENUM_KEYS[key]
    if isinstance(value, str) and value.strip().lower() in allowed:
        return True, value.strip().lower(), ""
    return False, None, "expected one of %s" % ", ".join(allowed)


def parse_settings(doc):
    """Classify and type-check a config document's `settings:` mapping.

    No clamp, no ratchet, no CLI: this layer answers only "which keys did the
    file spell, and are their values the right shape". `resolve_settings`
    decides what a well-typed value is worth. Nothing raises -- a hostile
    section is REFUSED, key by key, never fatal.
    """
    requested, typed, refused, disclosures = {}, {}, [], []
    raw = (doc or {}).get("settings")
    if raw is None:
        return Parsed(requested, typed, refused, disclosures)
    if not isinstance(raw, dict):
        return Parsed(requested, typed,
                      [_refusal("settings", None, "settings must be a mapping")],
                      ["target config's `settings:` is not a mapping; "
                       "the whole section is refused"])
    keys = list(raw)
    ignored = len(keys) - MAX_SETTINGS_KEYS
    if ignored > 0:
        # The cut is by DOCUMENT order; the loop below still reports in name
        # order, so what a run discloses does not depend on dict iteration.
        keys = keys[:MAX_SETTINGS_KEYS]
        disclosures.append("target config: %d more settings keys ignored"
                           % ignored)
    for key in sorted(keys, key=str):
        full = key if isinstance(key, str) else repr(key)
        name = _bounded(full)           # `full` classifies, `name` is recorded
        value = raw[key]
        scalar = isinstance(value, _SCALARS)
        # A non-finite float is refused BEFORE it can be recorded as a float:
        # json.dump's default allow_nan=True writes a bare NaN / Infinity,
        # which Python reads back and no other reader of run-manifest.json
        # accepts. Its bounded string form is recorded instead, so the refusal
        # still says what the file asked for. Checked ahead of the class
        # lookup because an UNKNOWN key records its value just the same.
        if isinstance(value, float) and not math.isfinite(value):
            shown = _fmt(value)
            requested[name] = shown
            refused.append(_refusal(name, shown, "value is not a finite number"))
            disclosures.append(_line(name, shown,
                                     "refused (value is not a finite number)"))
            continue
        klass = CLASS_OF.get(full)
        # The unknown-key branch (and its TOP_LEVEL_GRAIN hint) is checked
        # BEFORE the scalar check: `exclude_paths` is spelled at the wrong
        # level regardless of what shape its value takes, and the hint that
        # says so must fire even when the value is a list, not just when it
        # happens to be a scalar.
        if klass is None:
            hint = (" -- `exclude_paths` is a TOP-LEVEL key, not a settings key"
                    if full in TOP_LEVEL_GRAIN else "")
            shown = _recorded(value) if scalar else None
            if scalar:
                requested[name] = shown
            refused.append(_refusal(name, shown, "unknown key" + hint))
            disclosures.append(_line(name, shown, "refused (unknown key%s)" % hint))
            continue
        if not scalar:
            refused.append(_refusal(name, None, "value is not a scalar"))
            disclosures.append(_line(name, None, "refused (a settings value must be a scalar)"))
            continue
        requested[name] = _recorded(value)
        if klass == "operator":
            refused.append(_refusal(name, value, "operator-only key"))
            disclosures.append(_line(
                name, value, "refused (operator-only: it is the choice of the "
                             "person running the review, not of the repository "
                             "being reviewed)"))
            continue
        ok, normalised, why = _typed(full, value)
        if not ok:
            refused.append(_refusal(name, value, why))
            disclosures.append(_line(name, value, "refused (%s)" % why))
            continue
        typed[name] = normalised
    return Parsed(requested, typed, refused, disclosures)


Settings = namedtuple("Settings", "effective requested refused clamped disclosures")
EMPTY = Settings({}, {}, [], [], [])


def _rank(key, value):
    """How strict `value` is for `key`, as a number: higher is stricter.

    `max_verify` is the numeric one, and its None means UNCAPPED -- verify
    every queued finding -- which is stricter than any finite cap, hence the
    infinity. A value outside its key's vocabulary ranks below everything,
    which cannot happen for a parsed value and keeps the comparison total.
    """
    if key == "max_verify":
        return float("inf") if value is None else float(value)
    order = STRICTNESS[key]
    return float(order.index(value)) if value in order else -1.0


def resolve_settings(cli, parsed, defaults=None):
    """What the FILE contributes to this run, after the CLI, the clamp and
    the ratchet (spec §4, ruling 6).

    `cli` maps a classified key to the value the command line gave, or None
    where it gave none. `effective` holds only the keys the file actually
    supplies: a key the operator named on the command line is the OPERATOR's,
    in both directions, so the file's value for it is set aside and disclosed
    rather than compared. Callers compose each run value as
    `cli value if not None else resolved.effective.get(key)`.

    `defaults` exists for the tests and for the day a built-in default moves;
    production always passes None and gets DEFAULTS.
    """
    defaults = DEFAULTS if defaults is None else dict(DEFAULTS, **defaults)
    cli = cli or {}
    effective, clamped = {}, []
    refused = [dict(r) for r in parsed.refused]
    disclosures = list(parsed.disclosures)
    for key in sorted(parsed.typed):
        value = parsed.typed[key]
        if cli.get(key) is not None:
            disclosures.append(_line(key, value, "the command line's `%s` wins"
                                     % _fmt(cli[key])))
            continue
        if key in CLAMPS:
            low, high = CLAMPS[key]
            bounded = min(max(value, low), high)
            if bounded != value:
                clamped.append({"key": key, "requested": value, "effective": bounded})
                disclosures.append(_line(key, value, "clamped to %d (the band is %d-%d)"
                                         % (bounded, low, high)))
            effective[key] = bounded
            continue
        if CLASS_OF[key] == "gate":
            base = defaults.get(key)
            if _rank(key, value) >= _rank(key, base):
                effective[key] = value
                if value == base:
                    disclosures.append(_line(
                        key, value, "it is already the built-in default; nothing changes"))
            else:
                refused.append(_refusal(key, value, "loosens the built-in default (%s)"
                                        % _fmt(base)))
                disclosures.append(_line(key, value,
                                         "refused (it loosens the built-in default `%s`)"
                                         % _fmt(base)))
            continue
        effective[key] = value          # grain, no band (include_fixtures)
    return Settings(effective, dict(parsed.requested), refused, clamped, disclosures)


RESOLUTION_NAME = "config-resolution.json"
