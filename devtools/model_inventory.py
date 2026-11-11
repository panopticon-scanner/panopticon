#!/usr/bin/env python3
"""Every host model list in one table, with each list's last-verified date (#3563).

    python3 devtools/model_inventory.py [--json]

THE TABLES. Each one is a list that goes stale as providers ship and retire models:

- `profiles:<host>`: one per host block in `skill/reference/model-profiles.yml`,
  the role -> model table `model_resolver.resolve_model` reads first. The
  `_*_FALLBACK` dicts in model_resolver.py mirror it under a parity pin, so they
  carry no date of their own: one date per table.
- `allowlist:gemini`, `allowlist:agy`: `KNOWN_MODELS` in runners/gemini.py and
  runners/agy.py, the effective-model allowlists.
- `aliases:gemini`: `MODEL_ALIASES` in runners/gemini_home.py.

THE MARKER. Exactly one comment line in the contiguous comment block directly
above a table (a blank line ends the block):

    # models-verified: 2026-11-10 https://ai.google.dev/gemini-api/docs/models https://...

`models-verified:`, one space, an ISO date, then one or more space-separated
`https://` URLs, and nothing else. Prose may sit around it in the same block.
In the YAML, the block above a `hosts.<name>:` key; in Python, the block above
the assignment. A table with no marker is unverified and sorts first. A marker
that is malformed, doubled, not a real date, dated in the future (beyond a day
of timezone slack) or naming a non-https URL is an error, never ignored.

The tables are read as data: the YAML with `yaml.safe_load` (key lines from
`yaml.compose`), the Python sets with `ast.literal_eval`, so no runner module
is imported. No age check fails a build: the monthly sweep issue
(devtools/report_model_sweep.py) lists the stalest first instead.
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass, field
import datetime
import json
import os
import re
import sys

try:
    import yaml
except ImportError:      # the model-sweep workflow uses the runner image's python3-yaml
    sys.exit("model-inventory: PyYAML is required (python3-yaml); the model-sweep workflow "
             "expects the runner image to ship it (#3563)")

REPO = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
PROFILES = "skill/reference/model-profiles.yml"
# (table name, file, assignment name, host it constrains)
SETS = (
    ("allowlist:gemini", "skill/scripts/runners/gemini.py", "KNOWN_MODELS", "gemini"),
    ("allowlist:agy", "skill/scripts/runners/agy.py", "KNOWN_MODELS", "agy"),
    ("aliases:gemini", "skill/scripts/runners/gemini_home.py", "MODEL_ALIASES", "gemini"),
)
MARKER_KEY = "models-verified"
_MARKER = re.compile(r"models-verified: ([0-9]{4}-[0-9]{2}-[0-9]{2})((?: https://[!-~]{1,300})+)")
# A marker written late in the day ahead of UTC is not "in the future".
FUTURE_SLACK = datetime.timedelta(days=1)
# Role fields shown beside the model, in this order.
DETAIL_KEYS = ("tier", "model_reasoning_effort", "alias")


class MarkerError(ValueError):
    """A models-verified marker that does not follow the grammar."""


@dataclass(frozen=True)
class Marker:
    date: datetime.date
    urls: tuple[str, ...]


@dataclass
class Table:
    name: str
    path: str
    line: int
    marker: Marker | None
    rows: list[dict] = field(default_factory=list)
    members: frozenset[str] = frozenset()


def parse_marker(text: str, today: datetime.date | None = None) -> Marker:
    """The marker in `text` (a comment's body, without `#`), or MarkerError."""
    match = _MARKER.fullmatch(text.strip())
    if not match:
        raise MarkerError("malformed %s marker: %r" % (MARKER_KEY, text.strip()[:200]))
    try:
        date = datetime.date.fromisoformat(match.group(1))
    except ValueError:
        raise MarkerError("%s date %r is not a calendar date"
                          % (MARKER_KEY, match.group(1))) from None
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    if date > today + FUTURE_SLACK:
        raise MarkerError("%s date %s is in the future" % (MARKER_KEY, date))
    return Marker(date, tuple(match.group(2).split()))


def marker_above(lines: list[str], line: int, where: str,
                 today: datetime.date | None = None) -> Marker | None:
    """The marker in the comment block directly above 1-based `line`, if any."""
    found = []
    index = line - 2
    while index >= 0 and lines[index].strip().startswith("#"):
        body = lines[index].strip()[1:].strip()
        if body.startswith(MARKER_KEY):
            found.append(body)
        index -= 1
    if len(found) > 1:
        raise MarkerError("%s has %d %s markers; keep exactly one" % (where, len(found),
                                                                    MARKER_KEY))
    if not found:
        return None
    try:
        return parse_marker(found[0], today)
    except MarkerError as exc:
        raise MarkerError("%s: %s" % (where, exc)) from None


def _read(root: str, rel: str) -> str:
    with open(os.path.join(root, rel), encoding="utf-8") as fh:
        return fh.read()


def profile_tables(root: str, today: datetime.date | None = None) -> list[Table]:
    """One table per `hosts.<name>` block of model-profiles.yml."""
    text = _read(root, PROFILES)
    data = yaml.safe_load(text) or {}
    hosts = data.get("hosts") if isinstance(data, dict) else None
    node = yaml.compose(text)
    hosts_node = next((value for key, value in getattr(node, "value", [])
                       if getattr(key, "value", None) == "hosts"), None)
    if not isinstance(hosts, dict) or not isinstance(hosts_node, yaml.MappingNode):
        raise ValueError("%s has no hosts mapping" % PROFILES)
    lines = text.splitlines()
    tables = []
    for key, _value in hosts_node.value:
        host = key.value
        line = key.start_mark.line + 1
        where = "%s:%d (hosts.%s)" % (PROFILES, line, host)
        roles = hosts.get(host) or {}
        rows = []
        for role, cfg in roles.items():
            cfg = cfg if isinstance(cfg, dict) else {}
            rows.append({"host": host, "role": role, "model": cfg.get("model"),
                         "detail": ", ".join("%s=%s" % (k, cfg[k]) for k in DETAIL_KEYS
                                             if cfg.get(k) is not None)})
        tables.append(Table("profiles:" + host, PROFILES, line,
                            marker_above(lines, line, where, today), rows))
    return tables


def set_table(root: str, name: str, rel: str, target: str,
              today: datetime.date | None = None) -> Table:
    """The module-level `target = frozenset({...})` in `rel`, read by AST."""
    text = _read(root, rel)
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names = [node.target.id]
        else:
            continue
        if target not in names:
            continue
        value = node.value
        if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id == "frozenset" and len(value.args) == 1
                and not value.keywords):
            raise ValueError("%s %s is not a literal frozenset" % (rel, target))
        members = ast.literal_eval(value.args[0])
        if not all(isinstance(m, str) for m in members):
            raise ValueError("%s %s holds a non-string" % (rel, target))
        where = "%s:%d (%s)" % (rel, node.lineno, target)
        return Table(name, rel, node.lineno,
                     marker_above(text.splitlines(), node.lineno, where, today),
                     members=frozenset(members))
    raise ValueError("%s has no module-level %s" % (rel, target))


def inventory(root: str = REPO, today: datetime.date | None = None) -> list[Table]:
    """Every table, with each profile row's allowlist membership filled in."""
    tables = profile_tables(root, today)
    sets = [set_table(root, name, rel, target, today) for name, rel, target, _ in SETS]
    allowed: dict[str, set[str]] = {}
    for (_name, _rel, _target, host), table in zip(SETS, sets):
        allowed.setdefault(host, set()).update(table.members)
    for table in tables:
        for row in table.rows:
            members = allowed.get(row["host"])
            row["allowlisted"] = ("-" if members is None or row["model"] is None
                                  else "yes" if row["model"] in members else "NO")
    return tables + sets


def stalest_first(tables: list[Table]) -> list[Table]:
    """Unverified tables first, then the oldest verification date."""
    return sorted(tables, key=lambda t: (t.marker is not None,
                                         t.marker.date if t.marker else datetime.date.min,
                                         t.name))


def to_json(tables: list[Table]) -> dict:
    return {"tables": [{"name": t.name, "path": t.path, "line": t.line,
                        "verified": t.marker.date.isoformat() if t.marker else None,
                        "urls": list(t.marker.urls) if t.marker else [],
                        "members": sorted(t.members), "rows": t.rows}
                       for t in tables]}


def text_lines(tables: list[Table]) -> list[str]:
    lines = ["tables (stalest first):"]
    for t in stalest_first(tables):
        lines.append("  %-19s %-10s %s:%d%s" % (
            t.name, t.marker.date.isoformat() if t.marker else "unverified", t.path, t.line,
            "".join("\n      " + url for url in (t.marker.urls if t.marker else ()))))
    lines.append("models:")
    lines.append("  %-11s %-15s %-28s %-11s %s" % ("host", "role", "model", "allowlisted",
                                                   "detail"))
    for t in tables:
        for row in t.rows:
            lines.append(("  %-11s %-15s %-28s %-11s %s" % (
                row["host"], row["role"], row["model"] if row["model"] else "(inherit)",
                row["allowlisted"], row["detail"])).rstrip())
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="print JSON")
    args = parser.parse_args(argv)
    try:
        tables = inventory()
    except (MarkerError, ValueError, OSError, yaml.YAMLError) as exc:
        print("model-inventory: %s" % exc, file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(to_json(tables), indent=2, sort_keys=True))
    else:
        print("\n".join(text_lines(tables)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
