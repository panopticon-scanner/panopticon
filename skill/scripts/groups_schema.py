"""Parse + validate the 5.0 matrix `groups.yml` (match/tests/panels/exclude).

Extends the 4.x groups.yml (match-only) with the matrix fields. Pure: takes an
already-loaded dict, returns (groups, errors). No file I/O. See spec §3.
"""

DOMAINS = frozenset(
    {"SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG"})


def _as_domain_set(name, field, raw, errors):
    out = set()
    for d in raw or []:
        if d not in DOMAINS:
            errors.append(f"group {name}: {field} {d!r} is not a known domain")
        else:
            out.add(d)
    return out


def parse_groups(doc):
    """Return (groups, errors). `groups` maps name -> normalized group dict."""
    groups, errors = {}, []
    for name, raw in ((doc or {}).get("groups") or {}).items():
        raw = raw or {}
        match = list(raw.get("match") or [])
        if not match:
            errors.append(f"group {name}: match must be a non-empty list")
        floor = _as_domain_set(name, "panels", raw.get("panels"), errors)
        exclude = _as_domain_set(name, "exclude", raw.get("exclude"), errors)
        for d in sorted(floor & exclude):
            errors.append(f"group {name}: {d} is in both floor and exclude")
        groups[name] = {
            "match": match,
            "tests": list(raw.get("tests") or []),
            "floor": floor,
            "exclude": exclude,
        }
    return groups, errors
