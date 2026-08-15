"""Parse + validate the 5.0 matrix `groups.yml` (match/tests/panels/exclude).

Extends the 4.x groups.yml (match-only) with the matrix fields. Pure: takes an
already-loaded dict, returns (groups, errors). No file I/O. See spec §3.
"""

DOMAINS = frozenset(
    {"SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG"})


def _as_domain_set(name, field, raw, errors):
    out = set()
    if raw is None:
        return out
    if not isinstance(raw, list):
        errors.append(f"group {name}: {field} must be a list")
        return out
    for d in raw:
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
        raw_match = raw.get("match")
        if not isinstance(raw_match, list) or not raw_match:
            errors.append(f"group {name}: match must be a non-empty list")
            match = []
        else:
            match = list(raw_match)
        raw_tests = raw.get("tests")
        if raw_tests is None:
            tests = []
        elif not isinstance(raw_tests, list):
            errors.append(f"group {name}: tests must be a list")
            tests = []
        else:
            tests = list(raw_tests)
        floor = _as_domain_set(name, "panels", raw.get("panels"), errors)
        exclude = _as_domain_set(name, "exclude", raw.get("exclude"), errors)
        for d in sorted(floor & exclude):
            errors.append(f"group {name}: {d} is in both floor and exclude")
        groups[name] = {
            "match": match,
            "tests": tests,
            "floor": floor,
            "exclude": exclude,
        }
    return groups, errors
