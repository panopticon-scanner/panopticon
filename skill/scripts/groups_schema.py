"""Parse + validate the 5.0 matrix `groups.yml` (match/tests/panels/exclude).

Extends the 4.x groups.yml (match-only) with the matrix fields. Pure: takes an
already-loaded dict, returns (groups, errors). No file I/O. See spec §3.
"""
import re

DOMAINS = frozenset(
    {"SEC", "COD", "ARC", "TST", "QAL", "AGT", "DAT", "OPS", "ACC", "LNG"})

# #5.0-02: group names are interpolated into artifact FILENAMES and into trusted
# reviewer prompts, so a name from a (possibly hostile) committed groups.yml must
# be a strict token — no path separators, '..', leading dot, control chars, or
# trailing newline, which would escape .panopticon or inject into the task text.
_GROUP_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def _as_domain_set(name, field, raw, errors):
    out = set()
    if raw is None:
        return out
    if not isinstance(raw, list):
        errors.append(f"group {name}: {field} must be a list")
        return out
    for d in raw:
        if not isinstance(d, str) or d not in DOMAINS:
            errors.append(f"group {name}: {field} {d!r} is not a known domain")
        else:
            out.add(d)
    return out


def parse_groups(doc):
    """Return (groups, errors). `groups` maps name -> normalized group dict."""
    groups, errors = {}, []
    groups_dict = (doc or {}).get("groups") or {}
    if not isinstance(groups_dict, dict):
        errors.append("groups must be a mapping/object")
        groups_dict = {}
    for name, raw in groups_dict.items():
        if not isinstance(name, str) or ".." in name or not _GROUP_NAME_RE.match(name):
            errors.append("group name %r is invalid: must match "
                          "[A-Za-z0-9][A-Za-z0-9_.-]{0,63} with no path separators, "
                          "'..', or control characters (#5.0-02)" % (name,))
            continue
        if raw is None:
            raw = {}
        elif not isinstance(raw, dict):
            errors.append(f"group {name}: definition must be a mapping")
            raw = {}
        raw_match = raw.get("match")
        if not isinstance(raw_match, list) or not raw_match:
            errors.append(f"group {name}: match must be a non-empty list")
            match = []
        else:
            invalid_match = [x for x in raw_match if not isinstance(x, str) or not x.strip()]
            if invalid_match:
                errors.append(f"group {name}: match entries must be non-empty strings")
            match = [x for x in raw_match if isinstance(x, str) and x.strip()]
        raw_tests = raw.get("tests")
        if raw_tests is None:
            tests = []
        elif not isinstance(raw_tests, list):
            errors.append(f"group {name}: tests must be a list")
            tests = []
        else:
            invalid_tests = [x for x in raw_tests if not isinstance(x, str) or not x.strip()]
            if invalid_tests:
                errors.append(f"group {name}: tests entries must be non-empty strings")
            tests = [x for x in raw_tests if isinstance(x, str) and x.strip()]
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
