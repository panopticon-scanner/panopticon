"""Shared structural and artifact-root contracts for Panopticon plans."""
import hashlib
import json
import os

REVIEWER_ROLES = frozenset({"panel_review", "lens_sweep"})
DEPTH_ORDER = {"shallow": 0, "standard": 1, "deep": 2}
PANELS = frozenset({"code", "test", "security", "architecture",
                    "database", "redteam"})


def artifact_root(root):
    """Return a safe in-repo ``.panopticon`` path or fail closed."""
    logical_root = os.path.abspath(root)
    physical_root = os.path.realpath(logical_root)
    path = os.path.join(logical_root, ".panopticon")
    if os.path.islink(path):
        raise ValueError(".panopticon must be a real directory, not a symlink")
    if os.path.lexists(path) and not os.path.isdir(path):
        raise ValueError(".panopticon exists but is not a directory")
    try:
        contained = os.path.commonpath(
            [physical_root, os.path.realpath(path)]) == physical_root
    except ValueError:
        contained = False
    if not contained:
        raise ValueError(".panopticon resolves outside the target root")
    return path


def plan_issues(plan):
    """Return structural problems that make a persisted plan untrustworthy."""
    if not isinstance(plan, list):
        return ["plan is not a JSON array"]
    if not plan:
        return ["plan has no reviewer entries"]
    issues = []
    for index, entry in enumerate(plan):
        if not isinstance(entry, dict):
            issues.append("entry %d is not an object" % index)
            continue
        role = entry.get("role")
        if role not in REVIEWER_ROLES:
            issues.append("entry %d has unsupported role %r" % (index, role))
        for field in ("group", "panel", "out_file"):
            if not isinstance(entry.get(field), str) or not entry[field]:
                issues.append("entry %d has no non-empty %s" % (index, field))
        if entry.get("panel") not in PANELS:
            issues.append("entry %d has unsupported panel %r"
                          % (index, entry.get("panel")))
        files = entry.get("files")
        if (not isinstance(files, list) or not files
                or not all(isinstance(path, str) and path for path in files)):
            issues.append("entry %d has malformed files" % index)
        if entry.get("depth") not in DEPTH_ORDER:
            issues.append("entry %d has invalid depth %r"
                          % (index, entry.get("depth")))
        if entry.get("security_mode") not in ("standard", "redteam"):
            issues.append("entry %d has invalid security_mode %r"
                          % (index, entry.get("security_mode")))
        if not isinstance(entry.get("run_id"), str) or not entry["run_id"]:
            issues.append("entry %d has no run_id" % index)
        if entry.get("scope_bound") is not True:
            issues.append("entry %d is not bound to an authoritative group" % index)
        if not isinstance(entry.get("scope_sha256"), str) or not entry["scope_sha256"]:
            issues.append("entry %d has no scope_sha256" % index)
    return issues


def assignment_digest(assignment):
    """Canonical digest of one trusted discovery group assignment."""
    payload = {
        "name": assignment.get("name"),
        "files": sorted(assignment.get("files") or []),
        "panels": sorted(assignment.get("panels") or []),
        "depth": assignment.get("depth"),
        "security_mode": assignment.get("security_mode", "standard"),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def assignment_issues(plan, assignment):
    """Return plan-vs-discovery mismatches for one authoritative group."""
    expected_name = assignment.get("name")
    expected_files = set(assignment.get("files") or [])
    expected_panels = set(assignment.get("panels") or [])
    expected_depth = assignment.get("depth")
    expected_security = assignment.get("security_mode", "standard")
    expected_digest = assignment_digest(assignment)
    issues = []
    panel_reviews = set()
    for index, entry in enumerate(plan if isinstance(plan, list) else []):
        if not isinstance(entry, dict) or entry.get("role") not in REVIEWER_ROLES:
            continue
        if entry.get("group") != expected_name:
            issues.append("entry %d group does not match groups.json" % index)
        files = entry.get("files")
        if not isinstance(files, list) or not all(isinstance(path, str) for path in files):
            issues.append("entry %d files are malformed" % index)
        elif set(files) != expected_files:
            issues.append("entry %d files do not match groups.json" % index)
        if entry.get("security_mode") != expected_security:
            issues.append("entry %d security_mode does not match groups.json" % index)
        if (expected_depth in DEPTH_ORDER
                and DEPTH_ORDER.get(entry.get("depth"), -1) < DEPTH_ORDER[expected_depth]):
            issues.append("entry %d depth is below groups.json" % index)
        if entry.get("scope_sha256") != expected_digest:
            issues.append("entry %d scope_sha256 does not match groups.json" % index)
        if entry.get("role") == "panel_review":
            panel_reviews.add(entry.get("panel"))
    missing = sorted(expected_panels - panel_reviews)
    if missing:
        issues.append("plan omits authoritative panel review(s): %s" % ", ".join(missing))
    return issues


def output_issues(plan, root):
    """Return output-path mismatches for deterministic reviewer artifacts."""
    try:
        artifacts = artifact_root(root)
    except ValueError as exc:
        return [str(exc)]
    issues = []
    for index, entry in enumerate(plan if isinstance(plan, list) else []):
        if not isinstance(entry, dict) or entry.get("role") not in REVIEWER_ROLES:
            continue
        role = entry.get("role")
        if role == "panel_review":
            filename = "findings-%s-%s-panel_review.json" % (
                entry.get("group"), entry.get("panel"))
        else:
            lens = entry.get("lens")
            if not isinstance(lens, str) or not lens:
                issues.append("entry %d has no lens" % index)
                continue
            filename = "findings-%s-%s-lens_sweep-%s.json" % (
                entry.get("group"), entry.get("panel"), lens)
        expected = os.path.realpath(os.path.join(artifacts, filename))
        actual = entry.get("out_file")
        if (not isinstance(actual, str) or not os.path.isabs(actual)
                or os.path.realpath(actual) != expected or os.path.islink(actual)):
            issues.append("entry %d out_file does not match deterministic artifact path"
                          % index)
    return issues
