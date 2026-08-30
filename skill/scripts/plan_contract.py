"""Shared structural and artifact-root contracts for Panopticon plans."""
import os

try:  # dual import convention (#742): both `scripts.plan_contract` and a bare
    from scripts import groups_schema  # `import plan_contract` occur in-tree.
except ModuleNotFoundError:  # imported flat, with skill/scripts on sys.path
    import groups_schema


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


def driver_plan_issues(plan):
    """Return structural problems in a 5.0 DRIVER (matrix domain-cell) plan.

    The resumable driver fans out one reviewer per (group, domain) MATRIX CELL,
    so its `dispatch-plan-driver.json` declares domain cells. Each entry is a
    dict carrying a non-empty str `group`, a `domain` in groups_schema.DOMAINS,
    and an `out_file` whose BASENAME is exactly `findings-<group>-<domain>.json`
    (the deterministic spelling driver._cell_entry writes, so
    reconcile_findings_files agrees). Returns issue strings ([] = valid); a
    valid driver plan feeds reconcile_findings_files / snapshot_out_files.
    Structural only -- it declares which out_files the review fan-out was to
    write; it never confers scope trust (no scope_sha256/depth binding).

    #run10: this is now the ONLY plan contract. The 4.x per-group panel
    contract it was once "distinct from" (plan_issues / assignment_issues /
    output_issues, all keyed on the retired panel_review + lens_sweep roles)
    was retired with them -- it rejected every plan the driver can write.
    """
    if not isinstance(plan, list):
        return ["driver plan is not a JSON array"]
    if not plan:
        return ["driver plan has no reviewer entries"]
    issues = []
    for index, entry in enumerate(plan):
        if not isinstance(entry, dict):
            issues.append("entry %d is not an object" % index)
            continue
        group = entry.get("group")
        group_ok = isinstance(group, str) and bool(group)
        if not group_ok:
            issues.append("entry %d has no non-empty group" % index)
        domain = entry.get("domain")
        domain_ok = domain in groups_schema.DOMAINS
        if not domain_ok:
            issues.append("entry %d has unsupported domain %r" % (index, domain))
        out_file = entry.get("out_file")
        if not isinstance(out_file, str) or not out_file:
            issues.append("entry %d has no non-empty out_file" % index)
        elif group_ok and domain_ok and os.path.basename(out_file) != (
                "findings-%s-%s.json" % (group, domain)):
            issues.append("entry %d out_file basename does not match "
                          "findings-<group>-<domain>.json" % index)
    return issues
