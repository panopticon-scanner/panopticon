"""Common location records for the OCRDb gap and strain reports."""


def occurrence(finding, run_id=None):
    """Build an occurrence, or None when the finding has no file."""
    loc = finding.get("location") or {}
    if not loc.get("file"):
        return None
    record = {"file": loc["file"]}
    for key in ("line_start", "line_end"):
        if loc.get(key) is not None:
            record[key] = loc[key]
    if finding.get("id"):
        record["finding_id"] = finding["id"]
    if run_id:
        record["run_id"] = run_id
    return record
