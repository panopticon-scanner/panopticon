"""Delta review: diff hunks and on-diff / pre-existing classification."""
import json
import os

import scripts.diff_map as diff_map


def load_diff_hunks(path):
    """Load the orchestrator's diff-hunks.json; {} if absent/malformed."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}

    raw = data.get("hunks")
    if not isinstance(raw, dict):
        raw = {}
    hunks = {}
    for p, rs in raw.items():
        if not isinstance(rs, list):
            continue
        cleaned = []
        for r in rs:
            if isinstance(r, (list, tuple)) and len(r) == 2 and isinstance(r[0], int) and isinstance(r[1], int):
                cleaned.append((r[0], r[1]))
        hunks[str(p)] = cleaned
    data["hunks"] = hunks
    return data

def classify_findings(findings, hunks, tolerance):
    """Stamp each finding with delta = {on_diff, hunk, distance}."""
    # synthesize runs from the review root, so an absolute location.file (e.g.
    # the worktree-absolute paths --pr panels emit) relativizes correctly against
    # cwd before matching the git-relative hunk keys (#5.0-06).
    repo_root = os.getcwd()
    for f in findings:
        f["delta"] = diff_map.classify(f, hunks, tolerance, repo_root=repo_root)
