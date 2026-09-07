"""Phase 1 -- discovery: profile the repo and write the file/group inventory."""
import sys

from . import engine
from . import runio


def discovery_done(review_root, manifest):
    return runio._json_parses(runio._pano(review_root, "groups.json"))

def discovery_execute(review_root, manifest):
    _groups, errors = runio.load_committed_groups(review_root)
    if errors:
        raise runio.DriverError("discovery: " + "; ".join(errors))
    out = runio._pano(review_root, "groups.json")
    cmd = [sys.executable, runio._script("discovery.py"), "--repo-scan",
           "--security", manifest.get("security_mode", "standard"),
           review_root, "--out", out]
    scope = manifest.get("scope") or {"mode": "repo"}
    mode = scope.get("mode")
    if mode == "changed":
        cmd += ["--scope-changed"]
    elif mode == "files":
        cmd += ["--scope-files"] + list(scope.get("target") or [])
    else:
        _scope_arg = {"file": "--scope-file", "directory": "--scope-dir",
                      "group": "--scope-group"}.get(mode)
        if _scope_arg and scope.get("target"):
            cmd += [_scope_arg, scope["target"]]
    if manifest.get("base"):
        cmd += ["--base", manifest["base"]]
    if manifest.get("pr_base"):
        cmd += ["--pr-base", manifest["pr_base"]]
    _dc = (manifest.get("flags") or {}).get("diff_context")
    if _dc is not None:
        cmd += ["--diff-context", str(_dc)]
    # Chunk size was reachable only by calling discovery.py directly, so in
    # practice every run used the 15-file default. On a mid-size repo that is
    # the difference between a scan and a non-starter: solidus (3,622 files)
    # sharded into 291 subgroups, and cells are groups x domains, so it
    # projected past 4B tokens. It is an anti-drift flag because re-chunking
    # mid-run would silently repartition every cell the run has already done.
    _mpg = (manifest.get("flags") or {}).get("max_per_group")
    if _mpg is not None:
        cmd += ["--max-per-group", str(_mpg)]
    proc = runio._run_child(cmd, review_root, "discovery")
    if not runio._json_parses(out):
        raise runio.DriverError(
            "discovery: discovery --repo-scan produced no groups.json "
            "(rc=%s): %s" % (proc.returncode, runio._redact_output((proc.stderr or proc.stdout)[:400])))
    return engine.PhaseResult(kind="advanced", message="discovery: groups.json written")
