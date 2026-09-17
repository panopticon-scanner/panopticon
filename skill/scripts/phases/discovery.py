"""Phase 1 -- discovery: profile the repo and write the file/group inventory."""
import sys

from . import engine
from . import runio

# Scope modes whose file set is SELECTED rather than enumerated, so selecting
# nothing is a real answer: `-c`/`--pr` review a diff, and a diff with no
# reviewable file in it is a legitimately empty run. Every other mode names a
# target that exists (`discovery.py` exits 2 when `--scope-file`/`--scope-group`
# does not resolve), so zero groups there is a broken artifact, not an empty one.
_MAY_SELECT_NOTHING = ("changed", "files")

# One free re-run -- a truncated write is worth retrying -- and no more: a child
# that emits the same unusable artifact twice is deterministically broken, and
# re-running it forever costs the run's wall clock without changing the answer.
_MAX_DISCOVERY_ATTEMPTS = 2


def groups_artifact_errors(doc, manifest=None):
    """Every reason `.panopticon/groups.json` is not a usable inventory; [] when
    it is. The done-predicate's whole definition of "discovery happened".

    #1643: the predicate used to be `_json_parses`, and `{}` parses. A corrupt
    or truncated child output therefore COMPLETED the phase -- coverage derived
    zero groups, every downstream `all(...)` over an empty collection was true
    by definition, and the driver walked to a report having dispatched no review
    cell. The failure shape that matters for a scanner is not the one that
    errors; it is the one that succeeds emptily.

    Shape only, and the minimum of it: the run binding, a `groups` LIST, and per
    record the two fields every consumer reads (`_discovered_groups` takes
    `name` and `files`; `coverage_execute` keys the matrix on `name`). Anything
    richer belongs to `groups_schema`, which validates the committed
    `groups.yml` -- the file this one is DERIVED from, and the only one that had
    a validator.
    """
    manifest = manifest if isinstance(manifest, dict) else {}
    if not isinstance(doc, dict):
        return ["groups.json is not a JSON object"]
    errors = []
    if manifest and doc.get("run_id") != manifest.get("run_id"):
        errors.append("groups.json is stamped for run %r, not this run %r"
                      % (doc.get("run_id"), manifest.get("run_id")))
    groups = doc.get("groups")
    if not isinstance(groups, list):
        errors.append("groups.json carries no `groups` list")
        return errors
    for i, g in enumerate(groups):
        if not isinstance(g, dict):
            errors.append("groups[%d] is not an object" % i)
            continue
        name = g.get("name")
        if not (isinstance(name, str) and name.strip()):
            errors.append("groups[%d] has no name" % i)
        files = g.get("files")
        if not (isinstance(files, list) and all(isinstance(f, str) for f in files)):
            errors.append("group %r has no `files` list of strings"
                          % (name if isinstance(name, str) else i))
    mode = (manifest.get("scope") or {}).get("mode") or "repo"
    if not groups and mode not in _MAY_SELECT_NOTHING:
        errors.append("no groups at all, and this run's scope (%s) enumerates a "
                      "target that cannot legitimately be empty" % mode)
    return errors


def _bump_discovery_attempts(review_root):
    """Persisted malformed-round counter bounding the re-run above. Lives in the
    run folder beside groups.json, so `--reset` clears it with them."""
    path = runio._pano(review_root, "discovery-attempts.json")
    data = runio._load_json(path)
    n = int(data.get("malformed", 0)) + 1 if isinstance(data, dict) else 1
    runio._write_json(path, {"malformed": n})
    return n


def discovery_done(review_root, manifest):
    """Done only on a WELL-FORMED groups artifact -- see groups_artifact_errors."""
    return not groups_artifact_errors(
        runio._load_json(runio._pano(review_root, "groups.json")), manifest)

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
    doc = runio._load_json(out)
    if doc is None:
        raise runio.DriverError(
            "discovery: discovery --repo-scan produced no groups.json "
            "(rc=%s): %s" % (proc.returncode, runio._redact_output((proc.stderr or proc.stdout)[:400])))
    if isinstance(doc, dict):
        # The child is a repo profiler with no notion of a run -- it also serves
        # `panopticon discovery` by hand -- so the RUN BINDING is stamped by the
        # only party that knows it, exactly as coverage stamps coverage-*.json.
        # Without it, a previous run's inventory left in the folder reads as
        # this run's, which is the same "looks done, reviewed nothing" shape.
        doc["run_id"] = manifest.get("run_id")
        runio._write_json(out, doc)
    errors = groups_artifact_errors(doc, manifest)
    if errors:
        n = _bump_discovery_attempts(review_root)
        print("discovery: groups.json is not a usable inventory (attempt %d/%d): %s"
              % (n, _MAX_DISCOVERY_ATTEMPTS, "; ".join(errors)),
              file=sys.stderr, flush=True)
        if n >= _MAX_DISCOVERY_ATTEMPTS:
            raise runio.DriverError(
                "discovery produced no usable groups: " + "; ".join(errors))
        # The done-predicate still says no, so the engine re-selects this phase
        # and the child runs again -- one retry, then the error above.
        return engine.PhaseResult(kind="advanced",
                                  message="discovery: groups.json unusable, re-running")
    return engine.PhaseResult(kind="advanced", message="discovery: groups.json written")
