"""Phase 2 -- coverage: the scout checkpoint, chunk maps and per-group domains."""
import os
import sys

import scripts.coverage_model as coverage_model
import scripts.dispatch as dispatch
import scripts.groups_schema as groups_schema
import scripts.run_tools as run_tools
from scripts import hosts
from . import engine
from . import runio
from . import requests


def _discovered_groups(review_root):
    """(name, files) per group from discovery's groups.json."""
    data = runio._load_json(runio._pano(review_root, "groups.json")) or {}
    return [(g.get("name"), g.get("files") or [])
            for g in (data.get("groups") or [])
            if isinstance(g, dict) and g.get("name")]

def _scout_entry(review_root, manifest, group, files, host, registry_tools=None):
    """One host-agnostic scout dispatch entry (spec §4). The scout body +
    tool-policy line come from dispatch.render_prompt; the assignment is
    appended. Enforcement is host-declared (claude registers panopticon-scout)."""
    body = dispatch.render_prompt("scout.md", {}, host)
    security = manifest.get("security_mode", "standard")
    file_list = runio._abs_file_list(review_root, files)
    # #1053: ground the scout's tool recommendation in the real adapter registry
    # so it can only name scanners that exist -- an ungrounded scout invents
    # pytest/pylint/ruff/... and #1031 can only disclose them as
    # requested_unavailable noise. The list is the single source of truth from
    # run_tools, appended here so it reaches enforced and generic scouts alike.
    # run-9 E1: the caller passes a registry already gated to this run's languages
    # + applicable adapters (so the scout can't over-request cross-language tools);
    # fall back to the full universe for a direct caller that doesn't gate.
    if registry_tools is None:
        registry_tools = run_tools.recommendable_tools()
    registry = ", ".join(registry_tools)
    prompt = (body
              + "\n\n## Assignment\n\nGroup: %s\nSecurity mode: %s\n\nFiles:\n%s\n"
                % (group, security, file_list)
              + "\n## Available scanners\n\nRecommend `tools` ONLY from this "
                "registry — these are the only scanners that can run. Emit `[]` "
                "if none apply; never invent a tool name:\n%s\n" % registry
              + "\nReturn the ScopeProfile JSON for this group.")
    enforced = (hosts.posture(host, runio.host_evidence(review_root))
                [hosts.TOOL_POLICY_ENFORCED] == hosts.PROVEN)
    return {"id": "scout-%s" % group,
            "agent": dispatch.registered_agent_name("scout.md") if enforced else None,
            "enforced": enforced,
            "model": None,
            "prompt": prompt,
            "out_file": os.path.abspath(runio._pano(review_root, "scout-%s.json" % group))}

def coverage_done(review_root, manifest):
    # Vacuously done when discovery produced no groups (empty target); otherwise
    # done once every discovered group has a coverage file. (Evaluated only after
    # discovery, an earlier phase, so groups.json is already present.)
    return all(runio._json_parses(runio._pano(review_root, "coverage-%s.json" % g))
               for g, _ in _discovered_groups(review_root))

def _chunk_of_map(review_root):
    """{group name -> the review unit it was split out of}, from groups.json.

    Discovery states this outright (`chunk_of`), so the driver no longer has to
    infer it from the name. Authoritative where present; groups.json written
    before the field falls back to `_chunk_parent` (#1480).
    """
    data = runio._load_json(runio._pano(review_root, "groups.json")) or {}
    return {g["name"]: g["chunk_of"]
            for g in (data.get("groups") or [])
            if isinstance(g, dict) and g.get("name") and g.get("chunk_of")}

def _chunk_parent(name):
    """The committed parent of a discovery chunk `<name>_<i>` (#5.0-10), or None
    if `name` is not a `<something>_<digits>` chunk. Leftover `._N` chunks map to
    parent '.', never in the matrix, so they correctly keep an empty floor.

    Superseded by discovery's `chunk_of` field, which says this rather than
    guessing it; kept as the fallback for a pre-`chunk_of` groups.json. The
    guess is not reliable on its own -- it cannot tell a chunk of `API` from a
    committed group named `API_1` (#1480).
    """
    if not name or "_" not in name:
        return None
    head, _, tail = name.rpartition("_")
    return head if head and tail.isdigit() else None

# #3: bound the return-persist re-dispatch loop so a deterministically-broken
# host fails loud instead of re-dispatching the same garbage forever.
_MAX_SCOUT_ATTEMPTS = 3

def _scout_shape_errors(scout):
    """Load-bearing structural checks on a returned ScopeProfile -- a
    dependency-free subset of `scope-profile-schema.json`. The driver validates
    by hand rather than importing jsonschema so this check cannot become the
    thing that makes a scan need a third-party package at runtime. Checks
    only the invariants the coverage/dispatch path actually indexes; returns []
    when the shape is safe to consume, else human-readable errors.

    #run10 D3: validates exactly the fields the scout contract still asks for.
    The old `lenses` panel->array check (added for run-6) went with the field
    itself, along with the retired 4.x lens plumbing it guarded. A profile that
    still carries extra keys validates fine; they are simply never read."""
    if not isinstance(scout, dict):
        return ["not a JSON object"]
    errs = []
    for field in ("domains", "files", "tools"):
        v = scout.get(field)
        if v is None:
            continue
        if not isinstance(v, list):
            errs.append("`%s` must be an array" % field)
            continue
        # #run10 COD-B2A: checking only that the field IS an array let a nested
        # or object-valued ELEMENT through -- `{"domains": [["COD"]]}` or
        # `{"domains": [{"x": 1}]}` passed this gate and then crashed
        # coverage_execute with an uncaught TypeError (unhashable list) deep in
        # the set arithmetic, mid-phase, instead of being discarded and
        # re-dispatched here. These are return-persist values from an LLM, which
        # this file's own docstrings document as unreliable, so validate the
        # elements at the accept boundary too.
        bad = [x for x in v if not isinstance(x, str)]
        if bad:
            errs.append("`%s` must contain only strings (got %s)"
                        % (field, ", ".join(sorted({type(x).__name__ for x in bad}))))
    return errs

def _bump_scout_attempts(review_root, group):
    """Persisted per-group re-dispatch counter that bounds #3's retry loop.
    Lives alongside the scout outputs, so --reset clears it with them."""
    path = runio._pano(review_root, "scout-attempts.json")
    data = runio._load_json(path) if runio._json_parses(path) else {}
    if not isinstance(data, dict):
        data = {}
    n = int(data.get(group, 0)) + 1
    data[group] = n
    runio._write_json(path, data)
    return n

def coverage_execute(review_root, manifest):
    """Emit ALL pending scouts in one checkpoint (#1056), then compute each
    group's coverage as the floor widened by the scout's valid domains. Returns
    after one unit of work; the engine re-selects coverage until every group has
    a coverage file. Re-emits only the still-missing scouts on resume."""
    matrix, errors = runio.load_committed_groups(review_root)
    if errors:
        # #1091: fail loud like discovery_execute -- a missing/corrupt groups.yml
        # on a RESUME (discovery is already done, so its gate never re-runs) would
        # otherwise silently yield matrix={}, dropping the committed floor/exclude.
        raise runio.DriverError("coverage: " + "; ".join(errors))
    host = manifest.get("host", "claude")
    groups = _discovered_groups(review_root)
    # #1056: scouts are independent and there is exactly one per group, so a
    # per-group checkpoint (like the review fan-out) would be no better than the
    # old sequential loop -- run-5's 21 groups cost ~40 min of pure profiling
    # round-trips. Emit EVERY pending scout in one checkpoint so the host
    # dispatches them concurrently; on a crash/resume this re-emits only the
    # scouts that still have no output (durable state = the entries' out_files).
    pending_scouts = []
    for g, f in groups:
        if runio._json_parses(runio._pano(review_root, "coverage-%s.json" % g)):
            continue
        sp = runio._pano(review_root, "scout-%s.json" % g)
        # A scout is a RETURN-PERSIST file: read it tolerantly, or a fence-wrapped
        # but otherwise-valid profile reads as "no output" and re-dispatches
        # forever (run-9: 0/25 scouts fenced -> the whole phase silently looped).
        if not runio._return_json_parses(sp):
            pending_scouts.append((g, f))          # no output yet
            continue
        # #3: a scout that PARSES as JSON but has the wrong shape would slip
        # past the dict gate in the coverage loop below -- a `domains` value that
        # is not a list of domain codes silently widens the cell matrix to
        # nothing, or to garbage cells that fail their own done-predicate. (The
        # original run-6 instance was `lenses` returned as panel->object; that
        # field is gone, the failure mode is not.) Validate at the return-persist
        # accept boundary; on a mismatch, DISCARD the garbage and re-dispatch that
        # one scout. Cap the retries so a deterministically-broken host fails loud.
        scout = runio._load_return_json(sp)
        errs = _scout_shape_errors(scout)
        if errs:
            n = _bump_scout_attempts(review_root, g)
            print("scout output for group %s failed shape validation "
                  "(attempt %d/%d): %s"
                  % (g, n, _MAX_SCOUT_ATTEMPTS, "; ".join(errs)),
                  file=sys.stderr, flush=True)
            if n >= _MAX_SCOUT_ATTEMPTS:
                raise runio.DriverError(
                    "scout for group %s returned schema-invalid output %d times "
                    "(fix the agent or `--reset`): %s" % (g, n, "; ".join(errs)))
            try:
                os.remove(sp)                       # discard -> re-dispatch fresh
            except OSError:
                pass
            pending_scouts.append((g, f))
        else:
            # Normalize the accepted return-persist file in place: rewrite the
            # unwrapped JSON so the coverage read below and synthesize's raw
            # scout-*.json scan both get clean bytes, whatever wrapper the host
            # wrote. Unwrap AND persist the unwrapped form -- not just parse past.
            runio._write_json(sp, scout)
    if pending_scouts:
        # run-9 E1: gate the tool registry the scouts see to THIS repo's detected
        # languages + applicable adapters, computed once, so no scout over-requests
        # a cross-language scanner the runner can never select (the
        # requested_unavailable disclosure noise). Best-effort: any detection error
        # falls back to the full universe rather than blocking the scout dispatch.
        try:
            registry_tools = run_tools.recommendable_tools(
                languages=run_tools.detect_languages(review_root), target=review_root)
        except Exception:                       # noqa: BLE001 - never block dispatch
            registry_tools = None
        entries = [_scout_entry(review_root, manifest, g, f, host, registry_tools)
                   for g, f in pending_scouts]
        req = requests.write_dispatch_request(review_root, manifest["run_id"],
                                     "scout", None, entries)
        return engine.PhaseResult(kind="checkpoint", checkpoint="scout", group=None,
                           dispatch_request=req,
                           message="scout checkpoint for %d group(s)"
                                   % len(entries))
    # Every group now has a scout output -> compute coverage (one group per call:
    # local work, no dispatch, so the cadence is unchanged and cheap).
    chunk_of = _chunk_of_map(review_root)
    for group, files in groups:
        if runio._json_parses(runio._pano(review_root, "coverage-%s.json" % group)):
            continue
        scout_path = runio._pano(review_root, "scout-%s.json" % group)
        # #5.0-12: a scout that returns a non-object (e.g. a JSON array) parses as
        # JSON but would slip past `or {}` (a non-empty list is truthy) and crash
        # `.get` with an uncaught AttributeError. Validate the shape at the gate
        # and fail loud (status:error) instead.
        scout = runio._load_return_json(scout_path)
        if not isinstance(scout, dict):
            raise runio.DriverError("scout output for group %s is not a JSON object" % group)
        raw = scout.get("domains") or []
        spec = matrix.get(group)
        if spec is None:
            # #5.0-10: a group split into <name>_<i> chunks inherits its
            # committed floor/exclude/tests. `chunk_of` names that unit
            # outright; fall back to inferring it for an older groups.json.
            unit = chunk_of.get(group) or _chunk_parent(group)
            if unit is not None and unit != group:
                spec = matrix.get(unit)
        spec = spec or {}
        floor = spec.get("floor", set())
        # net against floor here so disclosure["scout_added"] reports only the
        # genuinely NEW domains (a domain already on the floor isn't "added").
        scout_added = {d for d in raw if d in groups_schema.DOMAINS} - set(floor)
        scout_invalid = sorted(set(raw) - groups_schema.DOMAINS)
        # #5.0-19: gate the universal-tier floor on this group's observable
        # surface, so a testless / db-free / single-module group does not spend
        # a DAT/TST/ARC cell manufacturing noise (BursarBuddy calibration:
        # those cells produced 59 of 97 noise findings and caught 0 vulns). COD
        # stays universal; a scout that requested a domain still gets it via
        # scout_added regardless of the gate, so this only drops floor domains
        # the scout omitted AND whose surface is objectively absent.
        gated_floor = coverage_model.applicable_global_floor(files, scout)
        # #run8 SEC-G2A: SEC has no place in the universal GLOBAL_FLOOR (a blanket
        # SEC floor reintroduces the #5.0-19 surfaceless noise), but a group whose
        # OBJECTIVE files carry a security surface -- a supply-chain
        # manifest/CI/Docker file, a db/SQLi file, or an auth/crypto/secrets file
        # -- must get a deterministic SEC review even when neither the committed
        # `panels:` nor the scout asked for it, so a mis-reporting or adversarial
        # groups.yml cannot silently skip its own security review.
        sec_floor = coverage_model.applicable_sec_floor(files)
        effective, disclosure = coverage_model.effective_panels(
            floor, scout_added, spec.get("exclude", set()),
            global_floor=gated_floor, signal_floor=sec_floor)
        cov = {
            "schema_version": 1,
            "group": group,
            "floor": disclosure["floor"],
            "excluded": disclosure["excluded"],
            "scout_added": disclosure["scout_added"],   # new domains, exclude-netted
            "scout_invalid": scout_invalid,             # dropped, disclosed
            "global_floor_suppressed": sorted(          # #5.0-19: surface absent
                coverage_model.GLOBAL_FLOOR - gated_floor),
            "sec_floor_applied": sorted(sec_floor),     # #run8 SEC-G2A: objective
            "effective": sorted(effective),             # security surface -> SEC forced on
            "scout_file": os.path.abspath(scout_path),
            "run_id": manifest["run_id"],
        }
        # #8c/#7: a committed `exclude` naming a NON_EXCLUDABLE domain (SEC,
        # #1084) is OVERRIDDEN -- effective_panels discloses it as
        # `exclude_rejected`, but the coverage-write used to DROP that key. So an
        # operator who reached for a fixture-corpus `exclude:`-sink got a SILENT
        # SEC panel on deliberately-vulnerable code, and 16 illusory HIGHs
        # reached the gate (run-6). Persist the override AND warn loudly: to drop
        # a path corpus entirely (fixtures included, SEC included), use top-level
        # `exclude_paths:`, which prunes before grouping so no domain reviews it.
        rejected = disclosure.get("exclude_rejected")
        if rejected:
            cov["exclude_rejected"] = rejected
            print("coverage: group %s exclude %s was OVERRIDDEN (non-excludable) "
                  "-- these domains still run. To drop paths entirely (e.g. a "
                  "fixture corpus), use top-level `exclude_paths:` in groups.yml, "
                  "not per-group `exclude:`." % (group, ", ".join(rejected)),
                  file=sys.stderr)
        runio._write_json(runio._pano(review_root, "coverage-%s.json" % group), cov)
        return engine.PhaseResult(kind="advanced",
                           message="coverage: group %s (floor+scout)" % group)
    return engine.PhaseResult(kind="advanced", message="coverage: complete")

def _effective_domains(review_root, group):
    cov = runio._load_json(runio._pano(review_root, "coverage-%s.json" % group)) or {}
    return list(cov.get("effective") or [])
