"""The codex family's probes: what a Codex host proves about itself.

Split out of `host_probes.py` (#1627). The `codex` row claims two
capabilities and both are measured from ONE headless surface inspection --
`_codex_surfaces` builds the real per-role sandbox once and every probe that
follows reads it, which is why `run_probes` threads a shared `measure`
callable through rather than letting each probe rebuild it.

What every family shares is reached by module attribute (`common.<name>`), so
each of those names still has exactly one definition and one patch target.
The probe-id -> function registry stays in `host_probes.py`.
"""
import concurrent.futures
import json
import os
import tempfile

from scripts import dispatch, hosts, model_resolver

from . import common


CODEX_EFFECTIVE_TOOLS = "codex-effective-tools"
CODEX_READ_SCOPE = "codex-read-scope"


def _codex_surfaces(registration_dir=None, inspector=None, runner=None):
    """Measure each role in the real Codex runtime, without a paid model call.

    A localhost Responses fixture enumerates the effective tools and attempts
    two synthetic reads through the SAME launcher used by the runner. No target
    content participates. Only run_probes' caller-local cache shares results;
    every driver invocation inspects the current runtime and registered shells.

    I-6: the five role inspections are independent, so they run concurrently,
    and the bundled model catalog -- identical for all of them -- is dumped
    once per call instead of once per role. Each role still gets its own
    launch, its own scope file and its own grants; nothing is shared that a
    mutation could hide behind.
    """
    from scripts import codex_host
    inspector = inspector or codex_host.inspect_surface
    directory = registration_dir or hosts.spec("codex").registration_dir
    with tempfile.TemporaryDirectory(prefix="panopticon-codex-probe-") as temporary:
        root = os.path.realpath(temporary)
        cell = os.path.join(root, "in-scope")
        os.mkdir(cell)
        inside, outside = os.path.join(cell, "inside.txt"), os.path.join(root, "outside.txt")
        for path in (inside, outside):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("Panopticon synthetic confinement fixture\n")
        # #1642: the refutation fixture. A hard link INSIDE the cell naming the
        # inode OUTSIDE it -- the one case where "this name is under the grant"
        # and "this content is in scope" come apart. Lexical authorization
        # admits the name; the broker has to refuse the inode. Planted once, so
        # every role drives the same three reads.
        #
        # A filesystem with no links to plant does NOT raise (fix round 1, F3).
        # This measurement is shared by both codex probes, so raising also
        # un-proved `codex-effective-tools` -- a claim about the effective V8
        # surface that has nothing to do with hard links, gating as REFUTED
        # (hosts.py) on somebody's tmp mount -- and, because the caller caches
        # only a successful measurement, ran the whole inspection twice. The
        # reason rides ALONG with each surface instead, and only
        # `probe_codex_read_scope` treats it as UNKNOWN. No fixture, no probe
        # paths: a two-read measurement must not stand in for the three-read one.
        linked = os.path.join(cell, "linked.txt")
        fixture_error = None
        try:
            os.link(outside, linked)
        except OSError as exc:
            fixture_error = ("the hard-link refutation fixture could not be planted at %s: %s"
                             % (linked, exc))
        probe_paths = None if fixture_error else (inside, outside, linked)
        jobs = []
        for role in (*common.DRIVER_ROLES, "setup-scan"):
            setup = role == "setup-scan"
            role_file = None if setup else dispatch.ROLE_FILES[role]
            shell = ("setup-scan (native default model and directory scope)" if setup else
                     os.path.join(directory, dispatch.registered_agent_filename("codex", role_file)))
            if not setup and not os.path.isfile(shell):
                raise FileNotFoundError("Codex reviewer shell is missing: %s" % shell)
            entry = {"id": "setup-scan" if setup else "probe-" + role,
                     "agent": None if setup else dispatch.registered_agent_name(role_file),
                     "enforced": not setup, "delivery": "return_json",
                     "model": None if setup else model_resolver.resolve_model("codex", role).get("model"),
                     "prompt": "Measure the available reviewer tools; return JSON.",
                     "scope": {"files": [] if setup else [inside], "dirs": [cell] if setup else [], "reads": []}}
            # Per ROLE, not per call: concurrent inspections would otherwise
            # overwrite one another's grants between write and launch.
            scope_path, allow_path = (os.path.join(root, "%s-%s.json" % (name, entry["id"]))
                                      for name in ("scope", "allowlist"))
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({entry["id"]: entry["scope"]}, fh)
            with open(allow_path, "w", encoding="utf-8") as fh:
                json.dump([], fh)
            env = dict(os.environ, PANOPTICON_ENTRY_ID=entry["id"],
                       PANOPTICON_READ_SCOPE=scope_path, PANOPTICON_WRITE_ALLOWLIST=allow_path)
            jobs.append((shell, entry, env, cell if setup else root))
        catalog = codex_host.catalog_loader(runner)

        def measure(job):
            shell, entry, env, review_root = job
            surface = inspector(entry, env, review_root, root, registration_dir=directory,
                                probe_paths=probe_paths, catalog=catalog)
            if fixture_error and isinstance(surface, dict):
                surface = dict(surface, hard_link_fixture=fixture_error)
            return shell, surface

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
            return list(pool.map(measure, jobs))


def _codex_measure(probe_id, settings_path, registration_dir, measure):
    from scripts import codex_host
    if settings_path is None:
        return None, (hosts.UNKNOWN, probe_id,
                      "Codex confinement is measured for driver loop --mode headless only; "
                      "a parent session may override native child-agent permissions")
    try:
        return (measure() if measure else _codex_surfaces(registration_dir)), None
    except FileNotFoundError as exc:
        # Missing registration is broken; missing CLI is an unavailable test.
        state = hosts.REFUTED if "reviewer shell is missing" in str(exc) else hosts.UNKNOWN
        return None, (state, probe_id, str(exc))
    except codex_host.LaunchRefused:
        # I-5: the suite's no-live-launch guard. Everything else here becomes
        # an honest UNKNOWN; this one must escape, or a test that reached a
        # real `codex` would read as "runtime unavailable" and stay green.
        raise
    except Exception as exc:
        return None, (hosts.UNKNOWN, probe_id, common.failure_detail(
            exc, "effective Codex inspection could not run"))


def _codex_surface_problem(surface):
    expected = {"mcp__panopticon_scope__read_file", "mcp__panopticon_scope__search",
                "mcp__panopticon_scope__list_files", "list_mcp_resources",
                "list_mcp_resource_templates", "read_mcp_resource"}
    forbidden = surface.get("forbidden") or {}
    if (set(surface.get("tools", [])) != expected
            or set(surface.get("direct_tools", [])) != {
                "functions.exec", "functions.wait", "functions.request_user_input"}
            or set(forbidden) != {"exec", "patch", "spawn", "fetch", "process", "require"}
            or any(value != "undefined" for value in forbidden.values())):
        return "effective Codex surface is not the confined read-only tool set"
    return None


def probe_codex_tool_policy(host, registration_dir=None, settings_path=None, measure=None):
    """Prove omission on Codex's effective V8 surface, not TOML prose."""
    surfaces, failure = _codex_measure(CODEX_EFFECTIVE_TOOLS, settings_path, registration_dir, measure)
    if failure:
        return failure
    paths = []
    for path, surface in surfaces:
        paths.append(path)
        problem = _codex_surface_problem(surface)
        if problem:
            return (hosts.REFUTED, CODEX_EFFECTIVE_TOOLS,
                    "%s: %s: %s" % (path, problem, json.dumps(surface, sort_keys=True)))
    if len(paths) != len(common.DRIVER_ROLES) + 1:
        return (hosts.UNKNOWN, CODEX_EFFECTIVE_TOOLS, "not every registered role was inspected")
    return (hosts.PROVEN, CODEX_EFFECTIVE_TOOLS,
            "effective Codex V8 ALL_TOOLS and forbidden globals inspected via localhost-only "
            "Responses fixture; shell/patch/agents/network absent; shells: %s" % ", ".join(paths))


def probe_codex_read_scope(host, registration_dir=None, settings_path=None, measure=None):
    """Exercise the actual MCP read path; disallow every alternate I/O tool.

    Three reads per role (#1642). The third is the planted hard link: a name
    inside the directory grant for an inode outside it, which every role must
    refuse -- and which the one DIRECTORY-granted role (setup-scan; every other
    role holds exact file grants, where the link is out of scope by name) must
    refuse BY the hard-link rule. A build where that rule is gone still denies
    the link for every file-granted role, so counting denials alone would read
    as proven; the wording is what says the boundary is live.
    """
    surfaces, failure = _codex_measure(CODEX_READ_SCOPE, settings_path, registration_dir, measure)
    if failure:
        return failure
    paths, by_the_rule = [], []
    for path, surface in surfaces:
        paths.append(path)
        problem = _codex_surface_problem(surface)
        if problem:
            return hosts.REFUTED, CODEX_READ_SCOPE, "%s: %s" % (path, problem)
        fixture_error = surface.get("hard_link_fixture")
        if fixture_error:
            # F3: this row's fixture, and only this row's verdict.
            return hosts.UNKNOWN, CODEX_READ_SCOPE, "%s: %s" % (path, fixture_error)
        reads = surface.get("reads")
        if not isinstance(reads, list) or len(reads) != 3:
            return (hosts.UNKNOWN, CODEX_READ_SCOPE, "%s: runtime returned no three-read measurement" % path)
        inside, outside, linked = reads
        if (not isinstance(inside, dict) or not isinstance(outside, dict)
                or inside.get("isError") is not False or outside.get("isError") is not True
                or "outside" not in json.dumps(outside).lower()
                or "scope" not in json.dumps(outside).lower()):
            return (hosts.REFUTED, CODEX_READ_SCOPE,
                    "%s: actual MCP in-scope allow / out-of-scope deny failed: %s"
                    % (path, json.dumps(reads, sort_keys=True)))
        if not isinstance(linked, dict) or linked.get("isError") is not True:
            return (hosts.REFUTED, CODEX_READ_SCOPE,
                    "%s: a hard link planted inside the directory grant, naming a file outside "
                    "it, was READ through the grant: %s" % (path, json.dumps(linked, sort_keys=True)))
        if "hard-linked" in json.dumps(linked).lower():
            by_the_rule.append(path)
    if len(paths) != len(common.DRIVER_ROLES) + 1:
        return (hosts.UNKNOWN, CODEX_READ_SCOPE, "not every registered role was inspected")
    if not by_the_rule:
        return (hosts.REFUTED, CODEX_READ_SCOPE,
                "no inspected role refused the planted hard link by the hard-link rule; the "
                "directory-granted role denied it only as an out-of-scope path, which a broker "
                "without the rule does too -- the directory-grant boundary is unproven")
    return (hosts.PROVEN, CODEX_READ_SCOPE,
            "actual Codex MCP read_file allowed the exact entry file, denied its outside-scope "
            "sibling, and refused a hard link planted inside the directory grant as hard-linked "
            "(%s); PANOPTICON_ENTRY_ID / PANOPTICON_READ_SCOPE bound to temporary grants; "
            "shells: %s" % (", ".join(by_the_rule), ", ".join(paths)))
