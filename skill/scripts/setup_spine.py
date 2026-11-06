"""Setup spine and brief (5.2 stage 1, spec §5.1): the deterministic,
bounded, sanitized picture of the repo the setup-scan agent starts from
(`build_spine`, persisted by `write_spine`), the bundled vocabularies and
catalogs, and the brief that renders them (`render_scan_brief`). Split out of
`setup_flow.py` along the #1589 seams (#3405). It reads the committed size
overrides through `setup_config` and imports nothing else of setup's.
"""
import json
import os
import re

from scripts import discovery
from scripts import discovery_catalog
from scripts import grouping_engine  # 5.2: stage-3 size policy + setup report
from scripts import coverage_model  # 5.2: the surfaces enum for the brief
from scripts import repo_config  # #1681: the one place the config names live
from scripts import setup_config  # #3405: the committed size overrides
from scripts import plan_contract  # #3409: the artifact directory's name
from scripts.phases import runio  # #1577: the confined no-follow writers


_SKILL_DATA = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_VOCAB_PATH = os.path.join(_SKILL_DATA, "capability_vocabulary.yml")
_AFFINITY_PATH = os.path.join(_SKILL_DATA, "capability_affinity.yml")
_LAYERS_PATH = os.path.join(_SKILL_DATA, "layer_vocabulary.yml")


def _sanitize_spine_token(token):
    s = re.sub(r"[\x00-\x1f\x7f-\x9f`]", "", str(token or "")).strip()
    return repr(s) if any(c in s for c in " \n\r\t\"'") else s


# --- 5.2 stage 1: the spine (spec §5.1) -------------------------------------
# Deterministic, bounded, sanitized (#1120). Everything the setup-scan agent is
# told about the repo before it explores for itself comes from here, and the
# same numbers (cap, ceiling, code_files) are what stage 3 applies -- the spine
# is persisted to .panopticon/setup-spine.json so the two cannot drift.

_SPINE_FILE = "setup-spine.json"
_MAX_TREE_ROWS = 80            # depth-2 directory rows rendered into the brief
_MAX_TEST_TREE_ROWS = 20
_MAX_MANIFESTS = 20
_MAX_LANGUAGES = 6
_MAX_MANIFEST_BYTES = 65536    # bounded read of an untrusted manifest
_EXT_LANG = {
    ".py": "Python", ".go": "Go", ".rs": "Rust", ".js": "JavaScript",
    ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".rb": "Ruby", ".java": "Java",
    ".kt": "Kotlin", ".kts": "Kotlin", ".cs": "C#", ".php": "PHP", ".c": "C",
    ".h": "C", ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++",
    ".swift": "Swift", ".scala": "Scala", ".ex": "Elixir", ".exs": "Elixir",
    ".erl": "Erlang", ".hs": "Haskell", ".dart": "Dart", ".lua": "Lua",
    ".sh": "Shell", ".bash": "Shell", ".vue": "Vue", ".svelte": "Svelte",
    ".m": "Objective-C", ".zig": "Zig", ".clj": "Clojure", ".sql": "SQL",
}
# Manifest basenames the framework probe reads (depth <= 2, so monorepo
# packages count) and the substrings that name a framework in each.
_MANIFEST_NAMES = frozenset({
    "package.json", "pyproject.toml", "requirements.txt", "setup.py", "setup.cfg",
    "go.mod", "Cargo.toml", "Gemfile", "pom.xml", "build.gradle",
    "build.gradle.kts", "composer.json", "mix.exs", "Package.swift",
    "pubspec.yaml", "CMakeLists.txt", "Makefile",
})
_FRAMEWORK_HINTS = {
    "package.json": (("\"react\"", "React"), ("\"next\"", "Next.js"),
                     ("\"vue\"", "Vue"), ("\"nuxt\"", "Nuxt"),
                     ("\"@angular/core\"", "Angular"), ("\"svelte\"", "Svelte"),
                     ("\"express\"", "Express"), ("\"fastify\"", "Fastify"),
                     ("\"@nestjs/core\"", "NestJS"), ("\"koa\"", "Koa"),
                     ("\"electron\"", "Electron")),
    "pyproject.toml": (("django", "Django"), ("flask", "Flask"),
                       ("fastapi", "FastAPI"), ("starlette", "Starlette"),
                       ("tornado", "Tornado"), ("sqlalchemy", "SQLAlchemy")),
    "requirements.txt": (("django", "Django"), ("flask", "Flask"),
                         ("fastapi", "FastAPI"), ("starlette", "Starlette"),
                         ("tornado", "Tornado"), ("sqlalchemy", "SQLAlchemy")),
    "go.mod": (("github.com/gin-gonic/gin", "Gin"), ("github.com/labstack/echo", "Echo"),
               ("github.com/gorilla/mux", "Gorilla"), ("github.com/go-chi/chi", "chi"),
               ("github.com/gofiber/fiber", "Fiber"), ("google.golang.org/grpc", "gRPC"),
               ("gorm.io/gorm", "GORM"), ("github.com/spf13/cobra", "Cobra")),
    "Cargo.toml": (("actix-web", "Actix"), ("axum", "Axum"), ("rocket", "Rocket"),
                   ("tokio", "Tokio"), ("diesel", "Diesel"), ("sqlx", "SQLx"),
                   ("clap", "clap")),
    "Gemfile": (("rails", "Rails"), ("sinatra", "Sinatra"), ("hanami", "Hanami")),
    "pom.xml": (("spring-boot", "Spring Boot"), ("springframework", "Spring"),
                ("quarkus", "Quarkus"), ("micronaut", "Micronaut")),
    "build.gradle": (("spring-boot", "Spring Boot"), ("springframework", "Spring"),
                     ("ktor", "Ktor"), ("android", "Android")),
    "build.gradle.kts": (("spring-boot", "Spring Boot"), ("ktor", "Ktor"),
                         ("android", "Android")),
    "composer.json": (("laravel/framework", "Laravel"), ("symfony/", "Symfony"),
                      ("slim/slim", "Slim")),
    "mix.exs": (("phoenix", "Phoenix"), ("ecto", "Ecto")),
    "pubspec.yaml": (("flutter", "Flutter"),),
}


def _depth2_rows(files):
    """`{node: (files, dominant_ext)}` over the depth-2 directory tree: a file
    rolls up to its first two path segments (`crates/searcher/src/x.rs` ->
    `crates/searcher`), a file one level deep to its top directory, a root
    file to `.`. Dominant ext = the most common extension under the node
    (ties -> alphabetical); `-` when the files have none."""
    counts: dict[str, int] = {}
    exts: dict[str, dict[str, int]] = {}
    for f in files:
        parts = f.split("/")
        node = "/".join(parts[:-1][:2]) or "."
        counts[node] = counts.get(node, 0) + 1
        ext = os.path.splitext(parts[-1])[1].lower()
        if ext:
            bucket = exts.setdefault(node, {})
            bucket[ext] = bucket.get(ext, 0) + 1
    rows = {}
    for node, n in counts.items():
        bucket = exts.get(node) or {}
        dom = min(bucket, key=lambda e: (-bucket[e], e)) if bucket else "-"
        rows[node] = (n, dom)
    return rows


def _detect_frameworks(repo, manifests):
    """Framework names whose marker substring appears in a manifest (bounded
    read, case-insensitive). Sorted, deduplicated; a manifest that cannot be
    read contributes nothing."""
    found = set()
    for rel in manifests:
        hints = _FRAMEWORK_HINTS.get(os.path.basename(rel))
        if not hints:
            continue
        try:
            with open(os.path.join(repo, rel), encoding="utf-8", errors="replace") as fh:
                text = fh.read(_MAX_MANIFEST_BYTES).casefold()
        except OSError:
            continue
        for marker, name in hints:
            if marker.casefold() in text:
                found.add(name)
    return sorted(found)


def build_spine(repo, max_per_group=None, max_groups=None, files=None):
    """Stage 1 (spec §5.1): everything mechanical the setup agent is told
    before it explores. `files` defaults to `discovery.discover_repo_files`;
    pass the list to keep a test hermetic. The cap resolves CLI > config >
    default and the ceiling CLI > config > `grouping_engine.ceiling_for`,
    exactly as `ingest_proposal` resolves them, so the numbers the agent
    plans against are the numbers stage 3 applies.

    Returns a JSON-serializable mapping (`schema_version` 1):
      files:      {total, code, commons, test_tree}
      cap, ceiling, ceiling_source ("cli" | "config" | "formula")
      tree:       [{path, files, ext}] depth-2 rows, most files first
      tree_more:  directories not listed (row cap)
      languages:  [{language, files}] over CODE files, most first
      manifests:  [path] dependency manifests at depth <= 2
      frameworks: [name] detected from the manifests
      claimed:    {"committed": {flat id: n}, "commons": {category: n},
                   "groups_yml": bool} -- every committed leaf is listed, a
                  leaf whose globs match nothing today as 0
      test_trees: [{path, files}] depth-2 directories the Tests sweep will take
    Every repo-derived token is passed through `_sanitize_spine_token`."""
    if files is None:
        files = discovery.discover_repo_files(repo)
    files = sorted(files)
    overrides = setup_config.config_overrides(repo)
    cap = max_per_group or overrides["max_per_group"] or discovery.DEFAULT_MAX_PER_GROUP
    kinds = grouping_engine.classify_files(files)
    code_files, n_commons, n_tests = grouping_engine.count_code_files(files)
    if max_groups:
        ceiling, source = int(max_groups), "cli"
    elif overrides["max_groups"]:
        ceiling, source = overrides["max_groups"], "config"
    else:
        ceiling, source = grouping_engine.ceiling_for(code_files, cap), "formula"
    san = _sanitize_spine_token
    rows = _depth2_rows(files)
    ordered = sorted(rows, key=lambda n: (-rows[n][0], n))
    tree = [{"path": san(n), "files": rows[n][0], "ext": san(rows[n][1])}
            for n in ordered[:_MAX_TREE_ROWS]]
    langs: dict[str, int] = {}
    for f, kind in kinds.items():
        if kind == "code":
            lang = _EXT_LANG.get(os.path.splitext(f)[1].lower())
            if lang:
                langs[lang] = langs.get(lang, 0) + 1
    languages = [{"language": lang, "files": langs[lang]}
                 for lang in sorted(langs, key=lambda x: (-langs[x], x))[:_MAX_LANGUAGES]]
    manifests = [f for f in files
                 if os.path.basename(f) in _MANIFEST_NAMES and f.count("/") <= 2]
    frameworks = _detect_frameworks(repo, manifests)
    committed = discovery._committed_matrix(repo)
    from scripts import setup_proposal as sp
    committed_view = {n: {"match": list(b.get("match") or []),
                          "tests": list(b.get("tests") or [])}
                      for n, b in sp.flatten_groups(committed).items()}
    assigned, leftovers = discovery_catalog.assign_by_catalog(files, committed_view)
    commons_counts: dict[str, int] = {}
    test_dirs: dict[str, int] = {}
    for f in leftovers:
        kind = kinds[f]
        if kind.startswith("commons:"):
            cat = kind.split(":", 1)[1]
            commons_counts[cat] = commons_counts.get(cat, 0) + 1
        elif kind == "tests":
            node = "/".join(f.split("/")[:-1][:2]) or "."
            test_dirs[node] = test_dirs.get(node, 0) + 1
    test_rows = sorted(test_dirs, key=lambda n: (-test_dirs[n], n))
    return {
        "schema_version": 1,
        "files": {"total": len(files), "code": code_files, "commons": n_commons,
                  "test_tree": n_tests},
        "cap": cap, "ceiling": ceiling, "ceiling_source": source,
        "tree": tree, "tree_more": max(0, len(rows) - _MAX_TREE_ROWS),
        "languages": languages,
        "manifests": [san(m) for m in manifests[:_MAX_MANIFESTS]],
        "frameworks": frameworks,
        "claimed": {"committed": {san(n): len(assigned.get(n, [])) for n in sorted(committed_view)},
                    "commons": dict(sorted(commons_counts.items())),
                    "groups_yml": bool(committed)},
        "test_trees": [{"path": san(n), "files": test_dirs[n]}
                       for n in test_rows[:_MAX_TEST_TREE_ROWS]],
    }


def format_spine(spine):
    """The `{repo_spine}` section of the brief: tree, languages, frameworks,
    manifests, what is already claimed, and the test trees with the sweep
    instruction (spec §5.1). Deterministic; no timestamps."""
    out = ["Depth-2 directory tree (a row counts the files that roll up to that node: "
           + "a file directly under a top-level directory counts there, deeper files "
           + "under their depth-2 directory; then the dominant extension):", ""]
    for row in spine["tree"]:
        out.append("    %-40s %5d  %s" % (row["path"], row["files"], row["ext"]))
    if spine.get("tree_more"):
        out.append("    (+%d more directories not listed)" % spine["tree_more"])
    langs = ", ".join("%s (%d)" % (x["language"], x["files"]) for x in spine["languages"])
    out += ["", "Languages (code files): %s" % (langs or "(none recognised)"),
            "Frameworks (from manifests): %s" % (", ".join(spine["frameworks"]) or "(none detected)"),
            "Manifests: %s" % (", ".join(spine["manifests"]) or "(none)"), ""]
    committed = spine["claimed"]["committed"]
    if committed:
        out.append("Already claimed by the committed root config (these win; do not re-propose "
                   "them; 0 = its globs match nothing today):")
        out += ["    %-40s %5d" % (n, k) for n, k in committed.items()]
    elif spine["claimed"].get("groups_yml"):
        out.append("Already claimed by the committed root config: nothing (it has no match: globs).")
    else:
        out.append("Already claimed by the committed root config: nothing (no committed config).")
    commons = spine["claimed"]["commons"]
    if commons:
        out.append("Claimed by the Commons classifier (docs/CI/build/config/deps -- not yours to group):")
        out += ["    %-40s %5d" % (n, k) for n, k in commons.items()]
    else:
        out.append("Claimed by the Commons classifier: nothing.")
    if spine["test_trees"]:
        out += ["", "Test trees (the Tests sweep will catch these; claim only unit tests "
                    + "scoped to your verticals via each group's `tests`):"]
        out += ["    %-40s %5d" % (t["path"], t["files"]) for t in spine["test_trees"]]
    else:
        out += ["", "Test trees: none detected (colocated tests belong to the vertical beside them)."]
    return "\n".join(out)


def format_budget(spine):
    """The `{budget}` section of the brief: the size arithmetic and the layer
    instruction (spec §5.1)."""
    f = spine["files"]
    how = {"cli": "from --max-groups",
           "config": "from settings: in %s" % repo_config.CONFIG_NAMES[0],
           "formula": "= max(%d, 2 * ceil(code_files / cap))" % grouping_engine.MIN_CEILING
           }[spine["ceiling_source"]]
    return "\n".join([
        "- files: %d total = %d code + %d commons + %d test tree"
        % (f["total"], f["code"], f["commons"], f["test_tree"]),
        "- cap (files per review group, --max-per-group): %d" % spine["cap"],
        # #1506: name the population, or the agent reads the ceiling as a
        # budget for EVERY leaf and proposes fewer verticals than the repo
        # affords. `Tests` and the Commons categories are the engine's, formed
        # after the proposal, and are not charged to this number.
        ("- ceiling (CODE review groups this repo affords): %d %s -- `Tests` and "
         + "the Commons categories are formed by the engine and are not counted "
         + "against it") % (spine["ceiling"], how),
        ("- propose `layers` ONLY for a vertical you estimate OVER the cap (%d files); "
         + "a layer under %d files merges back into its parent")
        % (spine["cap"], grouping_engine.FLOOR),
        "- aim for verticals of roughly cap/2 files or more; over the ceiling, the "
        + "smallest layers are collapsed first and verticals are never merged",
    ])


def write_spine(repo, spine):
    path = os.path.join(os.path.abspath(repo), plan_contract.ARTIFACT_DIR, _SPINE_FILE)
    with runio._open_w_nofollow(path) as fh:   # #1577
        json.dump(spine, fh, indent=1, sort_keys=True)
        fh.write("\n")
    return path


def read_spine(repo):
    """The persisted spine, or None when absent/unreadable/not a v1 mapping."""
    path = os.path.join(os.path.abspath(repo), plan_contract.ARTIFACT_DIR, _SPINE_FILE)
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        return None
    return doc


def _render_catalog_entry(name, entry, hints):
    """One catalog entry as the brief shows it: the prose the classifier is
    graded against (#1500), the aliases it may use, the hints it may NOT
    treat as authoritative, and the pool anchors. Missing fields are simply
    omitted (fixtures stay minimal; shipped data is checked by
    tests/test_catalog_data.py)."""
    lines = ["### %s" % name]
    for key, label in (("definition", "Definition"), ("boundary", "Boundary")):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            lines.append("%s: %s" % (label, value.strip()))
    aliases = [a for a in (entry.get("aliases") or []) if isinstance(a, str)]
    if aliases:
        lines.append("Aliases: %s" % ", ".join(aliases))
    if hints:
        lines.append("Hints (non-authoritative): %s" % ", ".join(hints))
    examples = ["%s `%s`" % (ex.get("repo"), ex.get("path"))
                for ex in (entry.get("examples") or [])
                if isinstance(ex, dict) and ex.get("repo") and ex.get("path")]
    if examples:
        lines.append("Examples: %s" % "; ".join(examples))
    see_also = [x for x in (entry.get("see_also") or []) if isinstance(x, str)]
    if see_also:
        lines.append("See also: %s" % ", ".join(see_also))
    return "\n".join(lines)


def _render_catalog(catalog):
    """`### name` blocks for every catalog name, in file order, separated by a
    blank line. Works on the 5.0 shape too (`names` + `hints`, no `entries`)."""
    entries = catalog.get("entries") or {}
    hints = catalog.get("hints") or {}
    blocks = []
    for name in catalog.get("names") or []:
        entry = entries.get(name) or {}
        entry_hints = [h for h in (hints.get(name) or entry.get("hints") or [])
                       if isinstance(h, str)]
        blocks.append(_render_catalog_entry(name, entry, entry_hints))
    return "\n\n".join(blocks)


def render_capability_catalog(vocabulary):
    """The `{capability_catalog}` section of the brief: every capability's
    definition, boundary, aliases, hints, examples and see_also (spec §5.1
    "catalogs, full prose"; closes #1500 -- the calibrated prose finally
    reaches the classifier)."""
    return _render_catalog(vocabulary) or "(no capability catalog bundled)"


def render_layer_catalog(layers):
    """The `{layer_catalog}` section: the layer entries in the same shape, or
    a one-line notice when no layer catalog is present (then the agent is told
    not to propose layers)."""
    if not layers or not layers.get("names"):
        return "(no layer catalog bundled -- do not propose `layers`)"
    return _render_catalog(layers)


def load_bundled_layers(layers_path=None):
    """Load the bundled layer vocabulary. Returns (layers, present: bool),
    mirroring `load_bundled_vocabulary`: present is False when the file is
    absent or the parse yields no names or reports errors."""
    from scripts import setup_proposal as sp
    lpath = layers_path or _LAYERS_PATH
    if not os.path.isfile(lpath):
        return {"names": []}, False
    layers, lerr = sp.load_layers(lpath)
    if lerr or not layers.get("names"):
        return {"names": []}, False
    return layers, True


def render_scan_brief(repo, vocabulary, layers=None, spine=None, host=None):
    """Render the setup-scan agent brief to .panopticon/setup-scan-brief.md
    (spec §5.1): the spine and size arithmetic, both catalogs in full prose,
    the surfaces enum for profiles. `spine` is `build_spine(...)`; None builds
    one with default sizes. `layers` is `load_bundled_layers()[0]`; None
    renders the no-layers notice.

    `host` renders the tool-policy paragraph from that host's real tool surface
    (#1677). It matters more here than at the other prompt sites: the setup
    entry is UNREGISTERED, so no `developer_instructions` translates the tool
    names for it -- this brief is the only document telling that agent what it
    may call. Defaults to None (the neutral Claude vocabulary), so every
    existing caller is unchanged."""
    from scripts import dispatch
    spine = spine or build_spine(repo)
    brief = dispatch.render_prompt("setup-scan.md", {
        "repo_spine": format_spine(spine),
        "budget": format_budget(spine),
        "capability_catalog": render_capability_catalog(vocabulary),
        "layer_catalog": render_layer_catalog(layers),
        "surfaces": ", ".join(sorted(coverage_model.SURFACES)),
    }, host=host)
    path = os.path.join(os.path.abspath(repo), plan_contract.ARTIFACT_DIR, "setup-scan-brief.md")
    with runio._open_w_nofollow(path) as fh:   # #1577
        fh.write(brief)
    return path


def load_bundled_vocabulary(vocabulary_path=None):
    """Load the bundled capability vocabulary. Returns (vocab, present: bool).
    present is False when the file is absent or the parse yields no names."""
    from scripts import setup_proposal as sp
    vpath = vocabulary_path or _VOCAB_PATH
    if not os.path.isfile(vpath):
        return {"names": []}, False
    vocab, verr = sp.load_vocabulary(vpath)
    if verr or not vocab.get("names"):
        return {"names": []}, False
    return vocab, True
