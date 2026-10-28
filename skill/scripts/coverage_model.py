"""Compute a group's effective panel set: floor forces ON, exclude forces OFF
(loudly), the scout widens the undeclared middle. Pure (no I/O, no state);
importing it pulls in `discovery` for the TST naming rule (#1770), which touches
`sys.path` as it always has. See spec §5.
"""

from typing import TYPE_CHECKING

import os

# #1770 ARC-3682668884: the TST floor's test-file signal is the UNION of
# discovery's naming rule and the local hints, so `discovery.TEST_PATTERNS` is a
# dependency of this module rather than a second, drifting derivation of "is
# this a test file". No module-level import runs the other way: `discovery`
# does not import this module, and the one edge back in its closure is lazy --
# `discovery._capability_aliases` imports `setup_proposal` (which imports this
# module) at CALL time, and it must stay lazy. This module, in turn, binds the
# `discovery` module object here and reads `discovery.is_test_file` only at
# call time, so neither order can see a half-initialised module. Same fallback
# shape as `discovery` uses for its own siblings -- this module is imported both as
# `scripts.coverage_model` (the driver's children, which get `skill/` on
# PYTHONPATH, and `setup_flow` / `grouping_engine` since #1766) and flat by
# `setup_proposal`, and the flat mode has only `skill/scripts` on sys.path.
if TYPE_CHECKING:
    from scripts import discovery
else:
    try:
        from scripts import discovery
    except ModuleNotFoundError:
        import discovery

# #5.0-11: the universal-tier domains ride a GLOBAL floor — every group reviews
# code/database/test/architecture regardless of its committed vertical floor.
# capability_affinity.yml documents these as "matrix-level, NOT affinity rows",
# but nothing implemented that: setup writes only the affinity (vertical) floor,
# so without this the flagship review silently skipped COD/DAT/TST/ARC on every
# group. Still subject to a per-group exclude (a docs-only group may opt out).
GLOBAL_FLOOR = frozenset({"COD", "DAT", "TST", "ARC"})
# #1084: domains a committed config's `exclude` can never silence. SEC is
# non-excludable so a target can't commit `exclude: [SEC]` to exempt its own
# code from security review. Deliberately NOT added to GLOBAL_FLOOR (that would
# reintroduce the #5.0-19 surfaceless-group noise) -- SEC still runs only where
# the floor or scout put it, but once there it cannot be excluded away.
NON_EXCLUDABLE = frozenset({"SEC"})


# #5.0-19: the universal-tier floor is GATED per group on OBSERVABLE file
# signals rather than injected unconditionally. BursarBuddy calibration
# (2026-08-16): DAT/TST/ARC on surfaceless groups produced 59 of 97 noise
# findings and caught ZERO answer-key vulns, because a testless / db-free /
# single-module group has nothing for those panels to review. COD stays
# universal (code is always present). The gate keys ONLY on objective file
# signals -- scout-asserted ScopeProfile fields (surfaces / has_tests) are
# intentionally NOT consulted here (#1193). A scout that wants a domain it did
# not objectively surface still gets it via scout_added in effective_panels, so
# coverage can widen but never narrow below observable signals.
_DB_FILE_HINTS = ("schema.prisma", ".prisma", ".sql", "migration", "/models/",
                  "/model/", "schema", "entity", "entities", ".orm", "seed",
                  "repository", "database", "/db.")
# These are HALF of the TST signal; `_has_test_surface` unions them with
# discovery's naming rule. Do not add a naming convention here that belongs in
# `discovery.TEST_PATTERNS` -- the union already picks that one up everywhere.
_TEST_FILE_HINTS = (".test.", ".spec.", "_test.", "_spec.", "/__tests__/",
                    "/tests/", "/test/", ".feature", "conftest", "test_")

# #1489: extensions with no code surface for COD to review. Deliberately a
# DENYLIST, so the gate fails OPEN: an unrecognized extension counts as source
# and keeps COD. Only a group that is ENTIRELY recognized assets loses it --
# stricter than the >=95%-non-source shape that was measured, because dropping a
# floor domain wrongly is worse than spending one cell.
#
# .svg is listed: it is reviewable text, but not by COD. The one real finding
# these groups produced was ARC's (a sprite set drifted out of parity with the
# readme logos) and ARC keeps its own >=2-directories gate, so that path is
# untouched.
_ASSET_EXTENSIONS = frozenset((
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff",
    ".tif", ".avif", ".heic",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".wav", ".ogg", ".oga", ".webm", ".mov", ".avi", ".m4a",
    ".zip", ".gz", ".bz2", ".xz", ".tar", ".7z", ".rar",
    ".pdf", ".bin", ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".wasm",
    ".psd", ".ai", ".sketch", ".fig",
))

# #3338: the SEC floor's code-group test fails closed without pretending every
# prose file is code. This is deliberately a small, explicit allowlist: an
# unfamiliar extension remains code and therefore gets SEC. Documentation is
# identified by FILE shape only, never by its group label or directory --
# `docs/conf.py`, `mkdocs.yml` and a JavaScript docs pipeline execute code and
# must stay on the floor. An extensionless document must match an exact,
# unambiguous conventional basename; prefix variants are accepted only with a
# documentation extension or `.txt`. `INSTALL` is deliberately absent because
# a GNU prose file and an executable install script have the same shape. Thus
# `README.sprocket` and `bin/readme-render` both fail toward SEC.
_DOC_EXTENSIONS = frozenset((
    ".md", ".markdown", ".mdown", ".mkd", ".rst", ".adoc", ".asciidoc",
))
_DOC_EXACT_NAMES = frozenset({
    "readme", "license", "licence", "changelog", "contributing", "notice",
    "authors", "copying", "security", "citation.cff",
})


def _is_asset(path):
    """The one membership test for `_ASSET_EXTENSIONS`: COD's floor and
    certification's size-skip rule read it, so the two cannot drift (#3283)."""
    return os.path.splitext(str(path))[1].lower() in _ASSET_EXTENSIONS


def _is_documentation(path):
    """True only for an explicitly recognized documentation file shape."""
    name = os.path.basename(str(path)).casefold()
    stem, extension = os.path.splitext(name)
    if extension in _DOC_EXTENSIONS:
        return True
    if name in _DOC_EXACT_NAMES:
        return True
    # Plain text is too broad to exempt wholesale (`requirements.txt` executes
    # dependency policy), but exact/prefixed conventional basenames keep their
    # meaning in a `.txt` spelling. Without an extension only the exact-name
    # check above applies: `security-scan` and `license_check` may be executables.
    if extension != ".txt":
        return False
    return any(stem == basename or stem.startswith(basename + "-")
               or stem.startswith(basename + "_")
               for basename in _DOC_EXACT_NAMES)


def has_sec_code_surface(files):
    """True when a group contains code for the deterministic SEC floor (#3338).

    Known assets and explicit documentation shapes are the only exemptions.
    Everything else, including an unknown extension, fails toward running SEC.
    The answer depends only on files: a group name or scout claim has no say.
    """
    return any(not _is_asset(path) and not _is_documentation(path)
               for path in (files or ()))


def has_code_surface(files):
    """True when at least one file could carry a COD defect (#1489).

    Fails open: only files whose extension is a KNOWN asset type are discounted,
    so anything unfamiliar still counts as reviewable source.
    """
    for f in files or ():
        if not _is_asset(f):
            return True
    return False


ASSET_SKIP_NOTE = ("%d asset file(s) over the semgrep size limit were not scanned "
                   "(not counted against certification)")


def _asset_size_skips(facts):
    """How many files a tool's `file_coverage` size-skipped when that is its
    WHOLE gap and every such file is a known asset; 0 otherwise -- the gap then
    counts, as before. Fails closed on everything it cannot account for: a
    listing that is absent, cut short or malformed, a rule timeout, a row it
    did not publish (`files_omitted`), a count the rows do not match, any
    unlocated record, and any file whose name lost its extension to the cut."""
    rows = facts.get("files") if isinstance(facts, dict) else None
    if not (isinstance(rows, list) and facts.get("size_listing") == "listed"
            and facts.get("unlocated_records") == 0 and facts.get("files_omitted") == 0
            and not facts.get("rule_timeouts") and not facts.get("unavailable_files")
            and not facts.get("capabilities_unavailable")
            and type(facts.get("size_skipped")) is int and facts["size_skipped"] == len(rows)
            and facts.get("unparsed_files") == len(rows)):
        return 0
    if all(isinstance(row, dict) and row.get("reason") == "size_skipped"
           and isinstance(row.get("file"), str) and _is_asset(row["file"]) for row in rows):
        return len(rows)
    return 0


def certifying_file_gaps(tools_file_partial):
    """#3283: (the scanner file gaps that still sink certification, the count of
    asset files whose only gap was semgrep's size limit). An image semgrep would
    never lint is no review gap; a size-skipped `.json` or `.go` still is -- a
    target can pad a security-relevant JSON past the limit, not a PNG."""
    if not isinstance(tools_file_partial, dict):
        return tools_file_partial, 0
    counted, assets = {}, 0
    for tool, facts in tools_file_partial.items():
        skipped = _asset_size_skips(facts)
        assets += skipped
        if not skipped:
            counted[tool] = facts
    return counted, assets


def with_asset_skip_note(note, assets):
    """`note` with the asset size-skip disclosure composed onto it, if any."""
    return "; ".join(filter(None, (note, ASSET_SKIP_NOTE % assets if assets else None))) or None


def _any_hint(files, hints):
    for f in files or ():
        # Treat a repository-relative root like every nested directory boundary.
        # Slash-delimited hints such as /tests/ still require both path separators.
        low = "/" + str(f).lower().lstrip("/")
        if any(h in low for h in hints):
            return True
    return False


def _has_test_surface(files):
    """The TST floor's signal: `discovery.is_test_file` OR `_TEST_FILE_HINTS`.

    Both halves are load-bearing (#1770 ARC-3682668884). Only discovery's
    `TEST_PATTERNS` know the SUFFIX conventions -- `AppTest.java`,
    `AccountTests.cs`, `AuthTest.php`, `app_tests.py` -- which no substring hint
    matches, so before the union a flat Java layout and every standard C#/PHP
    repo drew no guaranteed TST cell. Only the hints cover the plumbing the
    naming rule misses: a `conftest`, a `/tests/` corpus, a `.feature` file.

    The path is passed to `is_test_file` AS GIVEN, because those patterns are
    anchored and case-SENSITIVE (`Test\\.java$`); `_any_hint` lowercases instead.
    """
    for f in files or ():
        if discovery.is_test_file(str(f)):
            return True
    return _any_hint(files, _TEST_FILE_HINTS)


def applicable_global_floor(files, scout, global_floor=GLOBAL_FLOOR):
    """Subset of `global_floor` whose review surface is objectively present for
    this group (#5.0-19, #1193). COD is universal; DAT/TST/ARC gate ONLY on
    deterministic file signals. Scout-asserted ScopeProfile fields are ignored
    here so a mis-reporting scout cannot suppress a floor domain whose surface
    objectively exists (files present), and a scout-requested domain that is not
    objectively surfaced is still available via scout_added in effective_panels.
    The TST signal is the UNION of discovery's naming rule
    (`discovery.is_test_file` / `TEST_PATTERNS`) and `_TEST_FILE_HINTS`, so the
    two derivations of "is this a test file" cannot drift apart and leave the
    guarantee above unkept for a whole language's convention (#1770).
    Pure; the return is always a subset of `global_floor`.

    - COD: any file that is not a recognized binary/media asset (#1489). COD was
      previously unconditional, so a pure-asset group -- which `chunk_files`
      produces reliably, because it packs by directory -- still drew a COD cell.
      Across 7 calibration runs those cells returned 0 findings in every
      instance, against a 2.71-5.83 corpus baseline.
    - DAT: any db/schema/model/migration/seed file.
    - TST: any test-file signal, per `_has_test_surface`.
    - ARC: the group spans >= 2 distinct file directories (real cross-module
      structure).
    """
    files = list(files or [])
    keep = set()
    if "COD" in global_floor and has_code_surface(files):
        keep.add("COD")
    if "DAT" in global_floor and _any_hint(files, _DB_FILE_HINTS):
        keep.add("DAT")
    if "TST" in global_floor and _has_test_surface(files):
        keep.add("TST")
    distinct_dirs = {os.path.dirname(str(f)) for f in files}
    if "ARC" in global_floor and len(distinct_dirs) >= 2:
        keep.add("ARC")
    return frozenset(keep & set(global_floor))


def applicable_sec_floor(files):
    """`frozenset({"SEC"})` for every deterministic code group (#3338).

    Code is derived only from file shapes via `has_sec_code_surface`, never a
    group name or scout assertion (#1193). Known documentation and asset-only
    groups stay SEC-free (#5.0-19); an unfamiliar file type fails toward SEC.
    SEC remains NON_EXCLUDABLE once floored (#1084). The same per-file answer is
    the `exclude_paths` carve-out predicate, so security-looking binary names no
    longer re-admit PNGs or other known assets (#1757).
    """
    return frozenset({"SEC"}) if has_sec_code_surface(files) else frozenset()


def effective_panels(floor, scout_added, exclude, global_floor=GLOBAL_FLOOR,
                     signal_floor=frozenset()):
    """Return (effective_set, disclosure_dict).

    effective = (global_floor | signal_floor | floor | scout_added) - exclude.
    floor ∩ exclude is assumed empty (validated by groups_schema); exclude still
    wins mechanically here so a bad file degrades safe (a panel is never both run
    and disclosed-off). The global_floor (universal-tier COD/DAT/TST/ARC) and the
    signal_floor (objective-signal domains such as SEC via applicable_sec_floor)
    are folded into the declared floor so they are forced on AND disclosed
    (#5.0-11, #run8 SEC-G2A). A signal_floor domain that is also NON_EXCLUDABLE
    (SEC) therefore both force-runs and survives a committed `exclude`.
    """
    floor = set(floor) | set(global_floor) | set(signal_floor)
    scout_added = set(scout_added)
    raw_exclude = set(exclude)
    # #1084: a non-excludable domain (SEC) is dropped from the exclude set, so a
    # committed `exclude: [SEC]` can never remove it from what actually runs.
    exclude = raw_exclude - NON_EXCLUDABLE
    effective = (floor | scout_added) - exclude
    # NB: "floor" is the DECLARED floor (not netted against exclude); `effective`
    # is what actually runs. In a validation-forbidden floor∩exclude overlap a
    # domain can appear in both "floor" and "excluded" — the loudest disclosure.
    disclosure = {
        "floor": sorted(floor),
        "scout_added": sorted(scout_added - exclude),
        "excluded": sorted(exclude),
    }
    rejected = sorted(raw_exclude & NON_EXCLUDABLE)
    if rejected:
        # surface the attempted-but-ignored exclusion so it's never silent
        # (#1084). This does not assert the domain actually ran: a domain
        # named here can still be absent from `effective` when neither the
        # floor nor the scout ever put it there (#1838 SEC-71240568) -- check
        # `effective` (or `floor`) to know whether it ran.
        disclosure["exclude_rejected"] = rejected
    return effective, disclosure


# 5.2 §6.2: the scout brief's surface -> domain prose (skill/agents/scout.md
# "## Domains") as code, so domain selection is reproducible from surfaces and
# the setup post-pass can floor a `custom:` capability from its profile
# (#1490). The 13 surfaces are the scout's enum; anything else is ignored.
SURFACES = frozenset({
    "db_sql", "http_web", "auth", "crypto", "fs", "concurrency", "external_api",
    "money_pii", "serialization", "templating", "secrets_config",
    "architecture", "database",
})
_SEC_SURFACES = SURFACES - {"architecture"}
_DAT_SURFACES = frozenset({"db_sql", "database"})


def surfaces_to_domains(surfaces):
    """The scout mapping as a function: COD always; SEC on any surface but
    `architecture`; DAT on `db_sql`/`database`; ARC on `architecture`.
    TST/QAL/AGT/OPS/ACC/LNG come from non-surface signals and stay with the
    live scout. Unknown surfaces are ignored. Returns a sorted list."""
    found = {s for s in (surfaces or []) if isinstance(s, str)} & SURFACES
    out = {"COD"}
    if found & _SEC_SURFACES:
        out.add("SEC")
    if found & _DAT_SURFACES:
        out.add("DAT")
    if "architecture" in found:
        out.add("ARC")
    return sorted(out)
