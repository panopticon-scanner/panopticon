#!/usr/bin/env python3
"""Ingest raw static-analysis tool output into panopticon findings.

Files in *tools_dir* are matched by basename (without extension) against the
registered adapters in ``scripts.tools.ADAPTERS`` and routed to the matching
adapter for parsing. SARIF or JSON files whose basename has no registered
adapter are skipped with a diagnostic. Stdlib-only.
"""
import fnmatch
import glob
import json
import os
import sys

from scripts.tools import ADAPTERS
from scripts.tools.base import strip_ansi, target_root_cv
from scripts.tools.sarif_utils import (
    CWE_TAG,
    CVE_TAG,
    LEVEL_TO_SEV,
    NOISE_RULES,
    PREFIX,
    is_fixture_path,
    is_test_path,
    norm_uri,
    rules_index,
    _is_fixture_path,
    _is_test_path,
    _norm_uri,
    _rules_index,
    sarif_to_findings,
)
from scripts.run_tools import MAX_TOOL_OUTPUT_BYTES  # #run7 OPS-D1A: shared cap

# Re-export shared SARIF helpers so existing callers/tests keep working.
__all__ = [
    "CWE_TAG",
    "CVE_TAG",
    "LEVEL_TO_SEV",
    "NOISE_RULES",
    "PREFIX",
    "is_fixture_path",
    "is_test_path",
    "norm_uri",
    "rules_index",
    "_is_fixture_path",
    "_is_test_path",
    "_norm_uri",
    "_rules_index",
    "ingest_dir",
    "ingest_dir_detailed",
    "suppressed_counts",
    "sarif_to_findings",
]


# Top-level dirs that are never project source: a nested checkout, the git dir,
# and panopticon's OWN artifact tree.
_RUN_ARTIFACT_DIRS = {".worktrees", ".git", ".panopticon"}
# Dirs that are generated build output at ANY depth, plus their file extensions.
_GENERATED_DIRS = {"__pycache__"}
_GENERATED_SUFFIXES = (".pyc", ".pyo")
# VENDORED third-party dependencies at any depth. Same class as generated
# bytecode: present in the tree, scanned by every tool, and not the project's
# code to fix. #calibration-5 (solidus) -- eslint-security emitted 623 messages
# and 592 of them (95%) were in `vendor/`, almost all one rule
# (security/detect-object-injection) firing on bundled jQuery and friends.
# Deliberately conservative: only the conventional dependency directories, and
# only as a PATH SEGMENT, so a project file named `vendor_test.rb` or a
# legitimate `app/vendors/` model is untouched.
_VENDORED_DIRS = {"vendor", "node_modules", "bower_components", "third_party",
                  "vendored", ".bundle", ".yarn"}
# VIRTUALENVS, at any depth -- #1638 P09 (owner ruling D8). A virtualenv is
# vendored code that happens to live in the checkout: run-13 ingested 58 bandit
# findings from `.venv/` and they bought 46 of 128 tool-advisor dispatches
# (35.9%), returning 2 confirmations against 32 rejections and 12 not-material.
# METADATA FIRST: `pyvenv.cfg` is the marker every creator writes (venv,
# virtualenv, uv, pipenv, poetry-in-project), so it catches the ones named
# `env/` or `.direnv/` that no name list would.
_VENV_MARKER = "pyvenv.cfg"
_VENV_DIR_NAMES = {".venv", "venv"}
# NAMES SECOND, and unconditionally: ingest reads SARIF paths and often has no
# tree to stat (the CI gate points at a temp directory of artifacts). D8's
# accepted trade-off is that a `venv/` holding real tracked source is excluded
# anyway -- the name is reserved by convention. `site-packages` joins them: it
# is a virtualenv or a vendored install either way, and neither is ours to fix.
_VENV_NAME_SEGMENTS = _VENV_DIR_NAMES | {"site-packages"}
# Where a tools directory sits inside the scanned repo, used to derive the
# target root when no caller passes one.
_ARTIFACT_DIR = ".panopticon"
# The venv cache's slot for the RESOLVED root. A tuple, so it can never collide
# with the relative-directory strings that are the cache's other keys.
_REAL_ROOT_KEY = ("__realpath__",)


def _has_venv_marker(root, rel):
    """True when `<root>/<rel>` holds a `pyvenv.cfg` AND really is inside root.

    The realpath check is the confinement: a symlinked directory in the target
    that resolves outside it is not a tree we let mark anything.
    """
    directory = os.path.join(root, *rel.split("/"))
    if not os.path.isfile(os.path.join(directory, _VENV_MARKER)):
        return False
    real = os.path.realpath(directory)
    return real == root or real.startswith(root + os.sep)


def _under_a_virtualenv(dirs, target_root, cache=None):
    """True when some ancestor DIRECTORY of a finding carries a `pyvenv.cfg`.

    `dirs` is the finding's ancestor segments (no basename), so the marker is
    always `<ancestor>/pyvenv.cfg` -- a `pyvenv.cfg` planted anywhere else (a
    test fixture, say) marks its own directory and nothing above or beside it.
    A segment that could climb out of the root refuses before any stat. Lookups
    are memoized per directory for the whole ingest run: a venv holds thousands
    of files that would otherwise re-stat the same handful of directories. The
    ROOT's own resolution is memoized in the same cache (#1638 P09 F6) -- it was
    recomputed for every finding, and `realpath` is a syscall per path segment.
    """
    cache = {} if cache is None else cache
    root = cache.get(_REAL_ROOT_KEY)
    if root is None:
        root = cache[_REAL_ROOT_KEY] = os.path.realpath(target_root)
    rel = ""
    for seg in dirs:
        if seg in ("", ".", ".."):
            return False
        rel = "%s/%s" % (rel, seg) if rel else seg
        hit = cache.get(rel)
        if hit is None:
            hit = cache[rel] = _has_venv_marker(root, rel)
        if hit:
            return True
    return False


def _target_root_for(tools_dir):
    """The scanned repo root implied by a tools directory, or None.

    Every ingest site points at `<target>/.panopticon/[runs/<tag>/]tools`, so
    the root is the parent of that `.panopticon`. Derived rather than demanded
    of each caller because the four ingest sites must resolve the SAME root for
    the same directory: phases/verify pins its ingest to synthesize's so the
    tool-verify queue and the report agree on every finding id, and a root that
    differed between them would split that identity. None when there is no
    `.panopticon` ancestor (the CI gate scans a temp dir) -- the name fallback
    alone decides then.

    The NEAREST `.panopticon` segment is the run's: a checkout that itself sits
    under a `.panopticon` path would otherwise resolve to the directory above
    that path and stat markers against the wrong tree.
    """
    parts = os.path.abspath(tools_dir).split(os.sep)
    if _ARTIFACT_DIR not in parts:
        return None
    cut = len(parts) - 1 - parts[::-1].index(_ARTIFACT_DIR)
    return os.sep.join(parts[:cut]) or os.sep


def _is_run_artifact_path(fpath, target_root=None, venv_cache=None):
    """True for a tool finding located in something that is not project source.

    run_tools mounts the whole target read-only and the scanners walk ALL of it,
    while the agentic scan prunes these -- so the tool path re-finds what review
    never looks at. Three classes, all unconditional (unlike the fixture prune,
    which has an include_fixtures opt-in):

    - a NESTED CHECKOUT (`.worktrees/`) or the git dir -- run-9 E3.
    - `.panopticon/` -- panopticon's OWN artifact tree. run-10 D1: gitleaks
      flagged `private-key` inside
      `.panopticon/claude-redteam-repo-20260825-...-report-discarded.json`, i.e.
      THIS run re-found the rejected secret findings of a PREVIOUS run, and
      semgrep flagged the run's own `tools/gitleaks.sarif`. Every run left
      artifacts for the next run to re-adjudicate, so tool-axis noise compounded
      run over run instead of staying flat.
    - GENERATED bytecode (`__pycache__/`, `*.pyc`) at any depth -- a finding
      "in" compiled bytecode is unactionable and duplicates its own source file.
    - a PYTHON VIRTUALENV (#1638 P09, ruling D8) -- the same class, installed
      rather than committed. Metadata first: any ancestor directory carrying a
      `pyvenv.cfg` (needs *target_root*; without one there is no tree to stat).
      Names second, always: a `.venv`, `venv` or `site-packages` segment. The
      trade-off D8 accepts is that a `venv/` with no marker that holds real
      tracked source is excluded anyway -- the name is reserved by convention,
      and a substring (`src/venvutils.py`, `app/environments/`) never matches.
      Dependency AUDITING is untouched: pip-audit/osv-scanner/trivy read
      `requirements*.txt` / `pyproject.toml` / lockfiles, not the venv tree.

    Together the first three were 16 of run-10's 54 rejected tool findings
    (30%), each one costing a tool-advisor dispatch to reject.

    VENDORED dependencies are NOT here any more (#1578): they are the one class
    whose drop is disclosed per segment and handed back to a caller that must
    not lose it, so `_vendored_segment` owns them. This predicate keeps the
    classes that stay silent -- re-gating a previous run's own discarded report
    is the compounding noise run-10 D1 removed, and re-gating bytecode is a
    duplicate of its own source file.
    """
    norm = str(fpath).replace(os.sep, "/").lstrip("/")
    parts = norm.split("/")
    dirs = parts[:-1]
    if parts[0] in _RUN_ARTIFACT_DIRS:
        return True
    if any(p in _GENERATED_DIRS for p in dirs):
        return True
    if any(p in _VENV_NAME_SEGMENTS for p in dirs):
        return True
    if target_root and _under_a_virtualenv(dirs, target_root, venv_cache):
        return True
    return norm.endswith(_GENERATED_SUFFIXES)


def _vendored_segment(fpath):
    """The `_VENDORED_DIRS` directory this finding sits under, or None (#1578).

    Third-party code the project ships but does not author: a finding there is
    not the project's to fix, and the dependency scanners (osv-scanner, trivy,
    bundler-audit) already cover that surface BY VERSION, which is the
    actionable form. #calibration-5 (solidus): eslint-security emitted 623
    messages and 592 of them (95%) were under `vendor/`, almost all one rule
    firing on bundled jQuery.

    Returning the SEGMENT rather than a bool is the whole of #1578's mechanics
    ruling. The match is on a conventional NAME, not on provenance -- no
    lockfile, no vendoring marker, no `.gitattributes linguist-vendored` -- so a
    file the target chose to put under a directory called `vendor` is dropped
    on that name alone. That is defensible only while an operator can SEE it
    happen, which means the name has to travel with the count: `{"vendor": 592}`
    in `meta.coverage.tools_suppressed` distinguishes a bundled library from an
    evasion, and an aggregate "excluded N finding(s)" never could.

    Matched as a full path SEGMENT and never as the basename, so `app/vendors/`,
    `vendor_test.rb` and a file literally named `vendor` are untouched.
    """
    norm = str(fpath).replace(os.sep, "/").lstrip("/")
    for seg in norm.split("/")[:-1]:
        if seg in _VENDORED_DIRS:
            return seg
    return None


def _filter_parsed_findings(parsed, include_fixtures, exclude_globs,
                            target_root=None, venv_cache=None,
                            suppressed_out=None):
    """Split one adapter's parse into (kept, fx, gl, ra, suppressed-by-segment).

    #1578: a vendored drop is no longer anonymous. Each one is counted against
    the segment that caused it, and when `suppressed_out` is a list the finding
    itself is appended to it carrying a `suppressed` key naming that segment --
    which is how `security_gate` gets its findings back under redteam without
    the report having to publish them.
    """
    kept, fx_count, gl_count, ra_count = [], 0, 0, 0
    suppressed = {}
    for f in parsed:
        # #run7 QAL-D1A: normalize os.sep -> "/" before matching, mirroring
        # run_tools._is_excluded, so an exclude_glob behaves identically on both
        # the ingest and the scan path (a no-op on POSIX; correct on Windows).
        fpath = str((f.get("location") or {}).get("file", "")).replace(os.sep, "/")
        vendored = None
        if _is_run_artifact_path(fpath, target_root, venv_cache):   # not project source
            ra_count += 1
        elif (vendored := _vendored_segment(fpath)):                # #1578
            suppressed[vendored] = suppressed.get(vendored, 0) + 1
            if suppressed_out is not None:
                item = dict(f)
                item["suppressed"] = vendored
                suppressed_out.append(item)
        elif not include_fixtures and _is_fixture_path(fpath):
            fx_count += 1
        elif exclude_globs and any(fnmatch.fnmatch(fpath, g) for g in exclude_globs):
            gl_count += 1
        else:
            kept.append(f)
    return kept, fx_count, gl_count, ra_count, suppressed


def network_exclusions(manifest):
    """Adapters refused safe egress, distinct from an operator's scope choice."""
    from scripts.tools import egress
    network = manifest.get("network") if isinstance(manifest, dict) else None
    if not isinstance(network, dict):
        return {}
    return {name: posture for name, posture in network.items()
            if isinstance(name, str) and isinstance(posture, str)
            and posture.startswith(egress.EXCLUDED_PREFIX)}


def lost_required_coverage(manifest, dispositions):
    """Selected scanners that did not deliver usable coverage, with reasons.

    Returns an ordered ``{tool: {"kind": "absent"|"unusable", "reason": str}}``
    in the manifest's own selection order. This is the single definition of
    "required coverage we did not get", shared by the CI gate
    (`security_gate.evaluate`) and the report's tool axis -- #1512 existed
    because those two had separate answers and the report's was derived from the
    manifest alone, so a scanner that wrote unparseable bytes still certified.

    - `absent`   -- named in the manifest's `missing`, or selected with no
                    disposition at all (an inconsistent manifest claiming
                    production that ingestion never saw).
    - `unusable` -- output exists but ingestion could not use it: malformed,
                    truncated, oversized, unreadable, or no registered adapter.

    Operator scope exclusions are never required. An adapter excluded because
    safe egress was unavailable is lost coverage and is named as `network`.
    `empty` is completed coverage -- a scanner that ran and found nothing is the
    outcome the pipeline hopes for. `noscan` is deliberately NOT lost coverage
    either: #1335 judged it separately as a no-surface disclosure
    (`produced_noscan`, non-gating), and folding it in here would silently
    re-gate it.
    """
    missing = set(manifest.get("missing") or [])
    lost = {}
    for name in manifest.get("selected") or []:
        if not isinstance(name, str):
            continue
        disposition = dispositions.get(name) if dispositions else None
        if name in missing or disposition is None:
            lost[name] = {"kind": "absent", "reason": "no output"}
        elif disposition.get("status") == "failed":
            lost[name] = {"kind": "unusable",
                          "reason": disposition.get("reason") or "failed"}
    lost.update({name: {"kind": "network", "reason": reason}
                 for name, reason in network_exclusions(manifest).items()})
    return lost


def _scanned_files(raw):
    """The scanned-file count run_tools recorded on the artifact, or None.

    #1335: `runs[0].properties.panopticon_scanned_files` is stamped at capture
    time from a scanner's own stderr (semgrep today). None means the artifact
    makes no claim -- an older run, a tool with no such signal, or stderr that
    did not match. Only an explicit 0 is evidence of a no-op.
    """
    try:
        props = json.loads(raw)["runs"][0]["properties"]
        count = props["panopticon_scanned_files"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None
    return count if isinstance(count, int) and not isinstance(count, bool) else None


# #1236 (OPS-D1B): no adapter capped its own result list. Filed against
# bundler-audit's advisory loop, but the class is generic and THIS is where
# every adapter's parse() is called, so the bound lives here once instead of
# once per adapter. Set well above any honest scan: a repo that trips this has
# a pathological lockfile or a rule loop, which is exactly the case the bound
# is for.
MAX_ADAPTER_FINDINGS = 2000

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _cap_findings(parsed, tool):
    """Bound one adapter's yield, keeping the most severe. Returns (kept, dropped).

    Severity-ordered rather than first-N: dropping a CRITICAL to keep a page of
    notes would be worse than not capping. The sort is stable, so within a
    severity the adapter's own order survives.
    """
    if len(parsed) <= MAX_ADAPTER_FINDINGS:
        return parsed, 0
    ordered = sorted(parsed, key=lambda f: _SEVERITY_RANK.get(
        str(f.get("severity", "INFO")).upper(), len(_SEVERITY_RANK)))
    dropped = len(parsed) - MAX_ADAPTER_FINDINGS
    print("ingest note %s: %d findings exceeds the %d cap; kept the %d most "
          "severe, dropped %d (OPS-D1B #1236)"
          % (tool, len(parsed), MAX_ADAPTER_FINDINGS, MAX_ADAPTER_FINDINGS,
             dropped), file=sys.stderr)
    return ordered[:MAX_ADAPTER_FINDINGS], dropped


def ingest_dir_detailed(tools_dir, group, exclude_globs=None, include_fixtures=False,
                        target_root=None, suppressed_out=None):
    """Ingest raw tool-output files and report each adapter's disposition.

    Returns (findings, dispositions). dispositions maps each output file's
    adapter name (its filename stem) to {"status": ok|empty|noscan|failed,
    "findings": int} plus a "reason" when failed. This is the single
    authoritative walk — a file's disposition reflects exactly what parsing
    saw, so nothing downstream can classify it differently. `findings` is the
    adapter's raw yield BEFORE fixture exclusion, so an adapter whose findings
    were all fixture-noise still reads as having run (status/findings from the
    raw parse; only `out` is filtered).

    Fixture prune (default): unless *include_fixtures* is True, findings whose
    location.file lives under a test-fixture corpus dir (``_is_fixture_path``)
    are dropped — the tool-path equivalent of the agentic review-path prune
    (#434). The tool scanners (osv-scanner, trivy) walk the whole repo and
    report the intentionally-vulnerable fixtures under tests/fixtures/, which
    would otherwise dominate a self-scan. #1055: the prune is keyed on the
    explicit include_fixtures flag alone — redteam no longer auto-keeps fixture
    TOOL findings (that only re-adjudicated designed-vulnerable scaffolding);
    pass include_fixtures=True to opt in. Fixture CONTENT review is independent
    of this flag (it is governed by the config's routing on the review path).

    exclude_globs (F-CAL-2): additional fnmatch patterns matched against each
    finding's location.file; matches are dropped too. Both filters share one
    aggregate stderr note.

    suppressed_out (#1578): an optional list the VENDORED-path drops are
    appended to, each carrying a `suppressed` key naming the segment that
    dropped it. The returned `findings` never contain them either way -- the
    report-side suppression is what makes tool output usable, and 95% of
    run-12's tool noise was `vendor/`. A caller that must not lose a finding to
    a directory name (`security_gate.evaluate` under `--security redteam`) asks
    for them here instead of turning the exclusion off for everyone.

    target_root (#1638 P09): the scanned repo, against which a finding's
    ancestor directories are checked for a `pyvenv.cfg` virtualenv marker. It
    defaults to the root the tools directory itself implies, so every ingest
    site answers identically for the same directory whether or not it passed
    one; a caller that holds the root (the driver's phases do) passes it.
    """
    out = []
    dispositions = {}
    root = target_root or _target_root_for(tools_dir)
    venv_cache = {}   # per-run memo of the pyvenv.cfg lookups
    fx_excluded = 0   # dropped by the default fixture-corpus prune
    gl_excluded = 0   # dropped by an explicit exclude_glob
    ra_excluded = 0   # dropped as not-project-source (run-9 E3 / run-10 D1)
    suppressed = {}   # {segment: count} dropped as vendored (#1578)
    for path in sorted(glob.glob(os.path.join(tools_dir, "*.sarif"))
                       + glob.glob(os.path.join(tools_dir, "*.json"))):
        tool = os.path.splitext(os.path.basename(path))[0]
        adapter = ADAPTERS.get(tool)
        if adapter is None:
            print("ingest skip %s: no adapter registered" % path, file=sys.stderr)
            dispositions[tool] = {"status": "failed", "findings": 0,
                                  "reason": "no registered adapter"}
            continue
        try:
            # #run7 OPS-D1A: bound the read. This is a general entry point that
            # can be pointed at an arbitrary directory; the capped-writer feeds it
            # normally, but an oversized (or maliciously large) *.sarif/*.json
            # would otherwise be slurped whole into memory. Read one byte past the
            # cap to detect the overflow, then fail-closed on that file.
            with open(path, "rb") as fh:
                raw = fh.read(MAX_TOOL_OUTPUT_BYTES + 1)
        except OSError as e:
            print("ingest skip %s: %s" % (path, e), file=sys.stderr)
            dispositions[tool] = {"status": "failed", "findings": 0,
                                  "reason": "unparseable: %s"
                                  % (str(e).splitlines() or [""])[0]}
            continue
        if len(raw) > MAX_TOOL_OUTPUT_BYTES:
            print("ingest skip %s: output exceeds the %d-byte cap"
                  % (path, MAX_TOOL_OUTPUT_BYTES), file=sys.stderr)
            dispositions[tool] = {"status": "failed", "findings": 0,
                                  "reason": "oversize: exceeds %d-byte cap"
                                  % MAX_TOOL_OUTPUT_BYTES}
            continue
        if not raw.strip():
            print("ingest skip %s: empty output file" % path, file=sys.stderr)
            dispositions[tool] = {"status": "failed", "findings": 0,
                                  "reason": "empty output file"}
            continue
        # Some tools decorate stdout before the JSON payload (calibration
        # 2026-08-03: bandit's progress bar corrupted its SARIF). Strip ANSI
        # escape sequences first — a CSI introducer '\x1b[' otherwise makes the
        # scan below trim to the '[' of the escape code rather than the real
        # JSON (pip-audit's progress spinner) — then trim to the first JSON
        # start token (object OR array; eslint emits a top-level array) so a
        # cosmetic prefix never discards real findings.
        raw = strip_ansi(raw)
        starts = [i for i in (raw.find(b"{"), raw.find(b"[")) if i != -1]
        first = min(starts) if starts else -1
        if first > 0:
            print("ingest note %s: stripped %d bytes of non-JSON prefix"
                  % (path, first), file=sys.stderr)
            raw = raw[first:]
        # #1649: name the tree this parse is about. `invoke` ran in another
        # process (the tools container), so an adapter whose finding location
        # depends on WHICH manifest it audited resolves that here instead --
        # against the root this function already holds.
        token = target_root_cv.set(root)
        try:
            parsed = adapter.parse(raw, group)
        except Exception as e:  # noqa: BLE001 - tolerant by design
            print("ingest error %s: %s" % (path, e), file=sys.stderr)
            dispositions[tool] = {"status": "failed", "findings": 0,
                                  "reason": "unparseable: %s"
                                  % (str(e).splitlines() or [""])[0]}
            continue
        finally:
            target_root_cv.reset(token)
        raw_count = len(parsed)
        parsed, truncated = _cap_findings(parsed, tool)
        scanned = _scanned_files(raw)
        parsed, fx_cnt, gl_cnt, ra_cnt, sup_cnt = _filter_parsed_findings(
            parsed, include_fixtures, exclude_globs, root, venv_cache,
            suppressed_out)
        fx_excluded += fx_cnt
        gl_excluded += gl_cnt
        ra_excluded += ra_cnt
        for seg, n in sup_cnt.items():
            suppressed[seg] = suppressed.get(seg, 0) + n
        out.extend(parsed)
        if raw_count:
            status, reason = "ok", None
        elif scanned == 0:
            # #1335: no findings AND a run-time witness that nothing was scanned.
            # "empty" would credit coverage this adapter never provided.
            status, reason = "noscan", "scanned 0 files"
        else:
            status, reason = "empty", None
        dispositions[tool] = {"status": status, "findings": raw_count}
        if truncated:
            # Disclosed, never silent: `findings` stays the RAW count, so a
            # report reads "N seen, M dropped" rather than looking like a
            # smaller clean scan (#1236).
            dispositions[tool]["truncated"] = truncated
        if reason:
            dispositions[tool]["reason"] = reason
    sup_total = sum(suppressed.values())
    if fx_excluded or gl_excluded or ra_excluded or sup_total:
        reasons = []
        if fx_excluded:
            reasons.append("test-fixture corpus")
        if ra_excluded:
            reasons.append("not project source (nested checkout / git dir / "
                           ".panopticon artifacts / generated bytecode / "
                           "virtualenvs)")
        if sup_total:
            # #1578: named per segment with its count, not folded into the
            # aggregate above. This line is the stderr half of the SUM of
            # `meta.coverage.tools_suppressed` and `tools_suppressed_gated`
            # (#1701 splits the tally by what the gate counted); all exist so
            # an operator can tell a bundled library from a payload parked
            # under `vendor/`.
            reasons.append("vendored dependencies (%s)"
                           % ", ".join("%s: %d" % (seg, suppressed[seg])
                                       for seg in sorted(suppressed)))
        if gl_excluded:
            reasons.append(", ".join(exclude_globs))
        print("ingest: excluded %d finding(s) (%s)"
              % (fx_excluded + gl_excluded + ra_excluded + sup_total,
                 "; ".join(reasons)), file=sys.stderr)
    return out, dispositions


def suppressed_counts(suppressed):
    """`{segment: count}` from a `suppressed_out` list (#1578).

    One definition, because two consumers publish this number and they must not
    disagree about it: the report's `meta.coverage.tools_suppressed` and the CI
    gate's own line beside its verdict.
    """
    counts = {}
    for finding in suppressed or []:
        seg = (finding or {}).get("suppressed")
        counts[seg] = counts.get(seg, 0) + 1
    return counts


def ingest_dir(tools_dir, group, exclude_globs=None, include_fixtures=False,
               target_root=None, suppressed_out=None):
    """Ingest raw tool-output files from a directory and route them to the
    registered adapter for parsing. Files without a registered adapter or that
    fail to parse are skipped with a stderr diagnostic.

    Findings-only wrapper over ingest_dir_detailed (unchanged contract).
    """
    findings, _dispositions = ingest_dir_detailed(
        tools_dir, group, exclude_globs, include_fixtures, target_root,
        suppressed_out)
    return findings
