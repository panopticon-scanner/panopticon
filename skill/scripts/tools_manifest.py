#!/usr/bin/env python3
"""The tools manifest: `tools-manifest.json`'s schema and the ledgers it reads.

The one writer of the SCANNER coverage manifest -- what was selected, what was
produced, what is therefore missing, and the observations published beside them:
the egress each tool was granted, whether every capture went through the
redaction choke point, what the run did with the target's own inline suppression
comments and its `.gitleaksignore`, which configuration file each pinned scanner
ran under, the adapters the gate's globs disqualified, the virtualenv
directories the scan pruned and what an adapter refused to hand its scanner.
`security_gate` reads it, the tools phase copies `redacted` out of it and
`synthesize` refuses to certify against another run's, so every key here is a
published contract and the order they are written in is part of it.

NOT `run_manifest.py`, which writes the OTHER manifest -- the review RUN's (host,
run id, review root, baseline) -- and has a `write_manifest` of its own. Two
manifests, two modules, no shared code; `tests/test_run_manifest.py` is that
one's file.

Two of the four posture ledgers live here, beside their only reader: the network
posture (#1645) and the gitleaks ignore-file posture. The other two -- the
inline-suppression posture and the scanner-config posture -- belong to
`scanner_config`, which stages the files they are about. `run_tools` binds all
four back and is where each is cleared at the top of a scan and filled where the
argv is built; a ledger is the SAME dict object either way, so one name is one
ledger.

Separate from `run_tools` because that module was 2215 lines, outside this
repo's own 700-line ratchet, and absorbing every new scanner policy because
nothing pushed back (#1762, ARC-2609514778). This is part 3 of 3 of that split
and it moved the block whole: no key, value, order, byte or message changed, and
`tests/test_tools_manifest.py` compares the exact BYTES of seven manifests --
both security modes, `run_id` set and unset, the eslint coverage read, an
adapter refused its egress and the docker-absent shape -- against a golden
captured before the move.

The arrow points ONE way: nothing here imports `run_tools`, which imports this.
That is why `VENV_MAX_DEPTH` lives here while the walk that reads it back
(`find_virtualenvs`) stayed behind. Stdlib-only.
"""
import json
import os

from scripts import safe_write
# BY NAME, never `from scripts import scanner_config`: `write_manifest`'s
# published `scanner_config=` keyword would shadow a module binding inside the
# function body, so reaching a new constant that way needs a module ALIAS
# (`scanner_config as _scanner_config`) rather than the bare import.
from scripts.scanner_config import _SCANNER_CONFIG_POSTURE, _SUPPRESSION_POSTURE
from scripts.tool_capture import MAX_TOOL_OUTPUT_BYTES, _REDACTED_CAPTURES
from scripts.tools import egress

# How deep the virtualenv walk that found `excluded_dirs` looked, published as
# `depth_bound` so a reader knows the list is bounded rather than exhaustive. It
# lives HERE, and not with the walk, for the import direction: `run_tools` imports
# this module and never the reverse, and `write_manifest`'s `depth_bound` default
# is bound at `def` time, so the bound cannot be read back across the seam.
# `run_tools.find_virtualenvs` -- the walk that is actually bounded by it, and its
# other reader -- binds it back. Venvs live near the root, and that walk is paid
# on every scan.
VENV_MAX_DEPTH = 3


# What egress each tool was granted this run, keyed by tool name (#1645). Same
# construction and the same reason as `tool_capture._REDACTED_CAPTURES`:
# `run_tools()` clears it and fills it WHERE THE ARGV IS BUILT, so the manifest
# reports what the runner observed itself doing -- take the flags away and the
# claim goes with them, rather than a `proxied:` string surviving as an
# intention nothing enforces. Values are `"none"`, `"proxied:<allowlist>"` or
# the fail-closed `"excluded:online egress unavailable"`
# (scripts.tools.egress).
_NETWORK_POSTURE: dict[str, str] = {}

# Only a produced Gitleaks capture may carry this observation. Filled from the
# mount kept alive during its launch, then filtered to produced in write_manifest.
_IGNORE_FILE_POSTURE: dict[str, str] = {}


def _excluded_dir_row(d):
    """One `excluded_dirs` row for the manifest.

    #1740: `skipped` is the whole point of the row under redteam -- a name-only
    venv is DETECTED and scanned anyway. True for a caller that passed
    `find_virtualenvs` output directly, which is the pre-#1740 meaning of this
    list. #1839: `note` is present only when the runner had a reason of its own
    for scanning a directory it detected -- a marker with no environment under
    it, or a name no exclusion pattern can express -- so an operator reading
    `skipped: false` under `standard` is not left to guess which.
    """
    row = {"path": str(d["path"]), "reason": str(d["reason"]),
           "skipped": bool(d.get("skipped", True))}
    if d.get("note"):
        row["note"] = str(d["note"])
    return row


def write_manifest(path, selected, written, excluded_scope=(), run_id=None,
                   excluded_dirs=(), depth_bound=VENV_MAX_DEPTH, sanitized=None,
                   network=None, exclude_globs=(), suppression_comments=None,
                   scanner_config=None, ignore_files=None):
    """Write the exact selected/produced scanner set for coverage gating.

    `excluded_scope` names adapters that were applicable but whose entire
    surface fell under the gate's --exclude globs; they are disclosed (never
    required), and are kept out of `selected` so the missing-set invariant
    holds.

    `excluded_dirs` (#1638 P09) are the virtualenv directories this scan
    DETECTED, as ``{"path", "reason", "skipped"[, "note"]}`` rows -- so a report can say
    what was pruned and on what evidence (`pyvenv.cfg` or the conventional
    name) rather than leaving a silent hole in the scanned surface. #1740:
    `skipped` is what separates the two, because under `--security redteam` a
    name-only directory is detected and scanned anyway; it defaults to True, so
    a caller handing `find_virtualenvs` output straight in still publishes this
    list's pre-#1740 meaning. `depth_bound` is how deep
    the walk that found them looked: the list is what the SCANNERS were told to
    skip, and ingest drops virtualenv findings at any depth, so a reader knows
    the list is bounded rather than exhaustive. Additive: both fields are new in
    this schema version and every consumer reads them optionally, so an older
    manifest without them still loads.

    `sanitized` (#1646) is what an adapter refused to hand its scanner, per
    adapter: `{"pip-audit": {"source", "kept", "dropped": [{"line", "reason"}],
    "hashes_stripped"}}`. pip-audit is now given a GENERATED requirements file
    holding only bare PEP 508 lines, because resolving an editable/local/VCS/URL
    requirement runs the reviewed repo's build backend -- so the dependency
    audit can be PARTIAL, and this is where it says by how much and which lines.
    Stated on every manifest, `{}` included, so its absence cannot be read as
    "nothing was dropped" on a run that never measured.

    `exclude_globs` (#1740 fix round 1) are the `--exclude` path globs this
    scan was given -- the driver passes the repository's committed
    `exclude_paths:`, CI passes its own. `excluded_scope` beside it names the
    ADAPTERS those globs disqualified; this is the policy itself, so a reader
    can tell "no adapter was excluded" from "no policy was applied". Stated on
    every manifest, `[]` included, like `sanitized`.

    `file_coverage` carries bounded scanner file facts derived from the exact
    written capture. Partial source coverage leaves produced/missing unchanged;
    ingestion independently derives the same facts for legacy raw arrays.

    `redacted` (#1639 P11) says whether every capture this run wrote went
    through the redaction choke point, read off the ledger
    `tool_capture._redact_capture` keeps -- an observation, so replacing the
    choke point with identity makes the claim go false rather than leaving a
    stale `true` behind. The tools phase copies it into `tools-ran.json`.

    `suppression_comments` (#1839) is what this run does with an inline
    suppression comment in the target's own source, per tool: `"ignored"` where
    the pinned scanner's knob for it was passed (`--security redteam`),
    `"honoured"` where the comment stood -- `standard` is an operator scanning
    their own repository, and where no knob exists at the pin it is a residual;
    this repository's own CI (`security.yml` and the fork-PR
    `security-fork.yml`) scans in `redteam`, so nothing target-authored is
    honoured on either check -- and
    `"n/a"` for a tool whose argv honours no such comment at all. A tool with no
    row was not ASSESSED, which is deliberately not the same claim as `n/a`.
    Defaults to the ledger `run_tools()` filled while building each argv -- an
    observation, like `redacted` and `network`. For a FLAG-lever tool (bandit,
    gitleaks) that observation is the argv itself, so taking the flag away makes
    the claim change rather than leaving an intention behind; for an INGEST-lever
    tool (`scanner_config.SUPPRESSION_INGEST_LEVER`, semgrep today) the argv
    decides nothing and the row follows the run's mode, which is what does. This
    row is about COMMENTS only. `ignore_files` separately records the source-root
    `.gitleaksignore` observed at launch: `honoured` for a target file allowed
    under standard, `neutralised` for the redteam empty-file mount, and
    `absent` when no file exists. Only a produced Gitleaks scan gets a row.
    An explicit map follows the same observation override pattern as
    `suppression_comments`; it is still filtered to produced Gitleaks.

    One row is true for a reason that is NOT on the argv, and this is the
    schema of record, so it says so: semgrep's. At the pin the scanner reports
    a `# nosemgrep`'d result whether or not `--disable-nosem` is passed, so the
    row is RECORDED from the mode (fix round 2: reading it off the belt flag
    would publish `honoured` for a redteam run the moment the belt came off)
    and the INGEST enforces it --
    `ingest_tools.ingest_dir_detailed` drops those results under `standard` and
    publishes the count per tool as `suppressed_in_source`, which is where a
    reader sees HOW MUCH a honoured comment cost. `run_tools` never sees that
    number: this manifest is written before anything is ingested.

    `scanner_config` (#1839) is which configuration file each pinned scanner ran
    under: `"scanner-owned"` for a constant of ours staged in a scratch, and
    `"target .bandit (its skips and tests)"` for the one case the owner ruling
    of 2026-09-25 leaves with the operator -- a `.bandit` committed to the repository being scanned,
    honoured under `standard` and never under `redteam`. Same construction as
    `network` above: read off the argv the runner built.

    `network` (#1645) is the egress each tool was given: `"none"` for the
    `--network none` containers, `"proxied:<allowlist>"` for an ONLINE_ONLY
    adapter that ran behind this run's proxy, and `"excluded:online egress
    unavailable"` for one that could not be given an egress path and was
    therefore NOT run. "pip-audit: produced" has never said what that scanner
    could reach while it ran, and this is where the answer goes. Defaults to
    the ledger `run_tools()` filled while building each argv -- an observation,
    like `redacted` -- and an explicit value is for a caller that did not run
    the loop. The third posture also MOVES the adapter: it leaves `selected`
    for `excluded_scope`, the shape the gate already reads as "applicable, not
    required by scope, disclosed"; the network refusal independently prevents
    coverage certification. An adapter left in both lists would read as a
    required scanner that went missing (and `security_gate` rejects the
    overlap outright).
    """
    network = {str(k): str(v) for k, v in
               (_NETWORK_POSTURE if network is None else network).items()}
    refused = sorted(t for t, posture in network.items()
                     if posture.startswith(egress.EXCLUDED_PREFIX))
    selected = [t for t in selected if t not in set(refused)]
    excluded_scope = list(excluded_scope) + refused
    selected = list(dict.fromkeys(str(tool) for tool in selected))
    produced = sorted({os.path.splitext(os.path.basename(p))[0] for p in written})
    observed_ignore_files = (_IGNORE_FILE_POSTURE if ignore_files is None
                             else ignore_files)
    file_coverage = {}
    for capture_path in written:
        if os.path.basename(capture_path) == "eslint-security.json":
            from scripts.tools.eslint_security import file_coverage as eslint_coverage
            try:
                with open(capture_path, "rb") as capture:
                    data = capture.read(MAX_TOOL_OUTPUT_BYTES + 1)
                if len(data) <= MAX_TOOL_OUTPUT_BYTES:
                    file_coverage["eslint-security"] = eslint_coverage(json.loads(data))
            except (OSError, ValueError):
                pass  # ingestion retains the whole-capture failure path
    payload = {"schema_version": 1, "run_id": run_id,
               "file_coverage": file_coverage,
               "selected": selected, "produced": produced,
               "missing": sorted(set(selected) - set(produced)),
               # #1639 P11 F5: what the runner OBSERVED, not what it intends --
               # every capture written this run passed
               # `tool_capture._redact_capture`. False when nothing was written
               # (there is nothing to vouch for) and false if any capture
               # reached disk without the pass, so the phase can copy the
               # answer into `tools-ran.json` instead of asserting another
               # module's behaviour with a literal.
               "redacted": bool(produced) and all(
                   tool in _REDACTED_CAPTURES for tool in produced),
               "excluded_scope": sorted(dict.fromkeys(str(t) for t in excluded_scope)),
               "network": network,
               "suppression_comments": {
                   str(k): str(v) for k, v in
                   (_SUPPRESSION_POSTURE if suppression_comments is None
                    else suppression_comments).items()},
               "ignore_files": {"gitleaks": observed_ignore_files["gitleaks"]}
               if ("gitleaks" in produced
                   and isinstance(observed_ignore_files.get("gitleaks"), str)
                   and observed_ignore_files["gitleaks"] in
                   ("honoured", "neutralised", "absent")) else {},
               "scanner_config": {
                   str(k): str(v) for k, v in
                   (_SCANNER_CONFIG_POSTURE if scanner_config is None
                    else scanner_config).items()},
               "sanitized": dict(sanitized or {}),
               "exclude_globs": [str(g) for g in exclude_globs or ()],
               "excluded_dirs": [_excluded_dir_row(d) for d in excluded_dirs or ()],
               "depth_bound": depth_bound}
    # #1735: the driver points --manifest at `<run folder>/tools-manifest.json`,
    # inside the reviewed tree. Confine before the makedirs (a symlinked
    # intermediate would be traversed by it) and never open through a link.
    safe_write.confine_artifact_path(path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with safe_write.open_w_nofollow(path) as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    return payload
