#!/usr/bin/env python3
"""Setup/ingest flow: ingest a setup-scan proposal into a draft of the root
config, and add the readiness record to the report it writes. Extracted from
orchestrator.py (P6.4) so the driver can call it directly without going
through the orchestrator CLI wrapper.

#3405: the rest of setup lives beside it, split along the #1589 seams --
`setup_preflight` (the readiness checks), `setup_config` (the `.gitignore`
block, the manifest seed, `provision`, `migrate_config` and the committed
`settings:` reads) and `setup_spine` (the spine, the bundled vocabularies and
the scan brief). A name lives in exactly one of them and is reached by module
attribute, so each has one patch target; nothing is re-exported here.

#1681: the per-repo configuration is the committed root file `repo_config`
names, and everything setup writes at the root -- the seed and the draft --
goes through the ONE writer, `setup_proposal.dump_config_yaml`. The retired
JSON config is neither written nor read here.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scripts import discovery  # noqa: E402  (P6.5 Slice A: discovery primitives, moved off orchestrator)
from scripts import grouping_engine  # noqa: E402  (5.2: stage-3 size policy + setup report)
from scripts import repo_config  # noqa: E402  (#1681: the one place the config names live)
from scripts import tolerant_json  # noqa: E402  (#2959: the JSON depth bound)
from scripts import setup_config  # noqa: E402  (#3405: refusal, overrides, draft settings)
from scripts import setup_spine  # noqa: E402  (#3405: the bundled vocabulary paths)
# #1577 (SEC-D1C): the artifact writes below go through the driver's own
# confined O_NOFOLLOW writers rather than a plain open(). A target repo can
# commit any of these paths as a symlink, and first contact vets the
# `.panopticon` DIRECTORY (#3271), never the leaf. Imported as a module, not as
# names (tests/test_layout.py rule 1), and this direction only --
# `phases/setup.py` already calls into this module.
from scripts.phases import runio  # noqa: E402


# _committed_matrix/_matrix_catalog RELOCATED to discovery.py (P6.5 Slice A):
# they read the committed root config through repo_config + groups_schema and
# depend on nothing else from setup_flow. Aliases kept so existing callers
# (setup_flow.committed_matrix / setup_flow.matrix_catalog) still resolve.
committed_matrix = discovery._committed_matrix
matrix_catalog = discovery._matrix_catalog


# #1107: hard cap on the untrusted proposal file (a scanned repo can ship
# .panopticon/setup-proposal.json directly). Bounds the bytes read before parse.
_MAX_PROPOSAL_BYTES = 1_048_576   # 1 MiB -- far above any legitimate proposal


# #2229: ONE `_committed_exclude_paths`, in `discovery` -- the phase that owns
# the read. This side's copy printed the resolver's disclosures and swallowed
# both `doc.errors` and the `exclude_paths:` parse errors, while the discovery
# copy printed the errors and never the disclosures.
_committed_exclude_paths = discovery._committed_exclude_paths


def record_readiness(repo, readiness, section=None):
    """Add a readiness record to the setup report `ingest_proposal` has
    ALREADY written (#1603 fix round 1, I2).

    ORDER, not merely the call. The vocab-absent fallback seeds its flat
    config and THEN measures, so a readiness that cannot be taken costs the
    operator a disclosure and never the bootstrap; the normal path mirrors
    that -- the draft, the rendered report and its JSON are on disk before
    this runs, and this only ever adds to them. A crash in between leaves a
    report with no readiness rows, which every reader of this record already
    treats as "nobody looked" rather than as a pass.

    The three keys go BESIDE the four `ingest_proposal` owns; `section` is
    appended to the rendered report. A report that is absent or is not a JSON
    object -- a file planted at the name between the two writes -- is left
    exactly as it is rather than rewritten from scratch. Returns the paths
    updated.

    Writes go through the confining no-follow opener like every other setup
    artifact (#1577), so a symlink planted at either name refuses rather than
    writing through.
    """
    root = os.path.join(os.path.abspath(repo), ".panopticon")     # first contact vetted it
    json_path = os.path.join(root, "setup-report.json")
    document = runio._load_json(json_path)
    if not isinstance(document, dict):
        return []
    _replace(json_path,
             json.dumps({**document, **readiness}, indent=1, sort_keys=True) + "\n")
    written = [json_path]
    md_path = os.path.join(root, "setup-report.md")
    if section:
        try:
            with open(md_path, encoding="utf-8") as fh:
                rendered = fh.read()
        except OSError:
            return written
        _replace(md_path, rendered.rstrip("\n") + "\n\n" + section)
        written.append(md_path)
    return written


def _replace(path, text):
    """Write `text` over an artifact that is ALREADY complete, atomically
    (fix round 2, R1-3).

    `ingest_proposal` writes these two files straight through the confining
    opener, and there that is right: the file is being created, so a torn
    write loses nothing that existed. `record_readiness` is the other case --
    a crash mid-write would take `report`, `disclosure` and `diff` with it and
    leave the operator a setup report that is neither the old one nor the new.
    Tmp-then-`os.replace`, the shape `run_manifest._rewrite` and
    `phases/setup.record_dispatch_request` already use, through the same
    no-follow opener (#1577).

    The LIVE path is confined explicitly, first (fix round 3, R2-1). Writing
    straight through `_open_w_nofollow(path)` confined it as a side effect --
    `confine_artifact_path` is that opener's first act -- but staging confines
    the STAGING name, and `os.replace` renames over whatever is at the
    destination without looking. Nothing was ever written through a plant
    either way (the link is replaced, not followed, and the tmp shares every
    intermediate component), but the REFUSAL is the point: a symlink at
    `setup-report.json` stops the verb with an `error` status instead of
    vanishing silently. `runio._write_json` orders it the same way, and for
    the same reason (SEC-X0X).

    That ready-made writer is NOT reused here: it renders at `indent=2`,
    which would reformat a report written at `indent=1`, and the markdown is
    not JSON at all.
    """
    runio._confine_artifact_path(path)
    tmp = path + ".tmp"
    with runio._open_w_nofollow(tmp) as fh:
        fh.write(text)
    os.replace(tmp, path)


def ingest_proposal(repo=".", proposal_path=None, max_per_group=None, max_groups=None):
    """Ingest a setup-scan proposal -> assemble (aliases, layers, floors) ->
    stage 3 (grouping_engine.plan_groups: scoped assignment, Tests sweep,
    Commons, layers, ceiling) -> additive-merge vs the committed root config ->
    write the root draft + setup-report.md/.json. Returns a structured result:
    ok, draft, diff, disclosure, report, report_path. Never clobbers the
    committed config; nothing is written on any failure. No printing.

    The cap and the ceiling resolve CLI argument > `settings:` > default
    (`discovery.DEFAULT_MAX_PER_GROUP`; `grouping_engine.ceiling_for`).

    Readiness is NOT taken here and not written here: `record_readiness`
    below adds it once this has written the draft (#1603 fix round 1)."""
    from scripts import setup_proposal as sp
    refusal = setup_config.config_refusal(repo)          # I2: before anything is written
    if refusal:
        return {"ok": False, "errors": refusal}
    paths = (setup_spine._VOCAB_PATH, setup_spine._AFFINITY_PATH, setup_spine._LAYERS_PATH)
    if not all(os.path.isfile(p) for p in paths):
        return {"ok": False, "errors": [
            "data error: bundled vocabulary/affinity/layer data is missing "
            "(expected %s, %s, %s)" % paths]}
    vocab, verr = sp.load_vocabulary(setup_spine._VOCAB_PATH)
    affinity, aerr = sp.load_affinity(setup_spine._AFFINITY_PATH, vocab)
    layers, lerr = sp.load_layers(setup_spine._LAYERS_PATH)
    if verr or aerr or lerr:
        return {"ok": False, "errors": ["data error: %s" % e for e in verr + aerr + lerr]}
    proposal_path = proposal_path or os.path.join(
        os.path.abspath(repo), ".panopticon", "setup-proposal.json")
    try:
        # #run10 COD-F1B: the cap used to be os.path.getsize() and then a separate unbounded
        # open()+json.load() -- a stat-then-open pair. The bytes actually read were never
        # bounded: a proposal that grows (or a path swapped) between the two calls, or any
        # file whose size cannot be trusted from a stat (a FIFO/proc-like path reports 0),
        # was slurped whole. The target repo supplies this file, so bound the READ itself:
        # take cap+1 bytes and refuse if the extra byte materialized -- the cap is then a
        # property of what we consumed, not of a prior observation.
        with open(proposal_path, "rb") as fh:
            raw = fh.read(_MAX_PROPOSAL_BYTES + 1)
        if len(raw) > _MAX_PROPOSAL_BYTES:
            return {"ok": False, "errors": [
                "proposal %s exceeds the %d-byte cap -- refusing to ingest"
                % (proposal_path, _MAX_PROPOSAL_BYTES)]}
        proposal = json.loads(tolerant_json.depth_checked(raw.decode("utf-8")))   # #2959
    except (OSError, ValueError) as e:
        return {"ok": False, "errors": [
            "cannot read proposal %s: %s" % (proposal_path, e)]}
    assembled, disclosure = sp.assemble(proposal, vocab, affinity, layers=layers)
    if assembled is None:
        return {"ok": False, "errors": (
            ["proposal rejected -- no draft written:"]
            + ["  - %s" % e for e in disclosure["errors"]])}
    overrides = setup_config.config_overrides(repo)
    cap = max_per_group or overrides["max_per_group"] or discovery.DEFAULT_MAX_PER_GROUP
    ceiling = max_groups or overrides["max_groups"]
    committed = committed_matrix(repo)
    planned = grouping_engine.plan_groups(
        discovery.discover_repo_files(repo), committed, assembled, cap, ceiling=ceiling)
    merged, diff = sp.merge_additive(committed, planned["groups"], planned["claims"])
    report = planned["report"]
    # Serialize everything BEFORE opening any file: a serializer failure must
    # not leave a truncated draft beside a missing report.
    # #1504: the merge above shapes the `groups:` mapping only. Any top-level
    # key the operator committed -- `exclude_paths` (#1136) and `settings:`
    # (#1681) -- has to be carried across explicitly, or the draft they are told
    # to move over the committed file silently drops it and puts an excluded
    # corpus back in scope for every domain and every tool scan.
    draft_text = sp.dump_config_yaml(
        merged, exclude_paths=_committed_exclude_paths(repo),
        settings=setup_config._draft_settings(repo, max_per_group, max_groups))
    report_text = grouping_engine.format_report(report, disclosure)
    report_json = json.dumps({"schema_version": 1, "report": report, "disclosure": disclosure,
                              "diff": diff}, indent=1, sort_keys=True) + "\n"
    root = os.path.join(os.path.abspath(repo), ".panopticon")     # first contact vetted it
    draft = repo_config.draft_path(repo)
    report_path = os.path.join(root, "setup-report.md")
    for path, text in ((draft, draft_text), (report_path, report_text),
                       (os.path.join(root, "setup-report.json"), report_json)):
        with runio._open_w_nofollow(path) as fh:   # #1577
            fh.write(text)
    return {"ok": True, "draft": draft, "diff": diff, "disclosure": disclosure,
            "report": report, "report_path": report_path}
