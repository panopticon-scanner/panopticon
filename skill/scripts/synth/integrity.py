"""Findings-file integrity: planned vs ingested files, labels, the unenforced ack."""
import hashlib
import json
import os
import re
import sys

import scripts.evidence as evidence_mod
import scripts.group_runner as group_runner
import scripts.groups_schema as groups_schema


def duplicate_out_files(plan):
    """out_file values assigned to more than one reviewer entry in the merged
    plan (#936). A collision means two reviewers share a write target and one
    silently overwrites the other — a coverage risk that
    reconcile_findings_files' set-keyed view structurally cannot see."""
    if not isinstance(plan, list):
        return []
    seen, dupes = set(), set()
    for e in plan:
        if isinstance(e, dict) and isinstance(e.get("out_file"), str) and e.get("out_file"):
            of = os.path.normpath(e["out_file"])
            (dupes if of in seen else seen).add(of)
    return sorted(dupes)

_FINDINGS_NAME_RE = re.compile(r"^findings-(?P<group>.+)-(?P<domain>[A-Za-z]+)\.json$")

def _expected_from_filename(basename):
    """(group, domain) declared by a reviewer findings filename, or None when
    the name is not a reviewer findings file or its trailing token is not a
    known OCRDb domain. Domains are a fixed hyphen-free set, so the domain is
    the last token of the `{group}-{domain}` prefix even when the group name
    contains hyphens.

    #run10: this keyed on the 4.x `-panel_review` / `-lens_sweep-<lens>` suffix
    until those roles were retired (#1441). The only findings filename the
    pipeline can produce is phases.review._cell_entry's `findings-<group>-<domain>.json`
    (driver.py), which never matched -- so every caller below silently returned
    "nothing wrong" on every 5.x run. Keyed on the cell shape it now checks the
    files that actually exist.
    """
    m = _FINDINGS_NAME_RE.match(basename)
    if not m:
        return None
    domain = m.group("domain")
    if domain not in groups_schema.DOMAINS:
        return None
    return m.group("group"), domain

def mislabeled_findings_files(paths):
    """Reviewer findings files whose CONTENT contradicts the (group, domain)
    cell their filename declares (#937) — a mis-targeted or overwritten write.

    Flags a file as soon as its `_panopticon` cell stamp, or any finding's
    own `domain`, clearly disagrees with the filename; absent fields are
    never second-guessed. This is the byte-identity follow-up SKILL.md
    step 9 names. Distinct from phases.review._get_valid_cell_data, which guards the
    same stamp at review-phase done-detection for the cells the driver itself
    dispatched: this one screens whatever synthesize was actually handed."""
    bad = []
    for p in paths or []:
        exp = _expected_from_filename(os.path.basename(p))
        if not exp:
            continue
        group, domain = exp
        try:
            with open(p, encoding="utf-8") as fh:
                data = evidence_mod.load_json_tolerant(fh.read())
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        meta = data.get("_panopticon")
        if isinstance(meta, dict):
            md, mg = meta.get("domain"), meta.get("group")
            if (md and md != domain) or (mg and mg != group):
                bad.append(p)
    return sorted(set(bad))

def cross_domain_findings(paths):
    """Findings filed under a domain other than their cell's — REPORTED, never gating.

    #calibration-4 (gotify): #1443 revived this file's integrity check by
    re-pointing it from the dead 4.x `source_role`/`panel` fields to the 5.x
    shape, and while doing so also compared each finding's own `domain` to the
    filename's. Those two comparisons answer different questions. `source_role`
    and `panel` are PROVENANCE -- who wrote this file -- and their faithful 5.x
    analogue is the `_panopticon` stamp, which mislabeled_findings_files still
    checks and still gates on. A finding's `domain` is a CONTENT
    classification: an ARC reviewer that files a TST finding has not
    mis-targeted its write, it has stepped outside its lane.

    Treating the second as an integrity failure sank certification on a run
    whose file integrity was perfect: 0 stamp mismatches across 160 files, and
    3 cross-domain findings in 2 of them -- every one a `TST-X0X`, the
    catalog-gap code, filed by a reviewer that saw a testing gap and had no
    code in its own domain for it. Failing a whole run for that penalises
    exactly the gap-reporting the X0X schema exists to collect.

    So report it instead. Cross-domain filing is worth seeing -- it is a real
    signal about panel discipline and about catalog gaps -- but it is evidence
    about the REVIEW, not about whether the artifacts on disk can be trusted.
    """
    out = []
    for p in paths or []:
        exp = _expected_from_filename(os.path.basename(p))
        if not exp:
            continue
        _group, domain = exp
        try:
            with open(p, encoding="utf-8") as fh:
                data = evidence_mod.load_json_tolerant(fh.read())
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        findings = data.get("findings")
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            fd = f.get("domain")
            if fd and fd != domain:
                out.append({"file": p, "cell_domain": domain,
                            "finding_domain": fd,
                            "code": f.get("ocrdb_code") or f.get("code")})
    return sorted(out, key=lambda r: (r["file"], str(r["finding_domain"]), str(r["code"])))

def reconcile_findings_files(plan, ingested_paths):
    """(#146) Reconcile the findings files synthesize ingested against the
    dispatch plan's declared reviewer out_files. Returns (unexpected, missing)
    as sorted lists of the ORIGINAL path strings. Skipped (empty, empty) when
    no plan is present — an ordinary non-fan-out run, not tampering.
    """
    if not isinstance(plan, list) or not plan:
        return [], []
    # realpath, not abspath (#947 FIXME-1): macOS temp worktrees live under
    # /var/folders/... which is a SYMLINK to /private/var/... -- a cwd inside
    # the worktree yields /private/var paths while the plan recorded /var
    # ones, and abspath comparison flagged every file on a clean run.
    planned = {os.path.realpath(e["out_file"]): e["out_file"] for e in plan
               if isinstance(e, dict) and isinstance(e.get("out_file"), str)
               and e.get("out_file")}
    ingested = {os.path.realpath(p): p for p in ingested_paths or []}
    unexpected = sorted(ingested[a] for a in ingested if a not in planned)
    missing = sorted(planned[a] for a in planned if a not in ingested)
    return unexpected, missing

def _plan_hash(plan):
    """Canonical plan-content hash -- mirror of dispatch.plan_content_hash
    (#493 R2; a shared import is blocked by the two sys.path conventions,
    #742 -- keep the two in sync)."""
    return hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

def read_unenforced_ack(path=os.path.join(".panopticon", "unenforced-ack.json")):
    """Return the full ack dict when dispatch recorded --allow-unenforced, {} otherwise.

    The return value is truthy when acknowledged and falsy (empty dict) when not.
    Extra fields written by dispatch (e.g. ``write_guard_covers_bash``, ``note``)
    are included so callers can surface them in ``meta.integrity`` (#680).
    Unreadable/malformed => {} (tolerant)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or not data.get("acknowledged"):
        return {}
    return data


def integrity_section(plan_lists, files, run_dir, plans_seen, invalid_plans,
                      invalid_verify_queue):
    """`meta.integrity` as main() assembled it (WS-0 S3): planned-vs-ingested
    findings files, out_file collisions, mislabeled / cross-domain files, the
    unenforced ack (+ its #493 staleness check), the #493 R4 content-hash
    check, and the plan-loader's own counts. `plan_lists` is the per-file
    list load_dispatch_plans_detailed returned; `plans_seen` / `invalid_plans`
    / `invalid_verify_queue` are that loader's and load_verify_queue's
    disclosures, carried through so "no plan found" and "reconciled, nothing
    wrong" read apart."""
    plan = [e for pl in plan_lists for e in pl]
    unexpected, missing = reconcile_findings_files(plan, files)
    ack = read_unenforced_ack(os.path.join(run_dir, "unenforced-ack.json"))
    # #493 R2: an ack with no run binding over-reports risk forever -- a
    # stale ack from an earlier --allow-unenforced run would mark a fully
    # enforced run acknowledged. The ack now carries plan_sha256 (canonical
    # hash of the plan content it acknowledged); treat a non-matching ack as
    # STALE: report false + a loud note. A legacy ack without the field stays
    # trusted (pre-#493 artifacts).
    ack_stale = False
    if ack and ack.get("plan_sha256") is not None and plan_lists:
        hashes = {_plan_hash(pl) for pl in plan_lists}
        if ack["plan_sha256"] not in hashes:
            ack_stale = True
            print("synthesize: unenforced-ack.json does not hash-match any "
                  "on-disk dispatch plan -- STALE ack from a previous run; "
                  "reporting unenforced_acknowledged: false", file=sys.stderr)
    # #493 R4: after-the-fact content check -- when the orchestrator recorded
    # out-file hashes at fan-out end, verify the ingested bytes still match.
    content_checked, content_mismatched, content_snapshot_unreadable = \
        group_runner.verify_out_file_hashes(files)
    if content_mismatched:
        print("synthesize: %d findings file(s) changed AFTER the fan-out "
              "snapshot (content substitution?): %s"
              % (len(content_mismatched), ", ".join(content_mismatched)),
              file=sys.stderr)
    if content_snapshot_unreadable:
        # #run7 #1208: a present-but-corrupt out-file-hashes.json is a tamper
        # signal, not a missing snapshot -- fail closed rather than silently pass.
        print("synthesize: the fan-out out-file-hashes.json snapshot EXISTS but is "
              "unreadable/corrupt -- treating as tamper (fail-closed), not a missing "
              "snapshot; integrity is NOT certified.", file=sys.stderr)
    integrity = {"unexpected_findings_files": unexpected,
                 "missing_planned_files": missing,
                 "duplicate_out_files": duplicate_out_files(plan),
                 "mislabeled_findings_files": mislabeled_findings_files(files),
                 "cross_domain_findings": cross_domain_findings(files),
                 "unenforced_acknowledged": bool(ack) and not ack_stale,
                 "ack_stale": ack_stale,
                 "content_hashes_checked": content_checked,
                 "content_mismatched_files": content_mismatched,
                 "content_snapshot_unreadable": content_snapshot_unreadable,
                 "empty_dispatch_plans": sum(1 for pl in plan_lists if not pl),
                 "invalid_dispatch_plans": invalid_plans,
                 "invalid_verify_queue": invalid_verify_queue,
                 "plans_seen": plans_seen}
    if ack:
        # Surface the Bash-coverage disclosure fields written by dispatch so
        # they appear in meta.integrity in the final report (#680).
        # Default to False so consumers never see None for this field.
        integrity["write_guard_covers_bash"] = ack.get("write_guard_covers_bash", False)
    return integrity
