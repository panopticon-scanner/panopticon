"""The `driver setup` flow: scan + ingest, its manifest and SETUP_PHASES."""
import json
import os
import subprocess
import sys

from scripts import dispatch
from scripts import hosts
import scripts.loop_batch as loop_batch
from scripts import read_guard_hook
import scripts.host_disclosure as host_disclosure
import scripts.repo_config as repo_config
import scripts.run_manifest as run_manifest
import scripts.setup_flow as setup_flow
import scripts.runners.base as runners_base
import scripts.runners.batch as batch
from . import engine
from . import hard_links
from . import runio
from . import requests
from . import setup_ack
from . import setup_readiness


SETUP_MANIFEST = run_manifest.SETUP_MANIFEST_NAME

def _setup_manifest_path(review_root):
    return run_manifest.manifest_path(review_root, "setup")

def load_setup_manifest(review_root):
    return runio._load_json(_setup_manifest_path(review_root))

def record_dispatch_request(review_root, checkpoint, sha256, at=None):
    """`--setup`'s half of #1727: anchor the setup dispatch request's sha256 in
    `setup-manifest.json`, under the SAME key the run manifest uses.

    Setup is not a run (#1507): it keeps its own request
    (`.panopticon/setup-dispatch-request.json`) and its own manifest, and
    its namespace must be preserved when updating the record. Same tmp +
    `os.replace` shape as `run_manifest._rewrite`, through this package's
    own confining opener (the manifest is a `.panopticon` artifact and the
    target may have planted a symlink at either name). A tree with no setup
    manifest records nothing, exactly as the run-manifest side does.
    """
    manifest = load_setup_manifest(review_root)
    if manifest is None:
        return None
    manifest[run_manifest.DISPATCH_REQUEST] = {
        "checkpoint": checkpoint, "sha256": sha256,
        "at": at or run_manifest._now_iso()}
    path = _setup_manifest_path(review_root)
    tmp = path + ".tmp"
    with runio._open_w_nofollow(tmp) as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return manifest

def _read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()

# #1683 fix round 1: the operator's fix when a target's hard links cost the
# setup scan its directory Grep/Glob. ONE wording, named in the stderr line
# and in docs/guide/driver-run-loop.md's paragraph, because a disclosure nobody
# can act on is
# noise -- and the guard cannot tell a benign `git clone --local` store from a
# planted link, so re-cloning is the answer to both.
_HARD_LINK_REMEDY = ("re-clone the target without hard links (git clone "
                     "--no-hardlinks, or a fresh clone) to restore directory "
                     "Grep/Glob for the setup scan")


def _setup_scan_entry(review_root, prompt, host):
    """One return-persist dispatch entry for the read-only setup-scan agent
    (mirrors _scout_entry): the host dispatches it, gets proposal JSON back, and
    persists it to out_file. #1608: the entry carries `delivery` saying so.

    #1737 (AGT-B1D): this used to carry `agent: None, enforced: False`
    unconditionally, with a docstring arguing that a plain general-purpose
    dispatch was "sufficient and safe" because the template's tool_policy is
    read-only -- but that policy travelled as PROSE only. Nothing bounded the
    tool set a host hands a general-purpose agent, for the one dispatch that
    reads the WHOLE untrusted tree. `setup_scan` is a registered role now, so
    this entry names its shell and derives `enforced` from this invocation's
    own posture exactly the way the five phase sites do (#1720) -- with
    `--setup`'s own evidence artifact, which `driver loop --setup`'s posture
    step writes flat beside setup's other artifacts.

    When the posture does not prove enforcement -- no shells emitted yet, a
    host that cannot enforce -- the entry falls back to the shell-less shape
    it always had, and `scan_execute` makes the operator acknowledge that
    before it dispatches (`setup_ack.require_unenforced_scan_ack`).

    The MODEL stays None either way: R-F4-2, deliberately unbound, so the
    session's model runs this one-off classification. The registered shell
    binds none either (model_resolver's `setup_scan` row).
    """
    out_file = os.path.abspath(runio._pano(review_root, "setup-proposal.json"))
    root = os.path.abspath(review_root)
    # #1683: the ONE walk. This grant is the only directory read scope the
    # driver issues, and a PreToolUse hook may not os.walk the tree on every
    # Grep -- so the multiply-linked files are found HERE, once, and ride in
    # the scope. Past the cap the grant fails CLOSED on the directory itself:
    # every directory Grep/Glob under the review root is denied until the tree
    # is fixed, which is worth saying out loud rather than leaving the scan to
    # discover it one refusal at a time.
    linked, overflowed = hard_links.hard_links_under(root)
    if overflowed:
        print("driver setup: %d or more hard-linked files under %s (first: %s) -- "
              "past the read guard's cap, so the setup scan's Grep and Glob are "
              "denied over EVERY directory beneath it and it must Read files by "
              "name. A `git clone --local` store or a `cp -al` tree is the usual "
              "cause; a link there can name an inode outside the tree. Remedy: %s."
              % (len(linked), root, linked[0], _HARD_LINK_REMEDY),
              file=sys.stderr, flush=True)
        linked = [root]
    elif linked:
        print("driver setup: %d hard-linked file(s) under %s (first: %s) -- the "
              "setup scan's Grep and Glob are denied over any directory holding "
              "one, because a link there can name an inode outside the tree. "
              "Remedy: %s." % (len(linked), root, linked[0], _HARD_LINK_REMEDY),
              file=sys.stderr, flush=True)
    enforced = loop_batch.expected_enforced(review_root, host,
                                            namespace=loop_batch.SETUP_NAMESPACE)
    # The all-unknown posture `{}` is deliberate and unrelated to `enforced`
    # above: setup-scan.md grants no Write, so delivery() answers return_json
    # before it ever consults a posture, and handing it one would only invite
    # a reader to think the answer depends on it.
    mode, prefix = requests.delivery(host, {}, "setup-scan.md", out_file)
    entry = {"id": "setup-scan",
             # The role file SPELLED OUT, like the other four builders: the
             # #1727 routing guard reads this constant out of the AST to prove
             # the table names the shell this checkpoint really dispatches.
             "agent": dispatch.registered_agent_name("setup-scan.md") if enforced else None,
             "enforced": enforced,
             # R-F4-2: deliberately unbound -- an explicit `model: null` row in
             # model-profiles.yml, not an omission; see
             # test_setup_scan_is_deliberately_not_model_bound.
             "model": None,
             "prompt": requests.entry_marker("setup-scan") + prefix + prompt,
             "marker": read_guard_hook.marker_line("setup-scan"),
             "out_file": out_file,
             # O2: the scan reads the repository by design -- a DIRECTORY scope
             # over the review root, nothing outside it, and (#1683) the
             # hard-linked files beneath it, which are in it by NAME only.
             "scope": requests.scope(dirs=[root], hard_linked=linked)}
    if mode:
        entry["delivery"] = mode
    return entry

def _unbound_setup_artifact(review_root, name, manifest):
    """`(doc, reason)`: what `.panopticon/<name>` parsed as, and why it is not
    THIS setup run's evidence -- None when it is (SEC-579863541, #1841).

    `setup-proposal.json` and `setup-complete.json` are `runio._TOP_LEVEL`
    names, so `_pano` resolves them FLAT: fixed paths in a directory the
    reviewed tree owns and can `git add -f` past its own gitignore. The two
    done-predicates below were bare "does this file parse" tests on them, while
    the identical threat one file over (`run-manifest.json`) has had a rule
    since #1093. A planted proposal skips the setup-scan dispatch and makes the
    TARGET's own proposal the input to `setup_flow.ingest_proposal`; a planted
    marker satisfies BOTH predicates, so `driver setup` runs no phase at all
    and reports setup complete over a tree nothing classified.

    A REASON, reported by the caller, the way `_foreign_manifest_reason` does
    it: one helper decides, so the predicate and the stderr line can never
    disagree about what was refused. Both signals already exist here:

    * tracked-ness (`runio._manifest_committed`), the manifest guard's primary
      and non-secret signal -- a driver-written artifact is gitignored and
      untracked, so a tracked one was committed by the target. It applies to
      both names, and to the marker even when its `run_id` matches: a run id
      lives in a file the target can read, so it is not a secret either.
    * the marker's own `run_id`. `_scan_fallback` stamps it
      (`run_id=manifest["run_id"]`) and `run_setup_flow` pins the setup
      manifest ONCE, so the id is stable across resumes and a marker carrying
      another id -- or none at all -- was not written by this run. The proposal
      carries no such field, which is why tracked-ness is all it has.

    So an UNTRACKED `setup-proposal.json` is accepted as the host's own return
    of the setup-scan dispatch -- which is the residual, disclosed rather than
    closed (review finding 2, fix round 2): on a NON-GIT target nothing is
    tracked (`runio._manifest_committed` answers False there), so the proposal
    has no binding at all and only `setup-complete.json` is bound, by run id. A
    real binding for it is setup's own dispatch request, which carries this run's
    id and the request sha since #1727 -- a follow-up, not this fix.

    An absent or unparseable file is nobody's evidence and gets no reason: it
    satisfies no predicate anyway, and a refusal named over it would be noise --
    and the caller's `doc is None` is what keeps a missing artifact from costing
    a `git ls-files`.
    """
    path = runio._pano(review_root, name)
    doc = runio._load_json(path)
    if doc is None:
        return None, None
    if runio._manifest_committed(review_root, path):
        return doc, ("it is git-tracked in the target, and a driver-written setup "
                     "artifact is never committed -- remove it from the repository "
                     "(while it is there this phase ignores it and runs again)")
    if name != "setup-complete.json":
        return doc, None
    want = (manifest or {}).get("run_id")
    got = doc.get("run_id") if isinstance(doc, dict) else None
    if want and got == want:
        return doc, None
    # Fails CLOSED on a manifest with no id of its own: nothing can be bound to
    # a run that does not say which run it is.
    return doc, ("it carries run_id %r, not this setup run's %r -- "
                 "`driver setup --reset` starts over" % (got, want))

def _bound_setup_artifact(review_root, name, manifest):
    """True when `.panopticon/<name>` parses AND this run wrote it. ONE read for
    both halves, and an absent artifact still costs no `git ls-files`."""
    doc, reason = _unbound_setup_artifact(review_root, name, manifest)
    return doc is not None and reason is None

def _report_unbound_setup_artifacts(review_root, manifest):
    """Name every setup artifact that satisfies no done-predicate, once per
    invocation, off the same helper the predicates read.

    Here rather than inside the predicates because `run_engine` re-evaluates
    those up to twice each, and one refusal said four times reads as four
    problems. Called from inside `run_setup_flow`'s status `try`:
    `_manifest_committed` raises DriverError rather than trust an ambiguous git
    failure, and that refusal is this verb's `error` status like every other."""
    for name in ("setup-proposal.json", "setup-complete.json"):
        _doc, reason = _unbound_setup_artifact(review_root, name, manifest)
        if reason:
            print("driver setup: ignoring %s: %s" % (name, reason),
                  file=sys.stderr, flush=True)

def scan_done(review_root, manifest):
    return (_bound_setup_artifact(review_root, "setup-proposal.json", manifest)
            or _bound_setup_artifact(review_root, "setup-complete.json", manifest))

def scan_execute(review_root, manifest):
    """Provision + render the scan brief -> setup-scan checkpoint (vocab present);
    or flat-seed + readiness + a fallback-complete marker (vocab absent, Task 3)."""
    host = manifest.get("host", "claude")
    prov = setup_flow.provision(review_root)
    if prov["stale_config_json"]:
        # #1681: the retired JSON config is never read again. Say so once, here,
        # rather than leaving an operator editing a file nothing consults.
        print("driver setup: " + prov["stale_config_json"], file=sys.stderr, flush=True)
    vocab, present = setup_flow.load_bundled_vocabulary(manifest.get("vocabulary_path"))
    if not present:
        return _scan_fallback(review_root, manifest, host)   # Task 3
    # 5.2 stage 1: the spine is computed once, with the sizes the manifest
    # pinned, persisted for the record and rendered into the brief.
    spine = setup_flow.build_spine(review_root, max_per_group=manifest.get("max_per_group"),
                                   max_groups=manifest.get("max_groups"))
    setup_flow.write_spine(review_root, spine)
    layers, _ = setup_flow.load_bundled_layers()
    brief_path = setup_flow.render_scan_brief(review_root, vocab, layers=layers,
                                              spine=spine, host=host)
    entry = _setup_scan_entry(review_root, _read_text(brief_path), host)
    # Before the entry is written, let alone dispatched: an unenforced
    # setup-scan needs the operator's acknowledgement, and a refusal must
    # leave no dispatch request behind for a resume to pick up (#1737).
    setup_ack.require_unenforced_scan_ack(review_root, manifest, [entry])
    # #1507: setup's own namespace -- never the per-run resolver, which routed
    # this into whatever runs/latest pointed at and clobbered that run's request.
    req, sha = requests.write_dispatch_request_bound(
        review_root, manifest["run_id"], "scan", None, [entry], namespace="setup")
    return engine.PhaseResult(kind="checkpoint", checkpoint="scan", group=None,
                       dispatch_request=req, request_sha256=sha,
                       message="setup-scan checkpoint")

def ingest_done(review_root, manifest):
    return (os.path.isfile(repo_config.draft_path(review_root))
            or _bound_setup_artifact(review_root, "setup-complete.json", manifest))

def ingest_execute(review_root, manifest):
    """Ingest the returned proposal -> draft + setup report, with THIS setup's
    readiness answer recorded in it (#1603, owner ruling 2026-09-22).

    Readiness used to run on the vocab-absent fallback alone, so an operator
    whose tree had a capability vocabulary -- the common case -- never met the
    host-capability disclosure §5.1 makes mandatory. It runs here now, on the
    host this setup was invoked for, and -- mirroring the fallback's ORDER as
    well as its call (fix round 1) -- it is taken AFTER the draft and the
    report are written, so a readiness that cannot be taken costs the
    operator the disclosure and never the bootstrap.

    It does NOT gate either. `driver setup` is a disclosure surface and the
    run-time readiness phase is the one that fails closed; a setup refused
    for a missing Docker would refuse the very bootstrap whose report says
    how to fix it. A gap is made visible three other ways -- the completion
    line, the report's own section, and a non-empty `gaps` in
    setup-report.json.
    """
    res = setup_flow.ingest_proposal(review_root,
                                     max_per_group=manifest.get("max_per_group"),
                                     max_groups=manifest.get("max_groups"))
    if not res["ok"]:
        raise runio.DriverError("ingest: " + "; ".join(res["errors"]))
    # AFTER the draft (fix round 1, I2 -- see the docstring).
    record = _take_readiness(review_root, manifest.get("host", "claude"))
    try:
        setup_flow.record_readiness(review_root, record,
                                    section=setup_readiness._readiness_section(record))
    except OSError as exc:
        # R1-2: the same rule one statement later -- draft and report are
        # already on disk, so a full or read-only directory costs the rows and
        # not the status, and the artifact then reads as "nobody looked".
        # (`_open_w_nofollow`'s ValueError stays uncaught: a planted symlink
        # is the guard working, and `run_setup_flow` makes it an `error`.)
        print("driver setup: readiness not recorded in the setup report: %s"
              % exc, file=sys.stderr, flush=True)
    # The suffix rides here for symmetry with `_scan_fallback`'s and, like
    # that one, is DISCARDED: `run_engine` collects phase names, never their
    # messages. The operator's copy is composed in `run_setup_flow`.
    return engine.PhaseResult(kind="advanced",
                       message="setup: draft written %s; report %s; %s"
                       % (res["draft"], res["report_path"],
                          setup_readiness._readiness_suffix(record)))


def _take_readiness(review_root, host):
    """This setup's readiness record -- or the one row that says it could not
    be taken. NEVER raises (fix round 1, I2).

    `setup_flow.readiness` is mostly non-raising, but not by construction:
    `_check_host_shells` runs `import dispatch`, `hosts.spec` and the
    registration lookups outside its own try, and a row of the wrong width
    raises in `_readiness_record`. Both escaped `run_setup_flow` -- which
    catches only DriverError/EngineStalled/ValueError -- as a traceback with
    no JSON status, taking the bootstrap with it. A failure to MEASURE is a
    weaker reason to refuse a setup than a gap, which setup already survives.

    OPERATIONAL failures only. `Exception`, not `BaseException`: a
    KeyboardInterrupt or a SystemExit is the operator or the process leaving.
    And not the suite's `LaunchRefused` either -- see the clause below.

    The row carries the exception's CLASS as well as its text (a bare
    `RuntimeError()` renders as "", and a disclosure naming nothing is the
    mood §5.1 rejects), and `ok=None`, because nobody-looked is not a fault
    with a remedy -- `_readiness_suffix` then refuses to call such a record
    OK. The posture handed down is this invocation's own, never a second one
    measured here; `_check_host_shells` explains why (I1).
    """
    at = run_manifest._now_iso()
    try:
        return setup_readiness._readiness_record(setup_flow.readiness(
            review_root, host=host,
            envelope=loop_batch.envelope_for(review_root, loop_batch.SETUP_NAMESPACE)),
            probed_at=at)
    except runners_base.LaunchRefused:
        # NOT an operational failure: the suite's guard against starting a
        # real host binary, whose whole value is that it FAILS a test (fix
        # round 2, R1-1). `_check_host_shells` re-raises it by name for this
        # reason and the degrade below moved the swallow one frame up.
        raise
    except Exception as exc:        # noqa: BLE001 -- see the docstring
        return setup_readiness._readiness_record(
            [("readiness", None,
              "could not be taken: %s: %s" % (type(exc).__name__, exc))], probed_at=at)

SETUP_PHASES = (
    engine.Phase("scan", "checkpoint", scan_done, scan_execute),
    engine.Phase("ingest", "deterministic", ingest_done, ingest_execute),
)

_SETUP_ARTIFACTS = ("setup-scan-brief.md", "setup-spine.json", "setup-proposal.json",
                    "setup-report.md", "setup-report.json",
                    "setup-complete.json", SETUP_MANIFEST, runio.HOST_CAPABILITIES)

def _stale_batch_records(run_dir):
    """The `batch-<n>.json` records in `run_dir` that `--reset` may delete.

    The NAME is `batch.MANIFEST_RE`, the same pattern `loop_batch.recover_stale`
    matches: that one reads the iteration number back out of the name, so a
    file carrying none is not a record -- and a sweep sold as "batch-*.json"
    would still have deleted it (#1698 round 2).

    STALE is the other half. `--setup`'s records share the flat `.panopticon/`
    with every other setup run against this tree, so a record whose owner is
    still alive belongs to a `driver loop --setup` that is running RIGHT NOW,
    and deleting it is the same accident `recover_stale` refuses from the
    other direction: that loop's own rollback would then find nothing to take
    back. It is kept and said out loud. Every other answer -- a dead owner, a
    pid from another machine, no stamp at all -- goes: `--reset` is the
    operator saying this run is over, and none of those is a live process.
    """
    try:
        names = sorted(os.listdir(run_dir))
    except OSError:
        return []
    keep = []
    for name in names:
        if not batch.MANIFEST_RE.fullmatch(name):
            continue
        path = os.path.join(run_dir, name)
        doc = None if os.path.islink(path) else runio._load_json(path)
        # `owner_state` answers LIVE only for a dict carrying a pid; the
        # isinstance restates that so reading `pid` back off `doc` is visibly
        # safe rather than safe-by-reference-to-another-module.
        if isinstance(doc, dict) and batch.owner_state(doc) == batch.OWNER_LIVE:
            print("driver setup: keeping %s -- a `driver loop --setup` is still "
                  "running here (pid %r)" % (name, doc.get("pid")),
                  file=sys.stderr, flush=True)
            continue
        keep.append(path)
    return keep

def _clear_setup_artifacts(review_root):
    """Remove derived setup artifacts + the setup-manifest for --reset. NEVER
    touches the committed root config -- only the DRAFT beside it, which this
    flow derives and rewrites on every ingest (#1681).

    The capability evidence is cleared too (fix round 1, F2): `driver loop
    --setup` reads it back on every later invocation, and `driver.run`'s own
    `--reset` cannot reach it -- that one clears the REVIEW namespace, i.e. the
    per-run folder. A file the verb consults with no way to discard it is a
    remedy the refusal message names and does not deliver.

    So is a crashed batch's record (#1698). It is named by a PATTERN rather
    than a filename -- `batch-<n>.json`, one per iteration -- and it is swept
    from the flat run folder for the same reason as the capability evidence:
    `batch-<n>.json` is not in `runio._TOP_LEVEL`, so `_pano` would resolve it
    into some review run's `runs/<tag>/`, where the record belongs to that run
    and may name a process that is still going. Left behind, it met
    `Batch.open`'s O_EXCL on the next `--setup` run -- and since `--reset`
    skips recovery, the remedy the refusal names raised FileExistsError."""
    draft = repo_config.draft_path(review_root)
    setup_dir = os.path.dirname(_setup_manifest_path(review_root))
    # #1737: an acceptance is this invocation's, not a standing one. `--reset`
    # starts over, and starting over includes being asked again. Read at CALL
    # time, not into `_SETUP_ARTIFACTS`: `loop_batch` imports this module, so
    # `setup_ack` -- which reaches `loop_batch` through `requests` -- is only
    # partially initialized while this module's body runs (test_layout rule 1).
    names = _SETUP_ARTIFACTS + (setup_ack.SETUP_UNENFORCED_ACK,)
    for path in ([os.path.join(setup_dir, name) for name in names]
                 + _stale_batch_records(setup_dir)
                 + ([draft] if os.path.isfile(draft) else [])):
        try:
            os.remove(path)
        except OSError:
            pass

def _scan_fallback(review_root, manifest, host):
    """Vocab-absent path (parity with orchestrator.run_setup): flat top-dir seed
    + readiness gate, then a fallback-complete marker so both setup phases'
    done-predicates are satisfied -> run_engine completes without a checkpoint
    and without entering ingest."""
    path, created, names = setup_flow.seed_flat_manifest(review_root)
    # The seed first, then the measurement -- this path's own order, which
    # `ingest_execute` now mirrors. Same helpers as the normal path (#1603):
    # what this records and what it prints are what they were.
    record = _take_readiness(review_root, host)
    runio._write_json(runio._pano(review_root, "setup-complete.json"), dict(
        record, schema_version=1,
        mode="fallback", seed=path, created=created, groups=names,
        run_id=manifest["run_id"]))
    msg = ("setup: vocab-absent fallback — flat seed %s; %s"
           % (path, setup_readiness._readiness_suffix(record)))
    # LAST, and on its own lines (#1601): the clause is a list now, so
    # anything appended after it would land on the final remedy's line.
    if record["limitations"]:
        msg += "\n" + setup_readiness._limitations_clause(record["limitations"])
    return engine.PhaseResult(kind="advanced", message=msg)

def _drop_stale_fallback_marker(review_root):
    """A vocab-absent run wrote a mode:"fallback" setup-complete.json. Once the
    vocabulary is available again, that marker is stale — a real scan should
    supersede the flat seed. Remove it so the engine re-scans (self-healing; no
    --reset needed). No-op when there is no fallback marker or vocab is still
    absent."""
    marker = runio._load_json(runio._pano(review_root, "setup-complete.json"))
    if not (isinstance(marker, dict) and marker.get("mode") == "fallback"):
        return
    _vocab, present = setup_flow.load_bundled_vocabulary(None)
    if present:
        try:
            os.remove(runio._pano(review_root, "setup-complete.json"))
        except OSError:
            pass

def run_setup_flow(args, runner=subprocess.run, phases=SETUP_PHASES, posture=None):
    """The `driver setup` entrypoint: a separate two-phase flow (NOT a run
    phase). Resolves the review root, pins a minimal setup-manifest once, and
    advances scan->ingest through run_engine. Writes a draft; the owner reviews
    and commits it.

    `posture` (#1616 item 3) is the capability step `driver run` performs on
    every invocation -- `driver._establish_host_posture` -- passed IN rather
    than imported: `phases/*` may never reach an entry script
    (tests/test_layout.py rule 3), and this flow is driven by two of them.
    Called with this flow's own namespace, so the guard probes measure the
    settings file `driver loop --setup` really arms (the flat
    `.panopticon/host-settings.json`) and the evidence lands beside setup's
    other artifacts rather than in some earlier review run's folder.

    BOTH entrypoints pass it (#1737 fix round 1). `driver loop --setup` always
    did, because that is the path that ARMS both guards headlessly and
    therefore the one whose subject a probe has to have proven. `driver setup`
    now does too, because the evidence that step writes is no longer only a
    record: `_setup_scan_entry` and `require_unenforced_scan_ack` both read it,
    so a run that skipped the probe would gate on an artifact nothing in this
    invocation measured -- absent on a fresh target, or planted by the target.
    `posture=None` is a UNIT seam only: it runs the flow against whatever
    evidence the caller arranged, and no production caller passes it. Its
    refusal -- a posture that moved, a planted shadow shell -- is this verb's
    `error` status, the same one every other refusal here speaks."""
    review_root, _wt, _pr = runio.resolve_review_root(args.target, runner=runner)
    if getattr(args, "reset", False):
        _clear_setup_artifacts(review_root)               # Task 3
    _drop_stale_fallback_marker(review_root)
    manifest = load_setup_manifest(review_root)
    foreign_reason = runio._foreign_manifest_reason(
        manifest, review_root, _setup_manifest_path(review_root))
    if foreign_reason:
        # #run7/#run8 AGT-C1A: a target repo can force-commit its own
        # .panopticon/setup-manifest.json (gitignored but `git add -f`-able) to
        # preset an attacker-chosen `vocabulary_path` -- which setup_flow reads and
        # embeds verbatim into the classifier scan brief -- or `host`. Mirror the
        # run-manifest guard (#1093): a manifest that is git-tracked in this tree,
        # or whose stamped review_root isn't THIS checkout, is not a legitimate
        # resume state; discard and rebuild from args.
        print("driver: ignoring foreign setup-manifest.json (%s)" % foreign_reason,
              file=sys.stderr, flush=True)
        manifest = None
    if manifest is None:
        # 5.2 size policy, pinned at scan time so the brief's arithmetic and
        # the ingest's layers agree (anti-drift, like the run manifest's
        # max_per_group). CLI > `settings:`, resolved HERE so a config edit
        # between scan and ingest cannot move the numbers; None = default.
        overrides = setup_flow.config_overrides(review_root)
        manifest = {"schema_version": 1, "run_id": run_manifest.new_run_id(),
                    "review_root": os.path.abspath(review_root),
                    "target": os.path.abspath(args.target),
                    "host": args.host or runio._DEFAULTS["host"],
                    "vocabulary_path": None,
                    "max_per_group": (getattr(args, "max_per_group", None)
                                      or overrides["max_per_group"]),
                    "max_groups": getattr(args, "max_groups", None) or overrides["max_groups"]}
        runio._write_json(_setup_manifest_path(review_root), manifest)
    # #1737: read off THIS invocation's argv, every time, and never off the
    # stored manifest. `setup-manifest.json` sits at a `.panopticon` path a
    # hostile target can force-commit and is written once and reused, so a
    # stored `allow_unenforced` could otherwise grant an acceptance the
    # operator never made -- or withhold one they just made on the command
    # line. Recorded in the manifest so `driver loop --setup`'s phases (which
    # see only the manifest) read the same answer this invocation gave.
    manifest["flags"] = {"allow_unenforced":
                         bool(getattr(args, "allow_unenforced", False))}
    host = manifest.get("host", runio._DEFAULTS["host"])
    if posture is None and hosts.is_unenforced_fallback(host):
        # D1, mirroring driver.run()'s _establish_host_posture: printed from
        # the RESOLVED host (the manifest, whether just minted from args.host
        # or loaded from a prior invocation), once per `driver setup` call,
        # before either setup phase runs. `hosts.is_unenforced_fallback` (not
        # a bare `host == "generic"`) because tests/test_host_posture_wiring.py's
        # AST guard forbids phases/ deciding anything from a host's NAME.
        #
        # `posture is None` (fix round 1, F4): when a posture step is injected
        # it prints this itself, off the same resolved host, and two copies per
        # invocation is not "once". The standalone `driver setup` has no such
        # step, so this stays its own.
        print(host_disclosure.GENERIC_FALLBACK_NOTICE, file=sys.stderr)
    if posture is not None:
        error = posture(review_root, manifest, args, namespace="setup")
        if error:
            return runio._error_status(error)
    try:
        _report_unbound_setup_artifacts(review_root, manifest)
        result = engine.run_engine(review_root, manifest, phases)
    except (runio.DriverError, engine.EngineStalled, ValueError) as exc:
        # `ValueError` is item 24 R1-1: since #1577 the five setup artifacts are
        # written through the confined no-follow writers, whose whole-path
        # confinement refuses a planted component with a ValueError. That
        # refusal is the guard WORKING -- an outcome of this verb -- so it
        # belongs in the status protocol beside the two below, not on stderr as
        # a traceback with no JSON behind it.
        # #1637 P08 fix round 2: `driver run` converts the engine's progress
        # guard into an `error` status; this drives the SAME engine and was
        # still letting it escape as a traceback. One named class with two call
        # sites, only one of them converting, teaches the next reader that the
        # guarantee is per-caller rather than per-engine -- and `driver setup`
        # speaks the same status protocol, so a traceback is no more a status
        # here than it is there.
        return runio._error_status(str(exc))
    if result.get("status") == "complete":
        if os.path.isfile(repo_config.draft_path(review_root)):
            result["message"] = (
                "setup complete -- read .panopticon/setup-report.md, then DIFF "
                "%s against %s before moving it over: the draft rebuilds "
                "`groups:`, carries a committed `exclude_paths:` and "
                "`settings:` across and records the sizes you passed, but any "
                "other hand-kept top-level key is yours to re-apply"
                % (repo_config.DRAFT_NAME, repo_config.CONFIG_NAMES[0]))
            # #1603: surface 4 on the line the operator actually reads.
            # `ingest_execute`'s own message is discarded by the engine and
            # replaced here, exactly as the fallback's is, so a disclosure
            # left there would be a disclosure made to nobody (§5.1). Read
            # back off the report rather than passed down, because a
            # re-invocation that finds the work already done runs no phase at
            # all -- and an artifact with no readiness rows gets no clause,
            # never a clean verdict nobody measured.
            result["message"] += setup_readiness._readiness_tail(
                runio._load_json(runio._pano(review_root, "setup-report.json")))
        else:
            msg = ("setup complete -- vocab-absent fallback seeded a flat %s; "
                   "review, edit, and commit it" % repo_config.CONFIG_NAMES[0])
            # Sanitized, like the normal path's (fix round 1, I3): this
            # marker is a `.panopticon` file the reviewed tree can plant, and
            # both branches sit outside the status protocol's try.
            marker = setup_readiness._stored_record(runio._load_json(
                runio._pano(review_root, "setup-complete.json")))
            if marker["gaps"]:
                # The same clause the normal path prints, from the same helper
                # (#1603). This branch still says nothing when readiness is
                # clean; the ruling widened the CALLER, not this line.
                msg += " — " + setup_readiness._readiness_suffix(marker)
            # This is the message the operator actually reads -- _scan_fallback's
            # is replaced here -- so the limitations clause has to be restated,
            # or declaring it there would be declaring it to nobody (§5.1).
            if marker["limitations"]:
                msg += "\n" + setup_readiness._limitations_clause(marker["limitations"])
            result["message"] = msg
    return result
