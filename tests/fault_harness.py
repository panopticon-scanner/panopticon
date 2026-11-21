"""#3669: drive the whole pipeline through host failures, with no live model and no network.

A small fixture target is reviewed end to end by `orchestrate.loop` against
`orchestrate_helpers.FakeRunner`, which a `Plan` tells to fail a share of its launches. Every
dispatching phase is real (scout, review cells, domain advisors, backup advisors, tool advisors),
and so are discovery, synthesis and validation. Two things are faked: the host (the runner), and
the scanners (the `tools` child writes fixture output where Docker would have).

`tests/test_fault_injection.py` holds the cases and the invariants. This module is the fixture,
the fault plan, the driver and the report reader.
"""
import contextlib
import dataclasses
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
from unittest import mock

import scripts.claim_scope as claim_scope
import scripts.driver as driver
import scripts.loop_progress as loop_progress
import scripts.orchestrate as orchestrate
import scripts.phases.child as child
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.probes.claude_write_canary as canary
import scripts.runners.outage as outage
import scripts.synth.render as render
import scripts.synthesize as synthesize_cli
from scripts import hosts
from scripts import semgrep_targets
from tests._test_helpers import (adopt_panopticon, all_proven_artifact, docker_probe_runner,
                                 write_host_evidence)
from tests.orchestrate_helpers import FAULT_MODES, FAULT_OUTAGE, FakeRunner, Replies

SCOUT, REVIEW, ADVISOR, BACKUP, TOOL = "scout", "review", "advisor", "backup", "tool"
PHASES = (SCOUT, REVIEW, ADVISOR, BACKUP, TOOL)
#: How many `driver loop` invocations a case is given while the host keeps pausing it.
MAX_INVOCATIONS = 3
BASE_SEED = 3669


def phase_of(entry_id):
    """Which of `PHASES` dispatched `entry_id`."""
    if entry_id.startswith("scout-"):
        return SCOUT
    if entry_id.startswith("review-"):
        return REVIEW
    if entry_id.startswith("verify-tool-"):
        return TOOL
    if entry_id.startswith("verify-"):
        return BACKUP if "-backup" in entry_id else ADVISOR
    raise AssertionError("an entry no phase here dispatches: %s" % entry_id)


def _share(seed, entry_id):
    """Where `entry_id` falls in [0, 1) for `seed`: the whole of the randomness."""
    digest = hashlib.sha256(("%d:%s" % (seed, entry_id)).encode("utf-8")).hexdigest()
    return int(digest[:12], 16) / float(1 << 48)


@dataclasses.dataclass(frozen=True)
class Plan:
    """Which launches fail, and how.

    An entry in one of `phases` is SELECTED when its share for `seed` falls under `rate`
    percent. A persistent plan fails every launch of a selected entry: it never answers. A
    transient plan fails only its first launch, so a retry lands.
    """
    mode: str
    phases: tuple
    rate: int
    seed: int = BASE_SEED
    persistent: bool = True

    def __post_init__(self):
        if self.mode not in FAULT_MODES or not set(self.phases) <= set(PHASES):
            raise ValueError("not a fault plan: %r" % (self,))

    def selects(self, entry_id):
        return (phase_of(entry_id) in self.phases
                and _share(self.seed, entry_id) * 100 < self.rate)

    def mode_for(self, entry_id, launch):
        """`FakeRunner`'s question: what this launch does instead of answering, or None."""
        if not self.selects(entry_id) or (launch > 1 and not self.persistent):
            return None
        return self.mode

    def selected(self, entry_ids):
        return sorted(e for e in set(entry_ids) if self.selects(e))

    def seeded_for(self, entry_ids):
        """This plan under the first seed, counting up from its own, that selects an exact
        share of every targeted phase: `rate` percent of its entries, rounded, and never none
        of them. A hash alone would select nothing at all from two scouts at 10%."""
        by_phase: dict[str, list[str]] = {}
        for entry_id in set(entry_ids):
            by_phase.setdefault(phase_of(entry_id), []).append(entry_id)
        wanted = {phase: max(1, round(len(by_phase[phase]) * self.rate / 100))
                  for phase in self.phases if by_phase.get(phase)}
        for seed in range(self.seed, self.seed + 5000):
            plan = dataclasses.replace(self, seed=seed)
            if all(len([e for e in by_phase[phase] if plan.selects(e)]) == count
                   for phase, count in wanted.items()):
                return plan
        raise AssertionError("no seed gives %r an exact share of %r" % (self, wanted))


# --- the fixture target ------------------------------------------------------------------

_SOURCE = "".join("value_%d = %d\n" % (n, n) for n in range(1, 61))
_LOCK = "version = 3\n" + "".join(
    '\n[[package]]\nname = "%s"\nversion = "%s"\n'
    'source = "registry+https://github.com/rust-lang/crates.io-index"\n' % pair
    for pair in (("alpha-dep", "1.0.0"), ("beta-dep", "2.0.0")))
FILES = {"src/app.py": _SOURCE, "lib/util.py": _SOURCE, "Cargo.lock": _LOCK}
MATRIX = ("version: 1\ngroups:\n"
          "  app:\n    match: ['src/**', 'panopticon.yml']\n"
          "  lib:\n    match: ['lib/**', 'Cargo.lock']\n")
GROUP_FILE = {"app": "src/app.py", "lib": "lib/util.py"}
#: One claim per review cell, each at its own line and category so none merges with another.
_CLAIM = {"SEC": (5, "authz"), "COD": (20, "error-handling"), "ARC": (35, "coupling")}
#: The advisory scanner: several findings on one package, as the issue asks. Its findings are
#: CRITICAL, so tool findings are in play at the default gate and not only agent claims.
ADVISORIES = {"alpha-dep": ("1.0.0", ("RUSTSEC-2099-0001", "RUSTSEC-2099-0002",
                                       "RUSTSEC-2099-0003")),
              "beta-dep": ("2.0.0", ("RUSTSEC-2099-0004", "RUSTSEC-2099-0005"))}
#: semgrep (rule, file, line). `rule-merged` sits on the app/SEC claim's own line, so the two
#: are one issue seen twice: the tool finding that is merged with an agent finding.
SEMGREP = (("rule-merged", "src/app.py", 5), ("rule-alone", "src/app.py", 58),
           ("rule-refuted", "lib/util.py", 58))
#: The advisor that answers for `rule-merged`: once merged, the claim has no advisor of its own.
MERGED_ADVISOR = "verify-app-SEC-primary"
REFUTED_CLAIM = "refuted claim"
REFUTED_RULE = "rule-refuted"
UNSURE_ADVISORY = "RUSTSEC-2099-0005"
SCANNERS = ("osv-scanner", "semgrep")


class FixtureReplies(Replies):
    """What the agents say about the fixture: every claim confirmed, bar one agent claim and
    one semgrep finding that are refuted, and one advisory the advisor cannot decide."""

    def findings(self, entry):
        group, domain = entry["group"], entry["domain"]
        line, category = _CLAIM.get(domain, (50, "maintainability"))
        claims = [(line, category, "CRITICAL", "%s/%s defect" % (group, domain))]
        if (group, domain) == ("app", "SEC"):
            claims.append((45, "injection", "CRITICAL", REFUTED_CLAIM))
        return [{"title": title, "severity": severity, "domain": domain,
                 "code": "%s-A%dA" % (domain, n), "category": category,
                 "description": "a schema-valid test finding",
                 "source_role": "domain_panel",
                 "location": {"file": GROUP_FILE[group], "line_start": line}}
                for n, (line, category, severity, title) in enumerate(claims, 1)]

    def answered(self, entry, cell):
        return cell

    def verdict(self, entry, finding):
        if finding is not None:
            refuted = finding.get("title") == REFUTED_CLAIM
        else:
            claim = entry.get("prompt") or ""
            if UNSURE_ADVISORY in claim:
                return "NEEDS_MORE_INFO", "the fixture cannot decide this one"
            refuted = REFUTED_RULE in claim
        if refuted:
            return "REJECTED", "the fixture refutes this claim"
        return "CONFIRMED", "verified"


class PartialBackup(FixtureReplies):
    """#3695: a backup advisor that answers part of what it was handed. One review cell
    makes `CLAIMS` claims in one category, so its backup is handed all of them; the backup
    gives a verdict on the first and says nothing of the rest, on every attempt. With
    `whole`, it answers them all: the same target with nothing left undone."""
    CELL = ("app", "COD")
    CLAIMS = 3
    SHORT = "verify-app-COD-backup"

    def __init__(self, whole=False, short=None):
        self.whole = whole
        if short is not None:
            self.SHORT = short             # the entry that answers in part, if not the backup
        # A short PRIMARY leaves its backup one claim to check, and a backup is handed
        # only its scope: the fake answers the whole review cell unless told otherwise.
        self.one_claim = {self.SHORT, "verify-%s-%s-backup" % self.CELL}

    def findings(self, entry):
        if (entry["group"], entry["domain"]) != self.CELL:
            return super().findings(entry)
        line, category = _CLAIM[entry["domain"]]
        return [{"title": "%s/%s defect %d" % (self.CELL + (n,)), "severity": "CRITICAL",
                 "domain": entry["domain"], "code": "%s-A1A" % entry["domain"],
                 "category": category, "description": "a schema-valid test finding",
                 "source_role": "domain_panel",
                 "location": {"file": GROUP_FILE[entry["group"]], "line_start": line + n}}
                for n in range(self.CLAIMS)]

    def answered(self, entry, cell):
        return cell[:1] if entry["id"] in self.one_claim and not self.whole else cell

    def short(self):
        """The entries that answer only part of what they are handed."""
        return [] if self.whole else [self.SHORT]


class OutOfScope(FixtureReplies):
    """#3702: an advisor that speaks of claims it was not handed. `speaker` (an entry id)
    answers what it was handed as the fixture does, and also says `says` about every claim
    of the review cell `about` that it was not handed (only the one titled `only`, when
    given). With no `says`, nobody volunteers anything: the silent row beside it.

    The rest sets the scene. `triple` is a cell that makes three claims in one category, as
    `PartialBackup`'s does. `answers` is {entry id: how many of its handed claims it gives
    a verdict on}, for an advisor that falls short. `severity` is {cell: its claims'
    severity}: a HIGH claim summons no backup, so nothing stands over its primary."""

    def __init__(self, speaker=None, about=None, says=None, only=None, triple=None,
                 answers=None, severity=None):
        self.speaker, self.about, self.says, self.only = speaker, about, says, only
        self.triple, self.answers, self.severity = triple, answers or {}, severity or {}

    def findings(self, entry):
        cell = (entry["group"], entry["domain"])
        claims = super().findings(entry)
        if cell == self.triple:
            claims = [dict(claims[0], title="%s/%s defect %d" % (cell + (n,)),
                           location=dict(claims[0]["location"],
                                         line_start=claims[0]["location"]["line_start"] + n))
                      for n in range(3)]
        return [dict(claim, severity=self.severity.get(cell, claim["severity"]))
                for claim in claims]

    def answered(self, entry, cell):
        return cell[:self.answers.get(entry["id"], len(cell))]

    def volunteered(self, entry, handed):
        if self.says is None or entry["id"] != self.speaker:
            return []
        root = claim_scope.review_root_of_artifact_path(entry["out_file"])
        theirs = review._load_cell_findings(root, {"run_id": entry["run_id"]}, *self.about)
        mine = {finding["id"] for finding in handed}
        return [(finding["id"], self.says, "nobody handed this advisor this claim")
                for finding in theirs
                if finding["id"] not in mine and self.only in (None, finding["title"])]

    def short(self):
        """The entries that answer only part of what they are handed."""
        return sorted(self.answers)


class CopiedClaim(FixtureReplies):
    """#3707: a reviewer that copies another cell's claim. With `copy`, the reviewer of the
    cell `copier` emits, beside its own claim, one with the identity of the cell `owner`'s:
    the same domain, category, file, title and line, so the same id. The controller then
    hands that id to the copier's advisors as one of the cell's own.

    `says` is what the copier's advisors say of the copy, by stage ({"primary": ...,
    "backup": ...}); a stage not named confirms it. `owner_says` is what the owner's own
    advisors say of the claim. Without `copy` nobody copies anything: the silent run.
    `severity` is the claim's, and its copy's: a HIGH claim summons no backup, so the
    owner's backup does not stand over the two primaries. With `below_gate`, everything the
    copier's cell reports is INFO, its copy too: the cell does not reach the verify gate,
    so no advisor is ever dispatched for it. With `bad_owner`, the owner's reviewer returns
    its claim and a `null` beside it, every time: the driver refuses the file until the
    cell's review budget is spent, so no advisor is ever dispatched for the OWNER's cell,
    and synthesis still reads the claim out of the file.

    #3716: with `decoy`, what the copier emits is not a copy. It is another claim at the
    owner's line, in its category, under another title (so another id): dedupe keeps it,
    the first loaded, over the owner's claim. With `owner_says=None` the owner's advisors
    are asked about the claim and say nothing of it.

    #3727: with `demoted`, what the copier emits (the copy, or the decoy) claims
    `confidence: CERTAIN` and carries `DEMOTED`: a code whose default is LOW and an empty
    `severity_override`, which the controller resets to that default after the merge."""
    COPIER, OWNER = ("app", "COD"), ("lib", "COD")
    CLAIM = "%s/%s defect" % OWNER
    DECOY = "another reading of the %s/%s defect" % OWNER
    DEMOTED = {"confidence": "CERTAIN", "code": "ARC-A2D", "severity_override": {}}

    def __init__(self, copy=True, says=None, owner_says="CONFIRMED", severity="CRITICAL",
                 below_gate=False, bad_owner=False, decoy=False, demoted=False):
        self.copy, self.says, self.owner_says = copy, says or {}, owner_says
        self.severity, self.below_gate, self.bad_owner = severity, below_gate, bad_owner
        self.decoy, self.demoted = decoy, demoted

    def findings(self, entry):
        claims = super().findings(entry)
        copier = (entry["group"], entry["domain"]) == self.COPIER
        if self.copy and copier:
            claims += [dict(claim, **({"title": self.DECOY} if self.decoy else {}),
                            **(self.DEMOTED if self.demoted else {}))
                       for claim in super().findings(dict(entry, group=self.OWNER[0],
                                                          domain=self.OWNER[1]))]
        claims = [dict(claim, severity=self.severity)
                  if claim["title"] in (self.CLAIM, self.DECOY) else claim for claim in claims]
        if self.bad_owner and (entry["group"], entry["domain"]) == self.OWNER:
            return claims + [None]
        return [dict(claim, severity="INFO") for claim in claims] if (
            copier and self.below_gate) else claims

    def answered(self, entry, cell):
        silent = (self.owner_says is None
                  and (entry.get("group"), entry.get("domain")) == self.OWNER)
        return [finding for finding in cell
                if not (silent and finding.get("title") == self.CLAIM)]

    def verdict(self, entry, finding):
        if finding is None or finding.get("title") not in (self.CLAIM, self.DECOY):
            return super().verdict(entry, finding)
        if (entry["group"], entry["domain"]) == self.COPIER:
            return self.says.get(entry.get("stage", "primary"), "CONFIRMED"), "of its copy"
        return self.owner_says, "of its own claim"


class NoEcho(FixtureReplies):
    """#3709: a reviewer that returns its findings and never echoes the `targeted_review`
    list its entry handed it. With `echo`, it echoes that instead (a wrong list)."""

    def __init__(self, echo=None):
        self.echo = echo

    def attested(self, entry):
        return self.echo if entry.get("targeted_review") else None


def build_target(test_case):
    root = os.path.realpath(tempfile.mkdtemp())
    test_case.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
    for relative, body in FILES.items():
        path = os.path.join(root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    os.makedirs(os.path.join(root, ".panopticon"))
    adopt_panopticon(root)
    write_host_evidence(root, {c: hosts.PROVEN for c in hosts.CAPABILITIES})
    with open(os.path.join(root, "panopticon.yml"), "w", encoding="utf-8") as fh:
        fh.write(MATRIX)
    return root


def _semgrep_document(unparsed=()):
    """Semgrep's capture. `unparsed` are files it reports a syntax error for: the review
    then hands them to their group's SEC cell as `targeted_review` (#3614)."""
    results = [{"ruleId": rule, "level": "error", "message": {"text": rule},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": uri}, "region": {"startLine": line}}}]}
               for rule, uri, line in SEMGREP]
    # The two stamps a real capture carries: nothing over the size limit, no Dockerfile.
    stamps = {semgrep_targets.STAMP_KEY: {"limit": 1000000, "count": 0, "complete": True,
                                          "files": []},
              semgrep_targets.DOCKERFILE_STAMP_KEY: {"count": 0, "analyzed": 0, "unanalyzed": 0,
                                                     "complete": True, "files": []}}
    notes = [{"descriptor": {"id": "Syntax error"}, "level": "warning",
              "message": {"text": "Syntax error at line /src/%s:1:\n parser failed" % path}}
             for path in unparsed]
    invocations = ({"invocations": [{"executionSuccessful": True,
                                     "toolExecutionNotifications": notes}]} if notes else {})
    return {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                      "results": results, "properties": stamps, **invocations}]}


def _osv_document():
    packages = [{"package": {"name": name, "version": version, "ecosystem": "crates.io"},
                 "vulnerabilities": [{"id": advisory, "summary": "affected package",
                                      "database_specific": {"severity": "CRITICAL"}}
                                     for advisory in advisories],
                 "groups": []}
                for name, (version, advisories) in ADVISORIES.items()]
    return {"results": [{"source": {"path": "/src/Cargo.lock"}, "packages": packages}]}


def _scan(cmd, unparsed=()):
    """The `tools` child, without Docker: the captures two scanners would have left, and the
    manifest the runner writes about them."""
    out = cmd[cmd.index("--out") + 1]
    os.makedirs(out, exist_ok=True)
    for name, document in (("semgrep.sarif", _semgrep_document(unparsed)),
                           ("osv-scanner.json", _osv_document())):
        with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
            json.dump(document, fh)
    runio._write_json(cmd[cmd.index("--manifest") + 1],
                      {"schema_version": 1, "run_id": cmd[cmd.index("--run-id") + 1],
                       "selected": list(SCANNERS), "produced": list(SCANNERS), "missing": [],
                       "outputs": ["osv-scanner.json", "semgrep.sarif"]})
    return subprocess.CompletedProcess(cmd, 0, "", "")


def _synthesize_split(cmd, review_root, max_bytes):
    """Synthesis in this process, writing its report in parts no larger than `max_bytes`.
    The child takes no such argument, and a report big enough to split on its own would
    make every case slow."""
    out, err = io.StringIO(), io.StringIO()
    here = os.getcwd()
    os.chdir(review_root)
    try:
        with mock.patch.object(render.write_report, "__defaults__", (max_bytes,)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = synthesize_cli.main(cmd[2:])
            except SystemExit as exc:
                code = exc.code
    finally:
        os.chdir(here)
    return subprocess.CompletedProcess(cmd, code or 0, out.getvalue(), err.getvalue())


def _children(split_bytes, unparsed=()):
    real = child._run_child

    def run_child(cmd, review_root, phase, timeout=None):
        if phase == "tools":
            return _scan(cmd, unparsed)
        if phase == "synthesize" and split_bytes:
            return _synthesize_split(cmd, review_root, split_bytes)
        return real(cmd, review_root, phase, timeout=timeout)

    return run_child


# --- the driver --------------------------------------------------------------------------

@dataclasses.dataclass
class Outcome:
    """Everything one case left behind."""
    plan: Plan | None
    root: str
    statuses: list            # every invocation's status document, in order
    terminal: str             # what the invocations printed to stderr
    launched: list            # every launch, in order, healthy or not
    injected: list            # (entry id, mode) for every launch the plan failed
    report: dict | None       # the report with every part read back in, or None
    part_files: list          # the part and sibling files the report named
    html: str | None
    recovered: bool = False   # the plan was lifted and the loop run again
    stalled: list = dataclasses.field(default_factory=list)   # statuses before the recovery
    stalled_report: bool = False                              # ...and whether a report existed
    short: list = dataclasses.field(default_factory=list)     # entries that answered in part
    limited: list = dataclasses.field(default_factory=list)   # one LimitedResume per #3646 resume

    @property
    def status(self):
        return self.statuses[-1]["status"]

    @property
    def unanswered(self):
        """Entries with undone work: the ones the plan kept from ever answering, and the
        ones that answered only part of what they were handed (#3695)."""
        if self.plan is None or not self.plan.persistent or self.recovered:
            return sorted(self.short)
        return sorted(set(self.plan.selected(self.launched)) | set(self.short))

    def unanswered_in(self, *phases):
        return [e for e in self.unanswered if phase_of(e) in phases]


_PART = re.compile(r"_part(\d+)\.json\Z")


def read_report(root):
    """(report, continuation files): the report as one document, every part read back in.

    `render.write_report` moves `findings[]` past the first chunk into `<stem>_partN.json`
    and, for a large report, `discarded_claims` into `<stem>-discarded.json`. A reader that
    stops at the main file sees those findings as missing (#3667's first diagnosis did).

    The continuation files are found ON DISK, beside the report, and then held against what
    the report names: a part the report does not name, or a named part that is not there, is
    a loss in its own right, so it raises here before any invariant is asked."""
    return read_report_at(runio._pano(root, "report.json"))


def read_report_at(path):
    """`read_report` for the report at `path` (which may be the compat link to it)."""
    if not os.path.isfile(path):
        return None, []
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    directory, main = os.path.split(os.path.realpath(path))
    stem = main[:-len(".json")]
    beside = sorted(os.listdir(directory))
    parts = sorted((name for name in beside
                    if name.startswith(stem) and _PART.fullmatch(name[len(stem):])),
                   key=lambda name: int(_PART.fullmatch(name[len(stem):]).group(1)))
    siblings = [name for name in beside if name == stem + "-discarded.json"]
    meta = report.get("meta") or {}
    named = list(meta.get("parts") or []) + [
        name for name in [meta.get("discarded_claims_file")] if name]
    if named != parts + siblings:
        raise AssertionError("the report names %r; beside it are %r" % (named, parts + siblings))
    findings = list(report.get("findings") or [])
    discarded = list(report.get("discarded_claims") or [])
    for name in parts:
        with open(os.path.join(directory, name), encoding="utf-8") as fh:
            findings.extend(json.load(fh)["findings"])
    for name in siblings:
        with open(os.path.join(directory, name), encoding="utf-8") as fh:
            discarded.extend(json.load(fh)["discarded_claims"])
    return dict(report, findings=findings, discarded_claims=discarded), parts + siblings


def _loop_once(root, runner, split_bytes, unparsed=()):
    # No `--fail-on`: every case runs under the default gate (#3673), which is CRITICAL.
    args = driver.build_parser().parse_args(["loop", root])
    err = io.StringIO()
    with mock.patch("scripts.phases.child._run_child",
                    side_effect=_children(split_bytes, unparsed)), \
            mock.patch("scripts.runners.base.runner_for", return_value=runner), \
            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        # Under the wrapper `driver loop` runs under, so the terminal reads as an operator's
        # does: stamped lines, and the report's summary relayed at the end.
        status = loop_progress.stamped_call(True, orchestrate.loop, args)
    return status, err.getvalue()


# Bound at import: conftest stands the canary's `measure` down for every test, and the
# limited-resume row is the one place here that wants the real one (over a fake launch).
_REAL_CANARY_MEASURE = canary.measure


@dataclasses.dataclass
class LimitedResume:
    """One resume whose capability probe the host rate-limited (#3646)."""
    status: dict
    launches: int             # reviewer launches the resume made
    report: bool              # whether a report existed after it
    changed: list             # run-folder files whose bytes differ from before it


LIMIT_ENVELOPE = {"type": "result", "is_error": True, "result": "",
                  "error": {"type": "rate_limit_error", "message": "usage limit reached"}}


def host_limited_artifact(host="claude"):
    """The posture a resume probes under a host limit: the REAL write/read canary, its
    `claude -p` launch answered with the envelope a quota-limited CLI prints, and every
    other capability as the healthy fixture has it."""
    limited = mock.Mock(returncode=1, stdout=json.dumps(LIMIT_ENVELOPE), stderr="")
    with mock.patch.object(canary, "_launch", return_value=limited):
        measured = _REAL_CANARY_MEASURE()
    body = all_proven_artifact(host)
    for name, key in ((hosts.ARTIFACT_WRITE_GUARD, "write"),
                      (hosts.READ_SCOPE_CONFINED, "read")):
        verdict, detail = measured[key]
        assert verdict == canary.HOST_LIMITED, measured
        body["capabilities"][name] = {"state": hosts.UNKNOWN, "by": "write-canary",
                                      "detail": detail}
    return body


def _run_folder_bytes(root):
    found = {}
    for directory, _dirs, names in os.walk(runio._pano(root)):
        for name in names:
            path = os.path.join(directory, name)
            with open(path, "rb") as fh:
                found[os.path.relpath(path, root)] = fh.read()
    return found


def drive(test_case, plan=None, recover=False, split_bytes=None, replies=None, unparsed=(),
          limited_resumes=0):
    """One case: a fresh target, reviewed under `plan` until the loop stops for a reason other
    than a pause (or `MAX_INVOCATIONS` pauses). With `recover`, the host then heals and the
    loop is run again, as an operator would after an outage. `replies` is what the agents
    say, when it is not the fixture's usual answers. `unparsed` are the files Semgrep
    reports it could not parse. `limited_resumes` is how many times the operator resumes
    while the host still rate-limits the capability probe, before it heals (#3646)."""
    root = build_target(test_case)
    replies = replies or FixtureReplies()
    runner = FakeRunner(faults=plan, replies=replies)
    statuses, terminal = [], []

    def invoke():
        for _ in range(MAX_INVOCATIONS):
            status, said = _loop_once(root, runner, split_bytes, unparsed)
            statuses.append(status)
            terminal.append(said)
            if status["status"] != "paused":
                return

    invoke()
    recovered, stalled, stalled_report, limited = False, [], False, []
    if recover and statuses[-1]["status"] != "complete":
        stalled = [status["status"] for status in statuses]
        stalled_report = os.path.lexists(runio._pano(root, "report.json"))
        for _ in range(limited_resumes):
            before, launched = _run_folder_bytes(root), len(runner.launched)
            with mock.patch("scripts.host_probes.run_probes",
                            side_effect=lambda host, target, **kw: host_limited_artifact(host)):
                status, said = _loop_once(root, runner, split_bytes, unparsed)
            after = _run_folder_bytes(root)
            terminal.append(said)
            limited.append(LimitedResume(
                status=status, launches=len(runner.launched) - launched,
                report=os.path.lexists(runio._pano(root, "report.json")),
                changed=sorted(name for name in set(before) | set(after)
                               if before.get(name) != after.get(name))))
        runner.faults, recovered = None, True
        invoke()
    report, part_files = read_report(root)
    html = None
    html_path = ((statuses[-1].get("artifacts") or {}).get("html")
                 if statuses[-1]["status"] == "complete" else None)
    if html_path:
        with open(html_path, encoding="utf-8") as fh:
            html = fh.read()
    return Outcome(plan=plan, root=root, statuses=statuses, terminal="".join(terminal),
                   launched=list(runner.launched), injected=list(runner.injected),
                   report=report, part_files=part_files, html=html, recovered=recovered,
                   stalled=stalled, stalled_report=stalled_report, limited=limited,
                   short=list(getattr(replies, "short", list)()))


def module_patches():
    """The three patches every loop test here needs: probes that prove the host, a Docker
    that is up, and a backoff that does not sleep."""
    real_pause = outage.FailureTally.pause_before_launch

    def pause(tally, mode, pending, sleep=None, jitter=None):
        return real_pause(tally, mode, pending, sleep=lambda seconds: None, jitter=jitter)

    return (mock.patch("scripts.host_probes.run_probes",
                       side_effect=lambda host, target, **kw: all_proven_artifact(host)),
            mock.patch("scripts.phases.readiness_checks.DOCKER_RUNNER", docker_probe_runner()),
            mock.patch.object(outage.FailureTally, "pause_before_launch", pause))


def is_outage(plan):
    return plan is not None and plan.mode == FAULT_OUTAGE
