"""The two severity caps the active report applies to claims nobody has confirmed (#3231).

Severity is the scanner's or the reviewer's statement. Two kinds of claim reached
the 5.2 reports at HIGH with nothing behind that HIGH:

* **An unverified heuristic tool claim.** A semgrep audit or best-practice rule
  (`dangerous-subprocess-use-audit`, `arbitrary-sleep`) arrives at HIGH. When the
  tool-verify advisor is blind it stays active at HIGH as `NEEDS_MORE_INFO`, which
  was 30-40 audit and 8-10 sleep HIGHs per Codex run. A tool-sourced finding whose
  evidence is `tool_reported` or `needs_more_info` is therefore capped at MEDIUM
  here. An advisor `CONFIRMED` (`tool_confirmed`) keeps the scanner's severity.
  Three classes are never capped, because their severity is not a pattern
  heuristic: a secret (`ingest_tools.secret_class`: a secret adapter, a mixed
  adapter's per-finding secret kind, or a credential CWE), and a dependency
  advisory (`tools.ADVISORY_ADAPTERS`, or any finding that cites a CVE). Not
  under `--gate-unverified`, either. That flag is
  the operator asking for the stricter policy, and a cap there would lower what
  gates, so under it the active severity simply stays the scanner's.
* **A coverage-absence claim nothing confirms.** An OCRDb `TST-A1*`
  ("untested-units") finding says a module has no test. That is a claim about the
  repository, made from a fenced cell. It keeps HIGH only when the driver confirms
  it: no test file this run assigned anywhere is named after the module
  (`test_<stem>`) or imports it (`py_imports`). Otherwise it is capped at MEDIUM
  and names the tests that reference the module. A non-Python module has no import
  witness, so its absence cannot be confirmed; it is capped and says so
  (`measured: false`). This cap applies under every gate policy, because it is
  about the claim's premise, not about verification.

Each capped finding keeps its own record, `severity_cap: {from, reason, ...}`, and
`meta.severity_capped` lists the capped ids per reason. Runs after
`codes.apply_verdict_quality` and `_derive_evidence`: the first may revert an agent
severity to its OCRDb default, which is the severity a cap must start from, and the
second decides the evidence status this reads.
"""
import os

import scripts.discovery as discovery
import scripts.evidence as evidence_mod
import scripts.ingest_tools as ingest_tools
import scripts.py_imports as py_imports
import scripts.tools as tools
from . import codes as codes_mod

CAP_TO = "MEDIUM"
CAPPED = ("CRITICAL", "HIGH")
UNVERIFIED_STATUSES = frozenset({"tool_reported", "needs_more_info"})
# OCRDb TST category A1, "untested-units": TST-A1A zero-coverage-script,
# A1B uncovered function, A1C untested recovery function, A1D untested CLI wiring.
COVERAGE_ABSENCE_CODES = frozenset({"TST-A1A", "TST-A1B", "TST-A1C", "TST-A1D"})
UNVERIFIED_TOOL = "unverified_tool"
UNCONFIRMED_ABSENCE = "unconfirmed_coverage_absence"
REASONS = (UNVERIFIED_TOOL, UNCONFIRMED_ABSENCE)
# How many referencing tests one finding names. The count is always exact.
REFERENCES_SHOWN = 5
CONFIRMED_STATUSES = frozenset({"advisor_confirmed", "tool_confirmed", "backup_scope_limited"})

# The `note` each cap carries: WHY, in terms a reader can act on (R5). A CONFIRMED
# finding at MEDIUM reads as a contradiction unless it says what was confirmed and
# what could not be.
NOTE_UNVERIFIED = ("no advisor confirmed this scanner hit; an advisor CONFIRMED restores the "
                   "scanner's severity")
NOTE_REFERENCED = ("%d assigned test file(s) name or import this module (referenced_by); HIGH "
                   "needs a confirmed no-test-anywhere")
NOTE_UNMEASURED = "no-test-anywhere can't be measured for this language"
NOTE_UNMEASURED_CONFIRMED = ("advisor confirmed within this group; no-test-anywhere can't be "
                             "measured for this language")


def exempt_class(finding):
    """`"secret"`, `"advisory"` or None: the evidence classes the unverified cap skips."""
    if ingest_tools.secret_class(finding):
        return "secret"
    cites = finding.get("citations")
    if (evidence_mod.tool_name(finding) in tools.ADVISORY_ADAPTERS
            or (isinstance(cites, dict) and cites.get("cve"))):
        return "advisory"
    return None


def _cap(finding, reason, **detail):
    finding["severity_cap"] = {"from": finding["severity"], "reason": reason, **detail}
    finding["severity"] = CAP_TO


def _named_after(test_path, stem):
    """`tests/test_<stem>.py` or `<stem>_test.py` -- `inventory.test_target_stem`'s rule."""
    base = os.path.splitext(os.path.basename(test_path))[0]
    return base in ("test_" + stem, stem + "_test")


class _Witness:
    """Which assigned test files name or import a module; every test parsed at most once."""

    def __init__(self, root, groups_meta):
        self.root, self.cache = root, {}
        self.tests = [(g.get("name"), f) for g in groups_meta or [] if isinstance(g, dict)
                      for f in g.get("files") or [] if isinstance(f, str)
                      and discovery.is_test_file(f)]

    def references(self, module):
        stem = os.path.splitext(os.path.basename(module))[0]
        importing = set(py_imports.importers(
            self.root, module, [f for _g, f in self.tests if f.endswith(py_imports.PY)],
            self.cache))
        return sorted({(g, f) for g, f in self.tests
                       if f in importing or _named_after(f, stem)}, key=lambda r: r[1])


def unverified_tool_capped(finding, severity, status, run):
    """Is this scanner finding, at `severity` and evidence `status`, capped as unverified?"""
    return (not run.gate_unverified and severity in CAPPED
            and evidence_mod.is_tool_sourced(finding) and status in UNVERIFIED_STATUSES
            and exempt_class(finding) is None)


def may_be_coverage_absence_capped(finding, severity):
    """Is this a `TST-A1*` claim the coverage-absence cap can reach at `severity`? Whether
    it does needs the run's root and groups (`Caps`); this much the finding itself says."""
    return (finding.get("code") in COVERAGE_ABSENCE_CODES and severity in CAPPED
            and not evidence_mod.is_tool_sourced(finding))


class Caps:
    """Decides each cap without changing a finding, for `apply` and for `published`.
    One witness, built when a Python `TST-A1*` claim first needs it."""

    def __init__(self, run, groups_meta):
        self.run, self.groups_meta, self._witness = run, groups_meta, None

    def coverage_absence(self, finding, severity, status):
        """The cap's detail for this claim at `severity`, or None when it is not capped."""
        if not may_be_coverage_absence_capped(finding, severity):
            return None
        module = py_imports.norm((finding.get("location") or {}).get("file")) or ""
        if not module.endswith(py_imports.PY):
            return {"measured": False, "referenced_by": [],
                    "note": (NOTE_UNMEASURED_CONFIRMED if status in CONFIRMED_STATUSES
                             else NOTE_UNMEASURED)}
        if self._witness is None:
            root = self.run.root if self.run.root is not None else self.run.target
            self._witness = _Witness(root, self.groups_meta)
        refs = self._witness.references(module)
        if not refs:
            return None
        return {"measured": True, "references": len(refs),
                "referenced_by": [{"group": g, "file": t} for g, t in refs[:REFERENCES_SHOWN]],
                "note": NOTE_REFERENCED % len(refs)}

    def settled(self, finding, status, bundle):
        """The severity a row for `finding` settles at (#3727): after the code
        discipline (`codes.severity_after_discipline`) and the coverage-absence cap,
        by the functions that apply them. Nothing is changed.

        The unverified-scanner cap is left out on purpose. A scanner finding nobody
        has confirmed is capped at MEDIUM, and that cap is not a demotion of its row:
        the agent claim merged into it is the same issue, shown as the scanner's until
        an advisor confirms it, as it always was. No cell can bring it about: a cell
        cannot write a scanner finding, and a third claim at the line ends the merge
        across the two kinds."""
        severity = codes_mod.severity_after_discipline(finding, bundle)
        return CAP_TO if self.coverage_absence(finding, severity, status) is not None else severity


def apply(findings, run, groups_meta):
    """Cap every unconfirmed claim in `findings`, in place; returns the capped count."""
    capped, caps = 0, Caps(run, groups_meta)
    for f in findings:
        if unverified_tool_capped(f, f.get("severity"), (f.get("evidence") or {}).get("status"),
                                  run):
            _cap(f, UNVERIFIED_TOOL, note=NOTE_UNVERIFIED)
            capped += 1
    for f in findings:
        detail = caps.coverage_absence(f, f.get("severity"), (f.get("evidence") or {}).get("status"))
        if detail is not None:
            _cap(f, UNCONFIRMED_ABSENCE, **detail)
            capped += 1
    return capped


def capped_ids(findings):
    """`{reason: [ids]}` for `meta.severity_capped`; reasons with none are left out."""
    out: dict = {}
    for f in findings:
        cap = f.get("severity_cap")
        if isinstance(cap, dict) and cap.get("reason") in REASONS:
            out.setdefault(cap["reason"], []).append(f.get("id"))
    return {reason: sorted(i for i in ids if i) for reason, ids in out.items()}
