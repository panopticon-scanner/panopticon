"""The types `report-schema.json` pins: enforcing them, and normalizing to them.

THE PRINCIPLE (#1639 P15 / #1602, fix round 1). **The schema pins the
CONTROLLER's output.** Every input that comes from a review agent or from a
target-writable file is normalized to the pinned types BEFORE it reaches the
report, so a schema error can only ever mean a bug in panopticon itself --
never a lever a reviewed repository or a review agent can pull. That is what
makes it safe for a schema failure to be terminal (`ARTIFACT_INVALID`): the
only writer who can trip it is us. Without it, a reviewer that typed
`"cvss": 7.5` instead of `{"score": 7.5}`, or a target that pre-committed one
malformed file under `.panopticon`, would decide whether a paid-for run
produces a result.

Two halves, deliberately in one module so they cannot disagree about what the
pinned type IS: `schema_errors` validates on the way out, the `repair_*`
functions normalize on the way in, and the second derives its rules from the
first's schema file rather than restating them. EVERY boundary where agent or
target content enters is covered, against BOTH schemas the completion path
enforces (fix round 2):

  `repair_finding`   agent and tool findings, via `findings.normalize_finding`
  `repair_verdict`   an advisor's verdict, via THE sanitizer `evidence._agent_verdict`
                     -- PRESENTATION fields only, see REPAIRABLE_VERDICT_FIELDS
  `repair_groups_json`  the target-writable `.panopticon/groups.json`, at its read
  `integrity.cross_domain_findings`  agent-stated domains on a cross-domain claim
  `coverage_io.normalized_cell`      the target-writable `.panopticon/coverage-*.json`
  `codes.*` / `x0x_report._domain`   an agent `code` naming no OCRDb domain, for
                                     the x0x schema's `candidates[].domain` enum
  `report._role_from_discovered_by`  a finding with no usable `provenance.model`

`report.assemble`'s `meta.host_capabilities` subtree is the one deliberate
exception: copied verbatim from an untrusted artifact, it is described in the
schema without being constrained by it.

#1639 P15. `report.validate_report` hand-checked a selected list of fields --
top-level keys, finding ids/severities/panels, the CVSS-and-exploit rule for
security HIGH+ -- and never once loaded `skill/reference/report-schema.json`.
The two contracts therefore disagreed in the only direction that matters:
run-13's independent audit had to run its own Draft 7 validation to establish
that the report was valid, and Codex's repro built a report whose `meta`,
`summary` and `cross_panel` were all `null` and got no production error or
warning at all, while schema validation rejects all three. A published contract
that only a controller-side check enforces is a contract the normal completion
path does not have.

So the schema is loaded here, and it is loaded FAIL-CLOSED. An absent
`jsonschema`, an unreadable schema file or an unparseable one each return an
error rather than an empty list: "we could not check" and "we checked and it
passed" must never render as the same answer, which is exactly what a silent
`except ImportError: return []` would do. `jsonschema` is a declared runtime
dependency (`pyproject.toml`), so the import failing is a broken install, not
a supported mode.

This does NOT replace the hand checks. The schema expresses shape; it cannot
express "a security HIGH from an agent needs a CVSS score and an exploit
scenario", or "no two findings may share an id". Both run, and their errors
are one list (`report.validate_report`).

`driver._scout_shape_errors` still hand-rolls a dependency-free subset on
purpose -- it validates an AGENT's scout profile at a point where a missing
third-party package must not stop a run -- and is deliberately left alone.
"""
import json
import os
import sys

# skill/reference/, from skill/scripts/synth/: the shipped contracts every
# artifact is validated against.
REFERENCE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "reference")

REPORT_SCHEMA = "report-schema.json"
X0X_SCHEMA = "x0x-report-schema.json"

# synthesize's exit status for "this run wrote an artifact that does not
# satisfy its own published schema" (#1639 P15 ruling 2). Terminal completion,
# artifact validity and coverage certification are three different facts, and
# each gets its own channel: 1/2 are the GATE's verdicts (FAIL / INCONCLUSIVE,
# both of them valid reports about a coverage question), 3 is a corrupt OCRDb
# bundle, and this is the artifact itself being unreadable as what it claims to
# be. A consumer that sees 4 should not read the report at all.
ARTIFACT_INVALID = 4


def schema_errors(document, schema=REPORT_SCHEMA, schema_path=None):
    """Every way `document` fails its published schema, as error strings.

    `schema` names a file under `skill/reference/`; `schema_path` overrides the
    whole resolution (tests, and any future caller holding a schema elsewhere).
    Each error reads `schema: <json path>: <message>` so it sits alongside
    `validate_report`'s hand checks in one list and still says where it fired.

    Returns [] only when validation actually ran and found nothing.
    """
    path = schema_path or os.path.join(REFERENCE_DIR, schema)
    try:
        import jsonschema
    except ImportError:
        # Fail closed: a report that could not be validated is not a report
        # that passed. jsonschema is a declared runtime dependency.
        return ["schema: jsonschema not installed — report schema not validated"]
    try:
        with open(path, encoding="utf-8") as fh:
            document_schema = json.load(fh)
    except (OSError, ValueError) as exc:
        return ["schema: %s unreadable (%s) — report schema not validated"
                % (os.path.basename(path), exc)]
    validator = jsonschema.Draft7Validator(document_schema)
    # Sorted by json path so two runs over the same bad artifact print the same
    # list in the same order -- iter_errors' own order is unspecified, and this
    # text ends up in a report field and in stderr a human diffs.
    errors = sorted(validator.iter_errors(document),
                    key=lambda e: (e.json_path, e.message))
    return ["schema: %s: %s" % (e.json_path, e.message) for e in errors]


# ---------------------------------------------------------------------------
# The other direction: repairing an INPUT to the types the schema pins.
# ---------------------------------------------------------------------------
# Same module on purpose. One place knows what the report contract pins, and it
# both enforces that contract on the way out and normalizes untrusted input to
# it on the way in -- so the two can never disagree about what the pinned type
# IS. Every rule below is derived from `report-schema.json` itself rather than
# restated here; a vocabulary written down twice is the drift #1602 is about.

_FINDING_ITEM = None


def finding_item_schema():
    """The published `findings[]` item subschema, loaded once.

    Returns {} when the schema cannot be read -- repair then becomes a no-op
    and `schema_errors` is the one that fails closed. Repair must not be the
    thing that raises: it runs on every finding of every run.
    """
    global _FINDING_ITEM
    if _FINDING_ITEM is None:
        node = ((_report_doc().get("properties") or {}).get("findings") or {}).get("items")
        _FINDING_ITEM = node if isinstance(node, dict) else {}
    return _FINDING_ITEM


_REPORT_DOC = None


def _report_doc():
    """`report-schema.json` as a dict, loaded once; {} when unreadable.

    The repair half reads the same file the validating half does, so the two
    cannot disagree about what a pinned type IS. Unreadable makes every repair
    a no-op -- `schema_errors` is the half that fails closed.
    """
    global _REPORT_DOC
    if _REPORT_DOC is None:
        try:
            with open(os.path.join(REFERENCE_DIR, REPORT_SCHEMA),
                      encoding="utf-8") as fh:
                _REPORT_DOC = json.load(fh)
        except (OSError, ValueError):
            _REPORT_DOC = {}
    return _REPORT_DOC if isinstance(_REPORT_DOC, dict) else {}


# Fields whose non-conforming value is DROPPED rather than coerced, because the
# coercion would not be lossless -- it would invent a claim. `location.file`
# drives on-diff classification, group attribution and the LoC denominator, so
# `str(7)` there is not a repair, it is a fabricated path. Dropping it makes
# the whole location fall away (findings.normalize_finding's #1522 rule), which
# is the honest answer: the finding is real, its locus was not stated.
_DROP_NEVER_COERCE = ("location.file", "groups[].files[]")

# Fields a LATER controller stage owns outright, which this pass must leave
# alone: it would drop a value that stage is about to repair better (it knows
# what the field means; this pass only knows its type) or rebuild from scratch.
# Skipping one is a claim that the report cannot carry a bad value for it, so
# each entry says which stage makes that true -- and the meta-test PROVES the
# claim for every entry (it feeds a wrong-typed agent value through the real
# pipeline and checks the artifact carries the controller's answer instead),
# because round 1 shipped two entries that were simply false:
#
#   `delta` named `delta.classify_findings`, which only runs under
#   `--diff-hunks` -- so on every other run the key was skipped here and
#   touched by nothing, and an agent's `delta` reached the artifact verbatim.
#   `evidence` named `derive_evidence`, which does rebuild the object -- out of
#   the advisor's verdict, whose `reasoning` it copies through. True about
#   agent FINDINGS, false about the rebuild's own input (that boundary is now
#   `repair_verdict`).
#
# Round 3 removed two more, of a third shape: a normalizer that RAISES on the
# value it is declared to normalize, so skipping the repair does not hand the
# field to its owner, it hands the process a traceback.
#
#   `panel` named normalize_finding's `panel not in VALID_PANELS` -- a SET
#   membership test, which raises TypeError on an unhashable value before any
#   derivation can happen. `{"a": 1}` and `[1]` both ended the run.
#   `citations` named `enrich_citations`, which copies `epss` through verbatim;
#   `render.render_summary` then read `e.get("score")` off whatever that was.
#
# All four are gone. Two shapes to distrust: an entry naming a later STAGE
# rather than a normalizer (a stage that does not always run, or that rebuilds
# from a second untrusted source), and an entry whose normalizer cannot survive
# the value. The meta-test proves what is left, node by node, against the
# controller's own expected value.
_OWNED_DOWNSTREAM = {
    "id": "rewritten by evidence.matrix_finding_id after normalization (#1109)",
    "severity": "normalize_finding coerces case-insensitively and falls back to INFO",
    "confidence": "normalize_finding coerces, else derives it from `verdict`",
    "title": "normalize_finding rebuilds it from title/description, always a string",
    "short_title": "normalize_finding derives it from the repaired title",
    "fingerprint": "stamped by verdicts.resolve_findings from evidence.finding_fingerprint",
}


def _conforms(value, node):
    """Does `value` already satisfy this node's pinned type/enum/bound?"""
    if "enum" in node and value not in node["enum"]:
        return False
    if ("minimum" in node and isinstance(value, (int, float))
            and not isinstance(value, bool) and value < node["minimum"]):
        return False               # `line_start: 0` is an integer and still invalid
    types = node.get("type")
    if types is None:
        return True                        # unpinned (or anyOf/$ref): leave alone
    types = types if isinstance(types, list) else [types]
    for t in types:
        if t == "null" and value is None:
            return True
        if t == "boolean" and isinstance(value, bool):
            return True
        if t == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
        if t == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if t == "string" and isinstance(value, str):
            return True
        if t == "array" and isinstance(value, list):
            return True
        if t == "object" and isinstance(value, dict):
            return True
    return False


def _coerce(value, node, path):
    """(ok, value) -- `value` repaired to this node's pinned type, or dropped.

    The repairs are the lossless ones and only those: a numeric string or an
    integral float to an integer, a numeric string to a number, a scalar to the
    string spelling of itself, a lone conforming scalar to the one-element
    array it was meant to be (`"references": "CWE-89"`), and a bare CVSS score
    to the `{score}` object the schema pins. Anything else is dropped, because
    guessing is how a validator becomes a fabricator.
    """
    types = node.get("type")
    types = [] if types is None else (types if isinstance(types, list) else [types])
    if "enum" in node:
        return False, None                 # a value outside the vocabulary is not repairable
    if "integer" in types:
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        elif isinstance(value, str):
            try:
                value = int(value.strip())
            except ValueError:
                return False, None
        if isinstance(value, int) and not isinstance(value, bool):
            if "minimum" in node and value < node["minimum"]:
                return False, None
            return True, value
        return False, None
    if "number" in types and isinstance(value, str):
        try:
            return True, float(value.strip())
        except ValueError:
            return False, None
    if "string" in types and isinstance(value, (int, float)) and not isinstance(value, bool):
        if path in _DROP_NEVER_COERCE:
            return False, None
        return True, str(value)
    if "array" in types and not isinstance(value, list):
        # A single entry written where a list belongs -- keep it if it is the
        # thing the list holds, drop it otherwise.
        items = node.get("items") or {}
        if _conforms(value, items):
            return True, [value]
        return False, None
    if "object" in types and path == "cvss" and not isinstance(value, dict):
        ok, score = _coerce(value, {"type": "number"}, "cvss.score")
        if ok or isinstance(value, (int, float)) and not isinstance(value, bool):
            return True, {"score": float(score if ok else value)}
        return False, None
    return False, None


# #1639 P15 fix round 2 (F2): a field whose non-conforming value is replaced by
# a DEFAULT rather than removed, because removing it is what manufactures the
# invalid output. `provenance.discovered_by` is the case: drop it and
# `report._collect_models_used` has no role to publish, and the `None` it wrote
# instead is what ended the run. The repair must not create the bug it exists to
# prevent.
_DEFAULT_WHEN_DROPPED = {"provenance.discovered_by": "unknown"}


def _repair_node(value, node, path, changes):
    """(ok, value) for one value against one subschema; recurses into
    described objects and arrays. `changes` collects (path, what) for every
    field this pass repaired or dropped."""
    if not _conforms(value, node):
        ok, repaired = _coerce(value, node, path)
        if not ok and path in _DEFAULT_WHEN_DROPPED:
            ok, repaired = True, _DEFAULT_WHEN_DROPPED[path]
        if not ok:
            changes.append((path, "dropped"))
            return False, None
        changes.append((path, "repaired"))
        value = repaired
    if isinstance(value, dict):
        for key, sub in (node.get("properties") or {}).items():
            if key not in value:
                continue
            ok, repaired = _repair_node(value[key], sub, "%s.%s" % (path, key) if path else key,
                                        changes)
            if ok:
                value[key] = repaired
            else:
                value.pop(key, None)
        required = [k for k in (node.get("required") or []) if k not in value]
        if required:
            return False, None             # e.g. a location whose `file` was dropped
    elif isinstance(value, list) and node.get("items"):
        kept = []
        for entry in value:
            ok, repaired = _repair_node(entry, node["items"], "%s[]" % path, changes)
            if ok:
                kept.append(repaired)
        value = kept
    return True, value


def repair_finding(finding, warn=None):
    """Normalize one finding to the types `report-schema.json` pins.

    THE PRINCIPLE (#1639 P15 / #1602): the schema pins the CONTROLLER's output.
    Every input that comes from an agent or from a target-writable file is
    normalized to the pinned types BEFORE it reaches the report, so a schema
    error can only ever mean a controller bug -- never a lever a review agent
    or a scanned repository can pull. Without this, a reviewer that wrote
    `"cvss": 7.5` instead of `{"score": 7.5}` would end a whole paid-for run in
    `error`, and a target that pre-committed one malformed `.panopticon` file
    could do the same on purpose.

    Repairs in place and returns the finding. EVERY change is announced on
    stderr (or through `warn`) -- repairs included, not only drops: a value
    that did not match the contract is a fact about the reviewer's output, and
    silently swallowing it would trade one silence for another. Never raises --
    it runs on every finding of every run, and a malformed input must not be
    able to crash the pipeline either.
    """
    schema = finding_item_schema()
    if not schema or not isinstance(finding, dict):
        return finding
    changes = []
    for key, sub in (schema.get("properties") or {}).items():
        if key not in finding or key in _OWNED_DOWNSTREAM:
            continue
        ok, repaired = _repair_node(finding[key], sub, key, changes)
        if ok:
            finding[key] = repaired
        else:
            finding.pop(key, None)
    for path, what in changes:
        message = ("findings: %s: %s %s -- it did not match the type "
                   "report-schema.json pins for it"
                   % (finding.get("id") or "?", what, path))
        if warn is not None:
            warn(message)
        else:
            print(message, file=sys.stderr)
    return finding


# ---------------------------------------------------------------------------
# The SECOND agent boundary: an advisor's verdict.
# ---------------------------------------------------------------------------
# `repair_finding` runs at the findings-file ingest. The verify round then
# writes type-pinned fields onto those same findings from a different
# agent-authored source -- the advisor's verdict JSON -- AFTER that boundary
# (#1639 P15 fix round 2, F3). One advisor typing a list where a string belongs
# produced four schema errors and a terminal `error` on a run whose review had
# completed. Each verdict field is repaired against the report-schema node it
# ends up in, so this boundary and the findings boundary cannot disagree about
# the type either.
# PRESENTATION fields only, and that is a hard boundary (#1639 P15 fix round 3,
# R2-4). A verdict carries two kinds of key: what the advisor SAID (prose, a
# model name, citations -- copied into the report, type-pinned, repairable) and
# what the ADJUDICATION reads to decide an outcome (`verdict`, `stage`,
# `run_id`, `finding_id`, `missing_evidence`). Repairing one of the second kind
# is not a repair, it is a different answer: `missing_evidence` was in this map
# for one round, and because `scope_limited_paths` treats a non-list as "said
# nothing" ON PURPOSE -- the field is agent-supplied -- coercing `"a.py"` to
# `["a.py"]` moved the finding from `needs_more_info` (not gate-eligible) to a
# retained primary CONFIRMED published as `backup_scope_limited` (gate-eligible),
# in that direction only. It also bought nothing: the report's
# `evidence.missing_evidence` is written from the controller carrier
# `evidence.SCOPE_LIMITED_FIELD`, whose contents `scope_limited_paths` has
# already filtered to non-empty strings.
#
# tests/test_agent_verdict_guard.py holds the line: it AST-walks the
# adjudication functions and fails if any key they read appears here.
REPAIRABLE_VERDICT_FIELDS = {
    "reasoning": "evidence.reasoning",          # and provenance.confirmation_reasoning
    "model": "provenance.confirmed_by_model",
    "code": "provenance.advisor_code",
    "references": "references",
    "citations": "citations",
}


def _subschema(dotted):
    """The `findings[]` item subschema at a dotted path, or None."""
    node = finding_item_schema()
    for part in dotted.split("."):
        node = (node.get("properties") or {}).get(part)
        if not isinstance(node, dict):
            return None
    return node


def _as_prose(value):
    """An advisor's free text, as the string the report pins.

    A list of scalars is JOINED rather than dropped: an advisor that answered in
    bullets said something, and throwing its reasoning away to satisfy a type
    would lose the one part of a verdict a human actually reads.
    """
    if isinstance(value, list) and all(
            isinstance(x, (str, int, float, bool)) for x in value):
        return "; ".join(str(x) for x in value)
    return str(value)


def repair_verdict(verdict, warn=None):
    """Normalize one advisor verdict's report-bound fields to the pinned types.

    Called from `evidence._agent_verdict` -- THE verdict sanitizer, which
    `tests/test_agent_verdict_guard.py` forces every reader through, so this
    cannot be bypassed by a new read path. Repairs in place and returns the
    verdict; never raises.
    """
    if not isinstance(verdict, dict):
        return verdict
    changes = []
    for key, dotted in REPAIRABLE_VERDICT_FIELDS.items():
        if key not in verdict or verdict[key] is None:
            continue
        node = _subschema(dotted)
        if node is None:
            continue                       # schema unreadable: repair is a no-op
        value = verdict[key]
        if key == "reasoning" and not isinstance(value, str):
            value = _as_prose(value)
            changes.append((key, "repaired"))
        ok, repaired = _repair_node(value, node, key, changes)
        if ok:
            verdict[key] = repaired
        else:
            verdict.pop(key, None)
    for key, what in changes:
        message = ("verdicts: %s %s -- it did not match the type "
                   "report-schema.json pins for it" % (what, key))
        if warn is not None:
            warn(message)
        else:
            print(message, file=sys.stderr)
    return verdict


# ---------------------------------------------------------------------------
# The TARGET boundary: `.panopticon/groups.json`.
# ---------------------------------------------------------------------------
# Same principle, third source (#1639 P15 fix round 2, F6). `groups.json` is
# read out of `.panopticon/` inside the reviewed tree -- the same
# target-writable directory as the `coverage-*.json` files `coverage_io`
# already repairs -- and `plan.load_groups_json` is tolerant BY DESIGN: it
# announces a corrupt file and returns {} rather than abort a paid-for run.
# That promise stopped at the parse. Five of its fields reach the artifact or a
# bare subscript untouched: `groups[].name` and `groups[].files` are copied
# into the report's type-pinned `groups[]`, `parent` becomes a rolled-up unit's
# name, `security_mode` becomes `meta.security_mode` (an enum), and `mode` is
# used as a dict KEY -- so a list there raised TypeError, and a group without
# `files` a KeyError, from a file the target can write.
_GROUPS_KEEP_KEYS = ("name", "files", "parent")


def repair_groups_json(gj, warn=None):
    """Normalize the run's `groups.json` to the types the report pins.

    Repairs in place and returns `gj` ({} when it is not a dict). Never raises
    and never aborts: a group that cannot be repaired is dropped with a warning
    and the rest of the run proceeds, which is `load_groups_json`'s contract
    carried all the way to the artifact instead of only to the parse.
    """
    if not isinstance(gj, dict):
        return {}
    props = _report_doc().get("properties") or {}
    item = (((props.get("groups") or {}).get("items") or {}).get("properties")) or {}
    meta = ((props.get("meta") or {}).get("properties")) or {}
    changes = []
    if "groups" in gj:
        raw = gj["groups"]
        if not isinstance(raw, list):
            changes.append(("groups", "dropped"))
            raw = []
        kept = []
        for g in raw:
            if not isinstance(g, dict) or not isinstance(g.get("name"), (str, int, float)) \
                    or isinstance(g.get("name"), bool):
                changes.append(("groups[]", "dropped"))
                continue
            for key in _GROUPS_KEEP_KEYS:
                node = item.get(key) or ({"type": "string"} if key == "parent" else None)
                if node is None or key not in g:
                    continue
                ok, repaired = _repair_node(g[key], node, "groups[].%s" % key, changes)
                if ok:
                    g[key] = repaired
                else:
                    g.pop(key, None)
            if not isinstance(g.get("files"), list):
                # grading subscripts `g["files"]` directly; absent is not a
                # shape the report's groups[] can carry either (it is required).
                g["files"] = []
                changes.append(("groups[].files", "defaulted to []"))
            kept.append(g)
        gj["groups"] = kept
    if "mode" in gj and not isinstance(gj["mode"], str):
        # Read as a dict KEY (findings.MODE_TO_REVIEW_TYPE): unhashable raises.
        gj.pop("mode")
        changes.append(("mode", "dropped"))
    node = meta.get("security_mode") or {}
    if "security_mode" in gj and gj["security_mode"] is not None \
            and not _conforms(gj["security_mode"], node):
        gj.pop("security_mode")            # from_args then defaults it
        changes.append(("security_mode", "dropped"))
    for path, what in changes:
        message = ("groups.json: %s %s -- it did not match the type "
                   "report-schema.json pins for it" % (what, path))
        if warn is not None:
            warn(message)
        else:
            print(message, file=sys.stderr)
    return gj


_SANITIZED_ROW = ("source", "kept", "dropped", "hashes_stripped")


def repair_tools_sanitized(value, warn=None):
    """`tools-manifest.json`'s `sanitized` block, normalized to what the schema
    pins for `meta.tools.sanitized` (#1646).

    THE PRINCIPLE (see the module docstring and `synth/coverage_io`): the schema
    pins the CONTROLLER's output, so a target-sourced input is repaired to the
    pinned types AT ITS BOUNDARY. The manifest is written into the scanned tree
    and a hostile target can pre-commit one, so every field this block carries
    into the report -- and the HTML renders -- is checked here rather than
    trusted, and a malformed row costs a warning and the row, never the run and
    never an `artifact invalid` exit on a report the target authored a corner of.

    DROPPED, never coerced: a `kept` of "lots" has no honest integer, and
    inventing one would publish a number nobody measured. A bool is not an
    integer for this purpose -- `jsonschema` rejects `True` where `integer` is
    pinned, so an unrepaired one would fail the artifact it rode into. Keys the
    schema does not describe go too: `meta` is closed and the parity walk is
    stricter still.
    """
    changes = []
    out = {}
    if not isinstance(value, dict):
        if value not in (None, {}):
            changes.append(("sanitized", "dropped: not an object"))
        value = {}
    for name, row in value.items():
        if not isinstance(name, str):
            changes.append(("sanitized[%r]" % (name,), "dropped: name is not a string"))
            continue
        if not isinstance(row, dict):
            changes.append(("sanitized.%s" % name, "dropped: not an object"))
            continue
        kept_row = {}
        for field in _SANITIZED_ROW:
            if field not in row:
                continue
            got = row[field]
            if field == "source" and isinstance(got, str):
                kept_row[field] = got
            elif field == "kept" and isinstance(got, int) and not isinstance(got, bool):
                kept_row[field] = got
            elif field == "hashes_stripped" and isinstance(got, bool):
                kept_row[field] = got
            elif field == "dropped" and isinstance(got, list):
                kept_row[field] = [
                    {"line": r["line"], "reason": r["reason"]} for r in got
                    if isinstance(r, dict) and isinstance(r.get("line"), str)
                    and isinstance(r.get("reason"), str)]
                if len(kept_row[field]) != len(got):
                    changes.append(("sanitized.%s.dropped" % name,
                                    "dropped %d malformed row(s) from"
                                    % (len(got) - len(kept_row[field]))))
            else:
                changes.append(("sanitized.%s.%s" % (name, field), "dropped"))
        for extra in sorted(set(row) - set(_SANITIZED_ROW)):
            changes.append(("sanitized.%s.%s" % (name, extra),
                            "dropped: the schema describes no such field in"))
        out[name] = kept_row
    for path, what in changes:
        message = ("tools-manifest.json: %s %s -- it did not match the type "
                   "report-schema.json pins for it" % (what, path))
        if warn is not None:
            warn(message)
        else:
            print(message, file=sys.stderr)
    return out


def string_list(value):
    """The strings in `value` when it is a list, else [].

    The run artifacts name things -- tools, files, groups -- and a NAME is a
    string everywhere it lands: a `meta.coverage.tools_ran[]` entry, a
    `divergence` key, a sorted join in the terminal summary. One integer in
    `tools-manifest.json` crashed `render_summary` on a report that had already
    been written and validated, so the names are pinned where they are read.
    """
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []
