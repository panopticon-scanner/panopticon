"""An agent-written verdict enters the controller through ONE sanitizer, and
that must be structural.

#1638 P16, fix rounds 1 and 2. A verdict file is written by an advisor, so its
contents are untrusted input in exactly the sense the panel findings already are
(`review._load_cell_findings` strips `AGENT_FORBIDDEN_FIELDS` for that reason).
Round 1 closed the two loaders in `scripts.evidence` by hand; the re-review then
found a THIRD reader -- `phases/verify._cell_verdicts` -- where a planted
`_backup_missing_evidence` emptied a cell's backup scope, so no adversarial round
was dispatched at all. Per-reader discipline is what failed, so this file does
not name readers. It finds them.

A function is a verdict-read site when it either
  * NAMES the `verdicts` key of a parsed bundle anywhere but inside an
    `isinstance` shape check (which extracts nothing), or
  * enumerates verdict FILES through `evidence._iter_verdict_files`,

Naming the key rather than consuming it in one of the recognised ways is the
rule on purpose (fix round 3, D3): the round-2 walk enumerated ITERATION shapes
and caught three of the sixteen ordinary ways a reader is written -- `vs =
data["verdicts"]` then a loop passed silently. `TestTheDetectorSeesEveryOrdinary
ReaderShape` below pins all sixteen, plus the two shape-check forms that must
NOT be flagged.
and every such function must pass what it read through
`evidence._agent_verdict`, which is the single place that
  (a) strips every `_`-prefixed key -- the pipeline's own carriers, which an
      agent asserting one is asserting a controller decision; and
  (b) drops the controller-owned `stage`, so an advisor cannot promote its own
      verdict to the adversarial round. (`run_id` stays: it is an echo the
      advisor was handed and `match_verdict` checks, and on the bundle path the
      `_panopticon` stamp overwrites it regardless.)

A fourth reader therefore turns this file red instead of quietly reopening the
hole. The walk is AST-based because a text scan over these modules flags the
prose that explains the rule -- this docstring included.

This guard covers verdicts only. The findings counterpart is now
`test_agent_findings_guard.py` (#1674), which requires `agent_finding` at every
raw findings reader and removes private controller carriers there too.
"""
import ast
import os
import unittest

from conftest import SKILL_ROOT

import scripts.evidence as evidence
import scripts.synth.codes as codes_mod
import scripts.synth.validate_schema as validate_schema_mod

SCRIPTS = os.path.join(SKILL_ROOT, "scripts")
SANITIZER = "_agent_verdict"
FILE_ITERATOR = "_iter_verdict_files"
BUNDLE_KEY = "verdicts"

# Every verdict-read site that exists, as `module::function`. Listed so a walk
# that silently found NOTHING -- a renamed key, a broken parse -- fails loudly
# instead of passing forever, and so adding a reader is a visible decision.
KNOWN_READERS = {
    "scripts.evidence::load_verdict_bundles",
    "scripts.evidence::load_verdicts_detailed",
    "scripts.phases.persist::_verify_accepts",
    "scripts.phases.verify::_cell_verdicts",
}


def _py_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for filename in sorted(filenames):
            if filename.endswith(".py"):
                yield os.path.join(dirpath, filename)


def _module_name(path):
    relative = os.path.relpath(path, SCRIPTS)
    return "scripts." + relative[:-3].replace(os.sep, ".")


def _bundle_key_names(tree):
    """Module-level names bound to the literal `"verdicts"`, so `data[KEY]`
    reads as `data["verdicts"]`. Without this the walk is defeated by one
    perfectly ordinary constant."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if isinstance(value, ast.Constant) and value.value == BUNDLE_KEY:
            names.update(t.id for t in targets if isinstance(t, ast.Name))
    return names


def _key_nodes(node, key_names):
    """Every place in this function that names the bundle key:
    `x["verdicts"]`, `x[KEY]`, `x.get("verdicts")`, `x.get(KEY)`, and the same
    through `.pop`/`.setdefault`, a nested subscript, a walrus or an `or {}`
    default (fix round 4, N4).

    Naming it is the signal -- NOT one of the sixteen ways to then consume
    it. Round 2 enumerated iteration shapes and caught three of them: `vs =
    data["verdicts"]` followed by a loop, the most obvious way anyone would
    write the fourth reader, passed silently. A rule about what a reader DOES
    has a tail of shapes; a rule about what it NAMES does not."""
    def _is_key(value):
        return ((isinstance(value, ast.Constant) and value.value == BUNDLE_KEY)
                or (isinstance(value, ast.Name) and value.id in key_names))

    def _is_document(value):
        """A bundle is a document you HAVE -- a name you loaded a file into --
        not a value computed by calling something. `meta.coverage.verdicts` in
        the report is the same word about a different thing
        (`html_report._render_header`), and its receiver is a CALL result
        (`(meta.get("coverage") or {}).get("verdicts")`) rather than a document
        anyone bound, which is what tells them apart.

        So the rule is the receiver, and it is stated here as what it is (fix
        round 4, N4 -- the round-3 version said "an inline `json.load(fh)
        ["verdicts"]` is not seen" while the code said `isinstance(value,
        (ast.Name, ast.Attribute))`, which also let `data["bundle"]["verdicts"]`
        and the walrus form through). A document is a name, an attribute, a
        subscript or walrus binding of one, or a `x or {}` default around one.

        KNOWN LIMIT, stated rather than hidden (as `test_host_launch_guard`
        states its own): a receiver that is a CALL -- `json.load(fh)
        ["verdicts"]`, `_load(path).get("verdicts")` -- is not seen, and cannot
        be without flagging the report's coverage counts. Bind the document,
        which all four real readers already do."""
        if isinstance(value, (ast.Name, ast.Attribute, ast.NamedExpr)):
            return True
        if isinstance(value, ast.Subscript):
            return _is_document(value.value)
        # `(data or {})["verdicts"]` -- a default around a bound document is
        # still that document; `(meta.get("x") or {})` is not, because no
        # operand of it is.
        if isinstance(value, ast.BoolOp):
            return any(_is_document(v) for v in value.values)
        return False

    # `.get`, `.pop` and `.setdefault` all HAND YOU the list; which one a reader
    # picked is style, not meaning.
    accessors = ("get", "pop", "setdefault")
    found = []
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Subscript) and _is_key(sub.slice)
                and _is_document(sub.value)):
            found.append(sub)
        elif (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                and sub.func.attr in accessors and sub.args
                and _is_key(sub.args[0]) and _is_document(sub.func.value)):
            found.append(sub)
    return found


def _shape_check_nodes(node, key_names):
    """Key-naming nodes whose only role is `isinstance(x.get("verdicts"), list)`.

    A shape check extracts nothing, and two live ones are written exactly that
    way (`persist._accepts`, `verify._verify_bundle_labeled`); demanding a
    sanitizer from them would be a demand for meaningless code with no correct
    way to a green suite -- the same trap `test_host_launch_guard`'s
    `subprocess` gate exists to avoid."""
    inside = []
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                and sub.func.id == "isinstance"):
            inside.extend(id(n) for n in _key_nodes(sub, key_names))
    return set(inside)


def _read_reasons(node, key_names):
    """Why this function is a verdict-read site, or [] if it is not one."""
    shape_only = _shape_check_nodes(node, key_names)
    extracting = [n for n in _key_nodes(node, key_names)
                  if id(n) not in shape_only]
    reasons = []
    if extracting:
        reasons.append("names the `%s` key at line(s) %s"
                       % (BUNDLE_KEY,
                          ", ".join(str(n.lineno) for n in extracting)))
    if _calls(node, FILE_ITERATOR):
        reasons.append("enumerates verdict files via `%s`" % FILE_ITERATOR)
    return reasons


def _calls(node, name):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Attribute) and func.attr == name:
                return True
            if isinstance(func, ast.Name) and func.id == name:
                return True
    return False


def _read_sites():
    """[(module::function, path, why, node)] for every verdict-read site."""
    found = []
    for path in _py_files(SCRIPTS):
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), path)
        key_names = _bundle_key_names(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            why = _read_reasons(node, key_names)
            if why:
                found.append(("%s::%s" % (_module_name(path), node.name),
                              path, ", ".join(why), node))
    return found


class TestOneSanitizerForEveryVerdictReadPath(unittest.TestCase):

    def test_the_walk_finds_the_readers_we_know_about_and_no_others(self):
        found = {name for name, _p, _w, _n in _read_sites()}
        self.assertEqual(
            found, KNOWN_READERS,
            "verdict-read sites changed. A NEW one must call `evidence.%s` and "
            "be added here; a vanished one must be removed. Never widen "
            "KNOWN_READERS to silence the sanitizer test below." % SANITIZER)

    def test_every_verdict_read_site_goes_through_the_sanitizer(self):
        offenders = []
        for name, path, why, node in _read_sites():
            if not _calls(node, SANITIZER):
                offenders.append("%s (%s) at %s:%d"
                                 % (name, why, os.path.relpath(path, SCRIPTS),
                                    node.lineno))
        self.assertEqual(
            offenders, [],
            "a verdict written by an agent reached the controller without "
            "`evidence.%s`:\n%s" % (SANITIZER, "\n".join(offenders)))


class TestTheSanitizerItself(unittest.TestCase):
    """What the guard above is asserting is true OF. Both halves, because a
    sanitizer that stopped doing either job would leave every read site still
    calling it."""

    def test_it_strips_every_private_key(self):
        got = evidence._agent_verdict(
            {"finding_id": "F", "verdict": "CONFIRMED",
             evidence.SCOPE_LIMITED_FIELD: ["x.py"],
             "_merged_ids": ["OTHER"], "_group": "Spoofed", "_repo_root": "/etc",
             "_anything_at_all": 1})
        self.assertEqual([k for k in got if k.startswith("_")], [])
        self.assertEqual(got, {"finding_id": "F", "verdict": "CONFIRMED"})

    def test_it_drops_the_controller_owned_stage(self):
        got = evidence._agent_verdict(
            {"finding_id": "F", "verdict": "CONFIRMED", "run_id": "MINE",
             "stage": "backup"})
        # `stage` confers a ROUND and is gone; `run_id` is an echo the advisor
        # was handed, which the bundle loader overwrites from the stamp and the
        # legacy queue path checks with `match_verdict`.
        self.assertEqual(got, {"finding_id": "F", "verdict": "CONFIRMED",
                               "run_id": "MINE"})
        self.assertEqual(sorted(evidence.CONTROLLER_STAMPED), ["stage"])

    def test_it_keeps_everything_an_advisor_is_supposed_to_say(self):
        verdict = {"finding_id": "F", "verdict": "NEEDS_MORE_INFO",
                   "confidence": "POSSIBLE", "reasoning": "r",
                   "explored": ["a.py"], "references": ["a.py:1"],
                   "citations": {"cwe": []}, "code": "SEC-A1A",
                   "missing_evidence": ["b.py"],
                   "evidence_scope": {"granted": ["a.py"], "cap": 12}}
        self.assertEqual(evidence._agent_verdict(verdict), verdict)


if __name__ == "__main__":
    unittest.main()


# Fix round 3, D3. The round-2 detector enumerated ITERATION shapes, and caught
# three of the eleven ordinary ways a reader is written -- `vs =
# data["verdicts"]` followed by a loop, the most obvious of them, passed
# silently. Enumerating shapes is the wrong shape of rule: naming the bundle key
# at all, anywhere but a shape check, is what makes a function a reader. These
# are those eleven plus the receiver shapes round 4 added (sixteen entries), as
# source, so the claim "a new reader turns this file red" is tested rather than
# asserted.
READER_SHAPES = {
    "for_loop": "    for v in data['verdicts']:\n        out.append(v)\n",
    "extend": "    out.extend(data['verdicts'])\n",
    "listcomp": "    out = [v for v in data['verdicts']]\n",
    "local_alias": "    vs = data['verdicts']\n    for v in vs:\n        out.append(v)\n",
    "augassign": "    out += data['verdicts']\n",
    "list_call": "    out = list(data['verdicts'])\n",
    "get_or_empty": "    out = data.get('verdicts') or []\n",
    "slice": "    out = data['verdicts'][:]\n",
    "index": "    out.append(data['verdicts'][0])\n",
    "passed_to_helper": "    helper(data['verdicts'])\n",
    "module_constant": "    for v in data[KEY]:\n        out.append(v)\n",
    # Fix round 4, N4. The docstring claimed one blind spot (an inline
    # `json.load(fh)["verdicts"]`); the rule was "the receiver is a Name or an
    # Attribute", and these five ordinary ways of writing a fifth reader all sat
    # in the gap between the claim and the rule.
    "pop": "    out = data.pop('verdicts')\n",
    "setdefault": "    out = data.setdefault('verdicts', [])\n",
    "nested_subscript": "    out = data['bundle']['verdicts']\n",
    "walrus": "    out = (loaded := helper(data))['verdicts']\n",
    "or_default": "    out = (data or {})['verdicts']\n",
}

# A shape check extracts nothing and must NOT be called a reader -- two live
# ones (`persist.py`, `verify.py`) are written exactly this way, and demanding a
# sanitizer from them would be a demand for meaningless code.
SHAPE_CHECKS = {
    "isinstance_get": "    if not isinstance(data.get('verdicts'), list):\n        return None\n",
    "isinstance_subscript": "    if isinstance(data['verdicts'], list):\n        return None\n",
}

_MODULE = ('KEY = "verdicts"\n\n\ndef reader(data, out, helper):\n%s    return out\n')


def _detects(body):
    tree = ast.parse(_MODULE % body)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "reader")
    return bool(_read_reasons(fn, _bundle_key_names(tree)))


class TestTheDetectorSeesEveryOrdinaryReaderShape(unittest.TestCase):

    def test_every_reader_shape_is_detected(self):
        missed = sorted(name for name, body in READER_SHAPES.items()
                        if not _detects(body))
        self.assertEqual(missed, [], "these ways of reading a bundle would pass "
                         "the guard silently: %s" % missed)

    def test_a_shape_check_is_not_a_reader(self):
        flagged = sorted(name for name, body in SHAPE_CHECKS.items()
                         if _detects(body))
        self.assertEqual(flagged, [], "an `isinstance` shape check extracts "
                         "nothing and must not be told to sanitize: %s" % flagged)

    def test_a_function_that_never_names_the_key_is_not_a_reader(self):
        self.assertFalse(_detects("    out.append(data['findings'])\n"))
        self.assertFalse(_detects("    out = data.get('verdict')\n"))


# --------------------------------------------------------------------------
# What the sanitizer may REPAIR (#1639 P15 fix round 3, R2-4).
# --------------------------------------------------------------------------
# The sanitizer gained a second job in #1639 P15: normalizing the verdict's
# type-pinned fields to what `report-schema.json` says, so one advisor's
# `"reasoning": [1, 2]` cannot end a completed run in `error`. That is safe for
# fields the report only PRINTS, and unsafe for any field an adjudication
# function reads: there, a repair is not a repair, it is a different answer.
# `missing_evidence` was in the repair set for one round and did exactly that --
# `scope_limited_paths` treats a non-list as "said nothing" on purpose, so
# coercing it retained a primary CONFIRMED (gate-eligible) where the base
# published `needs_more_info`.
#
# Naming the functions rather than the keys, like the guard above: a new key
# read by the adjudication is caught even if nobody remembers this file.
ADJUDICATION_FUNCTIONS = (
    ("scripts/evidence.py", ("match_verdict_by_id", "match_verdict",
                             "scope_limited_paths", "resolve_duplicates")),
    ("scripts/synth/verdicts.py", ("resolve_findings",)),
    ("scripts/group_runner.py", ("verdict_is_done", "pending_verdicts")),
    # #1679: reads the winning verdict's `code` and can rewrite a finding's
    # `code` and `severity`. `matched` comes from `match_verdict` /
    # `match_verdict_by_id` above, so what reaches it is already sanitized --
    # this entry closes the gap in the FUNCTION list, which is what would have
    # named a future key.
    ("scripts/synth/codes.py", ("apply_verdict_quality",)),
)

# The one (module, key) pair an adjudication function reads DESPITE the repair.
# The assertion below offers exactly two resolutions -- the key leaves
# REPAIRABLE_VERDICT_FIELDS, or the reading is a product decision with a test
# that pins the new outcome -- and this is the second, so the reason and the
# test that holds it are written down here rather than inferred from an absence.
# `test_every_repair_exemption_is_still_load_bearing` fails if an entry stops
# being either read or repairable, so this cannot rot into a blanket.
REPAIR_EXEMPT = {
    ("scripts/synth/codes.py", "code"):
        "apply_verdict_quality gates the advisor's `code` through "
        "ocrdb.validate_code before it can replace a finding's, and the only "
        "values the repair can PRODUCE are the string spelling of a number "
        "(every other shape is dropped) -- no catalog contains one, so the "
        "repair cannot change which code is applied. Pinned by "
        "TestARepairedCodeCannotChangeAFinding.",
}


def _keys_read(path, names):
    """Every string key those functions subscript or `.get()`, plus the names
    actually found -- so a rename cannot silently empty this guard."""
    with open(os.path.join(SKILL_ROOT, path), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    keys, seen = set(), set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in names:
            continue
        seen.add(node.name)
        for inner in ast.walk(node):
            if (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "get" and inner.args
                    and isinstance(inner.args[0], ast.Constant)
                    and isinstance(inner.args[0].value, str)):
                keys.add(inner.args[0].value)
            if (isinstance(inner, ast.Subscript) and isinstance(inner.slice, ast.Constant)
                    and isinstance(inner.slice.value, str)):
                keys.add(inner.slice.value)
    return keys, seen


class TestRepairTouchesPresentationOnly(unittest.TestCase):

    def test_the_repairable_set_is_disjoint_from_what_adjudication_reads(self):
        repairable = set(validate_schema_mod.REPAIRABLE_VERDICT_FIELDS)
        for path, names in ADJUDICATION_FUNCTIONS:
            keys, seen = _keys_read(path, names)
            self.assertEqual(sorted(seen), sorted(names),
                             "%s: these adjudication functions were not found, so "
                             "the guard read nothing: %s"
                             % (path, sorted(set(names) - seen)))
            overlap = sorted(k for k in repairable & keys
                             if (path, k) not in REPAIR_EXEMPT)
            self.assertEqual(overlap, [], (
                "%s reads %s, and the verdict repair rewrites it. A field the "
                "adjudication reads is not a presentation field: repairing it "
                "changes which findings are published and gate-eligible, always "
                "in the same direction. Either the key leaves "
                "REPAIRABLE_VERDICT_FIELDS, or the change is a product decision "
                "with a test that pins the new outcome and a REPAIR_EXEMPT entry "
                "naming that test." % (path, overlap)))

    def test_every_repair_exemption_is_still_load_bearing(self):
        names = dict(ADJUDICATION_FUNCTIONS)
        for (path, key), why in REPAIR_EXEMPT.items():
            with self.subTest(path=path, key=key):
                self.assertIn(path, names, "%s is exempt but is no longer an "
                                           "adjudication module" % path)
                keys, _seen = _keys_read(path, names[path])
                self.assertIn(key, keys, "%s no longer reads %r, so the exemption "
                                         "is dead weight" % (path, key))
                self.assertIn(key, validate_schema_mod.REPAIRABLE_VERDICT_FIELDS,
                              "%r is no longer repairable, so the exemption is "
                              "dead weight" % key)
                self.assertTrue(why.strip(), "an exemption without a reason")


class TestARepairedCodeCannotChangeAFinding(unittest.TestCase):
    """The outcome REPAIR_EXEMPT's one entry claims, measured rather than argued.

    `apply_verdict_quality` reads the winning verdict's `code`, and `code` is
    repairable -- so the repair could in principle decide which OCRDb code a
    finding is published under, and through that code's default severity, its
    severity. It cannot: the repair's output is gated by `ocrdb.validate_code`,
    and every shape the repair can produce is either dropped or the string
    spelling of a number. No catalog entry is named `7`.
    """

    BUNDLE = {"domains": {"SEC": {"entries": {
        "SEC-A1A": {"name": "n1", "default_severity": "MEDIUM"},
        "SEC-B2B": {"name": "n2", "default_severity": "HIGH"}}}}}

    def _applied(self, raw_code):
        """A finding after a verdict carrying `raw_code` is repaired and applied."""
        verdict = validate_schema_mod.repair_verdict(
            {"code": raw_code, "verdict": "CONFIRMED", "stage": "primary"},
            warn=lambda _message: None)
        finding = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH",
                   "domain": "SEC"}
        codes_mod.apply_verdict_quality([finding], {id(finding): verdict},
                                        self.BUNDLE)
        return finding

    def test_no_repairable_shape_of_code_reaches_the_finding(self):
        for raw in (["SEC-B2B"], ["SEC-B2B", "SEC-A1A"], 7, 7.5, True,
                    {"code": "SEC-B2B"}, None, ""):
            with self.subTest(raw=raw):
                finding = self._applied(raw)
                self.assertEqual("SEC-A1A", finding["code"])
                self.assertNotIn("code_corrected_by", finding)
                self.assertEqual("HIGH", finding["severity"])

    def test_the_pin_is_not_vacuous_a_real_catalog_code_still_applies(self):
        finding = self._applied("SEC-B2B")
        self.assertEqual("SEC-B2B", finding["code"])
        self.assertEqual("agent:advisor", finding["code_corrected_by"])

    def test_the_presentation_path_is_deliberately_not_guarded(self):
        # `derive_evidence` reads `reasoning` and the controller carrier: it is
        # what builds the report's `evidence` object, and repairing its inputs
        # is the whole point. Naming it here keeps the exclusion deliberate.
        keys, _seen = _keys_read("scripts/evidence.py", ("derive_evidence",))
        self.assertIn("reasoning", keys)
        self.assertIn("reasoning", validate_schema_mod.REPAIRABLE_VERDICT_FIELDS)
