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
and caught three of the eleven ordinary ways a reader is written -- `vs =
data["verdicts"]` then a loop passed silently. `TestTheDetectorSeesEveryOrdinary
ReaderShape` below pins all eleven, plus the two shape-check forms that must NOT
be flagged.
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

Out of scope, and said out loud: the FINDINGS path. `synth/findings.
load_findings_detailed` strips `AGENT_FORBIDDEN_FIELDS` but no `_`-prefixed key,
so `_merged_ids` is still agent-settable there (re-review N5, pre-existing at
`fb799d3`, filed separately). This guard covers verdicts only, and the key it
walks for is `verdicts`.
"""
import ast
import os
import unittest

from conftest import SKILL_ROOT

import scripts.evidence as evidence

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
    `x["verdicts"]`, `x[KEY]`, `x.get("verdicts")`, `x.get(KEY)`.

    Naming it is the signal -- NOT one of the eleven ways to then consume it.
    Round 2 enumerated iteration shapes and caught three of eleven: `vs =
    data["verdicts"]` followed by a loop, the most obvious way anyone would
    write the fourth reader, passed silently. A rule about what a reader DOES
    has a tail of shapes; a rule about what it NAMES does not."""
    def _is_key(value):
        return ((isinstance(value, ast.Constant) and value.value == BUNDLE_KEY)
                or (isinstance(value, ast.Name) and value.id in key_names))

    def _is_document(value):
        """A bundle is a document you HAVE -- a name you loaded a file into --
        not a field dug out of another object. `meta.coverage.verdicts` in the
        report is the same word about a different thing
        (`html_report._render_header`), and its receiver is a computed
        expression rather than a bound document, which is what tells them apart.

        KNOWN LIMIT, stated rather than hidden (as `test_host_launch_guard`
        states its own): an inline `json.load(fh)["verdicts"]`, with no name
        bound first, is not seen. Bind the document -- which all four real
        readers, and every ordinary way of writing a fifth, already do."""
        return isinstance(value, (ast.Name, ast.Attribute))

    found = []
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Subscript) and _is_key(sub.slice)
                and _is_document(sub.value)):
            found.append(sub)
        elif (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                and sub.func.attr == "get" and sub.args and _is_key(sub.args[0])
                and _is_document(sub.func.value)):
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
# are the eleven, as source, so the claim "a fourth reader turns this file red"
# is tested rather than asserted.
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
