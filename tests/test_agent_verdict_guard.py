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
  * iterates the `verdicts` list of a parsed bundle, or
  * enumerates verdict FILES through `evidence._iter_verdict_files`,
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


def _reads_the_bundle_list(node):
    """`for v in data["verdicts"]` / `data.get("verdicts") or []` used as an
    ITERABLE -- not the `isinstance(data.get("verdicts"), list)` shape checks,
    which extract nothing and are how three of these functions start."""
    for sub in ast.walk(node):
        if isinstance(sub, (ast.For, ast.comprehension, ast.ListComp,
                            ast.GeneratorExp, ast.SetComp)):
            targets = ([sub.iter] if isinstance(sub, (ast.For, ast.comprehension))
                       else [g.iter for g in sub.generators])
        elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                and sub.func.attr == "extend":
            targets = list(sub.args)
        else:
            continue
        for target in targets:
            if _names_the_bundle_key(target):
                return True
    return False


def _names_the_bundle_key(node):
    """`x["verdicts"]`, `x.get("verdicts")`, or either with an `or []` around
    it -- anywhere inside the expression being iterated."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.Constant) \
                and sub.slice.value == BUNDLE_KEY:
            return True
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                and sub.func.attr == "get" and sub.args \
                and isinstance(sub.args[0], ast.Constant) \
                and sub.args[0].value == BUNDLE_KEY:
            return True
    return False


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
    """[(module::function, path, why)] for every verdict-read site in the tree."""
    found = []
    for path in _py_files(SCRIPTS):
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            why = []
            if _reads_the_bundle_list(node):
                why.append("iterates a bundle's `%s` list" % BUNDLE_KEY)
            if _calls(node, FILE_ITERATOR):
                why.append("enumerates verdict files via `%s`" % FILE_ITERATOR)
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
