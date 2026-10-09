"""#2951: no lone surrogate reaches an encoder.

`json.load` hands a lone surrogate over for a lone `\\udXXX` escape, and no encoder takes one. On main one such
string in one agent-authored finding ended the `synthesize.py` child with a traceback and status 1 -- which is also
the gate's FAIL status -- and, where the string seeds the finding's id, with no report at all. Each is now spelled as
the inert policy spells a code point (`\\ud800`, six visible characters), in four places:

* `findings.agent_finding` and `evidence._agent_verdict`, the one door each for an agent's findings and an advisor's
  verdicts. Their text is hashed (the id, the fingerprint) before anything is written, so it is spelled on the way in.
* `tools/base.parse_json_bytes` and the SARIF adapter's own parse, the door for a scanner's output, for that reason.
* `synth/report.build_report`, the backstop: everything else a report holds meets its first encoder at a writer,
  and every writer writes the report.
* The policy's own set, `inert.INERT_ESCAPE_CODE_POINTS`, so `inert_text` and the prompt's `_prompt_safe` cover a
  name that never was JSON.

Named limits. The child pins plant U+D800 alone: that every code point of the block is spelled, and nothing beside
the block moves, is pinned on the helper (`TestTheSpelling`). `--compare` reads reports already on disk and is not
covered. Nor is a nesting deeper than the stack, which ends the run in `redact.redact_tree` with or without a
surrogate; `inert.surrogate_free` is only pinned not to be the walk that raises.
"""
import ast
import contextlib
import copy
import io
import itertools
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scripts.evidence as evidence
import scripts.inert as inert
import scripts.ingest_tools as ingest_tools
import scripts.phases.review as review
import scripts.phases.runio as runio
import scripts.synth.findings as findings_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
import scripts.synthesize as syn
import scripts.tools.base as base
import scripts.tools.legacy_sarif as legacy_sarif
import tests.test_schema_parity as parity
from tests._test_helpers import SKILL_ROOT, first

SCRIPTS = os.path.join(SKILL_ROOT, "scripts")
SCRIPT_TIMEOUT = 120
RUN_ID = "RID-2951"
LONE = "\ud800"            # what `json.load` returns for the lone escape `\ud800`
SPELLED = "\\ud800"        # the six characters the inert policy writes for it


def strings(document):
    """Every string of a loaded JSON document, keys included."""
    todo = [document]
    while todo:
        item = todo.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            todo.extend(item)
            todo.extend(item.values())
        elif isinstance(item, list):
            todo.extend(item)


def surrogates(document):
    """The surrogates left in `document`'s strings, as `U+XXXX` so a failure prints."""
    return sorted({"U+%04X" % ord(ch) for text in strings(document) for ch in text if "\ud800" <= ch <= "\udfff"})


def a_finding(n, **fields):
    made = {"id": "CD-%03d" % n, "title": "smell %d" % n, "severity": "MEDIUM", "confidence": "POSSIBLE",
            "panel": "code", "category": "structure", "description": "a description",
            "location": {"file": "src/app.py", "line_start": n}}
    made.update(fields)
    return made


def _put(key, before=""):
    return lambda made, text: made.update({key: before + text})


# Where an agent can write a string into a finding. Each entry plants `text` in ONE place of a fresh finding.
PLACES = (
    ("title", lambda f, text: f.update(title=f["title"] + " " + text)),
    ("title, locus-free", lambda f, text: (f.pop("location"), f.update(title=f["title"] + " " + text))),
    ("short_title", _put("short_title", "short ")),
    ("location.file", lambda f, text: f["location"].update(file="src/app%s.py" % text)),
    ("location.function", lambda f, text: f["location"].update(function="fn" + text)),
    ("description", _put("description", "quoted ")),
    ("impact", _put("impact", "impact ")),
    ("remediation", _put("remediation", "fix ")),
    ("exploit_scenario", _put("exploit_scenario", "step ")),
    ("category", _put("category", "struct")),
    ("lens", _put("lens", "lens")),
    ("a references member", lambda f, text: f.update(references=["CWE-1", "ref " + text])),
    ("id", lambda f, text: f.update(id=f["id"] + text)),
    ("severity", _put("severity", "MEDIUM")),
    ("confidence", _put("confidence", "POSSIBLE")),
    ("panel", _put("panel", "code")),
    ("code", lambda f, text: f.update(code="COD-A1A" + text, domain="COD")),
    ("domain", lambda f, text: f.update(code="COD-A1A", domain="COD" + text)),
    ("severity_override.reason", lambda f, text: f.update(
        severity_override={"from": "LOW", "to": "MEDIUM", "reason": "why " + text})),
    ("evidence, which an agent may not set", lambda f, text: f.update(evidence={"status": "x" + text})),
    ("source, which an agent may not set", _put("source", "tool:")),
    ("a provenance value", lambda f, text: f.update(provenance={"model": "m" + text})),
    ("a nested value", lambda f, text: f.update(extra={"deep": {"list": ["v " + text]}})),
    ("a key", lambda f, text: f.update({"key" + text: "v"})),
    ("a nested key", lambda f, text: f.update(extra={"deep" + text: 1})),
    ("a private key", lambda f, text: f.update({"_k" + text: "v"})),
    ("an X0X candidate's title", lambda f, text: f.update(code="COD-X0X", domain="COD",
                                                          title=f["title"] + " " + text)),
    ("an X0X candidate's file", lambda f, text: (f.update(code="COD-X0X", domain="COD"),
                                                 f["location"].update(file="src/gap%s.py" % text))),
    ("an X0X candidate's description", lambda f, text: f.update(code="COD-X0X", domain="COD",
                                                                description="gap " + text)),
)

# The same for an advisor's verdict. The last four name no finding once planted, so only the door itself reads them.
VERDICT_PLACES = (
    ("reasoning", _put("reasoning", "because ")),
    ("model", _put("model", "m")),
    ("code", _put("code", "COD-A1A")),
    ("an explored member", lambda v, text: v.update(explored=["src/app.py", "x" + text])),
    ("a references member", lambda v, text: v.update(references=["ref " + text])),
    ("a citations member", lambda v, text: v.update(citations={"cwe": ["CWE-1" + text]})),
    ("a missing_evidence member", lambda v, text: v.update(verdict="NEEDS_MORE_INFO",
                                                           missing_evidence=["src/x%s.py" % text])),
    ("an evidence_scope.granted member", lambda v, text: v.update(evidence_scope={"granted": ["src/y%s.py" % text]})),
    ("a nested value", lambda v, text: v.update(extra={"deep": ["v " + text]})),
    ("a key", lambda v, text: v.update({"key" + text: "v"})),
    ("a private key", lambda v, text: v.update({"_k" + text: "v"})),
    ("stage, which an advisor may not set", _put("stage", "backup")),
)
UNBOUND_VERDICT_PLACES = (
    ("finding_id", lambda v, text: v.update(finding_id=v["finding_id"] + text)),
    ("run_id", _put("run_id", RUN_ID)),
    ("verdict", _put("verdict", "CONFIRMED")),
    ("confidence", _put("confidence", "LIKELY")),
)


def planted(text):
    """One finding for each of PLACES, `text` in that place and nowhere else."""
    made = []
    for n, (_, plant) in enumerate(PLACES, 1):
        made.append(a_finding(n))
        plant(made[-1], text)
    return made


def a_verdict(finding_id, plant=None, text=""):
    made = {"finding_id": finding_id, "verdict": "CONFIRMED", "confidence": "LIKELY", "reasoning": "because",
            "explored": ["src/app.py"], "references": [], "citations": {}}
    if plant:
        plant(made, text)
    return made


def loaded(findings):
    """`findings` as the synthesize loader reads them from a cell's file -- ids assigned, the input untouched."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "findings-app-COD.json")
        with open(path, "w") as fh:
            json.dump({"findings": findings}, fh)
        with contextlib.redirect_stderr(io.StringIO()):
            return findings_mod.load_findings_detailed([path])[0]


class TestTheSpelling(unittest.TestCase):
    """`inert.escape_surrogates` and the set: the whole block, the policy's one spelling, nothing else."""

    BLOCK = range(0xD800, 0xE000)

    def test_every_surrogate_is_spelled_as_the_policy_spells_a_code_point(self):
        wrong = [hex(point) for point in self.BLOCK
                 if {inert.escape_surrogates("a%cb" % point), base.inert_escape("a%cb" % point),
                     runio._prompt_safe("a%cb" % point)} != {"a\\u%04xb" % point}]
        self.assertEqual([], wrong)

    def test_the_set_holds_the_block_and_the_helper_reads_the_same_range(self):
        self.assertEqual(self.BLOCK, inert.SURROGATES)
        self.assertEqual(set(self.BLOCK),
                         {point for point in inert.INERT_ESCAPE_CODE_POINTS if 0xD000 <= point < 0xF000})

    def test_nothing_but_a_surrogate_moves(self):
        rest = "".join(map(chr, itertools.chain(range(0xD800), range(0xE000, sys.maxunicode + 1))))
        self.assertEqual(rest, inert.escape_surrogates(rest))

    def test_a_pair_is_one_character_and_two_halves_apart_are_two_surrogates(self):
        pair = json.loads('"\\ud83d\\ude00"')                # `json.load` joins the pair: U+1F600, no surrogate
        self.assertEqual(("\U0001f600", "\U0001f600"), (pair, inert.escape_surrogates(pair)))
        for halves in ('"\\ud83d x \\ude00"', '"\\ude00\\ud83d"'):
            with self.subTest(halves=halves):
                self.assertEqual(halves[1:-1], inert.escape_surrogates(json.loads(halves)))

    def test_every_mode_of_the_one_neutralizer_spells_it(self):
        for mode in base.INERT_MODES:
            with self.subTest(mode=mode):
                self.assertEqual("src/a%s b.py" % SPELLED, base.inert_text("src/a%s b.py" % LONE, mode=mode))

    def test_a_path_in_a_reviewers_prompt_is_spelled_and_the_entrys_own_files_are_not(self):
        # A name that never was JSON: on Linux `os.walk` hands an undecodable byte over as a lone surrogate.
        name = "src/caf\udce9.py"
        line = runio._abs_file_list("/review", [name])
        self.assertEqual("- /review/src/caf\\udce9.py", line)
        line.encode("utf-8")
        self.assertEqual(["/review/" + name], runio._abs_files("/review", [name]))    # the read guard's bytes


class TestTheWalk(unittest.TestCase):
    """`inert.surrogate_free`: every string of a document, and a document holding none comes back itself."""

    def test_a_document_holding_none_comes_back_itself(self):
        for document in ({"a": ["b", {"c": "tab\t ESC\x1b bidi‮ astral\U0001f600"}], "n": 1, "z": None},
                         ["x", ["y"]], "text", 7, 2.5, True, None, {}, []):
            with self.subTest(document=repr(document)[:40]):
                self.assertIs(document, inert.surrogate_free(document))

    def test_every_string_at_every_depth_is_spelled_and_the_original_is_untouched(self):
        def document(text):
            return {"key" + text: "v", "value": "v" + text, "list": ["m" + text, ["deeper" + text, 3]],
                    "nested": {"k" + text: {"v": text}}, "other": [1, None, True, 2.5, "plain"]}

        original = document(LONE)
        clean = inert.surrogate_free(original)
        self.assertEqual(document(SPELLED), clean)
        self.assertEqual(list(document(SPELLED)), list(clean))          # and in the order they were written
        self.assertEqual(document(LONE), original)
        self.assertEqual("a" + SPELLED, inert.surrogate_free("a" + LONE))

    def test_two_keys_that_spell_alike_keep_the_later_value(self):
        self.assertEqual({"k" + SPELLED: 2}, inert.surrogate_free({"k" + LONE: 1, "k" + SPELLED: 2}))

    def test_a_nesting_deeper_than_the_stack_is_walked(self):
        depth = 5 * sys.getrecursionlimit()
        document = bottom = []
        for _ in range(depth):
            bottom.append([])
            bottom = bottom[0]
        bottom.append("v" + LONE)
        clean = inert.surrogate_free(document)
        for _ in range(depth):
            clean = clean[0]
        self.assertEqual(["v" + SPELLED], clean)


class TestTheTwoDoors(unittest.TestCase):
    """`findings.agent_finding` and `evidence._agent_verdict`: the pass at each, and a clean payload read as main
    read it -- the same copy, the same nested objects."""

    def test_a_finding_holding_none_is_the_copy_main_made(self):
        raw = a_finding(1, references=["CWE-1"], description="tab\t newline\n ESC\x1b bidi‮ astral\U0001f600")
        before = copy.deepcopy(raw)
        clean = findings_mod.agent_finding(raw)
        self.assertEqual((before, before), (raw, clean))
        self.assertIsNot(raw, clean)
        for shared in ("location", "references"):                    # `dict(raw)`: nested values are not copied
            self.assertIs(raw[shared], clean[shared])

    def test_a_verdict_holding_none_is_read_as_main_read_it(self):
        raw = a_verdict("COD-123", lambda v, text: v.update(
            explored=["a.py"], citations={"cwe": ["CWE-1"]}, missing_evidence=["b.py"], extra={"k": ["v"]},
            reasoning="tab\t ESC\x1b bidi‮ astral\U0001f600"))
        before = copy.deepcopy(raw)
        clean = evidence._agent_verdict(raw)
        self.assertEqual((before, before), (raw, clean))
        for shared in ("explored", "citations", "missing_evidence", "extra"):
            self.assertIs(raw[shared], clean[shared])

    def test_every_string_of_a_finding_is_spelled(self):
        for place, plant in PLACES:
            raw, twin = a_finding(1), a_finding(1)
            plant(raw, LONE)
            plant(twin, SPELLED)
            before = copy.deepcopy(raw)
            with self.subTest(place=place), contextlib.redirect_stderr(io.StringIO()):
                clean = findings_mod.agent_finding(raw)
                self.assertEqual(findings_mod.agent_finding(twin), clean)
                self.assertEqual([], surrogates(clean))
                self.assertEqual(before, raw)

    def test_every_string_of_a_verdict_is_spelled(self):
        for place, plant in VERDICT_PLACES + UNBOUND_VERDICT_PLACES:
            raw, twin = a_verdict("COD-123", plant, LONE), a_verdict("COD-123", plant, SPELLED)
            before = copy.deepcopy(raw)
            with self.subTest(place=place), contextlib.redirect_stderr(io.StringIO()):
                clean = evidence._agent_verdict(raw)
                self.assertEqual(evidence._agent_verdict(twin), clean)
                self.assertEqual([], surrogates(clean))
                self.assertEqual(before, raw)

    def test_the_stripped_key_diagnostics_name_the_id_as_it_is_spelled(self):
        raw = a_finding(1, id="CD-001" + LONE, evidence={"status": "x"}, provenance={"confirmed_by": "me"})
        with contextlib.redirect_stderr(io.StringIO()) as said:
            findings_mod.agent_finding(raw, "cell.json")
        self.assertEqual(2, said.getvalue().count("from CD-001%s in cell.json" % SPELLED), said.getvalue())
        self.assertEqual([], surrogates(said.getvalue()))

    def test_both_loaders_give_a_planted_finding_the_id_of_its_spelled_twin(self):
        # The driver's `_load_cell_findings` and synthesize's `load_findings_detailed` derive the id separately,
        # and an advisor's verdict binds only if they agree (#1109).
        manifest = {"run_id": RUN_ID}
        for place, plant in PLACES:
            with self.subTest(place=place), tempfile.TemporaryDirectory() as root, \
                    contextlib.redirect_stderr(io.StringIO()):
                read = []
                for text in (LONE, SPELLED):
                    finding = a_finding(1)
                    plant(finding, text)
                    runio._write_json(runio._pano(root, "findings-app-COD.json"), {
                        "findings": [finding],
                        "_panopticon": {"run_id": RUN_ID, "role": "domain_panel", "domain": "COD", "group": "app"}})
                    path = runio._pano(root, "findings-app-COD.json")
                    ours = findings_mod.load_findings_detailed([path])
                    theirs = review._load_cell_findings(root, manifest, "app", "COD")
                    self.assertEqual(([{**found, "_group": "app"} for found in theirs], []), ours)
                    self.assertEqual(1, len(theirs))
                    read.append(theirs)
                self.assertEqual(read[0], read[1])
                self.assertEqual([], surrogates(read[0]))
                json.dumps(read[0], ensure_ascii=False).encode("utf-8")


def sarif(text=""):
    return {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": [{
        "id": "sqli" + text, "properties": {"tags": ["CWE-89"]}}]}},
        "results": [{"ruleId": "sqli" + text, "level": "error", "message": {"text": "SQL injection " + text},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app%s.py" % text},
                                                         "region": {"startLine": 3}}}]}]}]}


def dependency_check(text=""):
    return {"dependencies": [{
        "fileName": "commons%s-fileupload-1.4.jar" % text,
        "includedBy": [{"reference": "org.owasp%s:webgoat:2023.4" % text}],
        "vulnerabilities": [{"name": "CVE-2023-24998" + text, "severity": "MEDIUM", "cwes": ["CWE-770"],
                             "description": "Apache Commons FileUpload DoS " + text}]}]}


class TestAScannersOutput(unittest.TestCase):
    """The door for tool-authored text: what an adapter parses holds no lone surrogate, whichever field it reads."""

    def test_parse_json_bytes_hands_none_over_and_reads_a_clean_output_as_it_did(self):
        planted_output = json.dumps({"k" + LONE: ["v" + LONE, {"n": LONE}]}).encode()
        self.assertEqual({"k" + SPELLED: ["v" + SPELLED, {"n": SPELLED}]}, base.parse_json_bytes(planted_output))
        clean = b'\x1b[2Kbanner\n{"a": ["b\\u001b", "\\ud83d\\ude00"], "n": 1.5}'
        self.assertEqual({"a": ["b\x1b", "\U0001f600"], "n": 1.5}, base.parse_json_bytes(clean))

    def test_a_clean_output_is_the_object_the_parser_made_at_both_parses(self):
        made = {"runs": []}
        with mock.patch.object(base.json, "loads", return_value=made):
            self.assertIs(made, base.parse_json_bytes(b"{}"))
            with mock.patch.object(legacy_sarif.su, "sarif_to_findings") as converted:
                legacy_sarif.LegacySarifAdapter("semgrep").parse(b"{}", "app")
        self.assertIs(made, converted.call_args.args[0])

    def test_a_planted_scan_is_ingested_as_its_spelled_twin_and_can_be_fingerprinted(self):
        def ingested(text):
            with tempfile.TemporaryDirectory() as tools, contextlib.redirect_stderr(io.StringIO()):
                for name, output in (("semgrep.sarif", sarif(text)), ("dependency-check.json", dependency_check(text))):
                    with open(os.path.join(tools, name), "w") as fh:
                        json.dump(output, fh)
                return ingest_tools.ingest_dir(tools, "app")

        found = ingested(LONE)
        self.assertEqual(ingested(SPELLED), found)
        self.assertEqual(["tool:dependency-check", "tool:semgrep"], sorted(f["source"] for f in found))
        self.assertEqual([], surrogates(found))
        for finding in found:
            evidence.finding_fingerprint(finding)           # main raised here: the hash encodes its key

    def test_no_adapter_reads_json_past_the_door(self):
        # Structural: an adapter that calls `json.loads` on a scanner's output bare reopens the hole for its tool.
        # `egress.py` reads `docker network inspect`, which no target writes.
        bare = []
        for path in sorted(Path(SCRIPTS, "tools").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            wrapped = {id(call.args[0]) for call in ast.walk(tree)
                       if isinstance(call, ast.Call) and getattr(call.func, "id", "") == "surrogate_free"
                       and call.args}
            bare += ["%s:%d" % (path.name, call.lineno) for call in ast.walk(tree)
                     if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                     and call.func.attr in ("loads", "load") and getattr(call.func.value, "id", "") == "json"
                     and id(call) not in wrapped and path.name != "egress.py"]
        self.assertEqual([], bare)


class TestTheBackstop(unittest.TestCase):
    """`build_report` hands no lone surrogate to a writer, whatever fed it: over the richest run directory the suite
    builds (the schema-parity fixture), each run artifact in turn with a lone surrogate in EVERY value of it, then in
    every key of one depth of it (a file whose top-level keys are all renamed is not read at all).

    The findings files, the verdict bundle and the queue are left to their own doors' pins; this walks the rest --
    the files the CONTROLLER writes (groups, coverage, host capabilities, the tools manifest, the inventory, the
    hunk map) and the two scanner outputs. A named limit: this is coarser than one string at a time, since a value
    planted beside it can change how a string is read; that sweep (1,031 strings) is in the PR, not in the suite,
    for its price."""

    THEIR_OWN_PINS = ("agent-findings.json", "findings-app-SEC.json", "verdicts-app-SEC.json", "verify-queue.json")

    def test_a_report_holding_none_is_the_object_assemble_made_and_one_holding_any_is_its_spelled_copy(self):
        stages = dict.fromkeys(("verdicts_mod", "tool_axis_mod", "grading_mod", "cost_mod"), mock.DEFAULT)
        for assembled, spelled in (({"meta": {"target": "plain"}, "findings": []}, None),
                                   ({"meta": {"target": "x" + LONE}}, {"meta": {"target": "x" + SPELLED}})):
            with self.subTest(assembled=repr(assembled)[:40]), mock.patch.multiple(
                    report_mod, assemble=mock.Mock(return_value=assembled), **stages):
                built = report_mod.build_report(mock.MagicMock())
                if spelled is None:
                    self.assertIs(assembled, built)
                else:
                    self.assertEqual((spelled, {"meta": {"target": "x" + LONE}}), (built, assembled))

    def test_a_run_artifact_planted_whole_reaches_no_writer(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            real = syn.main
            with mock.patch.object(syn, "main", lambda argv: calls.append(list(argv)) or real(argv)):
                out, _ = parity._build_report(tmp)
            argv, out_dir = calls[-1], os.path.dirname(out)
            walked = []
            for path in sorted(Path(tmp).rglob("*")):
                if not path.is_file() or out_dir in str(path) or path.name in self.THEIR_OWN_PINS:
                    continue
                original = path.read_bytes()
                try:
                    document = json.loads(original)
                except ValueError:
                    continue
                for depth in range(_depth(document) + 1):
                    what = "the keys at depth %d" % depth if depth else "every value"
                    made = _planted(document, depth)
                    if made == document:
                        continue
                    walked.append(path.name)
                    path.write_text(json.dumps(made), encoding="utf-8")
                    with self.subTest(file=path.name, planted=what):
                        self.assertEqual("", self.final_pass(tmp, argv, out_dir))
                    path.write_bytes(original)
        self.assertLessEqual({"groups.json", "host-capabilities.json", "tools-manifest.json", "bandit.sarif",
                              "dependency-check.json"}, set(walked))      # not vacuous: the fixture's files

    def final_pass(self, tmp, argv, out_dir):
        """What went wrong when the final `synthesize.main` pass ran, or "" -- an exception out of it, a surrogate
        left in an artifact, or one on the stdout a child would have to encode."""
        for name in os.listdir(out_dir):
            os.remove(os.path.join(out_dir, name))
        real, previous, said = render_mod.write_report, os.getcwd(), io.StringIO()
        os.chdir(tmp)
        try:
            with mock.patch.object(render_mod, "write_report", lambda report, path, max_bytes=parity.SPLIT_BYTES:
                                   real(report, path, max_bytes=max_bytes)), \
                    contextlib.redirect_stdout(said), contextlib.redirect_stderr(io.StringIO()):
                syn.main(list(argv))
        except Exception as error:      # noqa: BLE001 -- the outcome under test
            return "%s out of synthesize.main" % type(error).__name__
        finally:
            os.chdir(previous)
        for name in sorted(os.listdir(out_dir)):
            text = Path(out_dir, name).read_text(encoding="utf-8")
            if name.endswith(".json") and surrogates(json.loads(text)):
                return "a surrogate left in %s" % name
        return "a surrogate on stdout" if surrogates(said.getvalue()) else ""


def _depth(node):
    """How many objects deep `node` nests (lists are not a level)."""
    inner = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
    return isinstance(node, dict) + max(map(_depth, inner), default=0)


def _planted(node, depth, at=1):
    """`node` with a lone surrogate appended to every string VALUE of it (`depth` 0), or to every key of the
    objects `depth` levels down and to nothing else."""
    if isinstance(node, dict):
        return {key + LONE if at == depth else key: _planted(value, depth, at + 1) for key, value in node.items()}
    if isinstance(node, list):
        return [_planted(value, depth, at) for value in node]
    return node + LONE if isinstance(node, str) and not depth else node


class TestTheRealChild(unittest.TestCase):
    """Through `synthesize.py` as the driver runs it: a child process, a findings file whose JSON holds the escape,
    and the artifacts on disk. A run on the lone surrogate must write what a run on its spelled twin writes."""

    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.base.cleanup)
        cls.runs = itertools.count(1)
        found = subprocess.run([sys.executable, os.path.join(SCRIPTS, "discovery.py"), "--repo-scan", cls.repo()],
                               capture_output=True, text=True, timeout=SCRIPT_TIMEOUT)
        assert found.returncode == 0, found.stderr
        cls.groups = json.loads(found.stdout)
        cls.group = first(cls.groups["groups"], "group")["name"]

    @classmethod
    def repo(cls):
        """A fresh copy of the one-file target, so no run reads what another left."""
        made = os.path.join(cls.base.name, "repo-%d" % next(cls.runs))
        os.makedirs(os.path.join(made, "src"))
        with open(os.path.join(made, "src", "app.py"), "w") as fh:
            fh.write("x = 1\n" * 100)
        return made

    def child(self, *flags, findings=None, verdicts=None, scans=None, groups=None):
        """One run, laid out as tests/test_e2e.py lays it out: (status, stderr, {artifact name: bytes})."""
        repo = self.repo()
        pano = os.path.join(repo, ".panopticon")

        def write(path, document):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                json.dump(document, fh)            # ensure_ascii: the file holds `\ud800`, as an agent's does
            return path

        argv = [sys.executable, os.path.join(SCRIPTS, "synthesize.py"), "--target", ".", "--run-id", RUN_ID,
                "--groups", write(os.path.join(repo, "groups.json"), groups or self.groups), *flags]
        if verdicts is not None:
            write(os.path.join(pano, "verdicts", "verdicts-%s-COD.json" % self.group), {
                "verdicts": verdicts, "_panopticon": {"run_id": RUN_ID, "role": "domain_advisor", "domain": "COD",
                                                      "group": self.group, "stage": "primary"}})
            argv += ["--verdicts-dir", os.path.join(pano, "verdicts")]
        for name, output in (scans or {}).items():
            write(os.path.join(pano, "tools", name), output)
        if scans:
            argv += ["--tools-dir", os.path.join(pano, "tools")]
        argv += ["--out", os.path.join(pano, "report.json")]
        if findings is not None:
            argv.append(write(os.path.join(pano, "findings-%s-COD.json" % self.group), {"findings": findings}))
        done = subprocess.run(argv, capture_output=True, cwd=repo, timeout=SCRIPT_TIMEOUT)
        found = sorted(Path(pano).glob("report*")) + [path for path in [Path(repo, "verify-queue.json")]
                                                      if path.exists()]
        # A report names the file a cross-domain row came from, so the run's own directory is in it.
        artifacts = {path.name: path.read_bytes().replace(os.path.realpath(repo).encode(), b"<repo>")
                     .replace(repo.encode(), b"<repo>") for path in found}
        return done.returncode, done.stderr.decode("utf-8", "backslashreplace"), artifacts

    def whole(self, run):
        """The run ended as its GATE decided and every artifact is text. Returns the report."""
        status, stderr, artifacts = run
        self.assertNotIn("Traceback", stderr)
        self.assertLessEqual({"report.json", "report-x0x.json", "report.json.html"}, set(artifacts), stderr)
        report = json.loads(artifacts["report.json"].decode("utf-8"))
        self.assertEqual({"FAIL": 1, "INCONCLUSIVE": 2}.get(report["summary"]["gate"], 0), status, stderr)
        for name, written in artifacts.items():
            text = written.decode("utf-8")              # strict: a file that is not UTF-8 raises here
            self.assertTrue(text.strip(), name)         # main left the page EMPTY where its writer raised
            if name.endswith(".json"):
                self.assertEqual([], surrogates(json.loads(text)), name)
        return report

    def same(self, run, twin):
        """`run` wrote, byte for byte, what `twin` wrote -- the moment and the directory of the run apart."""
        def undated(artifacts):
            when = json.loads(artifacts["report.json"])["meta"]["timestamp"].encode()
            return {name: written.replace(when, b"<when>") for name, written in artifacts.items()}

        self.assertEqual(twin[0], run[0])
        ours, theirs = undated(run[2]), undated(twin[2])
        self.assertEqual(sorted(theirs), sorted(ours))
        for name in ours:
            self.assertTrue(ours[name] == theirs[name], "%s differs from the spelled twin's" % name)

    def test_each_row_of_the_issue_alone(self):
        rows = (("a located finding's title", "title"), ("a located finding's location.file", "location.file"),
                ("a locus-free finding's title", "title, locus-free"), ("a finding's description only", "description"))
        control = self.child(findings=[a_finding(1)])
        self.assertEqual((0, 1), (control[0], len(self.whole(control)["findings"])))
        for row, place in rows:
            with self.subTest(row=row):
                finding = a_finding(1)
                dict(PLACES)[place](finding, LONE)
                run = self.child(findings=[finding])
                report = self.whole(run)
                self.assertEqual((0, 1), (run[0], len(report["findings"])), run[1])
                self.assertEqual(sorted(control[2]), sorted(run[2]))
                self.assertIn(SPELLED, "".join(strings(report["findings"])))        # the text stays visible
                self.assertIn(SPELLED.encode(), run[2]["report.json.html"])

    def test_every_place_of_a_finding_at_once_under_a_gate_that_fails_for_its_own_reason(self):
        flags = ("--gate-unverified", "--fail-on", "medium")
        run = self.child(*flags, findings=planted(LONE))
        report = self.whole(run)
        self.assertEqual(("FAIL", 1), (report["summary"]["gate"], run[0]))       # the gate's FAIL, with a report
        self.assertEqual(len(PLACES), len(report["findings"]))
        self.same(run, self.child(*flags, findings=planted(SPELLED)))

    def test_every_place_of_a_verdict_at_once(self):
        findings = [a_finding(n, code="COD-A1A", domain="COD") for n in range(1, len(VERDICT_PLACES) + 1)]
        ids = [found["id"] for found in loaded(findings)]
        self.assertEqual(len(findings), len(set(ids)))

        def bundle(text):
            return [a_verdict(fid, plant, text) for fid, (_, plant) in zip(ids, VERDICT_PLACES)]

        run = self.child(findings=findings, verdicts=bundle(LONE))
        report = self.whole(run)
        statuses = [found["evidence"]["status"] for found in report["findings"]]
        self.assertEqual(len(VERDICT_PLACES), len(statuses))
        self.assertNotIn("unverified", statuses)                # every verdict bound: the door was walked
        self.same(run, self.child(findings=findings, verdicts=bundle(SPELLED)))

    def test_a_scanners_output(self):
        def scans(text):
            return {"semgrep.sarif": sarif(text), "dependency-check.json": dependency_check(text)}

        run = self.child(findings=[a_finding(1)], scans=scans(LONE))
        report = self.whole(run)
        self.assertEqual(["agent", "tool:dependency-check", "tool:semgrep"],
                         sorted(found.get("source", "agent").split("/")[0] for found in report["findings"]))
        self.same(run, self.child(findings=[a_finding(1)], scans=scans(SPELLED)))

    def test_a_name_from_the_targets_tree(self):
        # Not an agent's text and never hashed: a group and its file, as discovery names them from the tree. Only
        # the backstop stands between this name and the page's writer.
        def groups(text):
            extra = {"name": "extra" + text, "files": ["src/b%s.py" % text], "panels": ["code"],
                     "parent": "extra" + text, "chunk_of": "."}
            return dict(self.groups, groups=self.groups["groups"] + [extra])

        run = self.child(findings=[a_finding(1)], groups=groups(LONE))
        self.assertIn("extra" + SPELLED, "".join(strings(self.whole(run))))
        self.same(run, self.child(findings=[a_finding(1)], groups=groups(SPELLED)))

    def test_the_queue_pass_writes_a_queue_without_one(self):
        run = self.child("--emit-verify-queue", findings=planted(LONE))
        self.assertEqual((0, ["verify-queue.json"]), (run[0], sorted(run[2])), run[1])
        queue = json.loads(run[2]["verify-queue.json"].decode("utf-8"))
        self.assertEqual([], surrogates(queue))
        twin = json.loads(self.child("--emit-verify-queue", findings=planted(SPELLED))[2]["verify-queue.json"])
        self.assertNotEqual(twin.pop("run_id"), queue.pop("run_id"))        # the queue's own, drawn per run
        self.assertEqual(twin, queue)

    def test_a_report_large_enough_to_split_writes_parts_without_one(self):
        big = [a_finding(n, title="big %d %s" % (n, LONE), description=("a line of text %s\n" % LONE) * 5000)
               for n in range(1, 13)]
        run = self.child(findings=big)
        report = self.whole(run)
        parts = [name for name in run[2] if "_part" in name]
        self.assertEqual(sorted(report["meta"]["parts"]), sorted(parts))
        self.assertTrue(parts)
        split = report["findings"] + [found for name in parts for found in json.loads(run[2][name])["findings"]]
        self.assertEqual(12, len(split))


if __name__ == "__main__":
    unittest.main()
