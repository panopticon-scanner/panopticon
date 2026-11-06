"""#3241: strict provider projections stay narrower than receipt schemas."""
import copy
import json
import os
import re
from pathlib import Path

import jsonschema

import scripts.phases.persist as persist
from tests.strict_output_schema import strict_output_schema


ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "skill" / "reference"
AGENTS = ROOT / "skill" / "agents"
GENERATION_NAMES = {
    "review": "review-cell-generation-schema.json",
    "primary": "verify-primary-generation-schema.json",
    "backup": "verify-backup-generation-schema.json",
    "tool": "tool-advisor-generation-schema.json",
}

VERSION = "schema_version"
# #3482: which output examples ask for `"schema_version": 1`, as their first
# key. Each row is its own ruling, so each flips, and reverts, alone; the
# key-set parity below compares every OTHER root key.
VERSION_ASKED_BY_PROMPT = {
    "domain-advisor.md": True,    # #3482 P1
    "domain-panel.md": True,      # #2104
    "advisor.md": True,           # #3482 P2
}
# ...and which Codex generation projections REQUIRE it, as `const: 1`.
VERSION_REQUIRED_BY_SCHEMA = {
    "review": True,               # #2104
    "primary": False,             # #3482 P4
    "backup": False,              # #3482 P4
    "tool": False,                # #3482 P4
}


def _load(name):
    with open(REFERENCE / name, encoding="utf-8") as stream:
        return json.load(stream)


def _entry(name, stage=None):
    if name == "review":
        out_file = "/r/.panopticon/runs/t/findings-app-COD.json"
    elif name == "tool":
        out_file = "/r/.panopticon/runs/t/verdicts/q-0001.json"
    else:
        out_file = "/r/.panopticon/runs/t/verdicts/verdicts-app-COD.json"
    entry = {"out_file": out_file}
    if stage is not None:
        entry["stage"] = stage
    return entry


def _resolve(schema, node):
    if set(node) == {"$ref"}:
        return schema["$defs"][node["$ref"].removeprefix("#/$defs/")]
    return node


def _item_variants(schema):
    item = schema["properties"][next(
        name for name in ("findings", "verdicts") if name in schema["properties"]
    )]["items"]
    nodes = item.get("anyOf", [item])
    return [_resolve(schema, node) for node in nodes]


def _property_union(schema):
    return set().union(*(set(node["properties"]) for node in _item_variants(schema)))


def test_each_production_shape_selects_its_generation_projection():
    cases = (
        (_entry("review"), GENERATION_NAMES["review"]),
        (_entry("primary"), GENERATION_NAMES["primary"]),
        (_entry("primary", "primary"), GENERATION_NAMES["primary"]),
        (_entry("backup", "backup"), GENERATION_NAMES["backup"]),
        (_entry("tool"), GENERATION_NAMES["tool"]),
    )
    for entry, expected in cases:
        selected = persist.generation_schema(entry)
        assert os.path.basename(selected) == expected
        assert selected == os.path.abspath(selected)


def test_an_unknown_verify_stage_omits_generation_constraint():
    assert persist.generation_schema(_entry("primary", "future")) is None


def test_all_generation_projections_pass_the_provider_screen():
    for name in GENERATION_NAMES.values():
        path = os.path.realpath(REFERENCE / name)
        assert strict_output_schema(path) == path, name


def test_the_review_projection_is_exhaustive_and_below_the_approved_budget():
    path = REFERENCE / GENERATION_NAMES["review"]
    schema = _load(path.name)
    # Six independently omitted top-level groups: location, severity override,
    # category, exploit scenario, citations, and CVSS. Nested shape choices use
    # strict anyOf, so omission itself is the 2**6 full-object matrix.
    assert len(_item_variants(schema)) == 64
    assert path.stat().st_size <= 64 * 1024


def test_each_probe_schema_matches_its_hosts_production_review_schema():
    paths = [REFERENCE / name for name in GENERATION_NAMES.values()]
    largest = max(paths, key=lambda path: path.stat().st_size)
    assert largest.name == GENERATION_NAMES["review"]
    assert persist.production_probe_schema("codex") == os.path.realpath(largest)
    assert persist.production_probe_schema("claude") == persist.role_schema(_entry("review"))


def test_projection_fields_are_the_fields_the_three_prompts_request():
    panel = (AGENTS / "domain-panel.md").read_text(encoding="utf-8")
    panel_block = panel.split("## Finding format", 1)[1].split("## Output", 1)[0]
    panel_fields = set(re.findall(r"`([a-z][a-z0-9_]*)(?=[:`])", panel_block))
    panel_fields -= {"file", "line_start", "line_end", "null", "permitted"}
    review = _load(GENERATION_NAMES["review"])
    assert _property_union(review) == panel_fields
    panel_output = panel.split("## Output", 1)[1].split("Write ONLY", 1)[0]
    panel_root = set(re.findall(r'^\s*"([a-z_]+)"\s*:', panel_output, re.M))
    panel_all = set(re.findall(r'"([a-z_]+)"\s*:', panel_output))
    assert set(review["properties"]) == panel_root
    review_stamp = _resolve(review, review["properties"]["_panopticon"])
    assert set(review_stamp["properties"]) == panel_all - panel_root

    advisor = (AGENTS / "domain-advisor.md").read_text(encoding="utf-8")
    verdict_block = advisor.split("Each verdict is one object per claim:", 1)[1]
    verdict_block = verdict_block.split("`evidence_scope` and", 1)[0]
    verdict_fields = set(re.findall(r'^\s{4,}"([a-z_]+)"\s*:', verdict_block, re.M))
    primary = _load(GENERATION_NAMES["primary"])
    backup = _load(GENERATION_NAMES["backup"])
    assert _property_union(primary) == verdict_fields - {"evidence_scope", "missing_evidence"}
    assert _property_union(backup) == verdict_fields
    advisor_output = advisor.split("## Output", 1)[1].split("Write ONLY", 1)[0]
    advisor_root = set(re.findall(r'^\s*"([a-z_]+)"\s*:', advisor_output, re.M))
    advisor_all = set(re.findall(r'"([a-z_]+)"\s*:', advisor_output))
    for schema in (primary, backup):
        # `schema_version` is pinned per side, below (#3482).
        assert set(schema["properties"]) - {VERSION} == advisor_root - {VERSION}
        stamp = _resolve(schema, schema["properties"]["_panopticon"])
        assert set(stamp["properties"]) == advisor_all - advisor_root
        assert "stamped_by" not in stamp["properties"]

    tool_prompt = (AGENTS / "advisor.md").read_text(encoding="utf-8")
    tool_example = tool_prompt.split("```json", 1)[1].split("```", 1)[0]
    tool_fields = set(re.findall(r'^\s*"([a-z_]+)"\s*:', tool_example, re.M))
    tool = _load(GENERATION_NAMES["tool"])
    assert set(tool["properties"]) - {VERSION} == tool_fields - {VERSION}


def _review_reply(enriched=False):
    finding = {
        "domain": "COD", "code": "COD-X0X", "severity": "LOW",
        "title": "t", "description": "d", "source_role": "domain_panel",
    }
    if enriched:
        finding.update({
            "severity_override": {
                "from": "MEDIUM", "to": "LOW", "reason": "dev-or-ci-tooling: fixture",
                "rung": "lower_when[0]",
            },
            "category": "prompt-injection",
            "location": {"file": "app.py", "line_start": 1, "line_end": 2},
            "exploit_scenario": "input reaches impact",
            "citations": {"cwe": ["CWE-20"]},
            "cvss": {"score": 3.1, "vector": "CVSS:3.1/AV:L"},
        })
    return {
        "schema_version": 1,
        "findings": [finding],
        "_panopticon": {
            "run_id": "RID", "role": "domain_panel", "domain": "COD", "group": "app",
        },
    }


def _verdict(backup=False, missing=False):
    verdict = {
        "finding_id": "COD-001", "verdict": "CONFIRMED", "confidence": "CERTAIN",
        "code": "COD-X0X", "reasoning": "r", "explored": ["app.py"],
        "references": ["app.py:1"], "citations": {"cwe": [], "owasp": [], "cve": []},
    }
    if backup:
        verdict["evidence_scope"] = {
            "granted": ["app.py"], "cap": 12, "truncated": False,
            "entry_cap": 48, "entry_truncated": False, "floor_count": 1,
        }
        if missing:
            verdict["missing_evidence"] = ["caller.py"]
    return verdict


def _as_required(name, reply):
    """`reply` led by `schema_version: 1` exactly when its projection requires it."""
    return {VERSION: 1, **reply} if VERSION_REQUIRED_BY_SCHEMA[name] else reply


def _verify_reply(stage="primary", missing=False):
    return _as_required(stage, {
        "verdicts": [_verdict(stage == "backup", missing)],
        "_panopticon": {
            "run_id": "RID", "role": "domain_advisor", "domain": "COD",
            "group": "app", "stage": stage,
        },
    })


def _tool_reply(missing=()):
    verdict = _verdict()
    verdict.pop("code")
    verdict["missing_evidence"] = list(missing)
    if missing:
        verdict["verdict"] = "NEEDS_MORE_INFO"
    return _as_required("tool", verdict)


def test_constrained_examples_pass_unchanged_receipt_contracts_after_stamping():
    cases = (
        (_entry("review"), GENERATION_NAMES["review"], "findings-envelope-schema.json",
         _review_reply(False)),
        (_entry("review"), GENERATION_NAMES["review"], "findings-envelope-schema.json",
         _review_reply(True)),
        (_entry("primary", "primary"), GENERATION_NAMES["primary"],
         "verdict-bundle-schema.json", _verify_reply("primary")),
        (_entry("backup", "backup"), GENERATION_NAMES["backup"],
         "verdict-bundle-schema.json", _verify_reply("backup", False)),
        (_entry("backup", "backup"), GENERATION_NAMES["backup"],
         "verdict-bundle-schema.json", _verify_reply("backup", True)),
        (_entry("tool"), GENERATION_NAMES["tool"], "advisor-verdict-schema.json",
         _tool_reply()),
        (_entry("tool"), GENERATION_NAMES["tool"], "advisor-verdict-schema.json",
         _tool_reply(["caller.py"])),
    )
    for entry, generation_name, receipt_name, reply in cases:
        jsonschema.validate(reply, _load(generation_name))
        stamped = persist._controller_stamp(entry, copy.deepcopy(reply))
        jsonschema.validate(stamped, _load(receipt_name))


def _output_example(prompt_file):
    """(root keys in order, example text) of a role's output example."""
    text = (AGENTS / prompt_file).read_text(encoding="utf-8")
    if prompt_file == "advisor.md":
        example = text.split("```json", 1)[1].split("```", 1)[0]
    else:
        example = text.split("## Output", 1)[1].split("Write ONLY", 1)[0]
    return re.findall(r'^\s*"([a-z_]+)"\s*:', example, re.M), example


def test_each_output_example_asks_for_the_version_as_pinned():
    # #3482 P1/P2: a row that asks puts `"schema_version": 1` first, as the panel does.
    for prompt_file, asked in VERSION_ASKED_BY_PROMPT.items():
        keys, example = _output_example(prompt_file)
        assert (VERSION in keys) == asked, prompt_file
        if asked:
            assert keys[0] == VERSION, prompt_file
            assert re.search(r'^\s*"schema_version": 1,$', example, re.M), prompt_file


def test_each_codex_projection_requires_the_version_as_pinned():
    # #3482 P4. A row that requires the version rejects a reply without it and
    # one with `2`, and accepts `1`. A row that does not is closed, so it
    # rejects the key outright.
    unversioned = {
        "review": {k: v for k, v in _review_reply().items() if k != VERSION},
        "primary": {k: v for k, v in _verify_reply("primary").items() if k != VERSION},
        "backup": {k: v for k, v in _verify_reply("backup", True).items() if k != VERSION},
        "tool": {k: v for k, v in _tool_reply(["caller.py"]).items() if k != VERSION},
    }
    for name, required in VERSION_REQUIRED_BY_SCHEMA.items():
        schema = _load(GENERATION_NAMES[name])
        validator = jsonschema.Draft7Validator(schema)
        bare = unversioned[name]
        if required:
            assert schema["properties"][VERSION] == {"type": "integer", "const": 1}, name
            assert list(schema["properties"])[0] == VERSION, name
            assert schema["required"][0] == VERSION, name
            assert validator.is_valid({VERSION: 1, **bare}), name
            assert not validator.is_valid(bare), name
            assert not validator.is_valid({VERSION: 2, **bare}), name
        else:
            assert VERSION not in schema["properties"], name
            assert validator.is_valid(bare), name
            assert not validator.is_valid({VERSION: 1, **bare}), name
