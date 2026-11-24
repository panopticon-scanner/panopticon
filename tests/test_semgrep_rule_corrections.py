import hashlib
import importlib.util
import json
from pathlib import Path
from collections import Counter

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
CORRECTIONS = ROOT / "tools-image" / "semgrep"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _write_manifest(path, entries):
    path.write_text(json.dumps({"schema_version": 1, "corrections": entries}))


def test_manifest_pins_the_five_proven_rule_files_and_bytes():
    manifest = json.loads((CORRECTIONS / "corrections.json").read_text())
    expected = {
        "python/lang/security/audit/insecure-file-permissions.yaml": (
            "33ce6040a85aa8a61e2bd005da9f9623c666eafd8afe31e4ada44d74d57b9bc2",
            "277117c47384f3d983aaac0ef7d654ebf5db67de24140bf0caf05a3bc8bd0c35",
        ),
        "python/lang/security/audit/dangerous-subprocess-use-audit.yaml": (
            "50f69dc35f47e405633559f54fc2b3bd344707221742400e74b1c902c1f76faa",
            "1dcab593d955a4a9177daa9dc56a31adbd35be18fc5c28e662bd7f0bd89e7a26",
        ),
        "yaml/github-actions/security/pull-request-target-code-checkout.yaml": (
            "64c8c419726b8ed1854c75de04b7e8fb944e86d54990b65a98bca9c216b65ceb",
            "08fdca91a5351917f36e6c2c0e1dd029e566063f41f272d14ec86176505d2e16",
        ),
        "python/lang/maintainability/return.yaml": (
            "d1b7a05811649bbeb6c570899ce46d5cdf46ed834441be4ab2a49a8fef16b5d3",
            "443934383c4f6543684350c98ac8a217eacb5a750f35249d9d211a7cff1e0793",
        ),
        "ai/ai-best-practices/hooks-path-traversal/hooks-path-traversal-python.yaml": (
            "41deee92decca0061b60bff9e4b1e65f6481581cdeac354004d43105e83e6474",
            "90492472215d2e59d7c391067b1bb152212a47dc7cd24dd2e11fe45e3fe0d5ef",
        ),
    }
    actual = {
        item["path"]: (item["source_sha256"], item["corrected_sha256"])
        for item in manifest["corrections"]
    }
    assert manifest["schema_version"] == 1
    assert actual == expected
    for item in manifest["corrections"]:
        replacement = CORRECTIONS / item["replacement"]
        assert _sha256(replacement.read_bytes()) == item["corrected_sha256"]


def test_replacements_keep_rule_ids_and_unrelated_return_rule():
    expected_ids = {
        "insecure-file-permissions.yaml": ["insecure-file-permissions"],
        "dangerous-subprocess-use-audit.yaml": ["dangerous-subprocess-use-audit"],
        "pull-request-target-code-checkout.yaml": ["pull-request-target-code-checkout"],
        "return.yaml": ["code-after-unconditional-return", "return-not-in-function"],
        "hooks-path-traversal-python.yaml": ["hooks-path-traversal-python"],
    }
    expected_envelope_hashes = {
        "insecure-file-permissions.yaml":
            "20a14e569e4aa27f88f676643f066026efa85880b03a1b753f74d7d32c89d5aa",
        "dangerous-subprocess-use-audit.yaml":
            "ca8e6a5a4024981cf6d97be829d28577fb1fd9b76039212665e3c3c371ca7e26",
        "pull-request-target-code-checkout.yaml":
            "fee45aba14805d5325673688f7b192d63cd96961dcd2e0aa1dd480260422f821",
        "return.yaml":
            "421815d3f18f5de10c44a50fa1969c35ecdc38aedb42587845293841a3d8d71a",
        "hooks-path-traversal-python.yaml":
            "eab40bfd38b4b61b15607195e020ff87fbe91474ac221f625d733bf7b6158e94",
    }
    for name, ids in expected_ids.items():
        parsed = yaml.safe_load((CORRECTIONS / "patches" / name).read_text())
        assert [rule["id"] for rule in parsed["rules"]] == ids
        envelope = [
            {
                key: rule[key]
                for key in ("id", "languages", "severity", "message", "metadata")
                if key in rule
            }
            for rule in parsed["rules"]
        ]
        serialized = json.dumps(
            envelope, sort_keys=True, separators=(",", ":")
        ).encode()
        assert _sha256(serialized) == expected_envelope_hashes[name]
    first_return_rule = yaml.safe_load(
        (CORRECTIONS / "patches" / "return.yaml").read_text()
    )["rules"][0]
    assert first_return_rule == {
        "id": "code-after-unconditional-return",
        "pattern": "return ...\n$S\n",
        "message": "code after return statement will not be executed",
        "languages": ["python"],
        "severity": "WARNING",
        "metadata": {"category": "maintainability", "technology": ["python"]},
    }


def test_hooks_path_traversal_pins_exact_sources_sinks_and_sanitizers():
    rule = yaml.safe_load(
        (CORRECTIONS / "patches" / "hooks-path-traversal-python.yaml").read_text()
    )["rules"][0]
    assert rule["pattern-sources"] == [
        {"pattern": "json.loads(...)", "exact": True},
        {"pattern": "json.load(...)", "exact": True},
    ]
    assert rule["pattern-sinks"] == [
        {"patterns": [
            {"pattern": pattern},
            {"focus-metavariable": "$SINK"},
        ]}
        for pattern in (
            "open($SINK, ...)",
            "os.remove($SINK)",
            "os.unlink($SINK)",
            "shutil.copy($SINK, ...)",
            "shutil.move($SINK, ...)",
            "pathlib.Path($SINK)",
        )
    ]
    assert rule["pattern-sanitizers"] == [
        {"pattern": "os.path.realpath(...)"},
        {"pattern": "os.path.abspath(...)"},
    ]


def test_permission_metavariable_patterns_have_no_single_child_wrapper():
    rule = yaml.safe_load(
        (CORRECTIONS / "patches" / "insecure-file-permissions.yaml").read_text()
    )["rules"][0]
    method = rule["patterns"][1]["metavariable-pattern"]
    bits = rule["patterns"][2]["pattern-either"][1]["patterns"][1][
        "metavariable-pattern"
    ]
    assert "patterns" not in method
    assert "pattern-either" in method
    assert "patterns" not in bits
    assert "pattern-either" in bits


def test_applicator_publishes_only_after_all_sources_validate(tmp_path):
    module = _load("apply_semgrep_corrections", CORRECTIONS / "apply_corrections.py")
    root = tmp_path / "rules"
    root.mkdir()
    first = root / "first.yaml"
    second = root / "second.yaml"
    first.write_bytes(b"first original\n")
    second.write_bytes(b"second drifted\n")
    patch_dir = tmp_path / "patches"
    patch_dir.mkdir()
    (patch_dir / "first.yaml").write_bytes(b"first corrected\n")
    (patch_dir / "second.yaml").write_bytes(b"second corrected\n")
    manifest = tmp_path / "corrections.json"
    _write_manifest(manifest, [
        {
            "path": "first.yaml",
            "source_sha256": _sha256(b"first original\n"),
            "replacement": "patches/first.yaml",
            "corrected_sha256": _sha256(b"first corrected\n"),
        },
        {
            "path": "second.yaml",
            "source_sha256": _sha256(b"second original\n"),
            "replacement": "patches/second.yaml",
            "corrected_sha256": _sha256(b"second corrected\n"),
        },
    ])

    with pytest.raises(module.CorrectionError, match="source drift"):
        module.apply_corrections(root, manifest)
    assert first.read_bytes() == b"first original\n"


def test_applicator_corrects_expected_source_and_rejects_second_apply(tmp_path):
    module = _load("apply_semgrep_corrections_second", CORRECTIONS / "apply_corrections.py")
    root = tmp_path / "rules"
    root.mkdir()
    target = root / "rule.yaml"
    target.write_bytes(b"original\n")
    patch_dir = tmp_path / "patches"
    patch_dir.mkdir()
    (patch_dir / "rule.yaml").write_bytes(b"corrected\n")
    manifest = tmp_path / "corrections.json"
    _write_manifest(manifest, [{
        "path": "rule.yaml",
        "source_sha256": _sha256(b"original\n"),
        "replacement": "patches/rule.yaml",
        "corrected_sha256": _sha256(b"corrected\n"),
    }])

    assert module.apply_corrections(root, manifest) == ["rule.yaml"]
    assert target.read_bytes() == b"corrected\n"
    with pytest.raises(module.CorrectionError, match="already corrected"):
        module.apply_corrections(root, manifest)


def test_engine_control_checker_requires_exact_results(tmp_path):
    module = _load("verify_semgrep_controls", CORRECTIONS / "verify_controls.py")
    controls = {
        "schema_version": 1,
        "files": {"probe.py": "value = 1\n"},
        "expected": [
            {"rule_id": "example", "path": "probe.py", "line": 1},
        ],
    }
    controls_path = tmp_path / "controls.json"
    controls_path.write_text(json.dumps(controls))
    materialized = tmp_path / "materialized"
    module.materialize(controls_path, materialized)
    assert (materialized / "probe.py").read_text() == "value = 1\n"

    result_path = tmp_path / "results.json"
    result_path.write_text(json.dumps({
        "errors": [],
        "results": [{
            "check_id": "prefix.example",
            "path": str(materialized / "probe.py"),
            "start": {"line": 1},
        }],
    }))
    module.check(controls_path, materialized, result_path)

    result_path.write_text(json.dumps({"errors": [], "results": []}))
    with pytest.raises(module.ControlError, match="result mismatch"):
        module.check(controls_path, materialized, result_path)


@pytest.mark.parametrize("expected", ["absent", [], {}, [{"rule_id": "example", "path": "probe.py"}],
                                      [{"rule_id": "example", "path": "probe.py", "line": True}],
                                      ["example"]])
def test_engine_control_checker_refuses_controls_that_expect_nothing(tmp_path, expected):
    # #3256: with no expected list, an empty Semgrep run compared equal and passed.
    module = _load("verify_semgrep_controls", CORRECTIONS / "verify_controls.py")
    controls = {"schema_version": 1, "files": {"probe.py": "value = 1\n"}}
    if expected != "absent":
        controls["expected"] = expected
    controls_path = tmp_path / "controls.json"
    controls_path.write_text(json.dumps(controls))
    module.materialize(controls_path, tmp_path / "m")
    result_path = tmp_path / "results.json"
    result_path.write_text(json.dumps({"errors": [], "results": []}))
    with pytest.raises(module.ControlError, match="no expected results|invalid expected control"):
        module.check(controls_path, tmp_path / "m", result_path)


def test_engine_controls_pin_required_positive_sets():
    controls = json.loads((CORRECTIONS / "controls.json").read_text())
    counts = Counter(
        (item["rule_id"], item["path"]) for item in controls["expected"]
    )
    assert counts == {
        ("insecure-file-permissions", "permissions.py"): 7,
        ("dangerous-subprocess-use-audit", "subprocesses.py"): 3,
        (
            "dangerous-subprocess-use-audit",
            "upstream-dangerous-subprocess-use-audit.py",
        ): 8,
        ("pull-request-target-code-checkout", "checkouts.yml"): 5,
        ("code-after-unconditional-return", "returns.py"): 1,
        ("return-not-in-function", "returns.py"): 2,
        ("hooks-path-traversal-python", "hooks-path-traversal.py"): 8,
        ("hooks-path-traversal-python", "upstream-hooks-path-traversal.py"): 4,
    }


def test_docker_build_applies_and_exercises_the_checked_corrections():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "COPY tools-image/semgrep /opt/panopticon/semgrep-corrections" in dockerfile
    assert "semgrep-corrections/apply_corrections.py" in dockerfile
    assert "--rules-root /opt/semgrep-rules" in dockerfile
    # #3762: the path-pattern check runs on the tree as it will ship: after the
    # corrections, in the same RUN, so a failure stops the layer.
    step = dockerfile[dockerfile.index("ARG SEMGREP_RULES_REF="):]
    step = step[:step.index("chmod -R a+rX /opt/semgrep-rules")]
    applied = step.index("semgrep-corrections/apply_corrections.py")
    checked = step.index("&& python3 /opt/panopticon/semgrep-corrections/check_rule_paths.py \\\n"
                         "       --rules-root /opt/semgrep-rules \\\n")
    assert applied < checked
    for item in json.loads((CORRECTIONS / "corrections.json").read_text())["corrections"]:
        assert "--config /opt/semgrep-rules/%s" % item["path"] in dockerfile
    assert "semgrep-corrections/verify_controls.py" in dockerfile
    assert "semgrep scan --quiet --metrics=off --disable-version-check --json" in dockerfile
    assert "materialize \"${control_tmp}/source\"" in dockerfile
    assert "check \"${control_tmp}/source\"" in dockerfile
    assert dockerfile.index("USER scanner") < dockerfile.index(
        "# Exercise the corrected vendored files"
    )


# --- #3762: the vendored rules' path patterns cannot be made slow -------------


def _path_check():
    return _load("check_rule_paths", CORRECTIONS / "check_rule_paths.py")


def _rule_file(tmp_path, text, name="rule.yaml"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_text(text)
    return tmp_path


def _rule(paths, rule_id="some.rule"):
    return yaml.safe_dump({"rules": [{"id": rule_id, "languages": ["python"],
                                      "pattern": "x", "paths": paths}]})


def test_a_star_is_counted_per_path_component_and_a_globstar_is_two():
    check = _path_check()
    assert check.MAX_STARS == 2
    for pattern, expected in (("*.py", [1]), ("**", [2]), ("**/*.py", [2, 1]),
                              ("*test*", [2]), ("**/a/**", [2, 0, 2]), ("a/b.py", [0, 0]),
                              ("*a*b*", [3]), ("***", [3]), ("**x*", [3]), ("/*/*/*/*", [0, 1, 1, 1, 1]),
                              ("**/*_*_*_*.csv", [2, 4]), ("", [0])):
        assert check.stars_per_component(pattern) == expected, pattern


@pytest.mark.parametrize("paths", [
    {"include": ["*test*"]},                       # two in one component
    {"exclude": ["**/wp-content/plugins/**/*.php"]},
    {"include": ["**"], "exclude": ["**/*/openssl/*.h", "*secrets.*.yaml"]},
    {"include": ["/*/*/*/*/*"]},                   # five stars, one a component
    {"include": []}, {}, None,
])
def test_patterns_within_the_limit_pass(tmp_path, paths):
    check = _path_check()
    root = _rule_file(tmp_path, _rule(paths))
    files, patterns = check.check_tree(root)
    assert files == 1
    assert patterns == sum(len(v) for v in (paths or {}).values())
    assert check.main(["--rules-root", str(root)]) == 0


@pytest.mark.parametrize("key, pattern, count", [
    ("include", "*a*b*", 3),
    ("exclude", "***", 3),                          # a globstar is two, and one more
    ("include", "**x*", 3),
    ("exclude", "src/*_*_*_*.csv", 4),              # the advisory's own shape
    ("include", "ok/*.py/*_*_*", 3),                # the last component alone
    ("exclude", "*a*b*/x.py", 3),                   # the first alone
    ("include", "src/*_*_*/lib/*.py", 3),           # one in the middle
])
def test_a_pattern_over_the_limit_fails_and_is_named(tmp_path, capsys, key, pattern, count):
    check = _path_check()
    paths = {"include": ["*.py"], "exclude": ["*test*"]}
    paths[key] = paths[key] + [pattern]
    root = _rule_file(tmp_path / "rules" / "python", _rule(paths, "python.slow-rule")).parent
    with pytest.raises(check.RulePathError) as refused:
        check.check_tree(root)
    said = str(refused.value)
    assert said.startswith("python/rule.yaml: rule 'python.slow-rule': `paths.%s` pattern %r "
                           "has %d `*` in one path component; the limit is 2" % (key, pattern, count))
    assert said.endswith("(#3762)")
    with pytest.raises(SystemExit) as stopped:
        check.main(["--rules-root", str(root)])
    assert stopped.value.code == 1
    err = capsys.readouterr().err
    assert "semgrep rule path check failed: python/rule.yaml: rule 'python.slow-rule'" in err
    assert repr(pattern) in err and "#3762" in err


def test_one_bad_rule_among_many_files_fails_the_tree(tmp_path):
    check = _path_check()
    _rule_file(tmp_path / "a", _rule({"include": ["*.py"]}))
    _rule_file(tmp_path / "b", _rule({"include": ["*.py"]}), "first.yml")
    _rule_file(tmp_path / "b", yaml.safe_dump({"rules": [
        {"id": "fine", "paths": {"include": ["*.js"]}},
        {"id": "slow", "paths": {"exclude": ["*_*_*"]}}]}), "second.yaml")
    (tmp_path / "b" / "notes.txt").write_text("rules: not yaml {")     # not a rule file's name
    with pytest.raises(check.RulePathError, match=r"^b/second\.yaml: rule 'slow': `paths\.exclude`"):
        check.check_tree(tmp_path)


@pytest.mark.parametrize("text, reason", [
    ("rules:\n  - id: x\n    paths: [unclosed\n", "cannot be read as a rule file"),
    ("\tnot: yaml: at: all\n", "cannot be read as a rule file"),
    ("- just\n- a list\n", "has no `rules` list"),
    ("rules: {}\n", "has no `rules` list"),
    ("", "has no `rules` list"),
    ("rules:\n  - just a string\n", "rule 0 is str, not a mapping"),
    ("rules:\n  - id: x\n    paths: '*.py'\n", "rule 'x': `paths` is str, not a mapping"),
    ("rules:\n  - id: x\n    paths: ['*.py']\n", "rule 'x': `paths` is list, not a mapping"),
    ("rules:\n  - id: x\n    paths:\n      include: '*.py'\n",
     "rule 'x': `paths.include` is str, not a list"),
    ("rules:\n  - id: x\n    paths:\n      exclude:\n        - 7\n",
     "rule 'x': a `paths.exclude` entry is int, not a string"),
    ("rules:\n  - id: x\n    paths:\n      include:\n        - [a, b]\n",
     "rule 'x': a `paths.include` entry is list, not a string"),
    ("rules:\n  - paths:\n      include: {a: b}\n", "rule 0: `paths.include` is dict, not a list"),
])
def test_what_cannot_be_read_as_semgrep_reads_it_fails_and_names_the_file(
        tmp_path, capsys, text, reason):
    check = _path_check()
    root = _rule_file(tmp_path / "rules" / "go", text, "broken.yaml").parent
    with pytest.raises(check.RulePathError) as refused:
        check.check_tree(root)
    assert str(refused.value).startswith("go/broken.yaml: ")
    assert reason in str(refused.value)
    assert str(refused.value).endswith("(#3762)")
    with pytest.raises(SystemExit) as stopped:
        check.main(["--rules-root", str(root)])
    assert stopped.value.code == 1
    assert "go/broken.yaml" in capsys.readouterr().err


def test_bytes_that_are_not_text_fail_and_name_the_file(tmp_path):
    check = _path_check()
    (tmp_path / "bad.yml").write_bytes(b"rules:\n  - id: \xff\xfe\n")
    with pytest.raises(check.RulePathError, match=r"^bad\.yml: cannot be read as a rule file"):
        check.check_tree(tmp_path)


def test_a_tree_with_no_rule_file_is_not_a_pass(tmp_path):
    check = _path_check()
    with pytest.raises(check.RulePathError, match="holds no rule file"):
        check.check_tree(tmp_path)
    with pytest.raises(check.RulePathError, match="not a directory"):
        check.check_tree(tmp_path / "absent")
    (tmp_path / "readme.md").write_text("no rules here\n")
    with pytest.raises(check.RulePathError, match="holds no rule file"):
        check.check_tree(tmp_path)


def test_only_the_top_level_paths_of_a_rule_is_read_as_semgrep_reads_it(tmp_path):
    """Semgrep 1.185.0 reads `paths` at the top level of a rule only (`rule.py`). A key
    of that name elsewhere, under `options` or `metadata`, is not a path filter and is
    not held to the limit; the rule's own is."""
    check = _path_check()
    text = yaml.safe_dump({"rules": [{
        "id": "x", "options": {"paths": {"include": ["*a*b*c*"]}},
        "metadata": {"paths": "*a*b*c*"}, "paths": {"include": ["*.py"]}}]})
    assert check.check_tree(_rule_file(tmp_path, text)) == (1, 1)
    alone = yaml.safe_dump({"rules": [{"id": "y", "options": {"paths": {"include": ["*a*b*c*"]}}}]})
    assert check.check_tree(_rule_file(tmp_path / "alone", alone)) == (1, 0)


def test_the_five_corrected_rule_files_pass(tmp_path):
    """The vendored rule set itself is not in this repository (the image build fetches
    it at `SEMGREP_RULES_REF`), so the whole set is checked by the build. What is here
    is checked here: the five replacement files the image installs."""
    check = _path_check()
    for item in json.loads((CORRECTIONS / "corrections.json").read_text())["corrections"]:
        target = tmp_path / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((CORRECTIONS / item["replacement"]).read_bytes())
    assert check.check_tree(tmp_path) == (5, 0)
