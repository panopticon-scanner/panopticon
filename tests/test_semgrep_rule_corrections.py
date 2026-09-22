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
    for item in json.loads((CORRECTIONS / "corrections.json").read_text())["corrections"]:
        assert "--config /opt/semgrep-rules/%s" % item["path"] in dockerfile
    assert "semgrep-corrections/verify_controls.py" in dockerfile
    assert "semgrep scan --quiet --metrics=off --disable-version-check --json" in dockerfile
    assert "materialize \"${control_tmp}/source\"" in dockerfile
    assert "check \"${control_tmp}/source\"" in dockerfile
    assert dockerfile.index("USER scanner") < dockerfile.index(
        "# Exercise the corrected vendored files"
    )
