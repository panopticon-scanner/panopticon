import tomllib
from pathlib import Path

# #run7 ARC-E2C: anchor via __file__, not the process cwd. Path("pyproject.toml")
# only resolved when pytest ran from the repo root; an IDE "run this file", a
# --rootdir, or a differently-cwd'd hook broke only this module.
_ROOT = Path(__file__).resolve().parent.parent


def test_authors_and_keywords_are_under_project_table():
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    data = tomllib.loads(text)
    assert "authors" in data["project"], "authors must be under [project]"
    assert "keywords" in data["project"], "keywords must be under [project]"
    assert "authors" not in data["project"].get("optional-dependencies", {})
    assert "keywords" not in data["project"].get("optional-dependencies", {})


def test_jsonschema_is_a_core_runtime_dependency():
    # #run7 ARC-F2E: jsonschema gates untrusted agent/Codex JSON before it is
    # published as a trusted artifact (codex_runner.validate_schema and the
    # discovery/model_resolver/score_gate validators). As a dev/test-only extra it
    # left every validator FAILING OPEN in a bare `pip install panopticon`. It is a
    # runtime dependency and must live under core [project.dependencies].
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    core = data["project"]["dependencies"]
    assert any(d.startswith("jsonschema") for d in core), \
        "jsonschema must be a core runtime dependency"
    for name, extra in data["project"].get("optional-dependencies", {}).items():
        assert not any(d.startswith("jsonschema") for d in extra), \
            f"jsonschema should not be duplicated in the {name!r} extra once core"
