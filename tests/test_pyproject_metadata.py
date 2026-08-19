import tomllib
from pathlib import Path


def test_authors_and_keywords_are_under_project_table():
    text = Path("pyproject.toml").read_text(encoding="utf-8")
    data = tomllib.loads(text)
    assert "authors" in data["project"], "authors must be under [project]"
    assert "keywords" in data["project"], "keywords must be under [project]"
    assert "authors" not in data.get("project.optional-dependencies", {})
    assert "keywords" not in data.get("project.optional-dependencies", {})
