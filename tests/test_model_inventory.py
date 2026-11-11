"""#3563: `devtools/model_inventory.py`, the model tables and their models-verified markers.

Fixture trees in a temp dir pin the marker grammar and its association; one pin
reads the real repository files and checks only that each table is found and
any marker present parses (Blue's part 1 writes them).
"""
import datetime
import json
import os

import pytest

import model_inventory as mi

TODAY = datetime.date(2026, 12, 1)
GOOD = "models-verified: 2026-11-10 https://example.test/models https://example.test/deprecations"

PROFILES = """\
hosts:
  {kimi_comment}kimi:
    scout:
      model: primary
      alias: kimi-for-coding
    setup_scan:
      model: null
  # Prose about the gemini lineup.
  # {gemini_marker}
  gemini:
    scout:
      model: gemini-a
    domain_panel:
      model: gemini-retired
    setup_scan:
      model: null
"""

GEMINI = """\
# {marker}
KNOWN_MODELS = frozenset({{
    "gemini-a",
}})
"""
AGY = """\
KNOWN_MODELS: frozenset = frozenset({"agy-a"})
"""
ALIASES = """\
MODEL_ALIASES = frozenset({"auto", "pro"})
"""


def tree(tmp_path, kimi_comment="", gemini_marker=GOOD, gemini_py_marker=GOOD,
         gemini_py=None, agy=AGY, aliases=ALIASES):
    files = {
        mi.PROFILES: PROFILES.format(kimi_comment=kimi_comment, gemini_marker=gemini_marker),
        mi.SETS[0][1]: gemini_py if gemini_py is not None else GEMINI.format(
            marker=gemini_py_marker),
        mi.SETS[1][1]: agy,
        mi.SETS[2][1]: aliases,
    }
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return str(tmp_path)


def by_name(tables):
    return {t.name: t for t in tables}


# --- the marker grammar -------------------------------------------------------------------------
def test_a_good_marker_parses():
    marker = mi.parse_marker(GOOD, TODAY)
    assert marker.date == datetime.date(2026, 11, 10)
    assert marker.urls == ("https://example.test/models", "https://example.test/deprecations")


@pytest.mark.parametrize("text", [
    "models-verified: 2026-11-10",                                  # no URL
    "models-verified: 2026-11-10 http://example.test/x",            # not https
    "models-verified:2026-11-10 https://example.test/x",            # no space
    "models-verified: 2026-11-10  https://example.test/x",          # two spaces
    "models-verified: 10-11-2026 https://example.test/x",           # not ISO
    "models-verified: 2026-11-10 https://example.test/x trailing",  # prose after
    "models-verified: 2026-11-10, https://example.test/x",
    "models verified: 2026-11-10 https://example.test/x",
    "models-verified: 2026-11-10 https://",                         # empty URL
    "models-verified: 2026-11-10 https://example.test/\x1b[2J",     # control byte
])
def test_a_malformed_marker_is_an_error(text):
    with pytest.raises(mi.MarkerError, match="malformed"):
        mi.parse_marker(text, TODAY)


@pytest.mark.parametrize("date", ["2026-02-30", "2026-13-01", "2026-00-10"])
def test_a_date_that_is_not_a_calendar_date_is_an_error(date):
    with pytest.raises(mi.MarkerError, match="not a calendar date"):
        mi.parse_marker("models-verified: %s https://example.test/x" % date, TODAY)


def test_a_future_date_beyond_a_day_of_slack_is_an_error():
    assert mi.parse_marker("models-verified: 2026-12-02 https://e.test/x", TODAY)
    with pytest.raises(mi.MarkerError, match="in the future"):
        mi.parse_marker("models-verified: 2026-12-03 https://e.test/x", TODAY)


# --- association --------------------------------------------------------------------------------
def test_markers_attach_to_the_table_directly_below(tmp_path):
    tables = by_name(mi.inventory(tree(tmp_path), TODAY))
    assert tables["profiles:gemini"].marker.date == datetime.date(2026, 11, 10)
    assert tables["profiles:kimi"].marker is None
    assert tables["allowlist:gemini"].marker.date == datetime.date(2026, 11, 10)
    assert tables["allowlist:agy"].marker is None
    assert tables["aliases:gemini"].marker is None
    assert tables["profiles:gemini"].line == 10


def test_a_blank_line_ends_the_comment_block(tmp_path):
    text = "# %s\n\nKNOWN_MODELS = frozenset({'gemini-a'})\n" % GOOD
    tables = by_name(mi.inventory(tree(tmp_path, gemini_py=text), TODAY))
    assert tables["allowlist:gemini"].marker is None


def test_a_marker_on_the_next_table_does_not_leak_upward(tmp_path):
    # The gemini marker sits above `gemini:`; kimi, above it in the file, stays unverified.
    tables = by_name(mi.inventory(tree(tmp_path), TODAY))
    assert tables["profiles:kimi"].marker is None


def test_two_markers_in_one_block_are_an_error(tmp_path):
    text = "# %s\n# %s\nKNOWN_MODELS = frozenset({'gemini-a'})\n" % (GOOD, GOOD)
    with pytest.raises(mi.MarkerError, match="2 models-verified markers"):
        mi.inventory(tree(tmp_path, gemini_py=text), TODAY)


def test_a_malformed_marker_names_the_table(tmp_path):
    with pytest.raises(mi.MarkerError, match=r"model-profiles.yml:10 \(hosts.gemini\): malformed"):
        mi.inventory(tree(tmp_path, gemini_marker="models-verified: soon"), TODAY)


def test_a_marker_in_the_yaml_attaches_by_key_line_not_text(tmp_path):
    # A marker above a nested key (a role) is not a table marker for the host.
    root = tree(tmp_path)
    path = os.path.join(root, mi.PROFILES)
    with open(path, encoding="utf-8") as fh:
        text = fh.read().replace("    scout:\n      model: primary",
                                 "    # %s\n    scout:\n      model: primary" % GOOD)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    tables = by_name(mi.inventory(root, TODAY))
    assert tables["profiles:kimi"].marker is None


# --- the sets, read by AST ----------------------------------------------------------------------
def test_sets_are_read_as_literals_including_annotated(tmp_path):
    tables = by_name(mi.inventory(tree(tmp_path), TODAY))
    assert tables["allowlist:gemini"].members == {"gemini-a"}
    assert tables["allowlist:agy"].members == {"agy-a"}
    assert tables["aliases:gemini"].members == {"auto", "pro"}


WHERE = r"skill/scripts/runners/gemini.py:1 \(KNOWN_MODELS\) "


@pytest.mark.parametrize("text, message", [
    ("KNOWN_MODELS = set({'a'})\n", WHERE + "is not a frozenset of a set display"),
    ("KNOWN_MODELS = frozenset(load())\n", WHERE + "is not a frozenset of a set display"),
    ("KNOWN_MODELS = frozenset('abc')\n", WHERE + "is not a frozenset of a set display"),
    ("KNOWN_MODELS = frozenset(['a'])\n", WHERE + "is not a frozenset of a set display"),
    ("KNOWN_MODELS = frozenset({1})\n", WHERE + "holds something other than string"),
    ("KNOWN_MODELS = frozenset({'a', ('b', ['c'])})\n",
     WHERE + "holds something other than string"),
    ("KNOWN_MODELS = frozenset({'a', NAME})\n", WHERE + "holds something other than string"),
    ("KNOWN_MODELS = frozenset({'a', *more})\n", WHERE + "holds something other than string"),
    ("OTHER = frozenset({'a'})\n", "no module-level KNOWN_MODELS"),
    ("def f():\n    KNOWN_MODELS = frozenset({'a'})\n", "no module-level KNOWN_MODELS"),
])
def test_a_set_out_of_shape_is_an_error_naming_the_file(tmp_path, text, message):
    with pytest.raises(ValueError, match=message):
        mi.inventory(tree(tmp_path, gemini_py=text), TODAY)


def test_a_set_out_of_shape_exits_1_through_main_not_a_traceback(tmp_path, capsys, monkeypatch):
    root = tree(tmp_path, gemini_py="KNOWN_MODELS = frozenset({'a', ('b', ['c'])})\n")
    real = mi.inventory
    monkeypatch.setattr(mi, "inventory", lambda: real(root, TODAY))
    assert mi.main([]) == 1
    assert "runners/gemini.py:1 (KNOWN_MODELS)" in capsys.readouterr().err


def test_the_set_module_is_never_imported(tmp_path):
    text = "raise SystemExit('imported')\nKNOWN_MODELS = frozenset({'gemini-a'})\n"
    assert by_name(mi.inventory(tree(tmp_path, gemini_py=text), TODAY))["allowlist:gemini"]


# --- rows and order -----------------------------------------------------------------------------
def test_rows_carry_allowlist_membership(tmp_path):
    tables = by_name(mi.inventory(tree(tmp_path), TODAY))
    gemini = {r["role"]: r for r in tables["profiles:gemini"].rows}
    assert gemini["scout"]["allowlisted"] == "yes"
    assert gemini["domain_panel"]["allowlisted"] == "NO"
    assert gemini["setup_scan"]["allowlisted"] == "-"     # inherit is not a model to allow
    kimi = {r["role"]: r for r in tables["profiles:kimi"].rows}
    assert kimi["scout"] == {"host": "kimi", "role": "scout", "model": "primary",
                             "detail": "alias=kimi-for-coding", "allowlisted": "-"}
    assert kimi["setup_scan"]["allowlisted"] == "-"


def test_an_alias_counts_as_allowlisted_for_its_host(tmp_path):
    root = tree(tmp_path)
    path = os.path.join(root, mi.PROFILES)
    with open(path, encoding="utf-8") as fh:
        text = fh.read().replace("model: gemini-retired", "model: pro")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    gemini = {r["role"]: r for r in by_name(mi.inventory(root, TODAY))["profiles:gemini"].rows}
    assert gemini["domain_panel"]["allowlisted"] == "yes"


def test_stalest_first_puts_unverified_then_oldest():
    def table(name, date):
        return mi.Table(name, "p", 1, mi.Marker(date, ("https://e.test",)) if date else None)
    order = mi.stalest_first([table("b", datetime.date(2026, 10, 1)), table("z", None),
                              table("a", datetime.date(2026, 11, 1)), table("c", None)])
    assert [t.name for t in order] == ["c", "z", "b", "a"]


def test_json_and_text_outputs(tmp_path, capsys, monkeypatch):
    root = tree(tmp_path)
    real = mi.inventory
    monkeypatch.setattr(mi, "inventory", lambda: real(root, TODAY))
    assert mi.main(["--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    gemini = next(t for t in doc["tables"] if t["name"] == "profiles:gemini")
    assert gemini["verified"] == "2026-11-10" and len(gemini["urls"]) == 2
    assert next(t for t in doc["tables"] if t["name"] == "allowlist:agy")["members"] == ["agy-a"]
    assert mi.main([]) == 0
    out = capsys.readouterr().out
    assert out.startswith("tables (stalest first):")
    assert "  profiles:kimi       unverified" in out
    assert all(line == line.rstrip() for line in out.splitlines())


def test_main_reports_a_bad_marker_and_exits_1(tmp_path, capsys, monkeypatch):
    root = tree(tmp_path, gemini_marker="models-verified: soon")
    real = mi.inventory
    monkeypatch.setattr(mi, "inventory", lambda: real(root, TODAY))
    assert mi.main([]) == 1
    assert "malformed models-verified marker" in capsys.readouterr().err


# --- the real repository ------------------------------------------------------------------------
def test_every_registered_table_is_found_in_the_repo_and_markers_parse():
    tables = by_name(mi.inventory())
    for name in ("profiles:claude", "profiles:codex", "profiles:gemini", "profiles:agy",
                 "profiles:kimi", "allowlist:gemini", "allowlist:agy", "aliases:gemini"):
        assert name in tables
    assert tables["allowlist:gemini"].members and tables["aliases:gemini"].members
    for table in tables.values():
        if table.name.startswith("profiles:") and table.name != "profiles:openrouter":
            assert any(row["model"] for row in table.rows), table.name
