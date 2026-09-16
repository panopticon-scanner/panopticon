"""Offline Codex MCP boundary tests: no host process, home writes, or network."""
import io
import json
import os

import pytest

from _test_helpers import hard_link_or_skip
from scripts import codex_read_tools as read_tools


@pytest.fixture
def tree(tmp_path):
    root = tmp_path.resolve()
    source = root / "source"
    source.mkdir()
    first = source / "first.py"
    first.write_text("alpha\nbeta\nalpha gamma\n", encoding="utf-8")
    second = source / "second.txt"
    second.write_text("beta second\n", encoding="utf-8")
    outside = root / "outside.txt"
    outside.write_text("private outside content\n", encoding="utf-8")
    return root, source, first, second, outside


def reader_for(tree, *, directories=False, reads=()):
    root, source, first, _, _ = tree
    return read_tools.Reader({"files": [] if directories else [str(first)],
                              "dirs": [str(source)] if directories else [],
                              "reads": list(map(str, reads))}, str(root))


def body(result):
    return result["content"][0]["text"]


def test_surface_has_only_narrow_reads():
    assert {tool["name"] for tool in read_tools.TOOLS} == {"read_file", "search", "list_files"}
    assert all(tool["inputSchema"]["additionalProperties"] is False for tool in read_tools.TOOLS)
    assert all(tool["annotations"] == {"readOnlyHint": True, "destructiveHint": False,
                                       "openWorldHint": False, "idempotentHint": True}
               for tool in read_tools.TOOLS)


def test_descriptions_are_single_line_and_carry_no_markdown():
    # These strings are published twice: as MCP tool descriptions, and -- since
    # #1639 P14 -- interpolated verbatim into the Codex reviewer's markdown
    # tool-policy paragraph, inside a parenthesis next to a code span. A
    # backtick would close that span early and a newline would end the
    # paragraph (or open a fence or heading), so the constraint the rendering
    # relies on is asserted here rather than left to convention.
    for tool in read_tools.TOOLS:
        description = tool["description"]
        assert description == description.strip()
        assert description.splitlines() == [description]
        assert "`" not in description


def test_numbered_relative_read_with_offset_and_limit(tree):
    result = reader_for(tree).call("read_file", {"path": "source/first.py", "offset": 2, "limit": 1})
    assert result["isError"] is False
    assert ":2:beta" in body(result)
    assert "alpha" not in body(result)
    assert "truncated" in body(result)


def test_files_reads_and_dirs_are_independent_grants(tree):
    _, _, first, second, outside = tree
    reader = reader_for(tree, reads=[outside])
    assert reader.call("read_file", {"path": str(first)})["isError"] is False
    assert reader.call("read_file", {"path": str(outside)})["isError"] is False
    assert reader.call("read_file", {"path": str(second)})["isError"] is True
    assert reader_for(tree, directories=True).call("read_file", {"path": str(second)})["isError"] is False


@pytest.mark.parametrize("path", ["outside.txt", "source/../outside.txt", "source-other/secret.py"])
def test_outside_paths_and_traversal_are_denied(tree, path):
    result = reader_for(tree, directories=True).call("read_file", {"path": path})
    assert result["isError"] is True
    assert "outside" in body(result) and "scope" in body(result)
    assert "private outside content" not in body(result)


def test_empty_scope_denies_every_read(tree):
    result = read_tools.Reader({}, str(tree[0])).call("read_file", {"path": str(tree[2])})
    assert result["isError"] is True


@pytest.mark.parametrize("scope", [None, [], {"files": "bad"}, {"files": ["relative"]},
                                    {"dirs": [None]}, {"reads": ["/invalid\0path"]}])
def test_malformed_scope_is_rejected(tree, scope):
    with pytest.raises(ValueError):
        read_tools.Reader(scope, str(tree[0]))


def test_search_is_literal_and_file_scope_requires_explicit_path(tree):
    reader = reader_for(tree)
    assert reader.call("search", {"pattern": "alpha"})["isError"] is True
    result = reader.call("search", {"pattern": "alpha", "path": "source/first.py"})
    assert result["isError"] is False
    assert ":1:alpha" in body(result) and ":3:alpha gamma" in body(result)
    assert body(reader.call("search", {"pattern": "a.*", "path": "source/first.py"})) == ""
    assert reader.call("search", {"pattern": "private", "path": "outside.txt"})["isError"] is True
    assert reader.call("search", {"pattern": "alpha", "path": "source"})["isError"] is True


def test_directory_search_and_listing_are_filtered(tree):
    reader = reader_for(tree, directories=True)
    listed = reader.call("list_files", {"pattern": "*.py"})
    assert listed["isError"] is False and "first.py" in body(listed)
    assert "second.txt" not in body(listed) and "outside.txt" not in body(listed)
    for arguments in ({"pattern": "beta"}, {"pattern": "beta", "path": "source"}):
        result = reader.call("search", arguments)
        assert result["isError"] is False
        assert "first.py" in body(result) and "second.txt" in body(result)
        assert "outside.txt" not in body(result)
    assert reader_for(tree).call("list_files", {})["isError"] is True


def test_symlink_leaf_and_directory_are_never_followed(tree):
    root, source, first, _, outside = tree
    reader = reader_for(tree, directories=True)
    first.unlink()
    first.symlink_to(outside)
    (source / "linked-directory").symlink_to(root, target_is_directory=True)
    for path in (first, source / "linked-directory" / "outside.txt"):
        result = reader.call("read_file", {"path": str(path)})
        assert result["isError"] is True and "private outside content" not in body(result)
    listed = body(reader.call("list_files", {}))
    assert "linked-directory" not in listed and "first.py" not in listed


def test_a_hard_link_inside_a_directory_grant_is_denied_by_both_readers(tree):
    # #1642: O_NOFOLLOW stops symlinks, not HARD links, and `_under` authorizes
    # by NAME. A target that plants a link inside the granted subtree naming a
    # same-filesystem inode outside it was read through the grant, because the
    # link IS the file. Both read_file and search route through `_read`.
    root, source, first, _, outside = tree
    planted = hard_link_or_skip(outside, source / "innocent.txt")
    reader = reader_for(tree, directories=True)
    for arguments in ({"path": planted}, {"path": "source/innocent.txt"}):
        result = reader.call("read_file", arguments)
        assert result["isError"] is True, body(result)
        assert "hard-linked" in body(result) and "st_nlink=2" in body(result)
        assert "private outside content" not in body(result)
    # An EXPLICIT search of the link is a refusal, exactly like read_file: the
    # reviewer named that file, and there is nothing else the answer could be.
    result = reader.call("search", {"pattern": "private", "path": planted})
    assert result["isError"] is True, body(result)
    assert "hard-linked" in body(result)
    assert "private outside content" not in body(result)
    # The singly-linked files of the same grant are untouched.
    assert reader.call("read_file", {"path": str(first)})["isError"] is False


def test_a_directory_search_skips_the_hard_link_and_keeps_every_other_match(tree):
    # Fix round 1 (F2): the per-file read used to let HardLinkDenied escape, so
    # ONE planted link anywhere under the grant refused the whole call and threw
    # away the matches already found -- an evasion lever costing an attacker one
    # `ln`. A read fence's job is to make the content unreachable, which a skip
    # does as well as an abort; the module already answers partially with a
    # named reason ([search truncated...]), so this one does too.
    root, source, first, second, outside = tree
    # 'first.py' < 'middle.txt' < 'second.txt': matches on both sides of it.
    planted = hard_link_or_skip(outside, source / "middle.txt")
    result = reader_for(tree, directories=True).call("search", {"pattern": "beta"})
    assert result["isError"] is False, body(result)
    text = body(result)
    assert "first.py:2:beta" in text and "second.txt:1:beta second" in text
    assert "private outside content" not in text
    assert "[skipped %s:" % planted in text
    assert "hard-linked" in text and "st_nlink=2" in text


def test_an_exact_file_grant_still_reads_a_hard_linked_file(tree):
    # The other half of the rule: a path the ORCHESTRATOR named is readable
    # whatever its link count -- `files`/`reads` are exact grants, so there is
    # no lexical subtree for a planted name to hide in.
    root, source, _, _, outside = tree
    planted = hard_link_or_skip(outside, source / "innocent.txt")
    for key in ("files", "reads"):
        reader = read_tools.Reader({key: [planted]}, str(root))
        result = reader.call("read_file", {"path": planted})
        assert result["isError"] is False, body(result)
        assert "private outside content" in body(result)


def test_a_file_named_by_both_grants_is_read_as_the_exact_one(tree):
    # A cell whose files sit inside a directory grant is the normal shape, and
    # an exact grant must not be narrowed by the directory it happens to be in.
    root, source, _, _, outside = tree
    planted = hard_link_or_skip(outside, source / "innocent.txt")
    reader = read_tools.Reader({"files": [planted], "dirs": [str(source)]}, str(root))
    assert reader.call("read_file", {"path": planted})["isError"] is False


def test_the_hard_link_denial_is_one_wording(tree):
    # Three brokers refuse the same thing; a divergent sentence is how one of
    # them silently stops being checked. read_guard_hook/kimi_guard_hook are
    # stdlib-only and cannot import this constant, so the copies are pinned.
    import scripts.kimi_guard_hook as kimi_guard_hook
    import scripts.read_guard_hook as read_guard_hook

    assert (read_tools.HARD_LINK_DENIAL == read_guard_hook.HARD_LINK_DENIAL
            == kimi_guard_hook.HARD_LINK_DENIAL)
    assert read_tools.HARD_LINK_DENIAL % 2 == (
        "read scope denies a hard-linked file inside a directory grant (st_nlink=2)")


def test_symlink_swap_between_scope_check_and_open_is_denied(tree, monkeypatch):
    _, _, first, _, outside = tree
    reader = reader_for(tree)
    original = reader._require

    def swap(path, **kwargs):
        original(path, **kwargs)
        first.unlink()
        first.symlink_to(outside)

    monkeypatch.setattr(reader, "_require", swap)
    result = reader.call("read_file", {"path": str(first)})
    assert result["isError"] is True
    assert "private outside content" not in body(result)


def test_parent_swap_during_descriptor_walk_is_denied(tree, monkeypatch):
    root, source, first, _, _ = tree
    outsider = root / "private"
    outsider.mkdir()
    (outsider / "first.py").write_text("private outside content", encoding="utf-8")
    original_open = os.open
    swapped = False

    def swap(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == "source" and not swapped:
            swapped = True
            source.rename(root / "original")
            source.symlink_to(outsider, target_is_directory=True)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap)
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {swap})
    result = reader_for(tree).call("read_file", {"path": str(first)})
    assert swapped and result["isError"] is True
    assert "private outside content" not in body(result)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO fixture")
def test_fifo_read_is_nonblocking_and_denied(tree):
    fifo = tree[1] / "fifo"
    os.mkfifo(fifo)
    result = reader_for(tree, directories=True).call("read_file", {"path": str(fifo)})
    assert result["isError"] is True
    assert "regular files only" in body(result)


def test_unsupported_secure_open_fails_closed(tree, monkeypatch):
    monkeypatch.setattr(os, "supports_dir_fd", set())
    result = reader_for(tree).call("read_file", {"path": str(tree[2])})
    assert result["isError"] is True and "unavailable" in body(result)


@pytest.mark.parametrize("name,arguments", [
    ("execute", {"command": "id"}), ("read_file", {}), ("read_file", []),
    ("read_file", {"path": "source/first.py", "offset": True}),
    ("read_file", {"path": "source/first.py", "offset": 100001}),
    ("read_file", {"path": "source/first.py", "limit": 1001}),
    ("read_file", {"path": "source/first.py", "write": "bad"}),
    ("search", {"pattern": ""}), ("search", {"pattern": []}),
    ("list_files", {"pattern": "x" * 4097}),
])
def test_invalid_tool_arguments_fail_closed(tree, name, arguments):
    assert reader_for(tree).call(name, arguments)["isError"] is True


def test_read_search_and_listing_limits(tree, monkeypatch):
    reader = reader_for(tree, directories=True)
    monkeypatch.setattr(read_tools, "MAX_FILE_BYTES", 10)
    assert "truncated" in body(reader.call("read_file", {"path": "source/first.py"}))
    assert "truncated" in body(reader.call("search", {"pattern": "alpha"}))
    # C-1: a cap now TRUNCATES the listing instead of refusing it -- the old
    # refusal made list_files unusable on any repository-sized directory grant.
    monkeypatch.setattr(read_tools, "MAX_FILES", 1)
    listed = reader.call("list_files", {})
    assert listed["isError"] is False
    assert "truncated" in body(listed)


def test_output_size_is_bounded(tree, monkeypatch):
    monkeypatch.setattr(read_tools, "MAX_OUTPUT_CHARS", 80)
    tree[2].write_text("x" * 1000, encoding="utf-8")
    result = reader_for(tree).call("read_file", {"path": str(tree[2])})
    assert len(body(result)) < 110 and "truncated" in body(result)


def test_binding_is_per_entry_and_accepts_explicit_review_root(tree):
    root, _, first, _, outside = tree
    scope_path = root / "scope.json"
    scope_path.write_text(json.dumps({"one": {"files": [str(first)]},
                                      "two": {"files": [str(outside)]}}), encoding="utf-8")
    env = {"PANOPTICON_ENTRY_ID": "one", "PANOPTICON_READ_SCOPE": str(scope_path),
           "PANOPTICON_REVIEW_ROOT": str(root)}
    reader = read_tools.load_reader(env)
    assert reader.call("read_file", {"path": "source/first.py"})["isError"] is False
    assert reader.call("read_file", {"path": "outside.txt"})["isError"] is True
    for invalid in ({}, {**env, "PANOPTICON_ENTRY_ID": "missing"},
                    {**env, "PANOPTICON_READ_SCOPE": "relative"}):
        with pytest.raises(ValueError):
            read_tools.load_reader(invalid)
    scope_path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError):
        read_tools.load_reader(env)


def exchange(reader, requests, **kwargs):
    sink = io.StringIO()
    source = io.StringIO("".join(json.dumps(request) + "\n" for request in requests))
    read_tools.serve(reader, source, sink, **kwargs)
    return [json.loads(line) for line in sink.getvalue().splitlines()]


def test_stdio_protocol_initialize_list_call_and_notifications(tree):
    replies = exchange(reader_for(tree), [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "read_file", "arguments": {"path": "outside.txt"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "resources/read"},
    ])
    assert len(replies) == 5
    assert replies[0]["result"]["protocolVersion"] == "2025-03-26"
    assert replies[1]["result"] == {}
    assert replies[2]["result"]["tools"] == read_tools.TOOLS
    assert replies[3]["result"]["isError"] is True
    assert replies[4]["error"]["code"] == -32601


def test_missing_binding_does_not_offer_an_unrestricted_fallback():
    replies = exchange(None, [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": "read_file", "arguments": {"path": "/secret"}}}],
                       binding_error="missing entry")
    assert replies[0]["result"]["isError"] is True
    assert "binding unavailable" in body(replies[0]["result"])


def test_resources_cannot_bypass_read_tools(tree):
    replies = exchange(reader_for(tree), [
        {"jsonrpc": "2.0", "id": 1, "method": "resources/list"},
        {"jsonrpc": "2.0", "id": 2, "method": "resources/templates/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "file:///secret"}},
    ])
    assert replies[0]["result"] == {"resources": []}
    assert replies[1]["result"] == {"resourceTemplates": []}
    assert replies[2]["error"]["code"] == -32601


def test_malformed_and_oversized_protocol_input(tree, monkeypatch):
    replies = exchange(reader_for(tree), [[], {"jsonrpc": "2.0", "id": 1,
                                              "method": "tools/list", "params": []}])
    assert all(reply["error"]["code"] == -32600 for reply in replies)
    sink = io.StringIO()
    read_tools.serve(reader_for(tree), io.StringIO("{\n"), sink)
    assert json.loads(sink.getvalue())["error"]["code"] == -32700
    monkeypatch.setattr(read_tools, "MAX_REQUEST_BYTES", 10)
    sink = io.StringIO()
    read_tools.serve(reader_for(tree), io.StringIO("x" * 11), sink)
    assert json.loads(sink.getvalue())["error"]["code"] == -32700


# --- C-1: enumeration must survive a real repository ------------------------


def test_vcs_and_dependency_directories_are_never_walked(tree, monkeypatch):
    root, source, _first, _second, _outside = tree
    git = source / ".git"
    git.mkdir()
    for number in range(20):
        (git / ("object-%d" % number)).write_text("x", encoding="utf-8")
    (source / "node_modules").mkdir()
    (source / "node_modules" / "dep.py").write_text("vendored", encoding="utf-8")
    (source / "nested").mkdir()
    (source / "nested" / "__pycache__").mkdir()
    (source / "nested" / "__pycache__" / "first.pyc").write_text("x", encoding="utf-8")
    monkeypatch.setattr(read_tools, "MAX_FILES", 8)
    listed = reader_for(tree, directories=True).call("list_files", {"pattern": "*"})
    assert listed["isError"] is False
    assert "first.py" in body(listed)
    assert ".git" not in body(listed)
    assert "node_modules" not in body(listed)
    assert "__pycache__" not in body(listed)
    assert "truncated" not in body(listed)


def test_list_files_narrows_by_path_and_denies_a_path_outside_the_grant(tree):
    root, source, _first, _second, _outside = tree
    nested = source / "nested"
    nested.mkdir()
    (nested / "third.py").write_text("gamma\n", encoding="utf-8")
    reader = reader_for(tree, directories=True)
    narrowed = reader.call("list_files", {"pattern": "*.py", "path": "source/nested"})
    assert narrowed["isError"] is False
    assert "third.py" in body(narrowed)
    assert "first.py" not in body(narrowed)
    denied = reader.call("list_files", {"pattern": "*", "path": str(root)})
    assert denied["isError"] is True
    assert "outside" in body(denied) and "scope" in body(denied)
    assert reader_for(tree).call(
        "list_files", {"pattern": "*", "path": "source"})["isError"] is True


def test_exceeding_an_enumeration_cap_truncates_rather_than_refusing(tree, monkeypatch):
    reader = reader_for(tree, directories=True)
    monkeypatch.setattr(read_tools, "MAX_FILES", 1)
    listed = reader.call("list_files", {"pattern": "*"})
    assert listed["isError"] is False
    assert "pass path= to narrow" in body(listed)
    assert "truncated" in body(listed)
    searched = reader.call("search", {"pattern": "beta"})
    assert searched["isError"] is False
    assert "pass path= to narrow" in body(searched)


def test_the_repository_checkout_itself_is_listable_under_production_caps():
    # N-I2: everything here is judged on paths RELATIVE to the checkout, and
    # the root is realpath'd. Asserting over the joined absolute text made the
    # answer depend on where the repo lives -- a checkout under `.worktrees/`
    # (this repo reserves it) or `/tmp` (now an excluded name) failed the
    # exclusion loop, and a path reached through a symlinked component made
    # every O_NOFOLLOW open fail, because Reader realpaths its cwd but leaves
    # scope["dirs"] at abspath.
    from conftest import REPO_ROOT
    root = os.path.realpath(REPO_ROOT)
    reader = read_tools.Reader({"files": [], "dirs": [root], "reads": []}, root)

    marker = reader.call("list_files", {"pattern": "*codex_read_tools.py"})
    assert marker["isError"] is False, body(marker)
    assert "skill/scripts/codex_read_tools.py" in body(marker).replace(os.sep, "/")

    listed = reader.call("list_files", {"pattern": "*"})
    assert listed["isError"] is False, body(listed)
    inside = [line for line in body(listed).splitlines()
              if line.startswith(root + os.sep)]
    assert inside
    for line in inside:
        relative = os.path.relpath(line, root)
        for segment in relative.split(os.sep)[:-1]:
            assert not read_tools._excluded_dir(segment), (segment, relative)


# --- N-I1: one maintenance point for what a walk prunes ---------------------


def test_the_exclusion_list_matches_the_one_discovery_prunes():
    """The broker cannot IMPORT discovery.EXCLUDE_DIRS.

    `codex_host.safety_config()` launches this module as
    `sys.executable -I <path>`, and `-I` implies `-P`: the script's directory
    is not on sys.path, so the broker is a standalone stdlib-only process by
    construction (a `from scripts import discovery` there would break every
    Codex read). The list is therefore duplicated, and this is what keeps the
    duplicate honest -- Codex's enumeration and Claude's agentic scan must
    prune the same names, or the two hosts cover the same tree differently.
    """
    from conftest import REPO_ROOT
    from scripts import discovery

    # The broker has no git, so it cannot read the target's .gitignore the way
    # discovery's `git ls-files --exclude-standard` surface does; these two
    # names are how it reaches the same answer. What actually keeps discovery
    # off them is `_filter_reviewable`'s dot-dir prune, which holds whatever
    # git reports: since #1638 P06 the tracked `.panopticon/groups.yml` IS
    # listed by `git ls-files`, and `discover_repo_files` still returns zero
    # `.panopticon/` entries. The .gitignore assertion below stays as the
    # second half of the parity -- both names remain ignored for the tools that
    # do read it, so the broker's hard-coded pair cannot drift unnoticed.
    gitignore_parity = {".panopticon", ".worktrees"}
    assert set(read_tools.EXCLUDED_DIRECTORIES) == set(discovery.EXCLUDE_DIRS) | gitignore_parity
    assert read_tools.EXCLUDED_DIRECTORY_GLOBS == discovery.EXCLUDE_DIR_GLOBS
    with open(os.path.join(REPO_ROOT, ".gitignore"), encoding="utf-8") as fh:
        ignored = fh.read()
    for name in gitignore_parity:
        assert name in ignored


def test_a_reviewable_build_directory_is_no_longer_hidden(tree):
    # The wave's own list added `build`/`dist`/`target`/`vendor`, which
    # discovery does NOT prune: a target keeping packaging code under build/
    # was reviewed by Claude and invisible to Codex.
    _root, source, _first, _second, _outside = tree
    for name in ("build", "dist", "target", "vendor"):
        (source / name).mkdir()
        (source / name / "packaging.py").write_text("reviewable\n", encoding="utf-8")
    listed = body(reader_for(tree, directories=True).call("list_files", {"pattern": "*.py"}))
    for name in ("build", "dist", "target", "vendor"):
        assert name + "/packaging.py" in listed.replace(os.sep, "/"), name


def test_the_walk_prunes_discoverys_directory_globs_too(tree):
    _root, source, _first, _second, _outside = tree
    egg = source / "panopticon.egg-info"
    egg.mkdir()
    (egg / "SOURCES.py").write_text("generated\n", encoding="utf-8")
    listed = body(reader_for(tree, directories=True).call("list_files", {"pattern": "*"}))
    assert "egg-info" not in listed


# --- N-M1 / N-M2: truncation must be true, countable and reproducible -------


def test_a_complete_listing_is_not_marked_truncated(tree, monkeypatch):
    # N-M1: the cap fired ON the MAX_FILES-th file, before anything had been
    # dropped, so a reviewer was told to narrow a path that was already whole.
    root, source, _first, _second, _outside = tree
    (source / "third.py").write_text("gamma\n", encoding="utf-8")
    monkeypatch.setattr(read_tools, "MAX_FILES", 3)
    listed = reader_for(tree, directories=True).call("list_files", {"pattern": "*"})
    assert listed["isError"] is False
    assert "truncated" not in body(listed)
    assert len(body(listed).splitlines()) == 3


def test_the_truncation_note_counts_what_it_actually_stopped_at(tree, monkeypatch):
    # N-M2: the note read "N of M entries shown" with N the pattern-filtered
    # count and M the enumerated count -- "1 of 5" over a 13-file tree.
    _root, source, _first, _second, _outside = tree
    for number in range(12):
        (source / ("extra-%02d.txt" % number)).write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(read_tools, "MAX_FILES", 5)
    listed = reader_for(tree, directories=True).call("list_files", {"pattern": "*.py"})
    assert listed["isError"] is False
    note = body(listed).splitlines()[-1]
    assert note == "[truncated: enumeration stopped at 5 files; pass path= to narrow]"


class _Entry:
    """A directory entry whose type is already decided.

    `os.scandir(fd)` hands back DirEntry objects that resolve their type
    against the open descriptor; the adversary below has to materialise them
    before that descriptor closes, so it snapshots the two questions the walk
    actually asks.
    """

    def __init__(self, entry):
        self.name = entry.name
        self._dir = entry.is_dir(follow_symlinks=False)
        self._file = entry.is_file(follow_symlinks=False)

    def is_dir(self, follow_symlinks=True):
        return self._dir

    def is_file(self, follow_symlinks=True):
        return self._file


class _Ordered:
    """What `os.scandir` returns: a context manager over entries."""

    def __init__(self, entries):
        self._entries = entries

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def __iter__(self):
        return iter(self._entries)


def _reverse_scandir(monkeypatch):
    """Hand the walk every directory in REVERSE lexicographic order.

    A filesystem's readdir order is its own business -- APFS returns something
    hash-shaped, ext4 something else -- so a test that merely runs twice on
    this machine proves determinism within one process and nothing about the
    property that matters. Forcing the worst order makes the assertion below
    discriminate the two implementations on any filesystem, which is the only
    way this test can be red on the code it was written against.

    Only the fd form is reordered: that is how the walk calls scandir, and
    every other caller in the process (pytest included) passes a path.
    """
    real = os.scandir

    def ordered(target):
        if not isinstance(target, int):
            return real(target)
        with real(target) as entries:
            return _Ordered(sorted((_Entry(e) for e in entries),
                                   key=lambda e: e.name, reverse=True))

    monkeypatch.setattr(os, "scandir", ordered)
    # The broker refuses to open anything unless `os.scandir` is one of the
    # functions that accept a descriptor (codex_read_tools._open's platform
    # check). Swapping the function drops it out of that set, so the stand-in
    # has to be declared fd-capable or every read is denied and the assertion
    # below would pass for the wrong reason.
    monkeypatch.setattr(os, "supports_fd", os.supports_fd | {ordered})


def test_a_truncated_walk_keeps_the_same_files_on_any_filesystem(tree, monkeypatch):
    # N-M2 pushed subdirectories onto the LIFO stack reverse-sorted, so the
    # walk DESCENDS lexicographically. R23-M1: within a directory, files were
    # still added in os.scandir order and the cap trips mid-directory, so
    # WHICH files survived from the boundary directory stayed exactly as
    # filesystem-dependent as before -- and the test that was supposed to
    # prove otherwise could not tell the two walks apart on APFS.
    _root, source, _first, _second, _outside = tree
    for name in ("delta", "alpha", "charlie", "bravo"):
        (source / name).mkdir()
        for number in range(3):
            (source / name / ("f%d.txt" % number)).write_text("x\n", encoding="utf-8")
    monkeypatch.setattr(read_tools, "MAX_FILES", 6)

    def listing():
        # Relative, for the same reason N-I2 exists: this test's own tmp_path
        # basename can contain a word the filter looks for, so judging
        # absolute lines discards them.
        text = body(reader_for(tree, directories=True).call("list_files", {"pattern": "*"}))
        return sorted(os.path.relpath(line, str(_root)).replace(os.sep, "/")
                      for line in text.splitlines() if line.startswith(str(_root))), text

    # Six names: the two files in `source`, then the lexicographically first
    # subtree whole, then as much of the next as fits. Not "some alpha file
    # survived" -- the exact prefix, which is the only claim worth making.
    expected = ["source/alpha/f0.txt", "source/alpha/f1.txt", "source/alpha/f2.txt",
                "source/bravo/f0.txt", "source/first.py", "source/second.txt"]

    kept, text = listing()
    assert text.splitlines()[-1].startswith("[truncated:")
    assert kept == expected

    # The same answer under a filesystem that hands back the worst possible
    # order. THIS is the assertion that goes red on the pre-fix walk, which
    # keeps source/bravo/f2.txt here instead of source/bravo/f0.txt.
    with monkeypatch.context() as adversary:
        _reverse_scandir(adversary)
        hostile, hostile_text = listing()
    assert hostile_text.splitlines()[-1].startswith("[truncated:")
    assert hostile == expected
