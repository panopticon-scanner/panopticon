"""Offline Codex MCP boundary tests: no host process, home writes, or network."""
import io
import json
import os

import pytest

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
    monkeypatch.setattr(read_tools, "MAX_FILES", 1)
    assert reader.call("list_files", {})["isError"] is True


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
