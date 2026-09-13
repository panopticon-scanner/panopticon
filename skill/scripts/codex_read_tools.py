"""Codex's stdio MCP read surface, bound to one armed dispatch entry.

No host launch or review workflow lives here. Paths are matched lexically to
the driver's realpath-normalised grants, then opened component by component
without following links. Platforms without secure descriptor-relative opens
fail closed; a sandbox or a prompt is not this server's policy boundary.
"""
from contextlib import contextmanager
import fnmatch
import json
import os
import stat
import sys


MAX_REQUEST_BYTES = 64 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_OUTPUT_CHARS = 48 * 1024
MAX_FILES = 4096
MAX_DIRECTORIES = 512
MAX_ENTRIES = 20000
MAX_SEARCH_BYTES = 8 * MAX_FILE_BYTES
SCOPE_KEYS = ("files", "dirs", "reads")
# Directory NAMES the walk skips at every depth. A directory grant is the whole
# repository for the setup scan, and a checkout's VCS store and vendored trees
# hold far more entries than its source does -- enumerating them exhausts the
# caps below before a single reviewable file is reached, which is what made
# list_files unusable on any real target. None of them is review material, so
# skipping them costs no coverage; a reviewer that genuinely needs one still
# has read_file on an explicitly granted path.
EXCLUDED_DIRECTORIES = (
    ".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv",
    "__pycache__", ".worktrees", ".panopticon", ".tox", ".mypy_cache",
    ".ruff_cache", ".pytest_cache", "dist", "build", "target",
)
TRUNCATION_NOTE = "[truncated: %d of %d entries shown; pass path= to narrow]"


def _tool(name, description, properties, required=()):
    return {"name": name, "description": description, "annotations": {
        "readOnlyHint": True, "destructiveHint": False,
        "openWorldHint": False, "idempotentHint": True}, "inputSchema": {
        "type": "object", "properties": properties, "required": list(required),
        "additionalProperties": False}}


TOOLS = [
    _tool("read_file", "Read bounded, numbered lines of one file in this entry's scope.", {
        "path": {"type": "string"}, "offset": {"type": "integer", "minimum": 1},
        "limit": {"type": "integer", "minimum": 1, "maximum": 1000}}, ("path",)),
    _tool("search", "Literal substring search. File-only scopes require an explicit file path.", {
        "pattern": {"type": "string"}, "path": {"type": "string"}}, ("pattern",)),
    _tool("list_files", "List files within this entry's directory grants; no file-only listing. "
          "Pass path to list one granted subdirectory.", {
        "pattern": {"type": "string"}, "path": {"type": "string"}}),
]


def _path(value, cwd):
    if not isinstance(value, str) or not value or "\0" in value or len(value) > 8192:
        raise ValueError("invalid scope path")
    return os.path.abspath(os.path.join(cwd, value))


def _under(path, directory):
    return path == directory or path.startswith(directory.rstrip(os.sep) + os.sep)


@contextmanager
def _open(path, *, directory=False):
    """Open a regular file/directory without any symlink traversal, even races.

    M-3, recorded limit: O_NOFOLLOW stops SYMlinks, not HARD links. A target
    repository that ships a hard link inside a directory grant to a file
    outside it stays readable through that grant, because the link is the
    file. This is inherent to path-based confinement -- Claude's read guard
    has the same property -- and closing it would mean refusing st_nlink > 1
    inside a directory grant, which also refuses ordinary hard-linked build
    output. Not fixed here; documented in docs/PANOPTICON.md's Codex section
    so it is a known boundary rather than an assumed one.
    """
    if (os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
            or os.open not in os.supports_dir_fd or os.scandir not in os.supports_fd):
        raise ValueError("secure read scope opens unavailable on this platform")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(os.sep, flags | os.O_DIRECTORY)
    try:
        parts = [part for part in path.split(os.sep) if part]
        for index, part in enumerate(parts):
            want_dir = directory or index < len(parts) - 1
            child = os.open(part, flags | (os.O_DIRECTORY if want_dir else 0), dir_fd=fd)
            os.close(fd)
            fd = child
        mode = os.fstat(fd).st_mode
        if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
            raise ValueError("read scope permits regular files only")
        yield fd
    finally:
        os.close(fd)


def _read(path):
    with _open(path) as fd:
        chunks, remaining = [], MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    data = b"".join(chunks)
    return data[:MAX_FILE_BYTES].decode("utf-8", errors="replace"), len(data) > MAX_FILE_BYTES


def _result(text, error=False):
    if len(text) > MAX_OUTPUT_CHARS:
        text = text[:MAX_OUTPUT_CHARS] + "\n[output truncated]"
    return {"content": [{"type": "text", "text": text}], "isError": error}


class Reader:
    def __init__(self, scope, cwd):
        self.cwd = os.path.realpath(cwd)
        if not isinstance(scope, dict):
            raise ValueError("missing or malformed read scope")
        self.scope = {}
        for key in SCOPE_KEYS:
            values = scope.get(key, [])
            if (not isinstance(values, list) or len(values) > MAX_FILES
                    or any(not isinstance(v, str) or not os.path.isabs(v) for v in values)):
                raise ValueError("malformed read scope " + key)
            self.scope[key] = frozenset(_path(value, self.cwd) for value in values)

    def _allowed(self, path):
        return (path in self.scope["files"] or path in self.scope["reads"]
                or any(_under(path, directory) for directory in self.scope["dirs"]))

    def _require(self, path, *, directory=False):
        allowed = (any(_under(path, d) for d in self.scope["dirs"])
                   if directory else self._allowed(path))
        if not allowed:
            raise ValueError("Denied: %s is outside this entry's read scope" % path)

    def _files(self, directories):
        """Bounded descriptor-based enumeration; never walk linked directories.

        Returns (files, truncated). A cap STOPS the walk and marks the answer
        truncated rather than refusing it: refusing made the only Glob a Codex
        reviewer has fail outright on every repository larger than the caps,
        while advising it to "narrow the path" -- which list_files had no way
        to accept. A bounded listing plus an explicit truncation line is both
        honest and actionable; `path` is how the reviewer narrows.
        """
        pending, found, visited, examined = sorted(directories, reverse=True), set(), 0, 0
        truncated = False
        while pending and not truncated:
            directory = pending.pop()
            visited += 1
            if visited > MAX_DIRECTORIES:
                truncated = True
                break
            with _open(directory, directory=True) as fd, os.scandir(fd) as entries:
                for entry in entries:
                    examined += 1
                    if examined > MAX_ENTRIES:
                        truncated = True
                        break
                    path = os.path.join(directory, entry.name)
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name not in EXCLUDED_DIRECTORIES:
                            pending.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        found.add(path)
                        if len(found) >= MAX_FILES:
                            truncated = True
                            break
        return sorted(found), truncated

    def _roots(self, arguments):
        """The directory grants one enumeration walks: all of them, or the
        single granted subtree `path` names (checked exactly like a read)."""
        if "path" in arguments:
            path = _path(arguments["path"], self.cwd)
            self._require(path, directory=True)
            return [path]
        if not self.scope["dirs"]:
            raise ValueError("listing outside directory scope denied; use an explicit granted file")
        return sorted(self.scope["dirs"])

    def call(self, name, arguments):
        try:
            descriptor = next((tool for tool in TOOLS if tool["name"] == name), None)
            if descriptor is None:
                raise ValueError("unknown read tool")
            schema = descriptor["inputSchema"]
            if (not isinstance(arguments, dict) or set(arguments) - set(schema["properties"])
                    or set(schema["required"]) - set(arguments)):
                raise ValueError("invalid read tool arguments")
            if name == "read_file":
                path = _path(arguments["path"], self.cwd)
                self._require(path)
                offset, limit = arguments.get("offset", 1), arguments.get("limit", 200)
                if (type(offset) is not int or type(limit) is not int
                        or not 1 <= offset <= 100000 or not 1 <= limit <= 1000):
                    raise ValueError("offset/limit outside bounded read range")
                data, truncated = _read(path)
                lines = data.splitlines()
                text = "\n".join("%s:%d:%s" % (path, n + 1, lines[n])
                                 for n in range(offset - 1, min(len(lines), offset - 1 + limit)))
                if truncated or len(lines) > offset - 1 + limit:
                    text += "\n[file truncated; request a narrower line range]"
                return _result(text)
            pattern = arguments.get("pattern", "*")
            if not isinstance(pattern, str) or not pattern or len(pattern) > 4096:
                raise ValueError("invalid bounded search/list pattern")
            if name == "list_files":
                files, truncated = self._files(self._roots(arguments))
                shown = [path for path in files
                         if fnmatch.fnmatchcase(os.path.relpath(path, self.cwd), pattern)]
                text = "\n".join(shown)
                if truncated:
                    text += ("\n" if text else "") + TRUNCATION_NOTE % (len(shown), len(files))
                return _result(text)
            walk_truncated = False
            if "path" in arguments:
                path = _path(arguments["path"], self.cwd)
                self._require(path)
                # Directory classification also refuses symlinks and nonregular files.
                try:
                    with _open(path):
                        pass
                    files = [path]
                except (IsADirectoryError, ValueError):
                    files, walk_truncated = self._files(self._roots(arguments))
            else:
                if not self.scope["dirs"]:
                    raise ValueError("search outside directory scope denied; supply an explicit granted file")
                files, walk_truncated = self._files(self._roots(arguments))
            matches, total = [], 0
            for path in files:
                self._require(path)
                data, truncated = _read(path)
                total += len(data.encode("utf-8"))
                for number, line in enumerate(data.splitlines(), 1):
                    if pattern in line:
                        matches.append("%s:%d:%s" % (path, number, line))
                        if len(matches) >= 200 or sum(map(len, matches)) >= MAX_OUTPUT_CHARS:
                            return _result("\n".join(matches) + "\n[search truncated]")
                if truncated or total >= MAX_SEARCH_BYTES:
                    return _result("\n".join(matches) + "\n[search truncated; pass path= to narrow]")
            text = "\n".join(matches)
            if walk_truncated:
                text += ("\n" if text else "") + TRUNCATION_NOTE % (len(matches), len(files))
            return _result(text)
        except (OSError, ValueError, TypeError) as exc:
            return _result("Read tool refused: " + str(exc), error=True)


def load_reader(env=None, cwd=None):
    env = os.environ if env is None else env
    entry_id, scope_path = env.get("PANOPTICON_ENTRY_ID"), env.get("PANOPTICON_READ_SCOPE")
    if (not isinstance(entry_id, str) or not entry_id or not isinstance(scope_path, str)
            or not scope_path or not os.path.isabs(scope_path)):
        raise ValueError("missing read scope entry/path binding")
    data, truncated = _read(scope_path)
    if truncated:
        raise ValueError("armed read scope is too large")
    scopes = json.loads(data)
    if not isinstance(scopes, dict) or entry_id not in scopes:
        raise ValueError("armed read scope does not name this entry")
    return Reader(scopes[entry_id], cwd or env.get("PANOPTICON_REVIEW_ROOT") or os.getcwd())


def serve(reader, source, sink, binding_error=None):
    """Newline-delimited MCP JSON-RPC; injectable streams keep tests offline."""
    while True:
        line = source.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            return
        if len(line) > MAX_REQUEST_BYTES:
            sink.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {
                "code": -32700, "message": "request exceeds bounded input size"}}) + "\n")
            sink.flush()
            return
        request_id = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                raise ValueError("invalid JSON-RPC request")
            if "id" not in request:
                continue
            if type(request["id"]) not in (str, int, type(None)):
                raise ValueError("invalid request id")
            request_id = request["id"]
            method, params = request.get("method"), request.get("params", {})
            if not isinstance(params, dict):
                raise ValueError("invalid request parameters")
            if method == "initialize":
                version = params.get("protocolVersion")
                result = {"protocolVersion": version if version in (
                    "2024-11-05", "2025-03-26", "2025-06-18") else "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "panopticon-read-scope", "version": "1.0"}}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "resources/list":
                result = {"resources": []}
            elif method == "resources/templates/list":
                result = {"resourceTemplates": []}
            elif method == "tools/call":
                result = (_result("Read scope binding unavailable: " + binding_error, error=True)
                          if binding_error else reader.call(params.get("name"), params.get("arguments", {})))
            else:
                sink.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "error": {
                    "code": -32601, "message": "method not found"}}) + "\n")
                sink.flush()
                continue
            response = {"jsonrpc": "2.0", "id": request_id, "result": result}
        except json.JSONDecodeError:
            response = {"jsonrpc": "2.0", "id": request_id, "error": {
                "code": -32700, "message": "invalid JSON"}}
        except (ValueError, TypeError, RecursionError) as exc:
            response = {"jsonrpc": "2.0", "id": request_id, "error": {
                "code": -32600, "message": "invalid request: " + str(exc)}}
        sink.write(json.dumps(response) + "\n")
        sink.flush()


def main():
    try:
        reader, error = load_reader(), None
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        reader, error = None, str(exc)
    serve(reader, sys.stdin, sys.stdout, error)


if __name__ == "__main__":
    main()
