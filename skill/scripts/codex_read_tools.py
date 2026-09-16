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
# How a path was authorized, threaded from `_require` into `_open` (#1642).
# A DIRECTORY grant names a SUBTREE, and `_under` matches it by name, so a link
# planted inside it can name an inode outside it; an EXACT grant names the file
# the orchestrator chose. `_open` needs that distinction and must not re-derive
# it, so the authorizer hands it over. DIR_GRANT is the default everywhere
# below: a caller that forgets to say gets the strict rule, not the loose one.
DIR_GRANT = "dirs"
EXACT_GRANT = "files"
# One wording for one rule, across three brokers. read_guard_hook and
# kimi_guard_hook are stdlib-only and standing alone (no package on sys.path),
# so each spells its own copy; tests/test_codex_read_tools.py::
# test_the_hard_link_denial_is_one_wording pins the three equal.
HARD_LINK_DENIAL = "read scope denies a hard-linked file inside a directory grant (st_nlink=%d)"
# Directory NAMES and basename GLOBS the walk skips at every depth. A directory
# grant is the whole repository for the setup scan, and a checkout's VCS store
# and dependency trees hold far more entries than its source does -- walking
# them exhausts the caps below before a single reviewable file is reached,
# which is what made list_files unusable on any real target.
#
# These MUST stay equal to discovery.EXCLUDE_DIRS / EXCLUDE_DIR_GLOBS, which
# say what the agentic scan prunes and carry the "single maintenance point"
# comment: a name here that is not there means Codex and Claude cover the same
# tree differently, silently. They are duplicated rather than imported because
# codex_host.safety_config() launches this module as `sys.executable -I
# <path>`, and -I implies -P: the script's directory is off sys.path, so the
# broker is stdlib-only by construction. tests/test_codex_read_tools.py::
# test_the_exclusion_list_matches_the_one_discovery_prunes pins the equality.
#
# The two additions are `.panopticon` and `.worktrees`. Discovery reaches the
# same answer through git -- its surface is `git ls-files --exclude-standard`,
# so everything the target ignores is already gone -- and the broker has no
# git; both are in this repo's .gitignore, which that same test checks.
EXCLUDED_DIRECTORIES = (
    ".eggs", ".git", ".hg", ".mypy_cache", ".panopticon", ".pytest_cache",
    ".ruff_cache", ".svn", ".tox", ".venv", ".worktrees", "__pycache__",
    "htmlcov", "node_modules", "tmp", "venv",
)
EXCLUDED_DIRECTORY_GLOBS = ("*.egg-info",)
# N-M2: what the walk actually did. The old wording, "N of M entries
# shown", paired the PATTERN-FILTERED count with the ENUMERATED count --
# "1 of 5" over a thirteen-file tree -- which is two different questions.
TRUNCATION_NOTE = "[truncated: enumeration stopped at %d files; pass path= to narrow]"
# Fix round 1 (F2): what a directory-wide search did NOT read, and why. One
# planted hard link must not refuse the whole call -- a read fence's job is to
# make that content unreachable, which a skip does as well as an abort, while
# an abort also destroys the in-scope answer and hands a target an evasion
# lever costing one `ln`. Same idiom as the truncation notes above: a partial
# answer with a named reason. An EXPLICIT `search path=<the link>` is still a
# refusal -- there the reviewer named that file and nothing else is an answer.
SKIPPED_NOTE = "[skipped %s: %s]"
# Fix round 2 (N1): and a BOUND on that block. Unbounded, the disclosure became
# the payload -- the notes lead the body and `_result` truncates the tail, so a
# few hundred planted links filled the answer with notes and pushed every real
# match out of it, which is F2's evasion again at a few hundred `ln`s instead of
# one. Eight names are enough to act on; the rest are a count. Constant-size, so
# it can neither be truncated away nor crowd out what the reviewer asked for.
MAX_SKIP_NOTES = 8
SKIPPED_MORE_NOTE = "[skipped %d more hard-linked files inside this directory grant]"
# Fix round 3 (N5): and a bound in BYTES, because eight notes are not eight
# bounded notes. `_open` walks component-by-component with dir_fd and `_files`
# joins without a length check, so the broker reaches -- and NAMES -- paths far
# past PATH_MAX: one link at the bottom of a 300-deep tree of 200-char names is
# a single ~60 KB note that eats the whole output budget on its own, which is
# N1's crowding-out again for one `ln` plus a mkdir loop. So each note's path is
# elided from the MIDDLE (both ends identify the file; the middle is the part a
# target pads), and the block as a whole is capped -- anything over either bound
# folds into the count, which is itself one constant-size line.
MAX_SKIP_NOTE_BYTES = 2048
SKIP_PATH_WINDOW = 48


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


def _excluded_dir(name):
    """Discovery's `_is_excluded_dir`, over the copies above."""
    return (name in EXCLUDED_DIRECTORIES
            or any(fnmatch.fnmatchcase(name, glob) for glob in EXCLUDED_DIRECTORY_GLOBS))


def _path(value, cwd):
    if not isinstance(value, str) or not value or "\0" in value or len(value) > 8192:
        raise ValueError("invalid scope path")
    return os.path.abspath(os.path.join(cwd, value))


def _under(path, directory):
    return path == directory or path.startswith(directory.rstrip(os.sep) + os.sep)


class HardLinkDenied(ValueError):
    """A multiply-linked file refused inside a directory grant (#1642).

    A ValueError like every other refusal here, so `call` reports it the same
    way -- but its OWN type, because search classifies file-vs-directory by
    catching ValueError out of `_open` and falling back to a walk. A denial read
    as "that path must be a directory" would answer a refused read with a
    listing of the grant instead of the refusal.
    """


@contextmanager
def _open(path, *, directory=False, grant=DIR_GRANT):
    """Open a regular file/directory without any symlink traversal, even races.

    M-3/#1642: O_NOFOLLOW stops SYMlinks, not HARD links, and `_under`
    authorizes a directory grant by NAME -- so a target repository that plants a
    link inside the granted subtree naming a same-filesystem inode outside it
    used to read through that grant, because the link IS the file. A regular
    file a DIRECTORY grant admits is therefore refused when it carries more than
    one link; a file an EXACT grant names (`scope.files`/`scope.reads`) is what
    the orchestrator chose on purpose and stays readable whatever its link
    count. The cost is deliberate: ordinary hard-linked build output under a
    directory grant is unreadable, and shows in the transcript as this denial
    (docs/PANOPTICON.md's Codex section says so).

    The link count is read off the OPEN DESCRIPTOR, after the same walk that
    refuses symlinks, so no rename or relink between the check and the read can
    widen it. Directories are not the subject -- a directory's link count is its
    subdirectory count, and `list_files` enumerates NAMES, which is not reading
    the content a grant confines.
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
        info = os.fstat(fd)
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise ValueError("read scope permits regular files only")
        if not directory and grant == DIR_GRANT and info.st_nlink > 1:
            raise HardLinkDenied(HARD_LINK_DENIAL % info.st_nlink)
        yield fd
    finally:
        os.close(fd)


def _read(path, *, grant=DIR_GRANT):
    with _open(path, grant=grant) as fd:
        chunks, remaining = [], MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    data = b"".join(chunks)
    return data[:MAX_FILE_BYTES].decode("utf-8", errors="replace"), len(data) > MAX_FILE_BYTES


def _elided(path, window=SKIP_PATH_WINDOW):
    """`path` with its middle replaced by an ellipsis, to a fixed width.

    Both ends are kept: the head says which grant it sits under and the tail
    names the file, which is what a reviewer with `list_files` needs to find it.
    Only the middle -- the segment a hostile tree pads -- is dropped.
    """
    if len(path) <= 2 * window + 1:
        return path
    return path[:window] + "\u2026" + path[-window:]


def _body(matches, skipped, more=0, tail=None):
    """One search body: the disclosure lines FIRST, then matches, then `tail`.

    Notes lead because `_result` truncates the TAIL of an over-long body, and a
    disclosure that can be cut off is not one. The truncation tail survives its
    own removal -- `_result` says the output was truncated -- but "this file was
    skipped, and why" exists nowhere else. `skipped` is capped by the caller at
    MAX_SKIP_NOTES notes AND MAX_SKIP_NOTE_BYTES bytes, with `more` carrying
    whatever either cap dropped, so the block that leads is bounded no matter
    how many links a target plants (N1) or how deep it buries them (N5).
    """
    notes = list(skipped) + ([SKIPPED_MORE_NOTE % more] if more else [])
    return "\n".join(notes + list(matches) + ([tail] if tail else []))


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
        """Which grant kind authorizes `path` (EXACT_GRANT/DIR_GRANT), or None.

        EXACT wins wherever both do: a cell's granted files usually sit inside
        some directory grant, and a file the orchestrator named must not be
        narrowed by the subtree it happens to live in (#1642).
        """
        if path in self.scope["files"] or path in self.scope["reads"]:
            return EXACT_GRANT
        if any(_under(path, directory) for directory in self.scope["dirs"]):
            return DIR_GRANT
        return None

    def _require(self, path, *, directory=False):
        """Authorize `path` and return HOW -- the fact `_open` needs and may not
        re-derive. `directory=True` asks only about directory grants."""
        grant = ((DIR_GRANT if any(_under(path, d) for d in self.scope["dirs"]) else None)
                 if directory else self._allowed(path))
        if grant is None:
            raise ValueError("Denied: %s is outside this entry's read scope" % path)
        return grant

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
            children, here = [], []
            with _open(directory, directory=True) as fd, os.scandir(fd) as entries:
                for entry in entries:
                    examined += 1
                    if examined > MAX_ENTRIES:
                        truncated = True
                        break
                    path = os.path.join(directory, entry.name)
                    if entry.is_dir(follow_symlinks=False):
                        if not _excluded_dir(entry.name):
                            children.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        here.append(path)
            # R23-M1: the cap trips inside ONE directory, so that directory's
            # files have to be ordered before the cap sees them or which of
            # them survives is whatever readdir felt like -- the half of the
            # stability claim that pushing children reverse-sorted does not
            # buy. The whole directory is read first because a lexicographic
            # prefix cannot be known from a partial read.
            for path in sorted(here):
                found.add(path)
                # N-M1: `>` not `>=`. Stopping ON the MAX_FILES-th file marked
                # a listing truncated before anything had been dropped, and
                # told the reviewer to narrow a path that was already whole.
                if len(found) > MAX_FILES:
                    found.discard(path)
                    truncated = True
                    break
            # N-M2: `pending` is a LIFO stack, so pushing this directory's
            # children reverse-sorted makes the walk DESCEND lexicographically.
            # With the sort above, a truncated listing is the tree's true
            # lexicographic prefix on every filesystem, not a sorted view of an
            # arbitrary subset.
            pending.extend(sorted(children, reverse=True))
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
                grant = self._require(path)
                offset, limit = arguments.get("offset", 1), arguments.get("limit", 200)
                if (type(offset) is not int or type(limit) is not int
                        or not 1 <= offset <= 100000 or not 1 <= limit <= 1000):
                    raise ValueError("offset/limit outside bounded read range")
                data, truncated = _read(path, grant=grant)
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
                    text += ("\n" if text else "") + TRUNCATION_NOTE % len(files)
                return _result(text)
            walk_truncated = False
            if "path" in arguments:
                path = _path(arguments["path"], self.cwd)
                grant = self._require(path)
                # Directory classification also refuses symlinks and nonregular files.
                try:
                    with _open(path, grant=grant):
                        pass
                    files = [path]
                except HardLinkDenied:
                    raise            # a refusal of THIS path, never "it is a directory"
                except (IsADirectoryError, ValueError):
                    files, walk_truncated = self._files(self._roots(arguments))
            else:
                if not self.scope["dirs"]:
                    raise ValueError("search outside directory scope denied; supply an explicit granted file")
                files, walk_truncated = self._files(self._roots(arguments))
            matches, skipped, more, total = [], [], 0, 0
            note_bytes = 0
            for path in files:
                try:
                    data, truncated = _read(path, grant=self._require(path))
                except HardLinkDenied as exc:
                    # F2: skip THIS file, disclose it, keep the rest of the
                    # answer. N1: name the first MAX_SKIP_NOTES, count the rest.
                    # N5: and stop at MAX_SKIP_NOTE_BYTES, whichever comes first,
                    # over paths elided to a fixed width. Both bounds are applied
                    # HERE, before the body is assembled, so whatever the notes
                    # do not spend is left to the matches.
                    note = SKIPPED_NOTE % (_elided(path), exc)
                    size = len(note.encode("utf-8")) + 1
                    if len(skipped) < MAX_SKIP_NOTES and note_bytes + size <= MAX_SKIP_NOTE_BYTES:
                        skipped.append(note)
                        note_bytes += size
                    else:
                        more += 1
                    continue
                total += len(data.encode("utf-8"))
                for number, line in enumerate(data.splitlines(), 1):
                    if pattern in line:
                        matches.append("%s:%d:%s" % (path, number, line))
                        if len(matches) >= 200 or sum(map(len, matches)) >= MAX_OUTPUT_CHARS:
                            return _result(_body(matches, skipped, more, "[search truncated]"))
                if truncated or total >= MAX_SEARCH_BYTES:
                    return _result(_body(matches, skipped, more,
                                         "[search truncated; pass path= to narrow]"))
            return _result(_body(matches, skipped, more,
                                 TRUNCATION_NOTE % len(files) if walk_truncated else None))
        except (OSError, ValueError, TypeError) as exc:
            return _result("Read tool refused: " + str(exc), error=True)


def load_reader(env=None, cwd=None):
    env = os.environ if env is None else env
    entry_id, scope_path = env.get("PANOPTICON_ENTRY_ID"), env.get("PANOPTICON_READ_SCOPE")
    if (not isinstance(entry_id, str) or not entry_id or not isinstance(scope_path, str)
            or not scope_path or not os.path.isabs(scope_path)):
        raise ValueError("missing read scope entry/path binding")
    # EXACT: the scope file is the env BINDING, not something a grant admits --
    # it is named by PANOPTICON_READ_SCOPE, which the launcher sets (#1642).
    data, truncated = _read(scope_path, grant=EXACT_GRANT)
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
