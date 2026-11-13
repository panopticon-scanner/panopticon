"""One native-language classifier shared by setup and targeted review."""
from __future__ import annotations

import os
import re
import stat

from scripts import inert


EXT_LANG = {
    ".py": "Python", ".go": "Go", ".rs": "Rust", ".js": "JavaScript",
    ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".rb": "Ruby", ".java": "Java",
    ".kt": "Kotlin", ".kts": "Kotlin", ".cs": "C#", ".php": "PHP", ".c": "C",
    ".h": "C", ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++",
    ".swift": "Swift", ".scala": "Scala", ".ex": "Elixir", ".exs": "Elixir",
    ".erl": "Erlang", ".hs": "Haskell", ".dart": "Dart", ".lua": "Lua",
    ".sh": "Shell", ".bash": "Shell", ".vue": "Vue", ".svelte": "Svelte",
    ".m": "Objective-C", ".zig": "Zig", ".clj": "Clojure", ".sql": "SQL",
}
_SHEBANG_LANG = {
    "bash": "Shell", "dash": "Shell", "ksh": "Shell", "sh": "Shell",
    "zsh": "Shell", "python": "Python", "ruby": "Ruby", "node": "JavaScript",
    "nodejs": "JavaScript", "php": "PHP", "lua": "Lua", "swift": "Swift",
    "scala": "Scala", "elixir": "Elixir", "escript": "Erlang", "dart": "Dart",
}
_SHEBANG_BYTES = 512
PATH_MAX = 4096


def repo_path(value):
    """Whether *value* is one canonical repository-relative path."""
    if (not isinstance(value, str) or not value or len(value) > PATH_MAX
            or "\\" in value or inert.inert_spelling(value) != value):
        return False
    parts = value.split("/")
    return not value.startswith("/") and all(part not in ("", ".", "..")
                                               for part in parts)


def _first_bytes(repo, rel):
    """A bounded first-line window opened below *repo* without symlinks."""
    if not repo or not repo_path(rel):
        return None
    if (not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY")
            or os.open not in os.supports_dir_fd):
        # Extensionless classification is optional evidence.  If the platform
        # cannot make the read race-safe, leave it unknown and fail closed.
        return None
    common = os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | common
    try:
        fd = os.open(os.path.realpath(repo), directory_flags)
    except (OSError, TypeError, ValueError):
        return None
    try:
        for part in rel.split("/")[:-1]:
            child = os.open(part, directory_flags, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(rel.split("/")[-1], os.O_RDONLY | common, dir_fd=fd)
        try:
            if not stat.S_ISREG(os.fstat(leaf).st_mode):
                return None
            return os.read(leaf, _SHEBANG_BYTES)
        finally:
            os.close(leaf)
    except (OSError, TypeError, ValueError):
        return None
    finally:
        os.close(fd)


def _interpreter(raw):
    line = raw.splitlines()[0].decode("utf-8", errors="replace") if raw else ""
    if not line.startswith("#!"):
        return None
    tokens = line[2:].strip().split()
    if not tokens:
        return None
    interpreter = os.path.basename(tokens[0])
    if interpreter == "env":
        tokens = tokens[1:]
        while tokens and (tokens[0].startswith("-") or "=" in tokens[0]):
            tokens = tokens[1:]
        if not tokens:
            return None
        interpreter = os.path.basename(tokens[0])
    return re.sub(r"[0-9]+(?:\.[0-9]+)*\Z", "", interpreter)


def classify(repo, rel):
    """Return ``(known, language)``; ``None`` language means known non-native."""
    if not repo_path(rel):
        return False, None
    ext = os.path.splitext(rel)[1].lower()
    if ext:
        return True, EXT_LANG.get(ext)
    raw = _first_bytes(repo, rel)
    if raw is None:
        return False, None
    return True, _SHEBANG_LANG.get(_interpreter(raw))


def native_language(repo, rel):
    """The map/shebang language for *rel*, or None when non-native/unknown."""
    return classify(repo, rel)[1]
