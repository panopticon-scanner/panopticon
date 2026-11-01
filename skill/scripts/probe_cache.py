"""Operator-side cache for host posture measurements (#3272 cut 9).

The reviewed tree cannot vouch for a measurement about the reviewer.  Cache
rows therefore live beside the run-stamp key under ``PANOPTICON_STATE_DIR``
and never under ``.panopticon``.  A row is reusable for at most 24 hours and
only for the same host, the same ``(sha256, version)`` external-app identity,
the same installed measuring code, and the same settings fingerprint.  A
future timestamp, missing identity, or unreadable/malformed cache is a miss:
the cache is an optimisation, never evidence by itself.

Target-authored shadow/discovery scans are deliberately outside this module.
They still run on every driver invocation; only conclusive host/CLI
measurements are cached.  An unknown result is measured again next time.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
import time

from scripts import _version, collect_usage, dispatch, hosts, run_stamp, safe_write


CACHE_SCHEMA_VERSION = 1
CACHE_KEY_REVISION = 2
CACHE_NAME = "host-probe-cache-%s.json"
CACHE_MAX_BYTES = 1 << 20
SETTING_MAX_BYTES = 4 << 20
CACHE_TTL_SECONDS = 24 * 60 * 60
SOURCE_ROOT = os.path.dirname(os.path.abspath(__file__))
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HOST = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
CLI_FLAGS_ID = "operational-cli-flags"
_now = time.time


def _measurement_source_names(root=None):
    """Every runtime Python source, a safe superset of probe dependencies."""
    root = os.path.abspath(root or SOURCE_ROOT)
    if not os.path.isdir(root):
        raise OSError("measurement source root is not a directory: %s" % root)
    names: list[str] = []
    for base, dirs, files in os.walk(root):
        dirs[:] = sorted(name for name in dirs if name != "__pycache__")
        names.extend(os.path.relpath(os.path.join(base, name), root)
                     for name in sorted(files) if name.endswith(".py"))
    if not names:
        raise ValueError("measurement source root contains no Python sources")
    return tuple(names)


def measurement_source_fingerprint(root=None):
    """Digest the installed measuring code; any unreadable source is a miss."""
    root = os.path.abspath(root or SOURCE_ROOT)
    digest = hashlib.sha256()
    for name in _measurement_source_names(root):
        raw = safe_write.read_regular_bytes(
            os.path.join(root, name), SETTING_MAX_BYTES)
        encoded_name = name.encode("utf-8", "surrogateescape")
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _digest_file(path):
    try:
        raw = safe_write.read_regular_bytes(path, SETTING_MAX_BYTES)
    except (OSError, ValueError):
        return None
    return hashlib.sha256(raw).hexdigest()


def _path_record(path, *, digest=True):
    """A bounded, JSON-shaped fingerprint of one settings input."""
    if not path:
        return None
    lexical = os.path.abspath(os.fspath(path))
    real = os.path.realpath(lexical)
    try:
        info = os.stat(real)
    except OSError as exc:
        parent = os.path.dirname(real) or os.curdir
        return {"path": lexical, "real": real, "missing": type(exc).__name__,
                "parent_writable": os.access(parent, os.W_OK)}
    kind = ("file" if stat.S_ISREG(info.st_mode)
            else "dir" if stat.S_ISDIR(info.st_mode) else "other")
    record = {"path": lexical, "real": real, "kind": kind,
              "mode": stat.S_IMODE(info.st_mode),
              "readable": os.access(real, os.R_OK),
              "writable": os.access(real, os.W_OK)}
    if kind == "file":
        record["size"] = info.st_size
    if kind == "file" and digest:
        record["sha256"] = _digest_file(real)
        # A content-identical atomic rewrite does not change what a probe
        # reads and must not rebuy it.  When the file is too large or cannot
        # be hashed, metadata is the conservative fallback.
        if record["sha256"] is None:
            record["mtime_ns"] = info.st_mtime_ns
    return record


def _registration_records(host, registration_dir):
    row = hosts.spec(host)
    directory = registration_dir or (row.registration_dir if row else "")
    records = [_path_record(directory)]
    if directory:
        for role_file in sorted(dispatch.ROLE_FILES.values()):
            records.append(_path_record(os.path.join(
                directory, dispatch.registered_agent_filename(host, role_file))))
    return records


def _template_records():
    records = [_path_record(_version.reference_path("model-profiles.yml"))]
    records.extend(_path_record(os.path.join(dispatch.TEMPLATE_DIR, role_file))
                   for role_file in sorted(dispatch.ROLE_FILES.values()))
    return records


def _settings_records(host, session_root, settings_path, home):
    records = [_path_record(settings_path)]
    if settings_path:
        records.append(_path_record(os.path.dirname(os.path.abspath(settings_path))))
    if host == "claude":
        operator_home = os.path.abspath(home or os.path.expanduser("~"))
        # The session-mode probes resolve this exact file.  The real-CLI
        # canary also retains Claude's user setting source, so those files are
        # inputs even though its run-owned --settings file is isolated.
        if session_root:
            records.append(_path_record(os.path.join(
                os.path.abspath(session_root), ".claude", "settings.local.json")))
        records.extend(_path_record(os.path.join(operator_home, suffix)) for suffix in (
            os.path.join(".claude", "settings.json"),
            os.path.join(".claude", "settings.local.json"),
            ".claude.json",
        ))
    elif host == "kimi":
        operator_home = os.path.abspath(home or os.path.expanduser("~"))
        kimi_home = os.environ.get("KIMI_CODE_HOME")
        if not kimi_home:
            kimi_home = os.path.join(operator_home, ".kimi-code")
        records.append(_path_record(os.path.join(os.path.abspath(kimi_home),
                                                 "config.toml")))
    return records


def settings_fingerprint(host, *, registration_dir=None, session_root=None,
                         settings_path=None, home=None):
    """Digest every stable setting that feeds a host probe."""
    row = hosts.spec(host)
    env_names = set(getattr(row, "detect_env", ()) if row else ())
    env_names.update("PANOPTICON_MODEL_%s" % role.upper()
                     for role in dispatch.ROLE_FILES)
    material = {
        "panopticon": _version.__version__,
        "measurement_sources": measurement_source_fingerprint(),
        "registration": _registration_records(host, registration_dir),
        "settings": _settings_records(host, session_root, settings_path, home),
        "templates": _template_records(),
        "environment": {name: os.environ.get(name) for name in sorted(env_names)},
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _wire_records(run_home):
    """Metadata for Kimi's bounded effective-surface input.

    The probe itself chooses the newest ``wire.jsonl``.  Names, sizes and
    nanosecond mtimes are enough to invalidate its cached result without
    reading every (potentially large) conversation wire merely to decide
    whether the real probe must read one.
    """
    if not run_home or not os.path.isdir(run_home):
        return [_path_record(run_home)]
    found = []
    for root, dirs, files in os.walk(run_home):
        dirs.sort()
        for name in sorted(files):
            if name == "wire.jsonl":
                path = os.path.join(root, name)
                record = _path_record(path, digest=False)
                try:
                    record["mtime_ns"] = os.stat(path).st_mtime_ns
                except (OSError, TypeError):
                    pass
                found.append(record)
                if len(found) >= 128:
                    return found
    return found or [_path_record(run_home)]


def dynamic_fingerprint(host, probe_id, *, session_root=None,
                        settings_path=None, home=None, run_home=None):
    """Digest the evidence that changes for only one probe."""
    material = None
    if host == "claude" and probe_id == "usage-source":
        if settings_path:
            from scripts.runners import base as runners_base
            material = _path_record(os.path.join(
                os.path.dirname(os.path.abspath(settings_path)), runners_base.LEDGER_FILE))
        else:
            operator_home = os.path.abspath(home or os.path.expanduser("~"))
            material = _path_record(os.path.join(
                operator_home, ".claude", "projects",
                collect_usage.project_slug(session_root or os.getcwd())))
    elif host == "kimi" and probe_id == "kimi-shell-surface":
        material = _wire_records(run_home)
    if material is None:
        return ""
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _app_identity(host, apps):
    row = hosts.spec(host)
    binary = getattr(row, "cli_binary", "") if row else ""
    matching = [app for app in apps if isinstance(app, dict)
                and app.get("name") == binary]
    if len(matching) != 1:
        return None
    sha, version = matching[0].get("sha256"), matching[0].get("version")
    if not (isinstance(sha, str) and _SHA256.fullmatch(sha)
            and isinstance(version, str) and version):
        return None
    return sha, version


def _cache_path(host):
    if not isinstance(host, str) or not _HOST.fullmatch(host):
        return None
    return os.path.join(run_stamp.state_dir(), CACHE_NAME % host)


def _load(path, host):
    try:
        flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                raise ValueError("unsafe probe-cache file")
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                raw = stream.read(CACHE_MAX_BYTES + 1)
        finally:
            if fd >= 0:
                os.close(fd)
        if len(raw) > CACHE_MAX_BYTES:
            raise ValueError("oversized probe-cache file")
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, RecursionError, MemoryError):
        return {}
    if (not isinstance(document, dict)
            or document.get("schema_version") != CACHE_SCHEMA_VERSION
            or document.get("host") != host
            or not isinstance(document.get("entries"), dict)
            or len(document["entries"]) > 32):
        return {}
    return document["entries"]


def _save(path, host, entries):
    """Best-effort atomic 0600 write; a cache failure never gates a run."""
    directory = os.path.dirname(path)
    staging = os.path.join(directory, ".%s.%s.tmp" % (
        os.path.basename(path), secrets.token_hex(8)))
    fd = -1
    try:
        run_stamp._ensure_dir(directory)
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(staging, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            json.dump({"schema_version": CACHE_SCHEMA_VERSION, "host": host,
                       "entries": entries}, stream, sort_keys=True,
                      separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staging, path)
    except (OSError, ValueError):
        pass
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(staging)
        except OSError:
            pass


def _clock():
    try:
        now = _now()
    except (OSError, OverflowError, TypeError, ValueError):
        return None
    if type(now) not in (int, float) or not math.isfinite(now):
        return None
    return now


def _fresh(measured_at):
    if (type(measured_at) not in (int, float)
            or not math.isfinite(measured_at)):
        return False
    now = _clock()
    if now is None:
        return False
    age = now - measured_at
    return 0 <= age <= CACHE_TTL_SECONDS


class ProbeCache:
    """One invocation's view of one host's persisted probe rows."""

    def __init__(self, host, apps, *, registration_dir=None, session_root=None,
                 settings_path=None, home=None):
        self.host = host
        self.path = _cache_path(host)
        self.identity = _app_identity(host, apps)
        self.enabled = self.path is not None and self.identity is not None
        try:
            if self.enabled:
                run_stamp._ensure_dir(os.path.dirname(self.path))
            self.settings = (settings_fingerprint(
                host, registration_dir=registration_dir, session_root=session_root,
                settings_path=settings_path, home=home) if self.enabled else "")
        except (OSError, TypeError, UnicodeError, ValueError):
            self.settings = ""
            self.enabled = False
        self.entries = _load(self.path, host) if self.enabled else {}
        self.dirty = False

    def _key(self, probe_id, dynamic=""):
        material = [CACHE_KEY_REVISION, self.host, *self.identity,
                    self.settings, probe_id, dynamic]
        encoded = json.dumps(material, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def get(self, probe_id, dynamic=""):
        if not self.enabled:
            return False, None
        row = self.entries.get(probe_id)
        key = self._key(probe_id, dynamic)
        if (not isinstance(row, dict) or row.get("key") != key
                or "value" not in row or not _fresh(row.get("measured_at"))):
            return False, None
        return True, row["value"]

    def put(self, probe_id, value, dynamic=""):
        if not self.enabled:
            return
        measured_at = _clock()
        if measured_at is None:
            return
        self.entries[probe_id] = {
            "key": self._key(probe_id, dynamic),
            "measured_at": measured_at,
            "value": value,
        }
        self.dirty = True

    def flush(self):
        if self.enabled and self.dirty:
            _save(self.path, self.host, self.entries)
            self.dirty = False
