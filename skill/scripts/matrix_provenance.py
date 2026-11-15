"""#3651: where a run's matrix came from. The driver's half of `matrix_identity`.

Two measurements, both taken once when the run manifest is created, so a resumed run reports
what was true when the run began:

* `origin` -- is the config file part of the reviewed commit, byte for byte? Asked of Git
  through `safe_git.probe` (a trusted git, the target's own configuration not trusted to run),
  and answered by comparing the blob the commit holds with the bytes on disk, hashed here.
  Not by `git status`: an index flag can hide a modified file from it. Anything that cannot
  be measured is `unknown`, and unknown is never reported as reused.

  `origin` describes the repository under review, so a repository can make its own matrix
  read as committed. That is correct: it IS the pinned repository's matrix.

* the setup draft -- does a working-tree config equal the draft this target's last setup run
  wrote? That record is kept in the OPERATOR's state directory, beside the run-stamp key, and
  never read from the target: a file in the reviewed tree cannot vouch for what our own setup
  proposed.
"""
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess

from scripts import config_schema, groups_schema, matrix_identity, repo_config, run_stamp, safe_git

DRAFTS_NAME = "matrix-drafts.json"
DRAFTS_SCHEMA_VERSION = 1
_MAX_DRAFTS_BYTES = 1 << 20
_MAX_TARGETS = 512


def digest_of(doc):
    """`config_sha256` of a parsed config document, or None when its groups do not validate:
    a config a run would refuse has no identity worth recording."""
    if not isinstance(doc, dict):
        return None
    leaves, errors = groups_schema.parse_groups(doc)
    if errors or not leaves:
        return None
    parsed = config_schema.parse_settings(doc)
    return matrix_identity.config_sha256(leaves, exclude_paths=doc.get("exclude_paths"),
                                         settings=parsed.typed)


def config_digest(review_root):
    """(config path relative to the root, its `config_sha256`), each None when there is no
    readable config. One read, through the reader every run uses."""
    document = repo_config.read_document(review_root)
    if document.path is None or document.doc is None:
        return None, None
    return os.path.relpath(document.path, review_root), digest_of(document.doc)


def text_digest(text):
    """`config_sha256` of a config's YAML text: what setup hashes for the draft it writes."""
    try:
        import yaml
        return digest_of(yaml.safe_load(text))
    except Exception:                    # noqa: BLE001 -- a draft that does not parse has no identity
        return None


def _blob_oid(data, hex_length):
    """Git's object id for a blob holding `data`, in the repository's own hash."""
    algorithm = hashlib.sha256 if hex_length == 64 else hashlib.sha1
    return algorithm(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


_GIT_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def origin(review_root, relpath, runner=subprocess.run):
    """`committed` when the file at `relpath` is, byte for byte, what the reviewed tree's HEAD
    holds there; `working_tree` when HEAD holds something else or nothing; `unknown` when
    Git could not say.

    `rev-parse` is the whole of what is asked: it is plumbing the probe's allowlist already
    admits, it reads no configuration, and the object id it prints is compared with a hash
    of the bytes on disk taken here. A tree or a submodule at that path has another id, and
    a symlink in the working tree is refused before this is reached."""
    if relpath not in repo_config.CONFIG_NAMES:
        return matrix_identity.ORIGIN_UNKNOWN
    path = os.path.join(review_root, relpath)
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):     # a link or a device is not a config
            return matrix_identity.ORIGIN_UNKNOWN
        with open(path, "rb") as fh:
            data = fh.read(repo_config.MAX_CONFIG_BYTES + 1)
        if len(data) > repo_config.MAX_CONFIG_BYTES:
            return matrix_identity.ORIGIN_UNKNOWN
        # The tree, not only HEAD: a failed path lookup means "absent" only once the commit's
        # own tree has verified (`run_manifest.git_path_baseline`'s rule).
        tree = safe_git.probe(review_root, ["rev-parse", "--verify", "HEAD^{tree}"],
                              runner=runner)
        if tree.returncode != 0 or not _GIT_OID.fullmatch((tree.stdout or "").strip()):
            return matrix_identity.ORIGIN_UNKNOWN
        held = safe_git.probe(review_root, ["rev-parse", "--verify", "HEAD:" + relpath],
                              runner=runner)
    except (OSError, subprocess.SubprocessError, safe_git.RepositoryRefused):
        return matrix_identity.ORIGIN_UNKNOWN
    if held.returncode != 0:
        return matrix_identity.ORIGIN_WORKING_TREE       # the commit has no such path
    oid = (held.stdout or "").strip()
    if not _GIT_OID.fullmatch(oid):
        return matrix_identity.ORIGIN_UNKNOWN
    return (matrix_identity.ORIGIN_COMMITTED if _blob_oid(data, len(oid)) == oid
            else matrix_identity.ORIGIN_WORKING_TREE)


def _drafts_path():
    return os.path.join(run_stamp.state_dir(), DRAFTS_NAME)


def _target_key(review_root):
    return hashlib.sha256(os.path.realpath(review_root).encode("utf-8", "surrogateescape")).hexdigest()


def _load_drafts():
    """`{target key: config_sha256}` from the operator's state directory, {} on any doubt:
    a file that is not ours, not private, oversized or malformed records nothing."""
    try:
        fd = os.open(_drafts_path(), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                return {}
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                raw = stream.read(_MAX_DRAFTS_BYTES + 1)
        finally:
            if fd >= 0:
                os.close(fd)
        document = json.loads(raw.decode("utf-8")) if len(raw) <= _MAX_DRAFTS_BYTES else None
    except (OSError, UnicodeError, ValueError, RecursionError, MemoryError):
        return {}
    if (not isinstance(document, dict) or not isinstance(document.get("drafts"), dict)
            or document.get("schema_version") != DRAFTS_SCHEMA_VERSION):
        return {}
    drafts = document["drafts"]
    return {key: value for key, value in drafts.items()
            if isinstance(key, str) and matrix_identity._sha(value)}


def record_draft(review_root, digest):
    """Remember that setup's latest draft for this target hashes to `digest`. Best effort:
    a state directory that cannot be written costs the "setup's proposal" note, never setup."""
    if not matrix_identity._sha(digest):
        return False
    drafts = _load_drafts()
    drafts.pop(_target_key(review_root), None)
    drafts[_target_key(review_root)] = digest           # newest last
    drafts = dict(list(drafts.items())[-_MAX_TARGETS:])
    path = _drafts_path()
    directory = os.path.dirname(path)
    staging = os.path.join(directory, ".%s.%s.tmp" % (DRAFTS_NAME, secrets.token_hex(8)))
    fd = -1
    try:
        run_stamp._ensure_dir(directory)
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            # No `sort_keys`: the mapping's order is the order of recording, which is what
            # decides whose record is dropped once there are too many.
            json.dump({"schema_version": DRAFTS_SCHEMA_VERSION, "drafts": drafts}, stream,
                      separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staging, path)
        return True
    except (OSError, ValueError):
        return False
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(staging)
        except OSError:
            pass


def draft_state(review_root, digest):
    """`unchanged` / `differs` against setup's last recorded draft for this target, or None
    when setup recorded none (or the config has no digest)."""
    recorded = _load_drafts().get(_target_key(review_root))
    if not recorded or not matrix_identity._sha(digest):
        return None
    return (matrix_identity.DRAFT_UNCHANGED if recorded == digest
            else matrix_identity.DRAFT_DIFFERS)


def describe(review_root, runner=subprocess.run):
    """What the run manifest records about its matrix: `{origin, config, config_sha256,
    setup_draft}`. Never raises: provenance is recorded, never enforced."""
    try:
        relpath, digest = config_digest(review_root)
        where = origin(review_root, relpath, runner=runner)
        draft = (draft_state(review_root, digest)
                 if where == matrix_identity.ORIGIN_WORKING_TREE else None)
    except Exception:                    # noqa: BLE001 -- a disclosure must not stop a run
        relpath, digest, where, draft = None, None, matrix_identity.ORIGIN_UNKNOWN, None
    return {"origin": where, "config": relpath, "config_sha256": digest, "setup_draft": draft}
