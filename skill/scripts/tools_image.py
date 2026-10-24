"""The tools image's identity, and the adapter code mounted over it (#3270).

The #3173 armor audit's provenance rule: the tools image DIGEST is the unit of
trust. run_tools names the image by a mutable tag, so this module turns the
tag into the image ID -- `docker image inspect`'s `.Id`, the content digest of
the image config. Every local image has one, whether pulled, re-tagged (CI) or
`docker build`-built, and it is local metadata, so it resolves offline. The
scan then DISPATCHES BY THAT ID, so the image that ran is the image recorded;
a tag moved mid-run cannot swap it.

`repo_digests` ride beside the id, informational only: a local build has
none, and halting on them would refuse every local build and CI's own
fallback build (owner ruling 2026-10-23, C2).

What the id does NOT cover is our adapter code: every dispatch mounts the
controller checkout's `skill/scripts` over the image's baked copy, so local
adapter fixes take effect without a rebuild. That tree is operator-side, never
the target, so the question is only WHICH code ran, and `adapter_code` -- one
sha256 over the mounted tree -- answers it (ruling C1).

An image the tag names whose id cannot be read HALTS (ImageIdentityError). No
docker, or no image under the tag, is NOT a halt: that stays the disclosed
skip (every selected tool `missing`, coverage not certified; ruling D1).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

import scripts.executable as executable

# `run_tools` exits with this when it halts on the image, and the tools phase
# turns it back into a halt of the run rather than a best-effort crash.
HALT_EXIT = 3
INSPECT_FORMAT = "{{.Id}} {{json .RepoDigests}}"
HALT_PREFIX = "run_tools: HALT: "
UNNAMEABLE = ("tools image %s cannot be named: docker reported no image id; "
              "refusing to scan with an image nobody can identify")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REPO_DIGEST = re.compile(r"[!-?A-~]{1,255}@sha256:[0-9a-f]{64}\Z")
_REF = re.compile(r"[!-~]{1,255}\Z")
_MAX_DIGESTS = 8
_SKIP_DIRS = frozenset({"__pycache__"})


class ImageIdentityError(ValueError):
    """The tools image exists but its id cannot be read: the run halts."""


def halting(main):
    """`main`, with a halt on the image or on an in-target PATH entry turned
    into one fixed stderr line and HALT_EXIT: run_tools is a best-effort child
    of the tools phase, which reads that exit back as a halt of the run."""
    def run(*args):
        try:
            return main(*args)
        except (ImageIdentityError, executable.TargetPathEntry) as exc:
            print(HALT_PREFIX + str(exc), file=sys.stderr)
            return HALT_EXIT
    return run


def identity(ref, stdout):
    """{ref, id, repo_digests} from `docker image inspect --format
    INSPECT_FORMAT <ref>`'s stdout, or ImageIdentityError."""
    text = stdout.decode("utf-8", "replace") if isinstance(stdout, bytes) else (stdout or "")
    head, _, rest = text.strip().partition(" ")
    if not _IMAGE_ID.match(head):
        raise ImageIdentityError(UNNAMEABLE % ref)
    try:
        listed = json.loads(rest) if rest.strip() else []
    except ValueError:
        listed = []
    return {"ref": ref, "id": head, "repo_digests": _digests(listed)}


def _digests(value):
    if not isinstance(value, list):
        return []
    return sorted({d for d in value if isinstance(d, str) and _REPO_DIGEST.match(d)})[:_MAX_DIGESTS]


def adapter_code(root):
    """`sha256:<hex>` over the tree mounted at /opt/panopticon/scripts: every
    file's path relative to `root`, sorted, then its bytes' sha256. Bytecode
    caches are left out (the interpreter writes them); a symlink contributes
    its link text, which is what the mount carries."""
    outer = hashlib.sha256()
    rows = []
    for here, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in files:
            if name.endswith(".pyc"):
                continue
            path = os.path.join(here, name)
            rows.append((os.path.relpath(path, root).replace(os.sep, "/"), path))
    for rel, path in sorted(rows):
        if os.path.islink(path):
            body = b"link:" + os.fsencode(os.readlink(path))
        else:
            with open(path, "rb") as fh:
                body = hashlib.sha256(fh.read()).digest()
        outer.update(rel.encode("utf-8", "surrogateescape") + b"\0" + body)
    return "sha256:" + outer.hexdigest()


def repair(value):
    """The manifest's `image` block as a report may carry it, or None. The
    manifest is target-writable: an id out of shape is dropped, never kept."""
    if not isinstance(value, dict) or not isinstance(value.get("ref"), str) \
            or not _REF.match(value["ref"]):
        return None
    image_id, code = value.get("id"), value.get("adapter_code")
    return {"ref": value["ref"],
            "id": image_id if isinstance(image_id, str) and _IMAGE_ID.match(image_id) else None,
            "repo_digests": _digests(value.get("repo_digests")),
            "adapter_code": code if isinstance(code, str) and _IMAGE_ID.match(code) else None}

