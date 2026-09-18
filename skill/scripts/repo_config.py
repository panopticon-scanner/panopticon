"""The root configuration file: names, resolution, and the capped read (#1681).

Per-repo configuration lives at `<review_root>/panopticon.yml` (or the
read-only alias `.panopticon.yml`), committed like any other linter config.
`.panopticon/` holds run artifacts only. This module is the ONE place that
spells those names; every reader resolves through `resolve`/`read_document`
and tests/test_repo_config_literals.py refuses a literal anywhere else.

The file is TARGET-AUTHORED input read before dispatch: it is capped at
MAX_CONFIG_BYTES (read-then-check, never partially parsed), a symlink at
either name is refused rather than followed, `version: 1` is required, and
unknown top-level keys are disclosed and ignored. `.panopticon/groups.yml`
is never read here: a tree that still carries one and no root file gets
`legacy_message`, and `setup_flow.migrate_config` is the only reader of it.

Stdlib + yaml only, so every module in the tree can import it without a cycle.
"""
import os
import stat
from collections import namedtuple

import yaml

CONFIG_NAMES = ("panopticon.yml", ".panopticon.yml")
DRAFT_NAME = "panopticon.yml.draft"
LEGACY_GROUPS_PATH = os.path.join(".panopticon", "groups.yml")
LEGACY_CONFIG_JSON = os.path.join(".panopticon", "config.json")
MAX_CONFIG_BYTES = 1_048_576
VERSION = 1
TOP_LEVEL_KEYS = frozenset({"version", "groups", "exclude_paths", "settings"})

Resolution = namedtuple("Resolution", "path disclosures")
Document = namedtuple("Document", "path doc errors disclosures")

_MIGRATE = "python3 skill/scripts/driver.py migrate-config"


def resolve(review_root):
    """(path, disclosures): the config file for a review root, or None.

    `panopticon.yml` wins over `.panopticon.yml`; both present is disclosed.
    A symlink at either name is refused (the file-level counterpart of
    `plan_contract.artifact_root`'s directory check) and disclosed: if any
    candidate is a symlink, the result is None even if the other name is a
    regular file (no both-present disclosure in that case)."""
    disclosures, found, symlink_seen = [], [], False
    for name in CONFIG_NAMES:
        path = os.path.join(review_root, name)
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            disclosures.append("config path %s is a symlink; refused" % path)
            symlink_seen = True
            continue
        if stat.S_ISREG(st.st_mode):
            found.append(path)
    if symlink_seen:
        return Resolution(None, disclosures)
    if len(found) == 2:
        disclosures.append("both `%s` and `%s` present; using `%s`"
                           % (CONFIG_NAMES[0], CONFIG_NAMES[1], CONFIG_NAMES[0]))
    return Resolution(found[0] if found else None, disclosures)


def legacy_present(review_root):
    return os.path.isfile(os.path.join(review_root, LEGACY_GROUPS_PATH))


def legacy_message(review_root):
    return ("`%s` is no longer read; move it to `%s` under a `groups:` key with "
            "`version: %d` (`%s %s` does this)"
            % (LEGACY_GROUPS_PATH, CONFIG_NAMES[0], VERSION, _MIGRATE, review_root))


def stale_config_json(review_root):
    """The disclosure for a retired `.panopticon/config.json`, or None."""
    if os.path.isfile(os.path.join(review_root, LEGACY_CONFIG_JSON)):
        return ("`%s` is no longer read by the driver; its keys live under "
                "`settings:` in `%s`" % (LEGACY_CONFIG_JSON, CONFIG_NAMES[0]))
    return None


def draft_path(review_root):
    return os.path.join(review_root, DRAFT_NAME)


def read_document(review_root):
    """(path, doc, errors, disclosures). `doc` is the validated mapping with
    unknown top-level keys dropped, or None: no config (errors empty), or
    authored-but-invalid (errors say why, run-8 COD-B1A). A legacy groups.yml
    beside a root file is ignored with a disclosure; alone, it is an error."""
    res = resolve(review_root)
    disclosures = list(res.disclosures)
    stale = stale_config_json(review_root)
    if stale:
        disclosures.append(stale)
    if legacy_present(review_root):
        if res.path is None:
            return Document(None, None, [legacy_message(review_root)], disclosures)
        disclosures.append("`%s` is present but no longer read; delete it"
                           % LEGACY_GROUPS_PATH)
    if res.path is None:
        return Document(None, None, [], disclosures)
    try:
        with open(res.path, "rb") as fh:
            data = fh.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        return Document(res.path, None, ["%s unreadable: %s" % (res.path, exc)], disclosures)
    if len(data) > MAX_CONFIG_BYTES:
        return Document(res.path, None,
                        ["%s exceeds %d bytes; refused" % (res.path, MAX_CONFIG_BYTES)],
                        disclosures)
    try:
        doc = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        return Document(res.path, None, ["%s unreadable: %s" % (res.path, exc)], disclosures)
    if not isinstance(doc, dict):
        return Document(res.path, None, ["%s must be a mapping" % res.path], disclosures)
    if doc.get("version") != VERSION or isinstance(doc.get("version"), bool):
        return Document(res.path, None,
                        ["%s must declare `version: %d` (found %r)"
                         % (res.path, VERSION, doc.get("version"))], disclosures)
    unknown = sorted(k for k in doc if k not in TOP_LEVEL_KEYS)
    if unknown:
        disclosures.append("%s: unknown top-level key(s) ignored: %s"
                           % (res.path, ", ".join(map(str, unknown))))
    kept = {k: v for k, v in doc.items() if k in TOP_LEVEL_KEYS}
    return Document(res.path, kept, [], disclosures)
