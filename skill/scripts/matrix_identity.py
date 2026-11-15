"""#3651: what identifies a review matrix, so two reports can be compared honestly.

Setup proposes a different matrix nearly every time it is asked, and a review's results move
with the matrix it ran under. A report therefore says three things about its matrix:

`matrix_fingerprint`
    A hash of the matrix AS IT WAS APPLIED: every review group's files and floor panels on the
    reviewed tree. Two runs with the same fingerprint reviewed the same cells. It is
    effect-based on purpose. Group order in the config is semantic (groups claim files
    first-match-wins), so a hash of the config text with its order thrown away would call two
    different matrices the same; a hash of the realised cells is order-free by construction
    and cannot. Two orderings that realise the same cells hash the same, and two that do not,
    do not. Panels a scout added are not part of it: they vary per run and are not the matrix.

`config_sha256`
    A hash of the config AS WRITTEN: its groups in authored order with their globs in authored
    order, its `exclude_paths` and the settings that shape the cut. Key order, comments and
    whitespace do not count. It answers a different question -- is this the file setup
    drafted? -- and it changes when a group is moved, as it must.

`origin`
    Whether the config is part of the reviewed commit (`committed`: a REUSED matrix, pinned
    with the repo) or a file written after it (`working_tree`: a FRESH one, by setup or by
    hand). `unknown` when that could not be measured, which is never reported as reused.

Pure: stdlib only, so `synth/` and the driver both import it. The Git and state-directory
halves are `matrix_provenance.py`.
"""
import hashlib
import json
import re

ORIGIN_COMMITTED, ORIGIN_WORKING_TREE, ORIGIN_UNKNOWN = "committed", "working_tree", "unknown"
ORIGINS = (ORIGIN_COMMITTED, ORIGIN_WORKING_TREE, ORIGIN_UNKNOWN)
# How a fresh config compares with the draft this target's last setup run recorded, in the
# operator's own state directory. None when setup recorded none.
DRAFT_UNCHANGED, DRAFT_DIFFERS = "unchanged", "differs"
DRAFTS = (DRAFT_UNCHANGED, DRAFT_DIFFERS)
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
#: The settings that change how the tree is cut (`config_schema.GRAIN_KEYS`).
GRAIN_SETTINGS = ("include_fixtures", "max_groups", "max_per_group")


def _digest(value):
    payload = json.dumps(value, ensure_ascii=True, separators=(",", ":"),
                         sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _strings(value):
    return [item for item in (value if isinstance(value, (list, tuple, set, frozenset)) else ())
            if isinstance(item, str)]


def realised(groups, coverages):
    """`{group name: {"files": [...], "panels": [...]}}`: the cells this run was set to
    review. `groups` is `groups.json`'s list and `coverages` the per-group coverage records
    the driver wrote. A group's panels are its FLOOR net of what it excludes; a group with
    no coverage record has none."""
    panels: dict[str, set] = {}
    for record in coverages if isinstance(coverages, (list, tuple)) else ():
        if isinstance(record, dict) and isinstance(record.get("group"), str):
            panels.setdefault(record["group"], set()).update(
                set(_strings(record.get("floor"))) - set(_strings(record.get("excluded"))))
    cells: dict[str, dict] = {}
    for group in groups if isinstance(groups, (list, tuple)) else ():
        if not isinstance(group, dict) or not isinstance(group.get("name"), str):
            continue
        cell = cells.setdefault(group["name"], {"files": set(), "panels": set()})
        cell["files"].update(_strings(group.get("files")))
        cell["panels"].update(panels.get(group["name"], ()))
    return {name: {"files": sorted(cell["files"]), "panels": sorted(cell["panels"])}
            for name, cell in sorted(cells.items())}


def matrix_fingerprint(groups, coverages):
    """The effect-based hash: equal exactly when two runs were set the same cells."""
    return _digest(realised(groups, coverages))


def config_sha256(leaves, exclude_paths=None, settings=None):
    """The hash of a config as written. `leaves` is `groups_schema.parse_groups`' result: an
    id-ordered mapping of validated leaves, whose order and whose glob order are kept."""
    groups = []
    for group_id, leaf in (leaves or {}).items():
        leaf = leaf if isinstance(leaf, dict) else {}
        groups.append([str(group_id), {
            "match": _strings(leaf.get("match")), "tests": _strings(leaf.get("tests")),
            "panels": sorted(_strings(leaf.get("floor"))),
            "exclude": sorted(_strings(leaf.get("exclude"))),
            "parent": leaf.get("parent") if isinstance(leaf.get("parent"), str) else None}])
    settings = settings if isinstance(settings, dict) else {}
    return _digest({"groups": groups, "exclude_paths": _strings(exclude_paths),
                    "settings": {key: settings[key] for key in GRAIN_SETTINGS
                                 if isinstance(settings.get(key), (bool, int))}})


def _sha(value):
    return value if isinstance(value, str) and _SHA256.fullmatch(value) else None


def block(fingerprint, origin=None, config=None, draft=None):
    """`meta.matrix`, with every field pinned to its vocabulary: an origin this build does not
    know is `unknown`, and a hash that is not one is null. The draft comparison is kept only
    for a working-tree config -- a committed one is the repo's, whoever first drafted it."""
    origin = origin if origin in ORIGINS else ORIGIN_UNKNOWN
    return {"origin": origin,
            "matrix_fingerprint": _sha(fingerprint),
            "config_sha256": _sha(config),
            "setup_draft": draft if origin == ORIGIN_WORKING_TREE and draft in DRAFTS else None}
