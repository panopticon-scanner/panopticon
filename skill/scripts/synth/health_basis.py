"""The run layout and policy qualifier attached to a health grade (#3528)."""
import hashlib
import json

import scripts.discovery as discovery


LEGACY_NOTE = "basis unknown (report predates #3528)"
_NOTE = ("policy score pending calibration; comparable only with runs of the "
         "same version, review type and layout (fingerprint %s)")


def positive_int(value):
    """A real positive int, or None for an absent/malformed run value."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def effective_size(groups_json, config, key):
    """One effective size knob: the discovery record wins over config.

    ``max_per_group`` is stamped by the discovery process that actually cut
    the groups. Older inventories have no stamp, so their clamped config value
    is the best available record. ``max_groups`` currently comes from that
    clamped record; accepting a future inventory stamp keeps this seam honest.
    """
    inventory = groups_json if isinstance(groups_json, dict) else {}
    value = positive_int(inventory.get(key))
    if value is not None:
        return value
    resolution = config if isinstance(config, dict) else {}
    effective = resolution.get("effective")
    return positive_int(effective.get(key)) if isinstance(effective, dict) else None


def _layout(groups):
    """Canonical sorted group -> sorted unique file list actually assigned."""
    collected: dict[str, set[str]] = {}
    for group in groups or []:
        if not isinstance(group, dict) or not isinstance(group.get("name"), str):
            continue
        files = group.get("files")
        collected.setdefault(group["name"], set()).update(
            path for path in (files if isinstance(files, list) else [])
            if isinstance(path, str))
    return {name: sorted(collected[name]) for name in sorted(collected)}


def layout_fingerprint(groups):
    """SHA-256 over canonical JSON, ASCII-escaped for any surrogate path."""
    payload = json.dumps(_layout(groups), ensure_ascii=True, separators=(",", ":"),
                         sort_keys=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _review_type(raw):
    if raw == "repo":
        return "full"
    if raw in ("changes", "pr"):
        return "delta"
    return "file-scoped"


def _cell_count(audit, key):
    rows = audit.get(key) if isinstance(audit, dict) else None
    return len(rows) if isinstance(rows, list) else None


# #1495: the bands were kept (#3328) on runs at the default scan settings, and the group size
# decides how many review cells look at the same code, so how much a run finds. A full review
# gets a certified letter only at the default size; any other moves it to provisional_grade.
# Compared on the EFFECTIVE value (discovery's stamp, after config clamps and flag precedence),
# so an explicit `--max-per-group 48` or a config at 48 is the default profile.
GRADED_MAX_PER_GROUP = discovery.DEFAULT_MAX_PER_GROUP
PROFILE_NOTE = ("grade provisional: this scan used a non-default group size of %d files (%s; "
                "the default is %d). A letter is certified only at the default scan settings, "
                "because the group size changes how much a scan finds in the same code")
_CAP_SOURCE = {"config": "set by the target's panopticon.yml settings",
               "flag": "set by the run's --max-per-group flag"}


def cap_source(run):
    """Where a run's effective cap came from, for the note only: the target's config when the
    clamped config record holds that value, else the run's own flag."""
    config = run.config if isinstance(getattr(run, "config", None), dict) else {}
    effective = config.get("effective")
    if isinstance(effective, dict) and positive_int(effective.get("max_per_group")) == \
            run.max_per_group:
        return "config"
    return "flag"


def profile(run):
    """'default', 'custom', or 'unknown' when the run recorded no effective cap."""
    cap = positive_int(getattr(run, "max_per_group", None))
    if cap is None:
        return "unknown"
    return "default" if cap == GRADED_MAX_PER_GROUP else "custom"


def custom_profile_note(run):
    """The provisional-grade reason for a full review at a non-default cap, else None.

    Delta and file-scoped reviews keep their letter behaviour (#1495 ruling Q1), and an unknown
    cap is left alone: nothing measured says it differs."""
    if getattr(run, "review_type", None) != "repo" or profile(run) != "custom":
        return None
    return PROFILE_NOTE % (run.max_per_group, _CAP_SOURCE[cap_source(run)], GRADED_MAX_PER_GROUP)


def build(run, reconciled, version, ocrdb_version):
    """Build ``summary.health.basis`` only from effective run records."""
    groups = reconciled.groups_meta
    return {
        "review_type": _review_type(run.review_type),
        "groups": len(_layout(groups)),
        "cells_planned": _cell_count(reconciled.cell_audit, "planned_pairs"),
        "cells_answered": _cell_count(reconciled.cell_audit, "reviewed"),
        "max_per_group": positive_int(run.max_per_group),
        "max_groups": positive_int(run.max_groups),
        "profile": profile(run),
        "layout_fingerprint": layout_fingerprint(groups),
        "version": version,
        "ocrdb_version": ocrdb_version,
    }


def qualifier(basis):
    """The policy qualifier for a current basis."""
    return _NOTE % basis["layout_fingerprint"]


def attach(health, run, reconciled, version, ocrdb_version):
    """Copy a computed health block and add provenance without touching it."""
    out = dict(health or {})
    basis = build(run, reconciled, version, ocrdb_version)
    out["basis"] = basis
    out["note"] = qualifier(basis)
    return out


def rendered_note(health):
    """A report's qualifier, or the explicit pre-#3528 legacy disclosure."""
    if isinstance(health, dict):
        basis = health.get("basis")
        fingerprint = (basis.get("layout_fingerprint")
                       if isinstance(basis, dict) else None)
        if (isinstance(fingerprint, str) and fingerprint.startswith("sha256:")
                and len(fingerprint) == 71
                and all(c in "0123456789abcdef" for c in fingerprint[7:])):
            return qualifier(basis)
    return LEGACY_NOTE
