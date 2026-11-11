"""The run layout and policy qualifier attached to a health grade (#3528)."""
import hashlib
import json

import scripts.discovery as discovery
import scripts.repo_config as repo_config


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
PROFILE_REASON = ("this scan used a non-default group size of %d files (%s; the default is %d). "
                  "A letter is certified only at the default scan settings, because the group "
                  "size changes how much a scan finds in the same code.")
# The run manifest folds a flag and the config into one `max_per_group` (driver._flags), so when
# the clamped config record holds the effective value, a flag of that same value can't be told
# apart from it; the wording says so.
_CAP_SOURCE = {"config": ("set by max_per_group in the target's %s, or a --max-per-group flag of "
                          "the same value" % repo_config.CONFIG_NAMES[0]),
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


def profile(run, coverages=None):
    """'default', 'custom', or 'unknown' when the run recorded no effective cap. A committed
    `exclude:` that removed a fixed-floor domain makes it 'custom' whatever the cap (#3548)."""
    if lever_cells(coverages, "exclude_deterministic"):
        return "custom"
    cap = positive_int(getattr(run, "max_per_group", None))
    if cap is None:
        return "unknown"
    return "default" if cap == GRADED_MAX_PER_GROUP else "custom"


def custom_profile_reason(run):
    """Why a full review at a non-default cap carries a provisional letter, else None.
    `grading.certify` composes it with any coverage reason into `coverage_note`.

    Delta and file-scoped reviews keep their letter behaviour (#1495 ruling Q1), and an unknown
    cap is left alone: nothing measured says it differs."""
    if getattr(run, "review_type", None) != "repo" or profile(run) != "custom":
        return None
    return PROFILE_REASON % (run.max_per_group, _CAP_SOURCE[cap_source(run)], GRADED_MAX_PER_GROUP)


# #3548: the target-authored levers that change review effort without touching the cap.
# A per-group `exclude:` that removes a domain the fixed floors would have run cuts review on
# the same code, exactly like a custom cap, so it moves the letter the same way. A domain only
# the scout asked for is named and never moves the letter (the scout is an LLM: counting it
# would let the same pinned repo and config certify on one run and not the next). `panels:` only
# adds review and `exclude_paths:` is how vendored code is left out, so both are disclosed only.
# Each template's first %s is the target's config file name.
EXCLUDE_REASON = ("this scan skipped review areas the target's %s excludes (%s). A letter is "
                  "certified only when every applicable review area ran, because skipping one "
                  "finds less in the same code.")
SCOUT_EXCLUDE_NOTE = "the scout asked for review areas the target's %s excludes (%s)"
EXCLUDE_PATHS_NOTE = ("exclude_paths in the target's %s removed %s file(s) from review "
                      "(%s more code file(s) kept for security review only)")
UNRECORDED = "an unrecorded number of"
MAX_LEVER_CELLS = 256      # basis.config_levers lists keep the first this many, sorted
_NAMED_CELLS = 10          # a reason or note names this many and counts the rest


def _count(value):
    """A real non-negative int, or None."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def lever_cells(coverages, key):
    """Sorted "group:DOMAIN" cells off the coverage records' `key` list, or None when no
    record carries it (records written before #3548: unknown, not "none")."""
    cells: set[str] = set()
    seen = False
    for cov in coverages or ():
        if not isinstance(cov, dict) or not isinstance(cov.get("group"), str):
            continue
        domains = cov.get(key)
        if not isinstance(domains, list):
            continue
        seen = True
        cells.update("%s:%s" % (cov["group"], d) for d in domains if isinstance(d, str))
    return sorted(cells) if seen else None


def _named(cells):
    shown = ", ".join(cells[:_NAMED_CELLS])
    return shown + (" and %d more" % (len(cells) - _NAMED_CELLS)
                    if len(cells) > _NAMED_CELLS else "")


def exclude_paths_record(groups_json):
    """What a committed `exclude_paths:` removed, off discovery's groups.json record: glob
    count, files no domain reviewed, and code files kept for SEC only. None without one."""
    inventory = groups_json if isinstance(groups_json, dict) else {}
    globs = inventory.get("exclude_paths")
    if not isinstance(globs, list):
        return None
    carve = inventory.get("exclude_paths_sec_carve_out")
    return {"globs": len(globs), "pruned": _count(inventory.get("excluded_count")),
            "sec_carved": _count(carve.get("count")) if isinstance(carve, dict) else None}


def exclude_reason(run, coverages):
    """Why a full review whose committed `exclude:` removed a fixed-floor domain carries a
    provisional letter, else None. Same review-type rule as `custom_profile_reason`."""
    if getattr(run, "review_type", None) != "repo":
        return None
    cells = lever_cells(coverages, "exclude_deterministic")
    return EXCLUDE_REASON % (repo_config.CONFIG_NAMES[0], _named(cells)) if cells else None


def custom_profile_reasons(run, coverages):
    """Every reason this run's letter is not comparable with the bands, cap first."""
    return [r for r in (custom_profile_reason(run), exclude_reason(run, coverages)) if r]


def config_notes(run, coverages):
    """Disclosures for `coverage_note` that do not move the letter (full review only)."""
    if getattr(run, "review_type", None) != "repo":
        return []
    notes = []
    scout = lever_cells(coverages, "exclude_scout")
    if scout:
        notes.append(SCOUT_EXCLUDE_NOTE % (repo_config.CONFIG_NAMES[0], _named(scout)))
    record = getattr(run, "exclude_paths", None)
    if isinstance(record, dict) and (record.get("pruned") or record.get("sec_carved")):
        pruned, carved = record.get("pruned"), record.get("sec_carved")
        notes.append(EXCLUDE_PATHS_NOTE % (
            repo_config.CONFIG_NAMES[0], UNRECORDED if pruned is None else pruned,
            UNRECORDED if carved is None else carved))
    return notes


def config_levers(run, coverages):
    """`basis.config_levers`: every target-authored lever, recorded whether or not it moved
    the letter. A list is None when no coverage record measured it."""
    def capped(key):
        cells = lever_cells(coverages, key)
        return None if cells is None else cells[:MAX_LEVER_CELLS]
    record = getattr(run, "exclude_paths", None)
    return {"domain_exclude": capped("exclude_deterministic"),
            "domain_exclude_scout": capped("exclude_scout"),
            "panels_added": capped("panels_added"),
            "exclude_paths": record if isinstance(record, dict) else None}


def build(run, reconciled, version, ocrdb_version):
    """Build ``summary.health.basis`` only from effective run records."""
    groups = reconciled.groups_meta
    coverages = getattr(reconciled, "coverages", None)
    return {
        "review_type": _review_type(run.review_type),
        "groups": len(_layout(groups)),
        "cells_planned": _cell_count(reconciled.cell_audit, "planned_pairs"),
        "cells_answered": _cell_count(reconciled.cell_audit, "reviewed"),
        "max_per_group": positive_int(run.max_per_group),
        "max_groups": positive_int(run.max_groups),
        "profile": profile(run, coverages),
        "config_levers": config_levers(run, coverages),
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
