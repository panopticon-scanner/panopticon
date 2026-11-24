"""How old the advisory data a scan ran against is (#3798).

Every advisory source a scan uses is frozen in the tools image when it is built, and the
scanners run offline: dependency-check's NVD database (`--noupdate`), Trivy's database
(`--skip-db-update`), osv-scanner's offline databases, the RustSec database
(`cargo-audit --no-fetch`) and the Ruby one (`bundler-audit --no-update`). A run can
only report an advisory that data already held, so the report says how old each source
is, and a run warns when one is stale or its date cannot be read.

The image build records the dates in one file (`tools-image/advisory-data/record.py`
writes `IMAGE_FILE`). This module is everything on the reading side:

- `read_argv`: the one short container launch that reads the file, hardened like a
  scanner launch (no network, read-only, no mount, capabilities dropped, bounded in
  time and output). This module launches nothing itself: the two callers (`run_tools`
  and the readiness phase) run it through their own seams and hand the result to
  `from_launch`, where a launch that failed or timed out reads as every source unknown.
- `parse_image_file`: the file's text, as read out of the image, to a timestamp per
  source. The text is the image's, so it is untrusted: a value that is not exactly a
  timestamp in the recorder's form is `None`, a key this module does not know is
  dropped, and nothing in the file is ever echoed.
- `block`: those timestamps and the time they were read, as the block the tools
  manifest and the report carry: per source a date, its age in whole days at that time,
  and `current`, `stale` or `unknown`.
- `from_manifest`: that block read back from a manifest, which sits in a directory the
  reviewed repository can write, validated again from nothing.
- `line` and `warning`: the two sentences every surface prints, so they cannot differ.

It moves no gate and no certification: this is disclosure (owner direction 2026-11-24).
"""
import datetime
import json
import re
from typing import Any

IMAGE_FILE = "/opt/panopticon/advisory-data.json"
MAX_FILE_BYTES = 16384
# The launch that reads it: seconds the caller waits, and seconds the container itself
# is allowed (so a wedged read does not outlive the caller's patience by much).
READ_TIMEOUT = 30
_IN_CONTAINER_TIMEOUT = 20
_READ_LIMITS = ("--memory", "256m", "--memory-swap", "256m", "--cpus", "1",
                "--pids-limit", "64")
SCHEMA_VERSION = 1
# Older than this many whole days is stale.
STALE_AFTER_DAYS = 7
# In the order they are printed.
SOURCES = (("nvd", "NVD"), ("osv", "OSV"), ("trivy", "Trivy"), ("rustsec", "RustSec"),
           ("ruby", "ruby-advisory-db"))
# The ecosystems the image warms an OSV database for (Dockerfile, the OSV step).
OSV_ECOSYSTEMS = ("Go", "Maven", "PyPI", "RubyGems", "crates.io", "npm")
STATUSES = ("current", "stale", "unknown")
UTC = datetime.timezone.utc
_TIMESTAMP = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\Z")
_DATE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")
# A date before this is not a date of advisory data; one more than a day after the
# read is a clock that cannot be believed. Either reads as unknown.
_EARLIEST_YEAR = 2015
_FUTURE_SLACK = datetime.timedelta(days=1)


def _moment(value):
    """The recorder's `YYYY-MM-DDTHH:MM:SSZ` as an aware datetime, else None."""
    if not isinstance(value, str):
        return None
    match = _TIMESTAMP.match(value)
    if not match:
        return None
    try:
        year, month, day, hour, minute, second = (int(part) for part in match.groups())
        found = datetime.datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except ValueError:
        return None
    return found if found.year >= _EARLIEST_YEAR else None


def _stamp(moment):
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_image_file(raw):
    """A datetime or None per source key, plus `osv_ecosystems`, from the image file's
    bytes or text.

    `osv` is the OLDEST ecosystem database, because a scan is as current as its oldest
    data, and `osv_ecosystems` maps each known ecosystem that had a readable time to it.
    Anything that is not the recorder's exact shape is None: this never raises on what
    the image holds."""
    empty: dict[str, Any] = dict({key: None for key, _label in SOURCES}, osv_ecosystems={})
    if isinstance(raw, bytes):
        if len(raw) > MAX_FILE_BYTES:
            return empty
        try:
            raw = raw.decode("utf-8")
        except UnicodeError:
            return empty
    if not isinstance(raw, str) or len(raw) > MAX_FILE_BYTES:
        return empty
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError):
        return empty
    if (not isinstance(document, dict) or document.get("schema_version") != SCHEMA_VERSION
            or type(document.get("schema_version")) is not int
            or not isinstance(document.get("sources"), dict)):
        return empty
    sources = document["sources"]
    found: dict[str, Any] = dict(empty)
    nvd = sources.get("nvd")
    if isinstance(nvd, dict):
        found["nvd"] = _moment(nvd.get("last_modified"))
    for key, field in (("trivy", "updated_at"), ("rustsec", "downloaded_at"),
                       ("ruby", "downloaded_at")):
        source = sources.get(key)
        if isinstance(source, dict):
            found[key] = _moment(source.get(field))
    osv = sources.get("osv")
    ecosystems: dict[str, datetime.datetime] = {}
    if isinstance(osv, dict) and isinstance(osv.get("ecosystems"), dict):
        for name in OSV_ECOSYSTEMS:
            moment = _moment(osv["ecosystems"].get(name))
            if moment is not None:
                ecosystems[name] = moment
    found["osv_ecosystems"] = ecosystems
    if ecosystems:
        found["osv"] = min(ecosystems.values())
    return found


def read_argv(docker, image, privilege_flags):
    """The argv that prints the image's file, at most one byte past the size cap.

    `privilege_flags` are the scanner launches' own (`scanner_config.
    privilege_drop_flags()`), passed in so there is one owner of that list. Nothing is
    mounted: the launch sees the image and nothing of the host or the target."""
    return ([docker, "run", "--rm", "--network", "none", "--read-only"]
            + list(_READ_LIMITS) + list(privilege_flags)
            + [image, "timeout", str(_IN_CONTAINER_TIMEOUT),
               "head", "-c", str(MAX_FILE_BYTES + 1), IMAGE_FILE])


def from_launch(returncode, output, read_at=None):
    """The block for one `read_argv` launch: its exit status and what it printed.

    `returncode` None is a launch that could not be started or timed out. That, a
    non-zero exit (an image built before #3798 has no file) and output that is not the
    recorder's are all the same answer: every source unknown. It never raises."""
    read_at = read_at or datetime.datetime.now(UTC)
    if returncode != 0 or not isinstance(output, (bytes, str)):
        return unread(read_at)
    return block(parse_image_file(output), read_at)


def _row(moment, read_at):
    """One source's row: its date, its age at `read_at`, and what that makes it."""
    if moment is None or moment > read_at + _FUTURE_SLACK:
        return {"date": None, "age_days": None, "status": "unknown"}
    # Counted between the two dates, as a reader of the two dates would count it.
    age = max(0, (read_at.date() - moment.date()).days)
    return {"date": moment.strftime("%Y-%m-%d"), "age_days": age,
            "status": "stale" if age > STALE_AFTER_DAYS else "current"}


def block(parsed, read_at):
    """The block the tools manifest and the report carry, from `parse_image_file`'s
    answer (or None, when the file could not be read at all) and the time of the read."""
    parsed = parsed or {}
    rows = {key: _row(parsed.get(key), read_at) for key, _label in SOURCES}
    # Each ecosystem's own date (the row's is the oldest of them), for the JSON only.
    rows["osv"]["ecosystems"] = {
        name: _row(moment, read_at)["date"]
        for name, moment in sorted((parsed.get("osv_ecosystems") or {}).items())}
    return {"read_at": _stamp(read_at), "stale_after_days": STALE_AFTER_DAYS, "sources": rows}


def unread(read_at):
    """The block for an image whose file could not be read: every source unknown."""
    return block(None, read_at)


def from_manifest(value):
    """`value` (a manifest's `advisory_data`) validated again from nothing, or None.

    The manifest is in the run folder, which the reviewed repository can write. The
    dates, ages and statuses are recomputed from the recorded dates and the recorded
    read time, so a planted `current` beside an old date is not believed, and a row
    that is not a date is unknown."""
    if not isinstance(value, dict):
        return None
    read_at = _moment(value.get("read_at"))
    rows = value.get("sources")
    if read_at is None or not isinstance(rows, dict):
        return None
    def dated(date):
        return (_moment(date + "T00:00:00Z")
                if isinstance(date, str) and _DATE.match(date) else None)

    parsed = {}
    for key, _label in SOURCES:
        row = rows.get(key)
        parsed[key] = dated(row.get("date")) if isinstance(row, dict) else None
    ecosystems = rows["osv"].get("ecosystems") if isinstance(rows.get("osv"), dict) else None
    parsed["osv_ecosystems"] = {
        name: dated(ecosystems.get(name)) for name in OSV_ECOSYSTEMS
        if isinstance(ecosystems, dict) and dated(ecosystems.get(name)) is not None}
    return block(parsed, read_at)


def _described(label, row, with_age):
    if row["status"] == "unknown":
        return "%s unknown" % label
    if with_age:
        return "%s %s (%d day%s old)" % (label, row["date"], row["age_days"],
                                         "" if row["age_days"] == 1 else "s")
    return "%s %s" % (label, row["date"])


def line(data):
    """`NVD 2026-11-23, OSV 2026-11-23, Trivy 2026-11-22, …`, or None with no block.

    `data` may come from any report or manifest, so it is validated again first: what
    is printed is this module's labels and dates it rebuilt, never the block's text."""
    data = from_manifest(data)
    if data is None:
        return None
    return ", ".join(_described(label, data["sources"][key], False) for key, label in SOURCES)


def warning(data):
    """The sentence for a run whose advisory data is stale or unknown, or None."""
    data = from_manifest(data)
    if data is None:
        return None
    behind = [_described(label, data["sources"][key], True) for key, label in SOURCES
              if data["sources"][key]["status"] != "current"]
    if not behind:
        return None
    return ("advisory data is older than %d days or of unknown age: %s. The scanners run "
            "offline against the data in the tools image, so a newer advisory is not "
            "reported. Pull or rebuild the image to refresh it. This is a warning: it does "
            "not change the gate or certification"
            % (STALE_AFTER_DAYS, "; ".join(behind)))
