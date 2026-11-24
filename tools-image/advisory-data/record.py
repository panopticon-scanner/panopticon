#!/usr/bin/env python3
"""Record how old each advisory source baked into the tools image is (#3798).

A scan runs offline against data frozen at image build: dependency-check's NVD
database, Trivy's database, osv-scanner's offline databases, and the RustSec and Ruby
advisory databases. It can only report an advisory that data already held, so the image
carries the date of each source, in one small file that `run_tools` copies into the
tools manifest and the report shows.

Run once in the image build, after the last data layer:

- **NVD:** `nvd.api.last.modified` and `nvd.api.last.checked` from dependency-check's
  database, read with the H2 shell in the release's own jar, as `nvd-cache-sync.sh`
  reads them. The database is read from a COPY: dependency-check opens the real one
  read-write even under `--noupdate`, and a lock or trace file left beside it by this
  step, as root, would wedge the scanner user's scan (#451).
- **Trivy:** `UpdatedAt` in its database's `metadata.json`.
- **OSV:** when each ecosystem's `all.zip` was downloaded (its modification time).
- **RustSec:** when the advisory database `cargo-audit --no-fetch` reads was cloned (the
  directory's modification time; its `.git` is removed in the same build step).
- **Ruby:** when the database `bundler-audit --no-update` reads was last fetched
  (`.git/FETCH_HEAD`, which a fetch rewrites even when nothing changed). Download
  times, not the newest advisory's date: a quiet week upstream is not stale data.

A source that cannot be read is recorded as null and the build goes on: the scan then
says `unknown` for it and warns. Every timestamp is normalised here to
`YYYY-MM-DDTHH:MM:SSZ`; the reader validates again, because to it this file is text
from an image.

Stdlib only: it runs before the skill is copied into the image.
"""

import argparse
import datetime
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

SCHEMA_VERSION = 1
MAX_METADATA_BYTES = 65536
NVD_KEYS = (("last_modified", "nvd.api.last.modified"), ("last_checked", "nvd.api.last.checked"))
_TIMESTAMP = re.compile(
    r"\A(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?"
    r"(Z|[+-]\d{2}(?::?\d{2})?)?(?:\[[A-Za-z_/+-]+\])?\Z")
_EPOCH_SECONDS = re.compile(r"\A\d{9,11}\Z")
_EPOCH_MILLIS = re.compile(r"\A\d{12,14}\Z")
UTC = datetime.timezone.utc


class Unreadable(Exception):
    pass


def _stamp(moment):
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalise(value):
    """`value` as `YYYY-MM-DDTHH:MM:SSZ`, or None when it is not a timestamp.

    Accepts an ISO 8601 / RFC 3339 timestamp (any fraction, `Z` or a numeric offset, an
    optional `[Zone]` suffix as Java prints one; no offset reads as UTC) and epoch
    seconds or milliseconds, which dependency-check has used for some properties."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    try:
        if _EPOCH_SECONDS.match(text):
            return _stamp(datetime.datetime.fromtimestamp(int(text), UTC))
        if _EPOCH_MILLIS.match(text):
            return _stamp(datetime.datetime.fromtimestamp(int(text) / 1000, UTC))
        match = _TIMESTAMP.match(text)
        if not match:
            return None
        year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
        offset = match.group(7) or "Z"
        zone = UTC
        if offset != "Z":
            digits = offset[1:].replace(":", "")
            minutes = int(digits[:2]) * 60 + int(digits[2:4] or 0)
            zone = datetime.timezone(datetime.timedelta(minutes=minutes if offset[0] == "+" else -minutes))
        return _stamp(datetime.datetime(year, month, day, hour, minute, second, tzinfo=zone))
    except (ValueError, OverflowError, OSError):
        return None


def trivy_updated_at(cache_dir):
    """`UpdatedAt` of the Trivy database under `cache_dir`."""
    path = os.path.join(cache_dir, "db", "metadata.json")
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_METADATA_BYTES + 1)
    except OSError as exc:
        raise Unreadable("cannot read %s: %s" % (path, exc.strerror or exc)) from exc
    if len(raw) > MAX_METADATA_BYTES:
        raise Unreadable("%s is larger than %d bytes" % (path, MAX_METADATA_BYTES))
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise Unreadable("%s is not JSON" % path) from exc
    found = normalise(document.get("UpdatedAt")) if isinstance(document, dict) else None
    if found is None:
        raise Unreadable("%s has no readable UpdatedAt" % path)
    return found


def osv_downloaded_at(db_dir):
    """{ecosystem: when its `all.zip` was written} for the OSV offline databases."""
    root = os.path.join(db_dir, "osv-scanner")
    try:
        names = sorted(os.listdir(root))
    except OSError as exc:
        raise Unreadable("cannot list %s: %s" % (root, exc.strerror or exc)) from exc
    found = {}
    for name in names:
        archive = os.path.join(root, name, "all.zip")
        try:
            status = os.stat(archive)
        except OSError:
            continue
        if status.st_size > 0:
            found[name] = _stamp(datetime.datetime.fromtimestamp(status.st_mtime, UTC))
    if not found:
        raise Unreadable("no ecosystem database under %s" % root)
    return found


def _modified(path):
    return _stamp(datetime.datetime.fromtimestamp(os.stat(path).st_mtime, UTC))


def rustsec_downloaded_at(db_dir):
    """When the RustSec advisory database under `db_dir` was cloned."""
    try:
        if not os.path.isdir(db_dir) or not os.listdir(db_dir):
            raise Unreadable("no advisory database at %s" % db_dir)
        return _modified(db_dir)
    except OSError as exc:
        raise Unreadable("cannot read %s: %s" % (db_dir, exc.strerror or exc)) from exc


def ruby_downloaded_at(db_dir):
    """When the Ruby advisory database under `db_dir` was last fetched."""
    for name in (os.path.join(".git", "FETCH_HEAD"), ".git"):
        try:
            return _modified(os.path.join(db_dir, name))
        except OSError:
            continue
    raise Unreadable("no fetched advisory database at %s" % db_dir)


def _one(pattern, what):
    found = glob.glob(pattern)
    if len(found) != 1:
        raise Unreadable("expected one %s, found %d (%s)" % (what, len(found), pattern))
    return found[0]


def _login(dc_home):
    """The database login dependency-check ships in its own jar: its public default."""
    jar = _one(os.path.join(dc_home, "lib", "dependency-check-core-*.jar"), "dependency-check-core jar")
    try:
        with zipfile.ZipFile(jar) as archive:
            text = archive.read("dependencycheck.properties").decode("utf-8")
    except (OSError, KeyError, UnicodeError, zipfile.BadZipFile) as exc:
        raise Unreadable("cannot read the database login from %s" % jar) from exc
    values = dict(line.split("=", 1) for line in text.splitlines()
                  if "=" in line and not line.startswith("#"))
    try:
        return values["data.user"], values["data.password"]
    except KeyError as exc:
        raise Unreadable("no %s in dependencycheck.properties" % exc) from exc


def _shell_rows(output):
    """Rows of `org.h2.tools.Shell -sql` output: a header, ` | `-separated cells, and a
    closing `(N rows, M ms)` line."""
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines or not lines[-1].lstrip().startswith("("):
        raise Unreadable("unexpected H2 shell output")
    return [tuple(cell.strip() for cell in line.split(" | ")) for line in lines[1:-1]]


def nvd_properties(dc_home, data_dir, runner=None, scratch=None):
    """{"last_modified", "last_checked"} from the NVD database under `data_dir`, each a
    normalised timestamp or None. The database file is copied and the copy is read."""
    database = os.path.join(data_dir, "odc.mv.db")
    if not os.path.isfile(database):
        raise Unreadable("no database at %s" % database)
    h2_jar = _one(os.path.join(dc_home, "lib", "h2-*.jar"), "h2 jar")
    user, password = _login(dc_home)
    runner = runner or subprocess.run
    with tempfile.TemporaryDirectory(prefix="advisory-nvd-", dir=scratch) as copy_dir:
        shutil.copyfile(database, os.path.join(copy_dir, "odc.mv.db"))
        url = "jdbc:h2:file:%s;ACCESS_MODE_DATA=r" % os.path.join(copy_dir, "odc")
        keys = ", ".join("'%s'" % key for _name, key in NVD_KEYS)
        try:
            # Fixed argv, no shell; `java` is the image's own.
            done = runner(["java", "-cp", h2_jar, "org.h2.tools.Shell", "-url", url,
                           "-user", user, "-password", password,
                           "-sql", "SELECT id, value FROM properties WHERE id IN (%s)" % keys],
                          capture_output=True, text=True, timeout=600, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise Unreadable("could not run the H2 shell: %s" % type(exc).__name__) from exc
    if done.returncode != 0:
        raise Unreadable("the H2 shell exited %s" % done.returncode)
    rows = dict(row[:2] for row in _shell_rows(done.stdout) if len(row) >= 2)
    found = {name: normalise(rows.get(key)) for name, key in NVD_KEYS}
    if found["last_modified"] is None:
        raise Unreadable("the database has no readable nvd.api.last.modified")
    return found


def record(dc_home, nvd_dir, trivy_cache, osv_db, rustsec_db, ruby_db, now=None,
           runner=None, say=None):
    """The document for the image. A source that cannot be read is null, and `say` is
    told why."""
    say = say or (lambda message: print("advisory-data: %s" % message, file=sys.stderr))
    sources = {}
    for name, read in (("nvd", lambda: nvd_properties(dc_home, nvd_dir, runner)),
                       ("trivy", lambda: {"updated_at": trivy_updated_at(trivy_cache)}),
                       ("osv", lambda: {"ecosystems": osv_downloaded_at(osv_db)}),
                       ("rustsec", lambda: {"downloaded_at": rustsec_downloaded_at(rustsec_db)}),
                       ("ruby", lambda: {"downloaded_at": ruby_downloaded_at(ruby_db)})):
        try:
            sources[name] = read()
        except Unreadable as exc:
            say("%s: not recorded: %s" % (name, exc))
            sources[name] = None
    return {"schema_version": SCHEMA_VERSION,
            "recorded_at": _stamp(now or datetime.datetime.now(UTC)),
            "sources": sources}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    parser.add_argument("--dc-home", default="/opt/dependency-check")
    parser.add_argument("--nvd-dir", default="/opt/odc-data")
    parser.add_argument("--trivy-cache", default="/opt/trivy-cache")
    parser.add_argument("--osv-db", default="/opt/osv-db")
    parser.add_argument("--rustsec-db", default="/home/scanner/.cargo/advisory-db")
    parser.add_argument("--ruby-db", default="/root/.local/share/ruby-advisory-db")
    args = parser.parse_args(argv)
    document = record(args.dc_home, args.nvd_dir, args.trivy_cache, args.osv_db,
                      args.rustsec_db, args.ruby_db)
    text = json.dumps(document, indent=1, sort_keys=True) + "\n"
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(args.out, 0o644)
    print("advisory-data: recorded in %s:" % args.out)
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
