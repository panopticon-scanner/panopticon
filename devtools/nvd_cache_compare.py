"""Do two dependency-check NVD databases give the same answers? (#3417)

    python3 devtools/nvd_cache_compare.py --dc-home dependency-check SEEDED FRESH

SEEDED and FRESH are two `odc-data` directories, for example one built by a
seeded sync and one by a full download on the same day. The sample is every CVE
whose id ends in `--suffix` (default "07", about 1% of them), taken from BOTH
databases, so a CVE that only one side has is a mismatch too. For each sampled
id it compares the CVSS v3 and v2 base scores and the set of CPE matches
(part, vendor, product, version and the four version bounds, vulnerable flag).

It prints counts and the mismatching ids, never the data itself, and exits 0
when the two agree, 1 when they don't, 2 when a database can't be read.
Databases are opened read-only, with the login dependency-check ships in its
own jar. Stdlib only, plus `java` and the release's H2 jar.
"""
import argparse
import glob
import os
import subprocess
import sys
import zipfile

SCORES_SQL = ("SELECT cve, v3BaseScore, v2Score FROM vulnerability "
              "WHERE cve LIKE '%%%s'")
CPES_SQL = ("SELECT v.cve, c.part, c.vendor, c.product, c.version, "
            "s.versionStartIncluding, s.versionStartExcluding, "
            "s.versionEndIncluding, s.versionEndExcluding, s.vulnerable "
            "FROM vulnerability v JOIN software s ON s.cveid = v.id "
            "JOIN cpeEntry c ON c.id = s.cpeEntryId WHERE v.cve LIKE '%%%s'")
SHOWN = 50


class Unreadable(Exception):
    pass


def login(dc_home):
    """(user, password) from dependency-check's own dependencycheck.properties."""
    jars = glob.glob(os.path.join(dc_home, "lib", "dependency-check-core-*.jar"))
    if len(jars) != 1:
        raise Unreadable("expected one dependency-check-core jar under %s/lib" % dc_home)
    with zipfile.ZipFile(jars[0]) as jar:
        text = jar.read("dependencycheck.properties").decode("utf-8")
    values = dict(line.split("=", 1) for line in text.splitlines()
                  if "=" in line and not line.startswith("#"))
    try:
        return values["data.user"], values["data.password"]
    except KeyError as exc:
        raise Unreadable("no %s in dependencycheck.properties" % exc) from exc


def parse_shell(output):
    """Rows of `org.h2.tools.Shell -sql` output: a header, ` | `-separated
    cells padded with spaces, and a closing `(N rows, M ms)` line."""
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines or not lines[-1].lstrip().startswith("("):
        raise Unreadable("unexpected H2 shell output")
    return [tuple(cell.strip() for cell in line.split(" | ")) for line in lines[1:-1]]


def h2_query(dc_home, user, password):
    """A `query(directory, sql) -> rows` reading through the release's H2 jar."""
    jars = glob.glob(os.path.join(dc_home, "lib", "h2-*.jar"))
    if len(jars) != 1:
        raise Unreadable("expected one h2 jar under %s/lib" % dc_home)

    def query(directory, sql):
        url = "jdbc:h2:file:%s;ACCESS_MODE_DATA=r" % os.path.join(os.path.abspath(directory), "odc")
        # Fixed argv, no shell; `java` from the operator's PATH on purpose (a dev
        # tool run by hand against two local databases, never by the product).
        proc = subprocess.run(  # nosec B603 B607
            ["java", "-cp", jars[0], "org.h2.tools.Shell", "-url", url,
             "-user", user, "-password", password, "-sql", sql],
            capture_output=True, text=True, timeout=600, check=False)
        if proc.returncode != 0:
            raise Unreadable("could not read %s: %s" % (directory, proc.stderr.strip()[-200:]))
        return parse_shell(proc.stdout)
    return query


def answers(query, directory, suffix):
    """{cve: (v3 score, v2 score, frozenset of CPE match rows)} for the sample."""
    found: dict[str, tuple[str, str, set[tuple[str, ...]]]] = {
        row[0]: (row[1], row[2], set()) for row in query(directory, SCORES_SQL % suffix)}
    for row in query(directory, CPES_SQL % suffix):
        if row[0] in found:
            found[row[0]][2].add(row[1:])
    return {cve: (v3, v2, frozenset(cpes)) for cve, (v3, v2, cpes) in found.items()}


def compare(seeded, fresh):
    """The disagreements between two `answers` maps, by kind."""
    common = seeded.keys() & fresh.keys()
    return {
        "only in seeded": sorted(seeded.keys() - fresh.keys()),
        "only in fresh": sorted(fresh.keys() - seeded.keys()),
        "different scores": sorted(c for c in common if seeded[c][:2] != fresh[c][:2]),
        "different CPE matches": sorted(c for c in common if seeded[c][2] != fresh[c][2]),
    }


def report(seeded, fresh, differences, out=None):
    out = out or sys.stdout
    print("sampled: %d CVEs in seeded, %d in fresh, %d in both"
          % (len(seeded), len(fresh), len(seeded.keys() & fresh.keys())), file=out)
    for kind, ids in differences.items():
        shown = ", ".join(ids[:SHOWN]) + (" (+%d more)" % (len(ids) - SHOWN) if len(ids) > SHOWN else "")
        print("%s: %d%s" % (kind, len(ids), (": " + shown) if ids else ""), file=out)
    agree = not any(differences.values())
    print("PASS: the two databases agree on the sample" if agree
          else "FAIL: the two databases disagree on the sample", file=out)
    return agree


def main(argv=None, query=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dc-home", default="dependency-check",
                        help="the unpacked dependency-check release (its lib/ jars)")
    parser.add_argument("--suffix", default="07",
                        help="sample the CVE ids ending in this (default 07, about 1%%)")
    parser.add_argument("seeded")
    parser.add_argument("fresh")
    args = parser.parse_args(argv)
    if not args.suffix.isdigit():
        parser.error("--suffix must be digits")
    try:
        if query is None:
            query = h2_query(args.dc_home, *login(args.dc_home))
        seeded = answers(query, args.seeded, args.suffix)
        fresh = answers(query, args.fresh, args.suffix)
    except Unreadable as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if not seeded and not fresh:
        print("error: the sample is empty in both databases", file=sys.stderr)
        return 2
    return 0 if report(seeded, fresh, compare(seeded, fresh)) else 1


if __name__ == "__main__":
    sys.exit(main())
