"""The keyed NVD sync, `.github/scripts/nvd-cache-sync.sh`, by behaviour.

#3224: the DependencyCheck zip is verified FAIL-CLOSED before anything runs
with the API key in its environment. #3251: a database is published only when
this update finished and the data is under 72 h old. #3417: the sync seeds
from the last published data image by digest, falls back to a full download by
name when the seed is unusable, and a seeded database is published only when
`nvd.api.last.checked` moved past the seed's -- a seed's `last.modified` is
recent whether or not today's update ran.

These run the real script with stub commands (shell functions, which bash
resolves before PATH) standing in for apt, curl, docker, java and the clock,
so they pin what the shell DOES, not how it is spelled.
"""
import datetime
import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests._test_helpers import REPO_ROOT

SCRIPT = os.path.join(REPO_ROOT, ".github", "scripts", "nvd-cache-sync.sh")
NOW = datetime.datetime(2026, 11, 4, 12, 0, 0, tzinfo=datetime.timezone.utc)   # a Wednesday
DIGEST = "sha256:" + "ab" * 32
KEY = "nvd-key-value-not-for-output"
HOUR = 3600
DAY = 24 * HOUR

# `date -u -d VALUE +%s` for the stub: ISO timestamps and dates, UTC.
_PARSE = """import datetime, sys
try:
    value = datetime.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
except ValueError:
    sys.exit(1)
if value.tzinfo is None:
    value = value.replace(tzinfo=datetime.timezone.utc)
print(int(value.timestamp()))
"""


def ago(seconds):
    """An ISO timestamp `seconds` before NOW, as dependency-check writes it."""
    return (NOW - datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def days_ago(days):
    return (NOW - datetime.timedelta(days=days)).strftime("%Y-%m-%d")


def seed(dc_version="10.0.3", full_build=None, modified=None, checked=None,
         marker=True, cp_rc=0):
    """A published data image: its marker and the two properties it carries."""
    return {"dc_version": dc_version, "full_build": full_build or days_ago(2),
            "modified": ago(5 * HOUR) if modified is None else modified,
            "checked": ago(20 * HOUR) if checked is None else checked,
            "marker": marker, "cp_rc": cp_rc}


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _run(curl_rc=0, sha_rc=0, sync_rc=0, db=False, modified=None, checked=None,
         java_rc=0, the_seed=None, weekday=3, event="schedule", full_rebuild=False,
         props="data.user=dc-user\\ndata.password=a=b\\n"):
    """Run the script with stubbed tools; return a dict describing the run.

    `the_seed` is None for "no seed image" (the digest lookup fails), else a
    `seed(...)`. `db` makes the update leave a database over the size floor;
    `modified`/`checked` are the properties it writes there (None: leaves
    them as they were, which over an empty directory means absent)."""
    with tempfile.TemporaryDirectory() as tmp:
        _write(os.path.join(tmp, "parse.py"), _PARSE)
        state = os.path.join(tmp, "state")
        os.makedirs(state)
        if the_seed is not None:
            for name in ("modified", "checked"):
                if the_seed[name] is not False:
                    _write(os.path.join(state, "seed", "nvd.api.last." + name), the_seed[name])
            if the_seed["marker"]:
                _write(os.path.join(state, "seed", "marker"), json.dumps(
                    {"dc_version": the_seed["dc_version"], "full_build": the_seed["full_build"]}))
        for name, value in (("modified", modified), ("checked", checked)):
            if value is not None:
                _write(os.path.join(state, "after", "nvd.api.last." + name), value)
        stubs = r"""
sudo() { return 0; }
curl() { : > dc.zip; return %(curl_rc)d; }
# Drain stdin as the real one does: a stub that returns unread can SIGPIPE
# the `echo` feeding it, which `pipefail` and `-e` turn into a silent exit.
sha256sum() { cat > /dev/null; return %(sha_rc)d; }
unzip() { if [ "$1" = -p ]; then printf '%(props)s'; fi; }
stat() { echo 104857601; }
date() {
  if [ "$2" = -d ]; then "%(py)s" "%(tmp)s/parse.py" "$3"; return; fi
  case "$2" in +%%s) echo %(now)d ;; +%%u) echo %(weekday)d ;; +%%F) echo %(today)s ;; esac
}
docker() {
  printf '%%s\n' "$*" >> "%(tmp)s/docker-calls"
  case "$1" in
    buildx) [ -d "%(state)s/seed" ] || return 1; printf '"%(digest)s"\n' ;;
    create) echo cid-1 ;;
    cp) local to="${@: -1}"
        [ -f "%(state)s/seed/marker" ] && cp "%(state)s/seed/marker" "$to/panopticon-seed.json"
        : > "$to/odc.mv.db"; mkdir -p "$to/.props"
        cp "%(state)s/seed/"nvd.api.* "$to/.props/" 2>/dev/null
        return %(cp_rc)d ;;
  esac
}
java() {
  local url="" sql=""
  printf '%%s\n' "$@" > "%(tmp)s/java-argv"
  while [ $# -gt 0 ]; do
    case "$1" in -url) url="$2" ;; -sql) sql="$2" ;; esac; shift
  done
  [ %(java_rc)d -eq 0 ] || return %(java_rc)d
  local dir="${url#jdbc:h2:file:./}"; dir="${dir%%%%/odc;*}"
  local key="${sql#*id=\'}"; key="${key%%\'}"
  printf 'ID | VALUE\n'
  [ -f "$dir/.props/$key" ] && printf '%%s | %%s\n' "$key" "$(cat "$dir/.props/$key")"
  printf '(1 row, 0 ms)\n'
}
timeout() {
  printf '%%s\n' "$@" > "%(tmp)s/dc-argv"
  if [ %(db)d = 1 ]; then
    : > odc-data/odc.mv.db; mkdir -p odc-data/.props
    cp "%(state)s/after/"nvd.api.* odc-data/.props/ 2>/dev/null
  fi
  return %(sync_rc)d
}
""" % {"curl_rc": curl_rc, "sha_rc": sha_rc, "props": props, "py": sys.executable,
       "tmp": tmp, "state": state, "now": int(NOW.timestamp()), "weekday": weekday,
       "today": NOW.strftime("%Y-%m-%d"), "digest": DIGEST,
       "cp_rc": (the_seed or {}).get("cp_rc", 0), "java_rc": java_rc,
       "db": 1 if db else 0, "sync_rc": sync_rc}
        env = {"PATH": os.environ.get("PATH", ""), "HOME": tmp,
               "DC_VERSION": "10.0.3", "DC_SHA256": "0" * 64,
               "REGISTRY": "ghcr.io", "NVD_IMAGE": "owner/repo-tools-nvd",
               "NVD_API_KEY": KEY, "GITHUB_EVENT_NAME": event}
        if full_rebuild:
            env["NVD_FULL_REBUILD"] = "1"
        with open(SCRIPT, encoding="utf-8") as fh:
            script = fh.read()
        # The script goes in on stdin after the stubs: a fixed argv, the same parse.
        proc = subprocess.run(["bash"], input=stubs + script, cwd=tmp, env=env,
                              capture_output=True, text=True, timeout=60)

        def lines(name):
            path = os.path.join(tmp, name)
            return open(path).read().splitlines() if os.path.exists(path) else []

        marker = os.path.join(tmp, "odc-data", "panopticon-seed.json")
        return {"rc": proc.returncode, "out": proc.stdout + proc.stderr,
                "dc": lines("dc-argv"), "launched": os.path.exists(os.path.join(tmp, "dc-argv")),
                "docker": lines("docker-calls"), "java": lines("java-argv"),
                "marker": json.load(open(marker)) if os.path.exists(marker) else None}


def _fresh(**kw):
    """A full download that finished: a database with a recent last.modified."""
    kw.setdefault("db", True)
    kw.setdefault("modified", ago(HOUR))
    kw.setdefault("checked", ago(0))
    return _run(**kw)


class TestTheKeyedSyncVerifiesFailClosed(unittest.TestCase):
    """#3224."""

    def test_a_digest_mismatch_stops_the_step_before_the_launch(self):
        run = _run(sha_rc=1)
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertFalse(run["launched"], "an unverified zip reached dependency-check.sh")

    def test_a_failed_download_stops_the_step_before_the_launch(self):
        run = _run(curl_rc=22)
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertFalse(run["launched"], "a failed download reached dependency-check.sh")

    def test_a_non_zero_full_download_still_reaches_the_db_check(self):
        # `set -e` must not swallow the #2508 status capture: on a full download
        # a non-zero status is let through to the checks, and here there is no
        # database, so the step fails THERE, by name.
        run = _run(sync_rc=1)
        self.assertTrue(run["launched"], run["out"])
        self.assertNotEqual(run["rc"], 0)
        self.assertIn("returned non-zero (rc=1) on a full download", run["out"])
        self.assertIn("odc.mv.db) was not produced", run["out"])

    def test_a_killed_sync_still_fails_by_its_own_message(self):
        run = _run(sync_rc=124)
        self.assertTrue(run["launched"], run["out"])
        self.assertNotEqual(run["rc"], 0)
        self.assertIn("killed by the 3000 s deadline", run["out"])

    def test_the_key_reaches_dependency_check_and_never_the_output(self):
        run = _fresh()
        self.assertEqual(run["rc"], 0, run["out"])
        self.assertEqual(run["dc"][run["dc"].index("--nvdApiKey") + 1], KEY)
        self.assertNotIn(KEY, run["out"])

    def test_every_update_disables_the_valid_for_hours_skip(self):
        # 10.0.3 skips an update, exit 0, when last.checked is under 4 h old.
        for the_seed in (None, seed()):
            with self.subTest(seeded=the_seed is not None):
                run = _run(the_seed=the_seed, db=True, modified=ago(HOUR), checked=ago(0))
                self.assertEqual(run["dc"][run["dc"].index("--nvdValidForHours") + 1], "0")


class TestTheStepRefusesAnUnfinishedOrStaleDatabase(unittest.TestCase):
    """#3251, on a full download."""

    def test_a_failed_sync_leaving_no_timestamp_is_not_published(self):
        run = _run(sync_rc=1, db=True)
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("the update did not finish", run["out"])

    def test_a_failed_sync_leaving_a_stale_database_is_not_published(self):
        run = _run(sync_rc=1, db=True, modified=ago(73 * HOUR))
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("(73 h old)", run["out"])
        self.assertIn("over 72 h old", run["out"])

    def test_a_clean_exit_does_not_excuse_a_stale_database(self):
        run = _run(db=True, modified=ago(73 * HOUR))
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("not publishing stale data", run["out"])

    def test_a_database_at_the_limit_passes(self):
        run = _run(db=True, modified=ago(72 * HOUR))
        self.assertEqual(run["rc"], 0, run["out"])
        self.assertIn("(72 h old)", run["out"])

    def test_a_non_zero_full_download_with_a_fresh_database_passes(self):
        # #2508's tolerance on the full leg, unchanged here (ruled on #3417).
        run = _run(sync_rc=1, db=True, modified=ago(HOUR))
        self.assertEqual(run["rc"], 0, run["out"])
        self.assertIn("on a full download", run["out"])

    def test_a_minute_past_the_limit_is_refused(self):
        run = _run(db=True, modified=ago(72 * HOUR + 60))
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("over 72 h old", run["out"])

    def test_a_value_ahead_of_the_clock_passes_within_the_skew_and_not_past_it(self):
        run = _run(db=True, modified=ago(-HOUR))
        self.assertEqual(run["rc"], 0, run["out"])
        run = _run(db=True, modified=ago(-HOUR - 60))
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("is in the future: %s" % ago(-HOUR - 60), run["out"])

    def test_an_empty_value_fails_by_name(self):
        run = _run(db=True, modified="")
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("has an empty nvd.api.last.modified", run["out"])

    def test_a_login_missing_from_the_jar_fails_by_name(self):
        for props in ("", "data.user=dc-user\\n", "data.password=p\\n"):
            with self.subTest(props=props):
                run = _fresh(props=props)
                self.assertNotEqual(run["rc"], 0, run["out"])
                self.assertIn("could not read the database login", run["out"])

    def test_the_read_opens_this_database_read_only_with_the_jars_login_and_asks_for_this_row(self):
        run = _fresh()
        self.assertEqual(run["rc"], 0, run["out"])
        argv = run["java"]
        self.assertEqual("jdbc:h2:file:./odc-data/odc;ACCESS_MODE_DATA=r", argv[argv.index("-url") + 1])
        self.assertEqual("dc-user", argv[argv.index("-user") + 1])
        self.assertEqual("a=b", argv[argv.index("-password") + 1])
        self.assertEqual("SELECT * FROM properties WHERE id='nvd.api.last.modified'",
                         argv[argv.index("-sql") + 1])

    def test_an_unreadable_database_fails_by_name(self):
        run = _fresh(java_rc=1)
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("could not read nvd.api.last.modified", run["out"])

    def test_a_value_that_is_not_a_timestamp_fails_by_name(self):
        run = _run(db=True, modified="soon")
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("is not a timestamp: soon", run["out"])


class TestASeededSync(unittest.TestCase):
    """#3417: seeded from the last published image, refused unless the update ran."""

    def test_a_normal_day_seeds_by_digest_and_publishes(self):
        run = _run(the_seed=seed(), db=True, checked=ago(0))
        self.assertEqual(run["rc"], 0, run["out"])
        self.assertIn("seeded from ghcr.io/owner/repo-tools-nvd@" + DIGEST, run["out"])
        create = [c for c in run["docker"] if c.startswith("create ")]
        self.assertEqual(create, ["create ghcr.io/owner/repo-tools-nvd@%s seed" % DIGEST])
        self.assertEqual(run["marker"], {"dc_version": "10.0.3", "full_build": days_ago(2)})

    def test_seeded_with_a_failed_update_and_a_recent_timestamp_refuses(self):
        # The #3251 row the issue names: the seed's last.modified is 5 h old, so
        # the age check alone would publish yesterday's data as today's.
        run = _run(the_seed=seed(), db=True, sync_rc=8)
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("updateonly failed (rc=8) over the seed", run["out"])
        self.assertNotIn("marker: dependency-check", run["out"])

    def test_seeded_with_a_clean_exit_but_no_update_refuses(self):
        # The validforhours skip's shape: exit 0, nothing written.
        run = _run(the_seed=seed(), db=True)
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("did not move past the seed's", run["out"])

    def test_seeded_with_last_checked_going_backwards_refuses(self):
        run = _run(the_seed=seed(checked=ago(HOUR)), db=True, checked=ago(2 * HOUR))
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("did not move past the seed's", run["out"])

    def test_a_quiet_nvd_day_publishes(self):
        # Nothing changed upstream: last.modified stays where the seed had it,
        # last.checked moves.
        run = _run(the_seed=seed(modified=ago(30 * HOUR)), db=True, checked=ago(0))
        self.assertEqual(run["rc"], 0, run["out"])
        self.assertIn("(30 h old)", run["out"])

    def test_a_seed_still_has_to_be_under_72_hours(self):
        run = _run(the_seed=seed(modified=ago(80 * HOUR)), db=True, checked=ago(0))
        self.assertNotEqual(run["rc"], 0, run["out"])
        self.assertIn("over 72 h old", run["out"])

    def test_the_seed_s_full_build_date_is_carried_forward(self):
        run = _run(the_seed=seed(full_build=days_ago(9)), db=True, checked=ago(0))
        self.assertEqual(run["rc"], 0, run["out"])
        self.assertEqual(run["marker"]["full_build"], days_ago(9))


class TestAnUnusableSeedFallsBackToAFullDownload(unittest.TestCase):
    """Each by name, and each over an empty directory with a fresh full_build."""

    def _full(self, reason, **kw):
        run = _fresh(**kw)
        self.assertEqual(run["rc"], 0, run["out"])
        self.assertIn("::notice::%s: full download" % reason, run["out"])
        self.assertNotIn("seeded from", run["out"])
        self.assertEqual(run["marker"], {"dc_version": "10.0.3", "full_build": days_ago(0)})
        return run

    def test_no_seed_image(self):
        run = self._full("no seed image ghcr.io/owner/repo-tools-nvd:dc-10.0.3")
        self.assertFalse([c for c in run["docker"] if c.startswith("create ")])

    def test_a_seed_without_a_marker(self):
        self._full("the seed carries no panopticon-seed.json", the_seed=seed(marker=False))

    def test_a_seed_from_another_dependency_check(self):
        self._full("the seed was made by dependency-check 10.0.2, not 10.0.3",
                   the_seed=seed(dc_version="10.0.2"))

    def test_a_seed_that_cannot_be_copied(self):
        self._full("could not copy the seed out of " + DIGEST, the_seed=seed(cp_rc=1))

    def test_a_seed_whose_last_modified_is_too_old_for_one_window(self):
        self._full("the seed's nvd.api.last.modified is over 90 days old",
                   the_seed=seed(modified=ago(91 * DAY)))

    def test_a_seed_without_last_modified_or_last_checked(self):
        self._full("the seed has no readable nvd.api.last.modified",
                   the_seed=seed(modified=False))
        self._full("the seed has no readable nvd.api.last.checked",
                   the_seed=seed(checked=False))

    def test_a_requested_full_rebuild(self):
        run = self._full("a full rebuild was requested", the_seed=seed(), full_rebuild=True)
        self.assertEqual(run["docker"], [])

    def test_the_weekly_rebuild_day_with_a_week_old_seed(self):
        self._full("weekly full rebuild (the seed's last full build is 7 days old)",
                   the_seed=seed(full_build=days_ago(7)), weekday=7)

    def test_a_31_day_old_full_build_whatever_the_day(self):
        self._full("the seed's last full build is 31 days old (cap 30)",
                   the_seed=seed(full_build=days_ago(31)))


class TestTheRebuildDayDoesNotCostAnUpdate(unittest.TestCase):
    """A failed rebuild day must not turn every following day into a full
    download: off the rebuild day, a seed under 30 days still seeds."""

    def _seeded(self, **kw):
        run = _run(db=True, checked=ago(0), **kw)
        self.assertEqual(run["rc"], 0, run["out"])
        self.assertIn("seeded from", run["out"])

    def test_not_the_rebuild_day_with_an_8_day_old_seed(self):
        self._seeded(the_seed=seed(full_build=days_ago(8)), weekday=1)

    def test_the_rebuild_day_with_a_6_day_old_seed(self):
        self._seeded(the_seed=seed(full_build=days_ago(6)), weekday=7)

    def test_a_dispatch_on_the_rebuild_day(self):
        # Only the schedule rebuilds on its own; a dispatch forces one by name.
        self._seeded(the_seed=seed(full_build=days_ago(8)), weekday=7,
                     event="workflow_dispatch")

    def test_a_29_day_old_full_build(self):
        self._seeded(the_seed=seed(full_build=days_ago(29)), weekday=2)


if __name__ == "__main__":
    unittest.main()
