"""#2933 phase 2: the CI shard bookkeeping in `scripts/ci_shards.py` and the
manifest plugin in `tests/ci_shard_manifest.py`.

Synthetic manifests only: no subprocess and no collection. The real proof is
the `shard-check` job reading the 13 manifests of an actual run.
"""
import contextlib
import io
import json
import os
import tempfile
import types
import unittest

import ci_shards
from tests import ci_shard_manifest as plugin

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = ["t.py::a", "t.py::b", "t.py::c", "t.py::d", "t.py::slow", "t.py::serial"]


def _m(selected, python="3.12", collected=TESTS):
    return {"python": python, "args": [], "collected": list(collected), "selected": list(selected)}


def _version(python, splits=2, collected=TESTS, serial=("t.py::serial",)):
    """A correct partition for one version: `splits` shards plus a serial leg."""
    parallel = [t for t in collected if t not in serial]
    legs = {}
    for g in range(splits):
        legs["%s-g%d" % (python, g + 1)] = _m(parallel[g::splits], python, collected)
    legs["%s-serial" % python] = _m(serial, python, collected)
    return legs


EXPECT = {"3.11": 3, "3.12": 4}


def _good():
    return {**_version("3.11"), **_version("3.12", splits=3)}


class ThePartitionTest(unittest.TestCase):
    def test_a_correct_partition_on_every_version_passes(self):
        self.assertEqual([], ci_shards.partition_errors(_good(), EXPECT))

    def test_a_serial_leg_that_lost_its_marker_filter_runs_tests_twice(self):
        # Condition A: `-m serial` dropped from one leg. The leg then runs the
        # whole collection, overlapping every shard.
        manifests = _good()
        manifests["3.12-serial"] = _m(TESTS)
        errors = ci_shards.partition_errors(manifests, EXPECT)
        self.assertEqual(1, len(errors), errors)
        self.assertIn("python 3.12: 5 test(s) ran in more than one job", errors[0])
        self.assertIn("3.12-serial", errors[0])

    def test_a_third_marker_filter_leaves_a_gap(self):
        # Condition A: the shards grow `and not slow` while the serial leg stays
        # `-m serial`, so the `slow` test runs nowhere.
        manifests = _good()
        for label in ("3.12-g1", "3.12-g2", "3.12-g3"):
            manifests[label]["selected"] = [t for t in manifests[label]["selected"]
                                            if t != "t.py::slow"]
        errors = ci_shards.partition_errors(manifests, EXPECT)
        self.assertEqual(["python 3.12: 1 collected test(s) ran in no job: t.py::slow"], errors)

    def test_a_dropped_shard_is_both_a_count_and_a_gap(self):
        manifests = _good()
        del manifests["3.11-g2"]
        errors = ci_shards.partition_errors(manifests, EXPECT)
        self.assertIn("python 3.11: 2 manifest(s), expected 3", errors)
        self.assertTrue(any("ran in no job" in e for e in errors), errors)

    def test_jobs_of_one_version_must_collect_the_same_tests(self):
        manifests = _good()
        manifests["3.12-g2"]["collected"] = TESTS[:-1]
        errors = ci_shards.partition_errors(manifests, EXPECT)
        self.assertTrue(any("3.12-g2 collected differently from 3.12-g1" in e for e in errors),
                        errors)

    def test_a_job_cannot_run_what_it_did_not_collect(self):
        manifests = _good()
        manifests["3.11-g1"]["selected"].append("t.py::ghost")
        errors = ci_shards.partition_errors(manifests, EXPECT)
        self.assertTrue(any("3.11-g1 ran 1 test(s) it did not collect: t.py::ghost" in e
                            for e in errors), errors)

    def test_every_version_must_collect_the_same_tests(self):
        # What lets coverage gate on 3.12 alone: no version-conditional collection.
        fewer = TESTS[:-2] + ["t.py::serial"]
        manifests = {**_version("3.11", collected=fewer), **_version("3.12", splits=3)}
        errors = ci_shards.partition_errors(manifests, EXPECT)
        self.assertEqual(["python 3.11 and 3.12 collected different tests (1): t.py::slow"],
                         errors)

    def test_an_unexpected_or_unnamed_version_is_an_error(self):
        manifests = {**_good(), "3.15-g1": _m(TESTS, python="3.15"), "x": _m(TESTS, python=None)}
        errors = ci_shards.partition_errors(manifests, EXPECT)
        self.assertIn("python 3.15: 1 unexpected manifest(s)", errors)
        self.assertIn("1 manifest(s) name no python version", errors)

    def test_a_long_list_is_quoted_short(self):
        many = ["t.py::%03d" % i for i in range(20)]
        manifests = {"3.12-g1": _m(many[:10], collected=many),
                     "3.12-serial": _m([], collected=many)}
        (error,) = ci_shards.partition_errors(manifests, {"3.12": 2})
        self.assertIn("10 collected test(s) ran in no job", error)
        self.assertTrue(error.endswith("(+5 more)"), error)


class TheCoverageFilesTest(unittest.TestCase):
    def _dir(self, names):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        for name in names:
            open(os.path.join(t.name, name), "w").close()
        return t.name

    def test_exactly_the_expected_count(self):
        names = [".coverage.cov-g1", ".coverage.cov-g2", ".coverage.cov-g3",
                 ".coverage.serial", "coverage.xml", "other"]
        self.assertEqual([], ci_shards.coverage_file_errors(self._dir(names), 4))

    def test_a_missing_or_extra_data_file_refuses_the_combine(self):
        (missing,) = ci_shards.coverage_file_errors(
            self._dir([".coverage.cov-g1", ".coverage.serial"]), 4)
        self.assertEqual("2 coverage data file(s) (.coverage.cov-g1, .coverage.serial), "
                         "expected 4", missing)
        self.assertTrue(ci_shards.coverage_file_errors(
            self._dir([".coverage.%d" % i for i in range(5)]), 4))
        self.assertEqual(["0 coverage data file(s) (none), expected 4"],
                         ci_shards.coverage_file_errors(self._dir([]), 4))


class TheDurationsMergeTest(unittest.TestCase):
    def test_each_shard_contributes_only_what_it_ran(self):
        # pytest-split merges into the file it read, so each shard's output still
        # carries the committed value for the OTHER shard's tests. Those must
        # not leak into the merge.
        committed = {"t.py::a": 9.0, "t.py::b": 9.0, "t.py::gone": 1.0}
        g1 = (_m(["t.py::a"]), dict(committed, **{"t.py::a": 1.234567}))
        g2 = (_m(["t.py::b", "t.py::new"]), dict(committed, **{"t.py::b": 2.0, "t.py::new": 0.5}))
        merged, errors = ci_shards.merge_durations([g1, g2])
        self.assertEqual([], errors)
        self.assertEqual({"t.py::a": 1.2346, "t.py::b": 2.0, "t.py::new": 0.5}, merged)

    def test_a_test_measured_twice_or_not_at_all_is_an_error(self):
        _merged, errors = ci_shards.merge_durations([
            (_m(["t.py::a"]), {"t.py::a": 1.0}),
            (_m(["t.py::a", "t.py::b"]), {"t.py::a": 1.0})])
        self.assertEqual(["measured twice: t.py::a", "ran but not measured: t.py::b"], errors)

    def test_staleness_is_scored_on_the_committed_split(self):
        committed = {"t.py::a": 1.0, "t.py::b": 1.0, "t.py::c": 1.0}
        pairs = [(_m(["t.py::a", "t.py::b"]), {}), (_m(["t.py::c", "t.py::new"]), {})]
        merged = {"t.py::a": 1.0, "t.py::b": 2.0, "t.py::c": 1.0, "t.py::new": 1.0}
        fraction, ratio = ci_shards.staleness(committed, pairs, merged)
        self.assertEqual((0.25, 1.5), (fraction, ratio))

    def test_the_warning_thresholds_are_strict(self):
        self.assertEqual([], ci_shards.stale_warnings(0.10, 1.15))
        self.assertEqual(2, len(ci_shards.stale_warnings(0.1001, 1.1501)))
        self.assertIn("15.7% of parallel-pass tests", ci_shards.stale_warnings(0.157, 1.0)[0])
        self.assertIn("1.30x apart", ci_shards.stale_warnings(0.0, 1.3)[0])


class TheCommandLineTest(unittest.TestCase):
    def _tree(self, files):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        for name, body in files.items():
            with open(os.path.join(t.name, name), "w", encoding="utf-8") as fh:
                json.dump(body, fh)
        return t.name

    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = ci_shards.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_check(self):
        tree = self._tree({"manifest-%s.json" % k: v for k, v in _good().items()})
        rc, out, err = self._run(["check", tree, "--expect", "3.11=3", "--expect", "3.12=4"])
        self.assertEqual((0, ""), (rc, err))
        self.assertIn("7 manifests; every collected test ran exactly once", out)
        rc, _out, err = self._run(["check", tree, "--expect", "3.11=3"])
        self.assertEqual(1, rc)
        self.assertIn("python 3.12: 4 unexpected manifest(s)", err)
        with self.assertRaises(SystemExit):
            self._run(["check", tree, "--expect", "3.11"])

    def test_merge_durations_writes_the_profile_and_warns_only(self):
        committed = {"t.py::a": 1.0}
        tree = self._tree({
            "manifest-cov-g1.json": _m(["t.py::a"]), "durations-cov-g1.json": {"t.py::a": 3.0},
            "manifest-cov-g2.json": _m(["t.py::b"]), "durations-cov-g2.json": {"t.py::b": 1.0},
            "committed.json": committed})
        out_path = os.path.join(tree, "out.json")
        rc, out, _err = self._run(["merge-durations", tree, "--committed",
                                   os.path.join(tree, "committed.json"), "-o", out_path])
        self.assertEqual(0, rc)   # stale, and still a pass
        with open(out_path, encoding="utf-8") as fh:
            self.assertEqual({"t.py::a": 3.0, "t.py::b": 1.0}, json.load(fh))
        self.assertIn("2 tests, 50.0% unknown to the committed profile, "
                      "committed split 3.00x max/min", out)
        self.assertEqual(2, out.count("::warning title=.test_durations is stale::"))

    def test_merge_durations_skips_a_manifest_with_no_durations_and_needs_one(self):
        # The 3.12 serial leg's manifest lands in the same download, with no
        # durations file: it is not part of the parallel-pass profile.
        tree = self._tree({
            "manifest-cov-g1.json": _m(["t.py::a"]), "durations-cov-g1.json": {"t.py::a": 1.0},
            "manifest-serial.json": _m(["t.py::serial"]), "committed.json": {"t.py::a": 1.0}})
        out_path = os.path.join(tree, "out.json")
        argv = ["merge-durations", tree, "--committed", os.path.join(tree, "committed.json"),
                "-o", out_path]
        self.assertEqual(0, self._run(argv)[0])
        with open(out_path, encoding="utf-8") as fh:
            self.assertEqual({"t.py::a": 1.0}, json.load(fh))
        os.remove(os.path.join(tree, "durations-cov-g1.json"))
        rc, _out, err = self._run(argv)
        self.assertEqual(1, rc)
        self.assertIn("no shard durations", err)

    def test_merge_durations_fails_on_a_double_measurement(self):
        tree = self._tree({
            "manifest-g1.json": _m(["t.py::a"]), "durations-g1.json": {"t.py::a": 1.0},
            "manifest-g2.json": _m(["t.py::a"]), "durations-g2.json": {"t.py::a": 1.0},
            "committed.json": {}})
        rc, _out, err = self._run(["merge-durations", tree, "--committed",
                                   os.path.join(tree, "committed.json"),
                                   "-o", os.path.join(tree, "out.json")])
        self.assertEqual(1, rc)
        self.assertIn("measured twice: t.py::a", err)
        self.assertFalse(os.path.exists(os.path.join(tree, "out.json")))

    def test_coverage_files(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        open(os.path.join(t.name, ".coverage.serial"), "w").close()
        self.assertEqual(0, self._run(["coverage-files", t.name, "--expect", "1"])[0])
        self.assertEqual(1, self._run(["coverage-files", t.name, "--expect", "4"])[0])


class _Config:
    """The parts of a pytest Config the plugin reads."""

    def __init__(self, path=None, worker=None, controller=False):
        self._path = path
        if worker is not None:
            self.workerinput = {"workerid": worker}
        self._controller = controller
        self.pluginmanager = self
        self.invocation_params = types.SimpleNamespace(args=("tests/", "-m", "not serial"))

    def has_plugin(self, name):
        """`pluginmanager.has_plugin`: xdist's controller registers "dsession"."""
        return self._controller and name == "dsession"

    def getoption(self, name, default=None):
        assert name == "shard_manifest", name
        return self._path


def _items(*nodeids):
    return [types.SimpleNamespace(nodeid=n) for n in nodeids]


class ThePluginTest(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dir = t.name
        self.path = os.path.join(t.name, "manifest.json")

    def _run(self, config, items, keep):
        """Collection as pytest drives it: our tryfirst hook, a deselection, finish."""
        before = list(items)
        plugin.pytest_collection_modifyitems(None, config, items)
        self.assertEqual(before, items, "the plugin must never change the collection")
        session = types.SimpleNamespace(config=config, items=[i for i in items if i.nodeid in keep])
        plugin.pytest_collection_finish(session)

    def test_inert_without_the_option(self):
        # Condition B: no option, so no file and no change, in a plain run, on
        # an xdist worker, and on the controller alike.
        for config in (_Config(), _Config(worker="gw0"), _Config(controller=True)):
            self._run(config, _items("a", "b"), {"a"})
            self.assertFalse(hasattr(config, plugin._COLLECTED))
        self.assertEqual([], os.listdir(self.dir))

    def test_nothing_loads_it_by_default(self):
        # Condition B: the local suite and the forge legs never load the plugin.
        # Only CI's `-p tests.ci_shard_manifest` does.
        for rel in ("pyproject.toml", "tests/conftest.py", "setup.cfg", "pytest.ini", "tox.ini"):
            path = os.path.join(ROOT, rel)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    self.assertNotIn("ci_shard_manifest", fh.read(), rel)

    def test_records_collected_before_deselection_and_selected_after(self):
        config = _Config(self.path)
        self._run(config, _items("a", "b", "c"), {"b"})
        with open(self.path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        self.assertEqual(["a", "b", "c"], manifest["collected"])
        self.assertEqual(["b"], manifest["selected"])
        self.assertRegex(manifest["python"], r"^3\.\d+$")
        self.assertEqual(["tests/", "-m", "not serial"], manifest["args"])

    def test_under_xdist_only_gw0_writes(self):
        for config in (_Config(self.path, controller=True), _Config(self.path, worker="gw1")):
            self._run(config, _items("a"), {"a"})
        self.assertEqual([], os.listdir(self.dir))
        self._run(_Config(self.path, worker="gw0"), _items("a"), {"a"})
        self.assertEqual(["manifest.json"], os.listdir(self.dir))

    def test_the_collection_hook_runs_first(self):
        # Ahead of the `-m` filter and pytest-split, so `collected` is everything.
        self.assertTrue(plugin.pytest_collection_modifyitems.pytest_impl["tryfirst"])


if __name__ == "__main__":
    unittest.main()
