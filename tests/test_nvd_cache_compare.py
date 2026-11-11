"""#3417: `devtools/nvd_cache_compare.py`, the seeded-vs-fresh check.

The comparison and the H2 shell parsing are pinned here with in-memory
answers; the real read (java and the release's H2 jar) runs in the one-off
workflow_dispatch that compares two real databases.
"""
import io
import os
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout

import nvd_cache_compare as ncc

CPE = ("a", "acme", "widget", "*", "1.0", "NULL", "NULL", "2.0", "TRUE")


def _db(scores, cpes=()):
    """A fake database: `scores` {cve: (v3, v2)} and `cpes` [(cve, *cpe)]."""
    return {"scores": [(c, v3, v2) for c, (v3, v2) in scores.items()],
            "cpes": [tuple(row) for row in cpes]}


def _query(dbs):
    seen = []

    def query(directory, sql):
        seen.append((directory, sql))
        return dbs[directory]["scores" if sql.startswith("SELECT cve,") else "cpes"]
    query.seen = seen
    return query


def _main(dbs, *argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = ncc.main(["seeded", "fresh", *argv], query=_query(dbs))
    return rc, out.getvalue(), err.getvalue()


class TheComparisonTest(unittest.TestCase):
    def test_two_databases_that_agree_pass(self):
        db = _db({"CVE-2024-0107": ("9.8", "7.5"), "CVE-2023-1207": ("NULL", "5.0")},
                 [("CVE-2024-0107",) + CPE])
        rc, out, _ = _main({"seeded": db, "fresh": db})
        self.assertEqual(rc, 0, out)
        self.assertIn("sampled: 2 CVEs in seeded, 2 in fresh, 2 in both", out)
        self.assertIn("PASS", out)

    def test_each_kind_of_disagreement_is_counted_and_named(self):
        seeded = _db({"CVE-1-0107": ("9.8", "7.5"), "CVE-2-0107": ("5.0", "5.0"),
                      "CVE-3-0107": ("1.0", "1.0"), "CVE-4-0107": ("2.0", "2.0")},
                     [("CVE-2-0107",) + CPE])
        fresh = _db({"CVE-1-0107": ("9.1", "7.5"), "CVE-2-0107": ("5.0", "5.0"),
                     "CVE-4-0107": ("2.0", "2.0"), "CVE-5-0107": ("3.0", "3.0")},
                    [("CVE-2-0107",) + CPE[:-1] + ("FALSE",)])
        rc, out, _ = _main({"seeded": seeded, "fresh": fresh})
        self.assertEqual(rc, 1, out)
        self.assertIn("only in seeded: 1: CVE-3-0107", out)
        self.assertIn("only in fresh: 1: CVE-5-0107", out)
        self.assertIn("different scores: 1: CVE-1-0107", out)
        self.assertIn("different CPE matches: 1: CVE-2-0107", out)
        self.assertIn("FAIL", out)

    def test_a_cpe_set_is_compared_as_a_set(self):
        other = ("a", "acme", "gadget", "*", "NULL", "NULL", "NULL", "NULL", "TRUE")
        seeded = _db({"CVE-1-0107": ("1", "1")}, [("CVE-1-0107",) + CPE, ("CVE-1-0107",) + other])
        fresh = _db({"CVE-1-0107": ("1", "1")}, [("CVE-1-0107",) + other, ("CVE-1-0107",) + CPE])
        self.assertEqual(_main({"seeded": seeded, "fresh": fresh})[0], 0)

    def test_it_prints_ids_and_counts_never_the_data(self):
        seeded = _db({"CVE-1-0107": ("9.8", "7.5")}, [("CVE-1-0107",) + CPE])
        fresh = _db({"CVE-1-0107": ("9.1", "7.5")}, [("CVE-1-0107",) + CPE])
        _, out, _ = _main({"seeded": seeded, "fresh": fresh})
        for value in ("9.8", "9.1", "acme", "widget"):
            self.assertNotIn(value, out)

    def test_a_long_list_is_cut_and_says_by_how_much(self):
        seeded = _db({"CVE-%04d-0107" % i: ("1", "1") for i in range(60)})
        rc, out, _ = _main({"seeded": seeded, "fresh": _db({"CVE-9999-0107": ("1", "1")})})
        self.assertEqual(rc, 1)
        self.assertIn("only in seeded: 60:", out)
        self.assertIn("(+10 more)", out)

    def test_both_sides_are_sampled_by_the_same_suffix(self):
        db = _db({"CVE-1-0042": ("1", "1")})
        query = _query({"seeded": db, "fresh": db})
        with redirect_stdout(io.StringIO()):
            ncc.main(["seeded", "fresh", "--suffix", "42"], query=query)
        self.assertEqual({d for d, _ in query.seen}, {"seeded", "fresh"})
        self.assertTrue(all(sql.endswith("LIKE '%42'") for _, sql in query.seen))

    def test_an_empty_sample_on_both_sides_is_an_error_not_a_pass(self):
        rc, _, err = _main({"seeded": _db({}), "fresh": _db({})})
        self.assertEqual(rc, 2)
        self.assertIn("the sample is empty", err)

    def test_a_suffix_that_is_not_digits_is_refused(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            ncc.main(["a", "b", "--suffix", "0' OR '1"], query=_query({}))

    def test_an_unreadable_database_exits_2_by_name(self):
        def query(directory, sql):
            raise ncc.Unreadable("could not read %s: boom" % directory)
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(ncc.main(["seeded", "fresh"], query=query), 2)
        self.assertIn("could not read seeded: boom", err.getvalue())


class TheH2ReadTest(unittest.TestCase):
    def test_shell_output_parses_to_rows(self):
        output = ("CVE           | V3BASESCORE | V2SCORE\n"
                  "CVE-2024-0107 | 9.8         | null\n"
                  "CVE-2023-1207 | null        | 5.0\n"
                  "(2 rows, 3 ms)\n")
        self.assertEqual(ncc.parse_shell(output),
                         [("CVE-2024-0107", "9.8", "null"), ("CVE-2023-1207", "null", "5.0")])

    def test_no_rows_and_unexpected_output(self):
        self.assertEqual(ncc.parse_shell("CVE | V3BASESCORE | V2SCORE\n(0 rows, 1 ms)\n"), [])
        for output in ("", "Exception in thread main\n"):
            with self.assertRaises(ncc.Unreadable):
                ncc.parse_shell(output)

    def _release(self, directory, properties=None, h2=1):
        lib = os.path.join(directory, "lib")
        os.makedirs(lib)
        if properties is not None:
            with zipfile.ZipFile(os.path.join(lib, "dependency-check-core-10.0.3.jar"), "w") as jar:
                jar.writestr("dependencycheck.properties", properties)
        for i in range(h2):
            open(os.path.join(lib, "h2-2.%d.jar" % i), "w").close()

    def test_the_login_comes_from_the_release_jar(self):
        with tempfile.TemporaryDirectory() as directory:
            self._release(directory, "# c\ndata.user=dc-user\ndata.password=a=b\n")
            self.assertEqual(ncc.login(directory), ("dc-user", "a=b"))

    def test_a_missing_login_or_jar_is_unreadable(self):
        for properties in ("data.user=u\n", None):
            with self.subTest(properties=properties), tempfile.TemporaryDirectory() as directory:
                self._release(directory, properties)
                with self.assertRaises(ncc.Unreadable):
                    ncc.login(directory)

    def test_the_h2_jar_must_be_exactly_one(self):
        for count in (0, 2):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                self._release(directory, h2=count)
                with self.assertRaises(ncc.Unreadable):
                    ncc.h2_query(directory, "u", "p")


if __name__ == "__main__":
    unittest.main()
