"""Tests for scripts.synth.codes: OCRDb code validation and severity ordinals.
"""
import contextlib
import io
import os
import json
import tempfile
import unittest
from unittest import mock

import scripts.synthesize as syn
import scripts.synth.codes as codes_mod
import scripts.ocrdb as ocrdb


class TestSevOrdinal(unittest.TestCase):
    def test_sev_ordinal_derived_from_shared_order(self):
        # #run7 QAL-D1B: _SEV_ORDINAL must be DERIVED from evidence.SEV_ORDER,
        # not a hand-literal that silently desyncs on a reorder/add/remove.
        import scripts.evidence as ev
        self.assertEqual(codes_mod._SEV_ORDINAL,
                         {s: i for i, s in enumerate(reversed(ev.SEV_ORDER))})
        self.assertLess(codes_mod._SEV_ORDINAL["LOW"], codes_mod._SEV_ORDINAL["HIGH"])
        self.assertEqual(codes_mod._SEV_ORDINAL["INFO"], 0)

class TestOcrdbCoverageHardening(unittest.TestCase):
    """#1034: domainless-code normalization, code/domain mismatch disclosure,
    and a distinct exit code for a corrupt bundle."""

    def _bundle(self):
        return ocrdb.load_bundle()

    def test_domainless_code_normalized_to_sentinel(self):  # #2
        f = {"code": "garbage"}  # no '-', no sibling domain -> no derivable domain
        cov = codes_mod.validate_finding_codes([f], self._bundle())
        self.assertEqual(f["code"], "ZZZ-X0X")  # reserved sentinel
        self.assertEqual(cov["domainless"], 1)
        self.assertEqual(cov["invalid_codes"], 1)  # still counted as "not real"

    def test_code_domain_mismatch_disclosed(self):  # #3
        b = self._bundle()
        cod = ocrdb.domain_menu(b, "COD")[0]["code"]  # a real COD code
        f = {"domain": "SEC", "code": cod}  # stated SEC, code says COD
        cov = codes_mod.validate_finding_codes([f], b)
        self.assertEqual(cov["code_domain_mismatch"], 1)
        self.assertEqual(f["code"], cod)  # valid code kept, not rewritten

    def test_corrupt_bundle_exits_3(self):  # #1
        # distinct from gate FAIL (1) / INCONCLUSIVE (2) so CI can tell them apart
        prev = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            fp = os.path.join(d, "findings.json")
            with open(fp, "w", encoding="utf-8") as fh:
                json.dump({"findings": []}, fh)
            out = os.path.join(d, "report.json")
            try:
                os.chdir(d)
                with (
                    mock.patch(
                        "scripts.ocrdb.load_bundle", side_effect=ValueError("bundle malformed")
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    rc = syn.main(["--target", "t", "--out", out, fp])
            finally:
                os.chdir(prev)
        self.assertEqual(rc, 3)
