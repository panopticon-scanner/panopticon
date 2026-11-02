"""#3351: machine-keyed receipts for crash-settled batch entries."""
import copy
import hashlib
import hmac
import os
import shutil
import tempfile
import unittest
from unittest import mock

import scripts.run_stamp as run_stamp
import scripts.runners.settlement as settlement_mod


class TestSettlementReceipt(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp(prefix="settlement-key-")
        self.addCleanup(shutil.rmtree, self.state, True)
        self.env = mock.patch.dict(os.environ, {"PANOPTICON_STATE_DIR": self.state})
        self.env.start()
        self.addCleanup(self.env.stop)
        run_stamp._KEY_CACHE.clear()
        self.addCleanup(run_stamp._KEY_CACHE.clear)
        self.context = {"run_id": "run-1", "review_root": "/tmp/review",
                        "namespace": "", "request_sha256": "a" * 64}
        self.fields = {
            "context": self.context, "batch": 4, "nonce": "b" * 32,
            "checkpoint": "review", "entry_id": "review-app-SEC",
            "ledger": {"version": 1, "start": 17, "end": 81,
                       "sha256": "c" * 64},
            "artifacts": [{"path": "/tmp/review/.panopticon/out.json",
                           "sha256": "d" * 64}],
            "refund_attempt": False,
        }

    def _expected(self):
        return {key: self.fields[key] for key in
                ("context", "batch", "nonce", "checkpoint", "entry_id")}

    def test_receipt_is_versioned_domain_separated_and_verifies(self):
        receipt = settlement_mod.issue(**self.fields)
        self.assertEqual(1, receipt["version"])
        self.assertEqual("panopticon-batch-settlement-1", receipt["domain"])
        self.assertRegex(receipt["hmac_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(settlement_mod.verifies(receipt, **self._expected()))

    def test_verification_binds_the_callers_exact_run_and_request_context(self):
        receipt = settlement_mod.issue(**self.fields)
        mutations = (
            ("run", lambda context: context.update(run_id="run-2")),
            ("root", lambda context: context.update(review_root="/tmp/other-review")),
            ("namespace", lambda context: context.update(namespace="setup")),
            ("request", lambda context: context.update(request_sha256="e" * 64)),
        )
        for label, mutate in mutations:
            with self.subTest(fact=label):
                expected = copy.deepcopy(self._expected())
                mutate(expected["context"])
                self.assertFalse(settlement_mod.verifies(receipt, **expected))

    def test_verification_binds_the_callers_batch_nonce_checkpoint_and_entry(self):
        receipt = settlement_mod.issue(**self.fields)
        changes = (
            ("batch", {"batch": 5}),
            ("nonce", {"nonce": "e" * 32}),
            ("checkpoint", {"checkpoint": "verify"}),
            ("entry", {"entry_id": "review-app-ACC"}),
            ("checkpoint-and-entry",
             {"checkpoint": "verify", "entry_id": "review-app-ACC"}),
        )
        for label, changed in changes:
            with self.subTest(fact=label):
                expected = self._expected()
                expected.update(changed)
                self.assertFalse(settlement_mod.verifies(receipt, **expected))

    def test_an_undomained_mac_is_not_a_settlement_signature(self):
        receipt = settlement_mod.issue(**self.fields)
        body = {key: value for key, value in receipt.items()
                if key != "hmac_sha256"}
        receipt["hmac_sha256"] = hmac.new(
            run_stamp.key(), settlement_mod._canonical(body), hashlib.sha256).hexdigest()
        self.assertFalse(settlement_mod.verifies(receipt, **self._expected()))

    def test_every_settlement_fact_is_authenticated(self):
        receipt = settlement_mod.issue(**self.fields)
        mutations = (
            lambda r: r.update(version=2),
            lambda r: r.update(domain="some-other-purpose"),
            lambda r: r.update(batch=5),
            lambda r: r.update(nonce="e" * 32),
            lambda r: r["ledger"].update(start=18),
            lambda r: r["artifacts"][0].update(sha256="f" * 64),
            lambda r: r.update(refund_attempt=True),
            lambda r: r.update(hmac_sha256="0" * 64),
        )
        expected = self._expected()
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                changed = copy.deepcopy(receipt)
                mutate(changed)
                self.assertFalse(settlement_mod.verifies(changed, **expected))

    def test_no_artifact_is_an_explicit_authenticated_fact(self):
        fields = dict(self.fields, artifacts=[])
        receipt = settlement_mod.issue(**fields)
        self.assertEqual([], receipt["artifacts"])
        self.assertTrue(settlement_mod.verifies(receipt, **{
            key: fields[key] for key in
            ("context", "batch", "nonce", "checkpoint", "entry_id")}))


if __name__ == "__main__":
    unittest.main()
