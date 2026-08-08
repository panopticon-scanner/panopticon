"""Systemic finding-ID prefix guard (#695 / run-3 TEST-010).

Every adapter stamps finding IDs as ``<prefix>-<n>``. Sixteen adapters keep
their prefixes in two independently-maintained places (class attributes and
``sarif_utils.PREFIX``), and until this file the only collision guard in the
suite was one hardcoded pairwise check (eslint-security ESS vs legacy ES).
Worse, ``LegacySarifAdapter.prefix`` silently falls back to ``"TL"`` for any
tool name missing from ``sarif_utils.PREFIX`` — so registering two new legacy
tools without PREFIX entries would give both the same prefix and no test
would object. These tests make prefix uniqueness a property of the registry,
not of whichever pair someone remembered to check.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "skill"))
from scripts.tools import ADAPTERS  # noqa: E402
import scripts.tools.legacy_sarif as legacy  # noqa: E402
import scripts.tools.sarif_utils as su  # noqa: E402


def prefix_collisions(adapters):
    """Map each colliding prefix to the sorted adapter names that share it."""
    by_prefix = {}
    for name, adapter in adapters.items():
        by_prefix.setdefault(adapter.prefix, []).append(name)
    return {p: sorted(names) for p, names in by_prefix.items() if len(names) > 1}


class TestPrefixRegistry(unittest.TestCase):
    def test_helper_detects_a_synthetic_collision(self):
        # The guard is only as good as its detector: prove it fires.
        class _A:
            def __init__(self, prefix):
                self.prefix = prefix
        fake = {"one": _A("XX"), "two": _A("XX"), "three": _A("YY")}
        self.assertEqual(prefix_collisions(fake), {"XX": ["one", "two"]})

    def test_all_registered_adapter_prefixes_are_unique(self):
        collisions = prefix_collisions(ADAPTERS)
        self.assertEqual(
            collisions, {},
            "finding-ID prefix shared by multiple adapters — IDs would "
            "collide across tools: %r" % collisions)

    def test_registered_legacy_adapters_never_use_the_tl_fallback(self):
        # A legacy adapter whose name is missing from sarif_utils.PREFIX gets
        # the shared "TL" fallback prefix — fine for ad-hoc parse-only use,
        # but in the registry it is a guaranteed silent collision waiting for
        # the second unlisted tool. Every REGISTERED legacy adapter must have
        # an explicit PREFIX entry.
        unlisted = sorted(
            name for name, adapter in ADAPTERS.items()
            if isinstance(adapter, legacy.LegacySarifAdapter)
            and adapter.name not in su.PREFIX)
        self.assertEqual(
            unlisted, [],
            "registered legacy adapters relying on the shared TL fallback "
            "prefix: %r — add explicit sarif_utils.PREFIX entries" % unlisted)


if __name__ == "__main__":
    unittest.main()
