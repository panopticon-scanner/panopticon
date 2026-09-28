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
import unittest

from scripts.tools import ADAPTERS
import scripts.tools.legacy_sarif as legacy
import scripts.tools.sarif_utils as su


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

    def test_prefix_keys_are_exactly_the_legacy_tools(self):
        # Every key in sarif_utils.PREFIX must correspond to a legacy SARIF
        # tool. Stale entries (e.g. the retired bare "eslint" adapter) would
        # otherwise sit in the registry forever with no consumer.
        #
        # #2235 (ARC-1125964489): the other direction was unpinned, and it is
        # the one with teeth. A legacy tool with NO PREFIX entry takes
        # `LegacySarifAdapter.prefix`'s shared "TL" fallback, so the second such
        # tool collides silently -- which is this file's whole subject. The test
        # above catches it only once the tool is REGISTERED in `ADAPTERS`; this
        # equality catches it when the tool is added to `LEGACY_SARIF_TOOLS`,
        # which is the edit that comes first.
        self.assertEqual(
            set(su.PREFIX), set(legacy.LEGACY_SARIF_TOOLS),
            "sarif_utils.PREFIX and LEGACY_SARIF_TOOLS have drifted; PREFIX-only "
            "%r, LEGACY_SARIF_TOOLS-only %r"
            % (sorted(set(su.PREFIX) - set(legacy.LEGACY_SARIF_TOOLS)),
               sorted(set(legacy.LEGACY_SARIF_TOOLS) - set(su.PREFIX))))

    def test_tool_cmd_keys_are_exactly_the_legacy_tools(self):
        # #2235 (ARC-3428598333/ARC-1125964489): `LEGACY_SARIF_TOOLS` names the
        # tools this adapter dispatches and `TOOL_CMD` holds their argv, in two
        # tables in the same module, pinned in neither direction. A name in
        # LEGACY_SARIF_TOOLS with no TOOL_CMD entry raises out of
        # `LegacySarifAdapter.invoke`; a TOOL_CMD entry with no
        # LEGACY_SARIF_TOOLS row gets its capture written with the wrong
        # extension by `run_tools` (`.json` instead of `.sarif`) and is then
        # ingested as the wrong format.
        self.assertEqual(
            set(legacy.TOOL_CMD), set(legacy.LEGACY_SARIF_TOOLS),
            "TOOL_CMD and LEGACY_SARIF_TOOLS have drifted; TOOL_CMD-only %r, "
            "LEGACY_SARIF_TOOLS-only %r"
            % (sorted(set(legacy.TOOL_CMD) - set(legacy.LEGACY_SARIF_TOOLS)),
               sorted(set(legacy.LEGACY_SARIF_TOOLS) - set(legacy.TOOL_CMD))))

    def test_registered_legacy_adapters_are_exactly_the_legacy_tools(self):
        # #2235: the third parallel table -- the five literal
        # `LegacySarifAdapter(...)` rows in `tools/__init__.py`'s ADAPTERS --
        # was pinned in neither direction either. A legacy tool that is never
        # registered cannot be dispatched as an adapter at all; a registered
        # name that LEGACY_SARIF_TOOLS does not carry is the extension bug
        # above, reached from the other side.
        registered = {name for name, adapter in ADAPTERS.items()
                      if isinstance(adapter, legacy.LegacySarifAdapter)}
        self.assertEqual(
            registered, set(legacy.LEGACY_SARIF_TOOLS),
            "the registered LegacySarifAdapter rows and LEGACY_SARIF_TOOLS have "
            "drifted; registered-only %r, LEGACY_SARIF_TOOLS-only %r"
            % (sorted(registered - set(legacy.LEGACY_SARIF_TOOLS)),
               sorted(set(legacy.LEGACY_SARIF_TOOLS) - registered)))


if __name__ == "__main__":
    unittest.main()
