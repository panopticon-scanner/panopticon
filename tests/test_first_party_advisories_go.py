"""#3623 Go: owner ruling G1(a) -- Go classifies nothing.

A go.mod declares `module M` and no version of its own: the main module's version
comes from VCS tags at build time, and so does a go.work `use` module's. The only
versioned in-tree identity is `require M vX` + `replace M => ./dir`, where vX is the
consumer's claim (often a placeholder pseudo-version), never proved by the module.
So every Go advisory -- the main module, a workspace module, a local replace target,
a registry module -- stays on the ordinary tool-advisor path. Fixtures only.
"""

import json
import os
import tempfile
import unittest

import scripts.evidence as evidence
import scripts.first_party_advisory as first_party_advisory
import scripts.ingest_tools as ingest_tools


APP = ("example.com/app", "v0.0.0-00010101000000-000000000000")
LIB = ("example.com/lib", "v1.2.3")
TOOLS = ("example.com/tools", "v0.1.0")
REGISTRY = ("golang.org/x/text", "v0.3.7")


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _go_tree(root):
    """A main module that requires and locally replaces a lib, in a go.work workspace
    with a tools module, plus one registry dependency."""
    _write(os.path.join(root, "go.mod"),
           "module example.com/app\n\ngo 1.22\n\n"
           "require (\n\texample.com/lib v1.2.3\n\tgolang.org/x/text v0.3.7\n)\n\n"
           "replace example.com/lib v1.2.3 => ./lib\n")
    _write(os.path.join(root, "go.sum"), "golang.org/x/text v0.3.7 h1:x=\n")
    _write(os.path.join(root, "lib", "go.mod"), "module example.com/lib\n\ngo 1.22\n")
    _write(os.path.join(root, "tools", "go.mod"), "module example.com/tools\n\ngo 1.22\n")
    _write(os.path.join(root, "go.work"), "go 1.22\n\nuse (\n\t.\n\t./lib\n\t./tools\n)\n")


def _finding(package, *, path, source):
    return {
        "id": "OS-001",
        "title": "%s %s: GO-2099-0001" % package,
        "source": source,
        "location": {"file": path, "line_start": 1},
        "tool_evidence": {"rule_id": "GO-2099-0001", "package_name": package[0],
                          "vulnerable_versions": package[1]},
    }


def _osv_document(path):
    def package(name, version, advisory):
        return {"package": {"name": name, "version": version, "ecosystem": "Go"},
                "vulnerabilities": [{"id": advisory, "summary": "affected module",
                                     "database_specific": {"severity": "HIGH"}}],
                "groups": []}
    return {"results": [{"source": {"path": "/src/" + path}, "packages": [
        package(*APP, "GO-2099-0001"), package(*LIB, "GO-2099-0002"),
        package(*TOOLS, "GO-2099-0003"), package(*REGISTRY, "GO-2099-0004")]}]}


def _trivy_document(package, path):
    advisory = "CVE-2099-23456"
    return {"runs": [{
        "tool": {"driver": {"name": "trivy", "rules": [{
            "id": advisory,
            "properties": {"security-severity": "8.1",
                           "tags": ["vulnerability", "security", "HIGH"]}}]}},
        "results": [{
            "ruleId": advisory, "level": "error",
            "message": {"text": "Package: %s\nInstalled Version: %s\nVulnerability %s\n"
                                "Severity: HIGH" % (package[0], package[1], advisory)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": path}, "region": {"startLine": 1}}}]}]}]}


class TestGoAdvisoriesStayWithTheAdvisor(unittest.TestCase):

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = os.path.realpath(d.name)
        _go_tree(self.root)

    def _ingest(self, name, document):
        # One fresh tool-output directory per ingest; ingest reads canonical names.
        tools = tempfile.mkdtemp(prefix="tools-out-", dir=self.root)
        with open(os.path.join(tools, name), "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        return ingest_tools.ingest_dir(tools, "g1", target_root=self.root)

    def assert_advisor_path(self, finding):
        self.assertFalse(evidence.is_first_party_advisory(finding))
        self.assertNotIn("package_origin", finding["tool_evidence"])
        self.assertNotIn("advisory_package", finding["tool_evidence"])

    def test_no_go_identity_is_classified_from_any_manifest(self):
        # The main module, the local replace target, a go.work `use` module and a
        # registry module, against every Go manifest a scanner might name, with every
        # version a scanner might report for an unversioned module.
        packages = (APP, ("example.com/app", ""), ("example.com/app", "(devel)"),
                    LIB, TOOLS, REGISTRY)
        for path in ("go.mod", "go.sum", "go.work", "lib/go.mod", "tools/go.mod"):
            for source in ("tool:osv-scanner", "tool:trivy"):
                for package in packages:
                    with self.subTest(path=path, source=source, package=package):
                        finding = _finding(package, path=path, source=source)
                        first_party_advisory.mark([finding], self.root,
                                                  first_party_advisory.IngestCache())
                        self.assert_advisor_path(finding)

    def test_osv_ingest_of_go_mod_keeps_every_module_on_the_advisor_path(self):
        for path in ("go.mod", "lib/go.mod"):
            with self.subTest(path=path):
                findings = self._ingest("osv-scanner.json", _osv_document(path))
                self.assertEqual(4, len(findings))
                for finding in findings:
                    self.assert_advisor_path(finding)
                    self.assertIn("Vulnerable dependency", finding["impact"])

    def test_trivy_ingest_of_go_mod_keeps_the_replace_target_on_the_advisor_path(self):
        for package in (LIB, APP, TOOLS):
            with self.subTest(package=package):
                findings = self._ingest("trivy.sarif", _trivy_document(package, "go.mod"))
                self.assertEqual(1, len(findings))
                self.assert_advisor_path(findings[0])

    def test_go_manifests_read_nothing_from_the_ingest_budget(self):
        # Nothing is classified, so nothing is read: the shared budget is untouched.
        cache = first_party_advisory.IngestCache()
        findings = [_finding(LIB, path="go.mod", source="tool:osv-scanner"),
                    _finding(TOOLS, path="go.work", source="tool:trivy")]
        first_party_advisory.mark(findings, self.root, cache)
        self.assertEqual(first_party_advisory.MAX_CARGO_MANIFEST_INGEST_BYTES,
                         cache.manifest_bytes_remaining)
        self.assertEqual({}, cache.manifests)
        self.assertEqual({}, cache.package_origins)


if __name__ == "__main__":
    unittest.main()
