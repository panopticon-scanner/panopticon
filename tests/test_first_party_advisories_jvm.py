"""#3623 Maven and Gradle: owner rulings J1 and J2 -- both classify nothing.

Gradle (J1): a build.gradle(.kts) sets `group` and `version` in a build script, and
gradle.lockfile lists only resolved external modules, never the build's own projects,
so no lock entry is ever a local project a manifest proves. Maven (J2): a reactor
module's pom.xml can state a literal groupId:artifactId:version, but nothing shows the
pinned scanners ever report a sibling reactor module, and a marker built for a case
never seen would be unproven surface. Every Maven and Gradle advisory -- a reactor
parent, a module, a Gradle project, a registry artifact -- stays on the ordinary
tool-advisor path. Revisit Maven only if a real run shows the scanners flagging
sibling reactor modules. Fixtures only.
"""

import json
import os
import tempfile
import unittest

import scripts.evidence as evidence
import scripts.first_party_advisory as first_party_advisory
import scripts.ingest_tools as ingest_tools
import scripts.tools as tools


PARENT = ("com.acme:acme-parent", "1.2.0")
CORE = ("com.acme:acme-core", "1.2.0")
APP = ("com.acme:acme-app", "1.2.0")
LIB = ("com.acme:acme-lib", "1.2.0")
REGISTRY = ("org.apache.commons:commons-text", "1.9")

# Every adapter the marker accepts, not just the two that report Maven today (#3696 review).
SOURCES = tuple("tool:" + name for name in sorted(tools.ADVISORY_ADAPTERS | {"trivy"}))

MANIFESTS = ("pom.xml", "core/pom.xml", "app/pom.xml", "gradle.lockfile",
             "lib/gradle.lockfile", "buildscript-gradle.lockfile",
             "gradle/verification-metadata.xml", "build.gradle", "lib/build.gradle.kts",
             "settings.gradle",
             # At the root too: only the root's own lock is ever read, so a subdirectory
             # copy alone would not show a read.
             "build.gradle.kts", "verification-metadata.xml", "settings.gradle.kts")


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _pom(artifact, *, parent=False, packaging="jar", modules=(), deps=""):
    head = ("  <parent>\n    <groupId>com.acme</groupId>\n"
            "    <artifactId>acme-parent</artifactId>\n    <version>1.2.0</version>\n"
            "  </parent>\n" if parent else
            "  <groupId>com.acme</groupId>\n  <version>1.2.0</version>\n")
    listed = "".join("    <module>%s</module>\n" % m for m in modules)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            "  <modelVersion>4.0.0</modelVersion>\n%s"
            "  <artifactId>%s</artifactId>\n  <packaging>%s</packaging>\n"
            "%s%s</project>\n"
            % (head, artifact, packaging,
               "  <modules>\n%s  </modules>\n" % listed if listed else "", deps))


def _jvm_tree(root):
    """A Maven reactor (a pom parent, a core jar, an app depending on core and on a
    registry artifact) beside a Gradle build with one lib project, both versioned with
    plain literals -- the strongest form either ecosystem has."""
    dep = ("  <dependencies>\n"
           "    <dependency><groupId>com.acme</groupId><artifactId>acme-core</artifactId>"
           "<version>1.2.0</version></dependency>\n"
           "    <dependency><groupId>org.apache.commons</groupId>"
           "<artifactId>commons-text</artifactId><version>1.9</version></dependency>\n"
           "  </dependencies>\n")
    _write(os.path.join(root, "pom.xml"),
           _pom("acme-parent", packaging="pom", modules=("core", "app")))
    _write(os.path.join(root, "core", "pom.xml"), _pom("acme-core", parent=True))
    _write(os.path.join(root, "app", "pom.xml"), _pom("acme-app", parent=True, deps=dep))
    _write(os.path.join(root, "settings.gradle"),
           "rootProject.name = 'acme-app'\ninclude 'lib'\n")
    _write(os.path.join(root, "build.gradle"),
           "allprojects {\n    group = 'com.acme'\n    version = '1.2.0'\n}\n"
           "dependencies {\n    implementation project(':lib')\n"
           "    implementation 'org.apache.commons:commons-text:1.9'\n}\n")
    _write(os.path.join(root, "lib", "build.gradle.kts"),
           'plugins { `java-library` }\nversion = "1.2.0"\n')
    lockfile = ("# This is a Gradle generated file for dependency locking.\n"
                "org.apache.commons:commons-text:1.9=compileClasspath,runtimeClasspath\n"
                "empty=\n")
    for path in ("gradle.lockfile", "lib/gradle.lockfile", "buildscript-gradle.lockfile"):
        _write(os.path.join(root, path), lockfile)
    for path in ("gradle/verification-metadata.xml", "verification-metadata.xml"):
        _write(os.path.join(root, path),
               '<?xml version="1.0" encoding="UTF-8"?>\n<verification-metadata/>\n')
    for path in ("build.gradle.kts", "settings.gradle.kts"):
        _write(os.path.join(root, path), 'version = "1.2.0"\n')


def _finding(package, *, path, source):
    tool_evidence = {"rule_id": "GHSA-xxxx-yyyy-zzzz", "package_name": package[0],
                     "vulnerable_versions": package[1]}
    if source == "tool:osv-scanner":
        # As osv-scanner reports it. Without this the finding is refused for declaring
        # no ecosystem, before any JVM manifest could be read -- which would hide a
        # marker that reads a pom.xml and then leaves the finding unclassified.
        tool_evidence["ecosystem"] = "Maven"
    return {
        "id": "OS-001",
        "title": "%s %s: GHSA-xxxx-yyyy-zzzz" % package,
        "source": source,
        "location": {"file": path, "line_start": 1},
        "tool_evidence": tool_evidence,
    }


def _osv_document(path):
    def package(name, version, advisory):
        return {"package": {"name": name, "version": version, "ecosystem": "Maven"},
                "vulnerabilities": [{"id": advisory, "summary": "affected artifact",
                                     "database_specific": {"severity": "HIGH"}}],
                "groups": []}
    return {"results": [{"source": {"path": "/src/" + path}, "packages": [
        package(*PARENT, "GHSA-0000-0000-0001"), package(*CORE, "GHSA-0000-0000-0002"),
        package(*APP, "GHSA-0000-0000-0003"), package(*LIB, "GHSA-0000-0000-0004"),
        package(*REGISTRY, "GHSA-0000-0000-0005")]}]}


def _trivy_document(package, path):
    advisory = "CVE-2099-34567"
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


class TestJvmAdvisoriesStayWithTheAdvisor(unittest.TestCase):

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = os.path.realpath(d.name)
        _jvm_tree(self.root)

    def _ingest(self, name, document):
        # One fresh tool-output directory per ingest; ingest reads canonical names.
        tools = tempfile.mkdtemp(prefix="tools-out-", dir=self.root)
        with open(os.path.join(tools, name), "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        return ingest_tools.ingest_dir(tools, "j1", target_root=self.root)

    def assert_advisor_path(self, finding):
        self.assertFalse(evidence.is_first_party_advisory(finding))
        self.assertNotIn("package_origin", finding["tool_evidence"])
        self.assertNotIn("advisory_package", finding["tool_evidence"])

    def test_no_jvm_identity_is_classified_from_any_manifest(self):
        # The reactor parent, a reactor module, the module depending on it, a Gradle
        # project and a registry artifact, against every Maven and Gradle manifest a
        # scanner might name, under every adapter the marker accepts and both name
        # spellings a scanner might report.
        packages = (PARENT, CORE, APP, LIB, REGISTRY, ("acme-core", "1.2.0"),
                    ("com.acme:acme-core", "1.2.0-SNAPSHOT"))
        for path in MANIFESTS:
            for source in SOURCES:
                for package in packages:
                    with self.subTest(path=path, source=source, package=package):
                        finding = _finding(package, path=path, source=source)
                        first_party_advisory.mark([finding], self.root,
                                                  first_party_advisory.IngestCache())
                        self.assert_advisor_path(finding)

    def test_osv_ingest_keeps_every_artifact_on_the_advisor_path(self):
        for path in ("pom.xml", "core/pom.xml", "app/pom.xml", "gradle.lockfile",
                     "lib/gradle.lockfile"):
            with self.subTest(path=path):
                findings = self._ingest("osv-scanner.json", _osv_document(path))
                self.assertEqual(5, len(findings))
                for finding in findings:
                    self.assert_advisor_path(finding)
                    self.assertIn("Vulnerable dependency", finding["impact"])

    def test_trivy_ingest_keeps_reactor_modules_on_the_advisor_path(self):
        for package, path in ((CORE, "app/pom.xml"), (PARENT, "pom.xml"),
                              (LIB, "gradle.lockfile")):
            with self.subTest(package=package):
                findings = self._ingest("trivy.sarif", _trivy_document(package, path))
                self.assertEqual(1, len(findings))
                self.assert_advisor_path(findings[0])

    def test_a_maven_record_at_another_ecosystems_lock_is_not_first_party(self):
        # #3760, the case that made this file's headline false: an OSV record that says
        # Maven, pointed at a Cargo.lock whose own package has the same name and version.
        with open(os.path.join(self.root, "Cargo.lock"), "w", encoding="utf-8") as fh:
            fh.write('version = 3\n\n[[package]]\nname = "acme-core"\nversion = "1.2.0"\n')
        with open(os.path.join(self.root, "Cargo.toml"), "w", encoding="utf-8") as fh:
            fh.write('[package]\nname = "acme-core"\nversion = "1.2.0"\n')
        crate = ("acme-core", "1.2.0")
        for ecosystem, expected in (("Maven", None), ("maven", None), ("MAVEN", None),
                                    ("crates.io", "first_party")):
            with self.subTest(ecosystem=ecosystem):
                finding = _finding(crate, path="Cargo.lock", source="tool:osv-scanner")
                finding["tool_evidence"]["ecosystem"] = ecosystem
                cache = first_party_advisory.IngestCache()
                first_party_advisory.mark([finding], self.root, cache)
                self.assertEqual(expected, finding["tool_evidence"].get("package_origin"))
                if expected is None:
                    self.assertEqual(first_party_advisory.MAX_CARGO_MANIFEST_INGEST_BYTES,
                                     cache.manifest_bytes_remaining)
                    self.assertEqual({}, cache.package_origins)

    def test_jvm_manifests_read_nothing_from_the_ingest_budget(self):
        # Nothing is classified, so nothing is read: the shared budget is untouched.
        cache = first_party_advisory.IngestCache()
        # Every identity against every manifest path under every adapter (#3696 review:
        # two paths left a pom.xml read unnoticed).
        findings = [_finding(package, path=path, source=source)
                    for path in MANIFESTS for source in SOURCES
                    for package in (PARENT, CORE, APP, LIB, REGISTRY)]
        self.assertIn("tool:dependency-check", SOURCES)
        first_party_advisory.mark(findings, self.root, cache)
        self.assertEqual(first_party_advisory.MAX_CARGO_MANIFEST_INGEST_BYTES,
                         cache.manifest_bytes_remaining)
        self.assertEqual({}, cache.manifests)
        self.assertEqual({}, cache.package_origins)


if __name__ == "__main__":
    unittest.main()
