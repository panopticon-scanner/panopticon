"""SpotBugs + FindSecBugs adapter for Java/Kotlin security findings."""
from __future__ import annotations
import os
import sys

from scripts.claim_scope import confined_to_root

from .base import (as_list, make_finding, omit_none, run_tool, scratch_cwd,
                   target_root_cv)

# The two vendor versions `_SPOTBUGS_CWE` below was generated from -- a
# version bump that regenerates the table without updating these, or updates
# these without regenerating the table, now fails a test instead of going
# stale silently (#2275, #2285). Nothing at run time reads them; the
# provenance comment below already names both.
_TABLE_SPOTBUGS_VERSION = "4.8.6"
_TABLE_FINDSECBUGS_VERSION = "1.13.0"

# Every CWE core SpotBugs 4.8.6 or FindSecBugs 1.13.0 itself assigns to a bug
# pattern (#2275, COD-1501398192), from each vendor's own `findbugs.xml`, on
# 2026-09-28. Two sources, no category filter (a vendor maps a CWE to a
# non-SECURITY pattern too -- core's EI_EXPOSE_REP -> CWE-374 is one -- and
# the adapter already cited regardless of category):
#   * core SpotBugs 4.8.6: `findbugs.xml` at the root of `spotbugs.jar`,
#     itself inside the release tarball the Dockerfile pins
#     (SPOTBUGS_VERSION=4.8.6; tarball sha256, its SPOTBUGS_SHA256, is
#     b9d4d25e53cd4202b2dc19c549c0ff54f8a72fc76a71a8c40dee94422c67ebea); the
#     jar's OWN sha256, measured against the pinned tools image rather than
#     pinned by name in the Dockerfile, is
#     69fde8787971a26b2372d416015d806bf7df4f847f7121bd5eeef239324cf180. 38 of
#     its 497 patterns carry a cweid.
#   * the FindSecBugs 1.13.0 plugin: `findbugs.xml` inside
#     `findsecbugs-plugin.jar`, sha256
#     c239763a8c327b5fb653a34dece6398578bf435b9a32c212bb8e1abe701368a5 --
#     matching the Dockerfile's FINDSECBUGS_SHA256 pin directly. 107 of its
#     144 patterns carry a cweid.
# 145 entries total (38 + 107; the two vendors' type names do not overlap).
# Patterns neither vendor maps stay uncited on purpose -- each vendor's own
# answer, not a gap this table should paper over: core's own findbugs.xml
# lists the golden's DM_DEFAULT_ENCODING that way, and also
# XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER; the plugin does the same for
# HTTP_PARAMETER_POLLUTION, the SERVLET_*/*_ENDPOINT families, COOKIE_USAGE
# and the rest of its 37. This replaces a hand-written seven-entry table.
# Six of those seven were always real -- COMMAND_INJECTION,
# PATH_TRAVERSAL_IN, WEAK_TRUST_MANAGER, WEAK_HOSTNAME_VERIFIER and both
# SQL_* entries, which are core's patterns, not the plugin's -- and only
# HARDCODED_KEY named one neither vendor has ever emitted, so SpotBugs fed
# nothing to policy C's credential clause (ingest_tools.gates_when_suppressed)
# through that one dead entry. Regenerated with a throwaway script, not
# checked in: unzip BOTH `spotbugs.jar`'s and `findsecbugs-plugin.jar`'s
# `findbugs.xml` and take every <BugPattern> with a `cweid` from each.
# Reading `cweid` from the tool's own `-xml:withMessages` output at run time,
# instead of a table baked in here, is a later route (it needs a real-image
# round and a golden refresh, out of scope for this fix).
_SPOTBUGS_CWE = {
    "ANDROID_BROADCAST": "CWE-276",
    "ANDROID_EXTERNAL_FILE_ACCESS": "CWE-276",
    "ANDROID_GEOLOCATION": "CWE-359",
    "ANDROID_WEB_VIEW_JAVASCRIPT": "CWE-79",
    "ANDROID_WEB_VIEW_JAVASCRIPT_INTERFACE": "CWE-285",
    "ANDROID_WORLD_WRITABLE": "CWE-276",
    "BAD_HEXA_CONVERSION": "CWE-704",
    "BC_IMPOSSIBLE_CAST": "CWE-570",
    "BC_IMPOSSIBLE_DOWNCAST": "CWE-570",
    "BC_IMPOSSIBLE_DOWNCAST_OF_TOARRAY": "CWE-570",
    "BC_IMPOSSIBLE_INSTANCEOF": "CWE-570",
    "BC_VACUOUS_INSTANCEOF": "CWE-571",
    "BLOWFISH_KEY_SIZE": "CWE-326",
    "BX_BOXING_IMMEDIATELY_UNBOXED_TO_PERFORM_COERCION": "CWE-192",
    "CIPHER_INTEGRITY": "CWE-353",
    "COMMAND_INJECTION": "CWE-78",
    "COOKIE_PERSISTENT": "CWE-539",
    "CRLF_INJECTION_LOGS": "CWE-117",
    "CUSTOM_INJECTION": "CWE-74",
    "CUSTOM_MESSAGE_DIGEST": "CWE-327",
    "DANGEROUS_PERMISSION_COMBINATION": "CWE-732",
    "DC_DOUBLECHECK": "CWE-609",
    "DC_PARTIALLY_CONSTRUCTED": "CWE-609",
    "DESERIALIZATION_GADGET": "CWE-502",
    "DES_USAGE": "CWE-327",
    "DMI_CONSTANT_DB_PASSWORD": "CWE-259",
    "DMI_EMPTY_DB_PASSWORD": "CWE-259",
    "DM_EXIT": "CWE-382",
    "ECB_MODE": "CWE-327",
    "EI_EXPOSE_BUF": "CWE-374",
    "EI_EXPOSE_BUF2": "CWE-374",
    "EI_EXPOSE_REP": "CWE-374",
    "EI_EXPOSE_REP2": "CWE-374",
    "EL_INJECTION": "CWE-94",
    "ENTITY_LEAK": "CWE-212",
    "ENTITY_MASS_ASSIGNMENT": "CWE-915",
    "ESync_EMPTY_SYNC": "CWE-585",
    "EXTERNAL_CONFIG_CONTROL": "CWE-15",
    "FI_EXPLICIT_INVOCATION": "CWE-586",
    "FI_PUBLIC_SHOULD_BE_PROTECTED": "CWE-583",
    "GROOVY_SHELL": "CWE-94",
    "HARD_CODE_KEY": "CWE-321",
    "HARD_CODE_PASSWORD": "CWE-259",
    "HAZELCAST_SYMMETRIC_ENCRYPTION": "CWE-327",
    "HRS_REQUEST_PARAMETER_TO_COOKIE": "CWE-113",
    "HRS_REQUEST_PARAMETER_TO_HTTP_HEADER": "CWE-113",
    "HTTPONLY_COOKIE": "CWE-1004",
    "HTTP_RESPONSE_SPLITTING": "CWE-113",
    "IL_INFINITE_RECURSIVE_LOOP": "CWE-674",
    "IMPROPER_UNICODE": "CWE-176",
    "INFORMATION_EXPOSURE_THROUGH_AN_ERROR_MESSAGE": "CWE-209",
    "INSECURE_COOKIE": "CWE-614",
    "IP_PARAMETER_IS_DEAD_BUT_OVERWRITTEN": "CWE-563",
    "J2EE_STORE_OF_NON_SERIALIZABLE_OBJECT_INTO_SESSION": "CWE-579",
    "JACKSON_UNSAFE_DESERIALIZATION": "CWE-502",
    "JSP_INCLUDE": "CWE-98",
    "JSP_JSTL_OUT": "CWE-79",
    "JSP_SPRING_EVAL": "CWE-917",
    "JSP_XSLT": "CWE-94",
    "LDAP_ENTRY_POISONING": "CWE-90",
    "LDAP_INJECTION": "CWE-90",
    "LI_LAZY_INIT_STATIC": "CWE-543",
    "LI_LAZY_INIT_UPDATE_STATIC": "CWE-543",
    "MALICIOUS_XSLT": "CWE-94",
    "MODIFICATION_AFTER_VALIDATION": "CWE-176",
    "NORMALIZATION_AFTER_VALIDATION": "CWE-176",
    "NP_SYNC_AND_NULL_CHECK_FIELD": "CWE-585",
    "NULL_CIPHER": "CWE-327",
    "OBJECT_DESERIALIZATION": "CWE-502",
    "OGNL_INJECTION": "CWE-94",
    "PADDING_ORACLE": "CWE-326",
    "PATH_TRAVERSAL_IN": "CWE-22",
    "PATH_TRAVERSAL_OUT": "CWE-22",
    "PLAY_UNVALIDATED_REDIRECT": "CWE-601",
    "PREDICTABLE_RANDOM": "CWE-330",
    "PREDICTABLE_RANDOM_SCALA": "CWE-330",
    "PT_ABSOLUTE_PATH_TRAVERSAL": "CWE-36",
    "PT_RELATIVE_PATH_TRAVERSAL": "CWE-23",
    "QBA_QUESTIONABLE_BOOLEAN_ASSIGNMENT": "CWE-481",
    "REC_CATCH_EXCEPTION": "CWE-396",
    "REDOS": "CWE-400",
    "RSA_KEY_SIZE": "CWE-326",
    "RSA_NO_PADDING": "CWE-780",
    "RU_INVOKE_RUN": "CWE-572",
    "RV_RETURN_VALUE_IGNORED_BAD_PRACTICE": "CWE-253",
    "SCALA_COMMAND_INJECTION": "CWE-78",
    "SCALA_PATH_TRAVERSAL_IN": "CWE-22",
    "SCALA_PLAY_SSRF": "CWE-918",
    "SCALA_SENSITIVE_DATA_EXPOSURE": "CWE-200",
    "SCALA_SQL_INJECTION_ANORM": "CWE-89",
    "SCALA_SQL_INJECTION_SLICK": "CWE-89",
    "SCALA_XSS_MVC_API": "CWE-79",
    "SCALA_XSS_TWIRL": "CWE-79",
    "SCRIPT_ENGINE_INJECTION": "CWE-94",
    "SEAM_LOG_INJECTION": "CWE-94",
    "SF_DEAD_STORE_DUE_TO_SWITCH_FALLTHROUGH": "CWE-484",
    "SF_DEAD_STORE_DUE_TO_SWITCH_FALLTHROUGH_TO_THROW": "CWE-484",
    "SF_SWITCH_FALLTHROUGH": "CWE-484",
    "SPEL_INJECTION": "CWE-94",
    "SPRING_CSRF_PROTECTION_DISABLED": "CWE-352",
    "SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING": "CWE-352",
    "SPRING_UNVALIDATED_REDIRECT": "CWE-601",
    "SQL_INJECTION": "CWE-564",
    "SQL_INJECTION_ANDROID": "CWE-89",
    "SQL_INJECTION_HIBERNATE": "CWE-564",
    "SQL_INJECTION_JDBC": "CWE-89",
    "SQL_INJECTION_JDO": "CWE-89",
    "SQL_INJECTION_JPA": "CWE-89",
    "SQL_INJECTION_SPRING_JDBC": "CWE-89",
    "SQL_INJECTION_TURBINE": "CWE-564",
    "SQL_INJECTION_VERTX": "CWE-564",
    "SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE": "CWE-89",
    "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING": "CWE-89",
    "STATIC_IV": "CWE-329",
    "STRUTS_FORM_VALIDATION": "CWE-106",
    "TDES_USAGE": "CWE-326",
    "TEMPLATE_INJECTION_FREEMARKER": "CWE-94",
    "TEMPLATE_INJECTION_PEBBLE": "CWE-94",
    "TEMPLATE_INJECTION_VELOCITY": "CWE-94",
    "TRUST_BOUNDARY_VIOLATION": "CWE-501",
    "UNENCRYPTED_SERVER_SOCKET": "CWE-319",
    "UNENCRYPTED_SOCKET": "CWE-319",
    "UNSAFE_HASH_EQUALS": "CWE-203",
    "UNVALIDATED_REDIRECT": "CWE-601",
    "URLCONNECTION_SSRF_FD": "CWE-918",
    "WEAK_HOSTNAME_VERIFIER": "CWE-295",
    "WEAK_MESSAGE_DIGEST_MD5": "CWE-328",
    "WEAK_MESSAGE_DIGEST_SHA1": "CWE-328",
    "WEAK_TRUST_MANAGER": "CWE-295",
    "WICKET_XSS1": "CWE-79",
    "XML_DECODER": "CWE-502",
    "XPATH_INJECTION": "CWE-643",
    "XSS_JSP_PRINT": "CWE-79",
    "XSS_REQUEST_PARAMETER_TO_SEND_ERROR": "CWE-81",
    "XSS_REQUEST_WRAPPER": "CWE-79",
    "XSS_SERVLET": "CWE-79",
    "XXE_DOCUMENT": "CWE-611",
    "XXE_DTD_TRANSFORM_FACTORY": "CWE-611",
    "XXE_SAXPARSER": "CWE-611",
    "XXE_SCHEMA_FACTORY": "CWE-611",
    "XXE_VALIDATOR": "CWE-611",
    "XXE_XMLREADER": "CWE-611",
    "XXE_XMLSTREAMREADER": "CWE-611",
    "XXE_XPATH": "CWE-611",
    "XXE_XSLT_TRANSFORM_FACTORY": "CWE-611",
}

# SpotBugs/FindSecBugs exposes TWO orthogonal signals that this adapter used to
# conflate (COD-C1A #1408):
#   * <BugInstance rank="1..20"> is the bug's SEVERITY (scariness). SpotBugs
#     buckets it Scariest(1-4) / Scary(5-9) / Troubling(10-14) / Of Concern
#     (15-20) -- this is what the Java severity/impact is.
#   * <BugInstance priority="1..3"> is the analyzer's CONFIDENCE that the match
#     is real (1=high, 2=normal, 3=low), explicitly NOT severity.
# Read rank -> severity and priority -> confidence, rather than reading priority
# as severity and hardcoding confidence, which relabelled a high-confidence
# low-severity bug as HIGH (and buried a genuinely severe but less-certain bug
# as LOW/MEDIUM) while discarding the real confidence signal entirely.

# priority -> confidence, matching the brakeman adapter's high/medium/low house
# style; an absent/unknown priority is conservatively POSSIBLE.
_PRIORITY_TO_CONFIDENCE = {
    "1": "CERTAIN",   # SpotBugs high confidence
    "2": "LIKELY",    # SpotBugs normal confidence
    "3": "POSSIBLE",  # SpotBugs low confidence
}


# SpotBugs reports a `sourcepath` relative to the SOURCE ROOT it compiled --
# `org/dummy/App.java`, the package path -- never a repo path. Everything
# downstream resolves `location.file` against the REPO root instead: the
# delta/`--pr` gate matches it to diff hunks, the tool-verify round scopes its
# advisor with `phases/coverage.group_files_containing` (a tool finding carries
# no group, so its FILE is what finds the cell), `grading` attributes findings
# to groups by it, and every exclude glob matches against it. So on a standard
# JVM layout the package path placed NOTHING (ARC-284455831) -- it scoped that
# advisor to one file that does not exist -- while the adapter's own comment
# claimed it stayed matchable.
#
# These are the source roots Maven and Gradle put sources under, in the order a
# project holding more than one wants them read: main before test, Java before
# Kotlin (this adapter covers both -- #2188), then a bare `src`, then the target
# root itself for a layout that is already repo-relative.
_SOURCE_ROOTS = ("src/main/java", "src/test/java",
                 "src/main/kotlin", "src/test/kotlin", "src", "")

# The one disclosure value: this finding's `location.file` is NOT a repo path.
_UNRESOLVED = "unresolved"


def _repo_relative(candidate: str) -> str | None:
    """`candidate` as a normalized relative path, or None if it is not one.

    Both candidates -- a `SourceLine`'s `sourcepath` and the `<Class
    classname>` derivation -- come from the TARGET's own bytecode debug info,
    so both are target-controlled on a redteam scan, and `location.file` is
    what steers the advisor's read grant (#1096). An absolute path, a `..`
    escape and a backslash-separated path are refused HERE rather than
    published and confined downstream.
    """
    if not candidate or os.path.isabs(candidate) or "\\" in candidate:
        return None
    clean = os.path.normpath(candidate)
    if clean in (os.curdir, os.pardir) or clean.startswith(os.pardir + os.sep):
        return None
    return clean


def _resolve_under_root(root: str, relative: str) -> str | None:
    """`relative` as a repo-relative path to a real file, or None.

    Probes `_SOURCE_ROOTS` in order and returns the FIRST that is a regular file
    inside `root`. The three predicates are `and`-ed in ONE expression, so their
    order changes the evaluation cost and not the outcome. What each is for:

    * `confined_to_root`, because `os.path.isfile` FOLLOWS symlinks. A committed
      `src/main/java/org -> /etc` is a readable file by every other test here,
      and resolving it would publish a `location.file` outside the reviewed tree
      -- the channel #1096 and #run8 ARC-F2A exist for. It is the one predicate
      nothing else covers, which is why it has a test of its own.
    * `isfile`, which refuses a package DIRECTORY of the same name and a
      dangling symlink (false for a broken link and an absent path alike).
    * `lexists`, only as a cheap short-circuit keeping `realpath` off the miss
      path -- on a typical tree five of the six roots miss.

    `scripts.claim_scope.confined_to_root` is the one implementation of that
    predicate (`phases/runio` and `phases/verify_tools` alias it; it is a
    stdlib-only leaf precisely so every side can reach it) -- this adapter must
    not grow a fourth copy of a security check.
    """
    for prefix in _SOURCE_ROOTS:
        probe = os.path.join(prefix, relative)      # join("", x) is x
        full = os.path.join(root, probe)
        if os.path.lexists(full) and confined_to_root(root, probe) \
                and os.path.isfile(full):
            return probe
    return None


def _locate(*candidates: str) -> tuple[str, str | None]:
    """(`location.file`, the `path_resolution` disclosure or None).

    The repo path this finding is about when the tree is in reach and holds it,
    and otherwise the package path with the reason it places nothing. The
    target root reaches `parse` through `base.target_root_cv`, the way
    pip-audit's `_located_at` takes it: `invoke` ran in the tools container and
    `ingest_tools` parses on the host, so the tree is named around the parse or
    not at all (the CI gate parses captured bytes with no tree).

    RESOLUTION comes first, across ALL candidates: the bug's `sourcepath`, the
    enclosing class's, then the `<Class classname>` derivation -- three separate
    fields, not the same one three times. Only when none of them resolves is the
    first SHAPE-LEGAL candidate published with the disclosure. Returning on the
    first shape-legal one instead let a sourcepath that merely looks like a path
    short-circuit a derivation that would have resolved; the preference order
    still decides an unresolvable tie, and there `sourcepath` is the better
    guess (an inner class derives `Holder$1.java`, which never exists).

    Duplicates are collapsed rather than probed twice: on ordinary output all
    three candidates are the same string.

    A `<Method>`'s `SourceLine` is deliberately NOT a fourth candidate: a
    `role="METHOD_CALLED"` Method names the CALLEE's file, which on the pinned
    golden is a JDK source in no repository. The cost of leaving it out is
    narrow -- a bug with no direct-child SourceLine but a class-level one still
    gets the class's file AND its start line, so only a bug whose ONLY
    SourceLine is a Method's falls to the classname derivation at line 1, a
    shape the golden does not contain. Do not re-litigate without a real sample.
    """
    root = target_root_cv.get()
    legal = list(dict.fromkeys(
        relative for relative in (_repo_relative(c) for c in candidates)
        if relative is not None))
    if root:
        for relative in legal:
            resolved = _resolve_under_root(root, relative)
            if resolved:
                return resolved, None
    return (legal[0], _UNRESOLVED) if legal else ("", _UNRESOLVED)


def _line_start(start: str | None) -> int:
    """A `SourceLine start` as a line number the report schema accepts.

    `report-schema.json` gives `location.line_start` `minimum: 1` and the
    normalization contract validates tool findings against it, so ONE unusable
    value must not invalidate the whole report. SpotBugs' own
    `SourceLineAnnotation` writes -1 for an unknown line -- a class compiled
    without line-number debug info, or a synthetic location -- and the
    attribute is target-authored, so anything at all can appear in it. Absent,
    empty, `-1`, `0` and `abc` all clamp to 1, the way `_rank_to_severity`
    already treats an unparseable rank: raising here instead would come out of
    `parse`, and `ingest_tools`' tolerant `except Exception` reads that as
    "unparseable" and loses the ENTIRE spotbugs document.
    """
    if start is None:
        return 1
    try:
        line = int(start)
    except (TypeError, ValueError):
        return 1
    return line if line >= 1 else 1


def _rank_to_severity(rank: str | None) -> str:
    """Map a SpotBugs bug rank (1=scariest .. 20=of concern) to our severity
    scale. An absent or unparseable rank falls to the neutral middle bucket
    rather than borrowing the (unrelated) confidence signal."""
    if rank is None:
        return "MEDIUM"
    try:
        r = int(rank)
    except (TypeError, ValueError):
        return "MEDIUM"
    if r <= 4:
        return "CRITICAL"   # Scariest
    if r <= 9:
        return "HIGH"       # Scary
    if r <= 14:
        return "MEDIUM"     # Troubling
    return "LOW"            # Of Concern


class SpotBugsAdapter:
    name = "spotbugs"
    prefix = "SB"
    DROP_IF_NO_LOCATION = False

    @staticmethod
    def _classes_dir(target: str):
        for rel in (("target", "classes"), ("build", "classes")):
            d = os.path.join(target, *rel)
            if os.path.isdir(d):
                return d
        return None

    def is_applicable(self, target: str) -> bool:
        # #run7 COD-C2A: SpotBugs/FindSecBugs analyzes JVM BYTECODE (.class), not
        # source. A build-manifest repo with no compiled output (the common
        # read-only static-analysis case) was marked applicable, then invoke ran
        # against a dir with zero .class files -> empty XML / "selected but
        # unproduced". Require a manifest AND a compiled classes dir. (Without a
        # build step Java coverage is impossible; gating applicability is the
        # honest fix rather than pretending to cover un-built repos.)
        markers = ["pom.xml", "build.gradle", "build.gradle.kts"]
        has_manifest = any(os.path.exists(os.path.join(target, m)) for m in markers)
        return has_manifest and self._classes_dir(target) is not None

    def invoke(self, target: str) -> tuple[bytes, int]:
        classes = self._classes_dir(target) or target
        spotbugs_home = os.environ.get("SPOTBUGS_HOME", "/opt/spotbugs")
        plugin_jar = os.path.join(spotbugs_home, "plugin", "findsecbugs-plugin.jar")
        cmd = [
            os.path.join(spotbugs_home, "bin", "spotbugs"),
            "-textui", "-xml", "-pluginList", plugin_jar,
            classes,
        ]
        # #1877: spotbugs reads cwd-relative configuration (exclude/include
        # filter files), so it runs from an empty scratch; the classes dir is
        # named on argv, so argv is byte-unchanged.
        with scratch_cwd("spotbugs-cwd-") as cwd:
            return run_tool(cmd, timeout=600, cwd=cwd)

    @staticmethod
    def _trim_to_xml(text: str) -> str:
        """Drop anything before the XML document.

        #calibration-6: spotbugs runs on a JVM, and scans run `--network none`,
        so log4j cannot resolve the container hostname and writes

            ERROR Could not determine local host name ... UnknownHostException

        to STDOUT ahead of the report. `ET.fromstring` then dies with
        `syntax error: line 1, column 0` and the whole Java axis is lost.

        The JSON adapters have had this tolerance since bandit's progress bar
        (`ingest_tools` trims to the first `{` or `[`), but that trim cannot
        help an XML payload -- it only looks for JSON start tokens. This is the
        XML equivalent, and it belongs here rather than in ingest because only
        this adapter knows its output is XML.

        Deliberately anchored to the document start, not to a `<` anywhere: a
        prefix line containing a stray angle bracket must not be mistaken for
        the report.
        """
        for marker in ("<?xml", "<BugCollection"):
            i = text.find(marker)
            if i > 0:
                print("spotbugs: stripped %d bytes of non-XML prefix "
                      "(log noise before the report)" % i, file=sys.stderr)
                return text[i:]
            if i == 0:
                return text
        return text

    def parse(self, raw: bytes, group: str) -> list[dict]:
        # Required, not optional hardening: the stdlib parser expands the
        # internal entities this one refuses, and readiness gates on the package
        # itself (#2363). No fallback -- an install without it raises
        # ModuleNotFoundError from here, loud.
        #
        # HERE and not at module level (#2369): `scripts.tools`'s package body
        # imports every adapter, and the driver imports that package through its
        # host probes, so a module-level import put defusedxml on the driver's
        # own import path. An install without it was then a traceback out of
        # `import scripts.driver` instead of the readiness `dependencies` row
        # that names its `pip install`.
        import defusedxml.ElementTree as ET
        text = self._trim_to_xml(raw.decode("utf-8", errors="replace").strip())
        if not text:
            return []
        root = ET.fromstring(text)
        out = []
        n = 1
        for bug in root.findall("BugInstance"):
            btype = bug.get("type", "")
            severity = _rank_to_severity(bug.get("rank"))
            confidence = _PRIORITY_TO_CONFIDENCE.get(bug.get("priority", ""), "POSSIBLE")
            # #2188: the bug's OWN SourceLine, which SpotBugs emits as a
            # DIRECT child. `.//SourceLine` returned the first in document
            # order -- always the enclosing <Class>'s, whose start is the
            # class's first line -- so every finding in a class landed tens of
            # lines from the code it is about (65, 69 and 66 read as 11 on the
            # pinned golden). A <Method>'s span is skipped for the same reason
            # and one more: a role="METHOD_CALLED" Method names the CALLEE's
            # file, which on that golden is a JDK source in no repository.
            own = bug.find("SourceLine")
            class_line = bug.find("Class/SourceLine")
            source = own if own is not None else class_line
            sourcepath = source.get("sourcepath", "") if source is not None else ""
            line = source.get("start") if source is not None else None
            # A separate candidate, not a fallback on the ELEMENT: a direct-child
            # SourceLine can carry `start` and no `sourcepath` at all, and
            # discarding the class's sourcepath there traded a resolvable path
            # for a derivation that, for an inner class, never exists.
            class_sourcepath = (class_line.get("sourcepath", "")
                                if class_line is not None else "")
            # #run7 COD-C3A: a bug with no usable SourceLine still gets a file,
            # derived from the BugInstance's <Class classname>
            # (com.example.App -> com/example/App.java), rather than an empty
            # location.file. (We KEEP the finding -- #1196 -- unlike the
            # SCS/#476 drop policy, which discarded compiler-diagnostic noise.)
            # It is a package path like the sourcepath, so it is matchable by
            # the delta/--pr gate only once `_locate` has resolved it against
            # the tree -- and the finding says so when it could not be.
            cls = bug.find("Class")
            classname = cls.get("classname", "") if cls is not None else ""
            derived = (classname.replace(".", "/") + ".java") if classname else ""
            file_path, unresolved = _locate(sourcepath, class_sourcepath, derived)
            cwe = _SPOTBUGS_CWE.get(btype)
            out.append(make_finding(
                self, n, group,
                title=f"{btype}",
                severity=severity,
                confidence=confidence,
                category="jvm_security",
                location={"file": file_path, "line_start": _line_start(line)},
                description=f"SpotBugs/FindSecBugs detected issue type {btype}.",
                impact="Potential security flaw in JVM bytecode.",
                remediation="Review the FindSecBugs documentation for this bug type and refactor.",
                citations={"cwe": as_list(cwe)},
                tool_evidence=omit_none({"rule_id": btype,
                                         "path_resolution": unresolved}),
            ))
            n += 1
        return out
