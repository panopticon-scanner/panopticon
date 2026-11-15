"""Human disclosures the report's two views share.

#3270 adds the provenance lines: the tools image a scan was dispatched by, and
every external app the run launched. They read `meta.tools.image` and
`meta.apps`, which synth has repaired; this module stays import-free.

The rest is for the adapter that executes the target's build.

roslyn-secguard builds the reviewed repository (its MSBuild and analyzer code),
so it is opt-in and off by default (#3265, owner ruling 2026-10-23), and when
it does run it builds ONE solution or project (#3248). The report's Markdown
and HTML views say both the same way; this module owns the sentences, so
neither view carries a second copy. Every sentence is a constant with the
adapter's name and a count in it -- nothing else from the target.
"""

NOT_RUN = ("%s not run: it executes the target's build; pass "
           "--allow-target-build to enable.")


def not_run_lines(coverage):
    """One line per name in `meta.coverage.target_build_not_run`, sorted; [] on
    anything else. `synth.tool_axis` has already repaired the list to the
    adapters this build knows execute a target build."""
    names = coverage.get("target_build_not_run") if isinstance(coverage, dict) else None
    if not isinstance(names, list):
        return []
    return [NOT_RUN % name for name in sorted({n for n in names if isinstance(n, str) and n})]


def partial_audit_line(name, count):
    """The coverage-line sentence for a `meta.tools.sanitized` row (#1646).

    pip-audit's dropped rows are requirement lines; roslyn-secguard's are the
    projects its one build did not reach (#3248), so the sentence names them as
    such rather than as requirements."""
    if name == "roslyn-secguard":
        return ("%s: %d project%s not analysed (outside the one solution or "
                "project it builds)" % (name, count, "" if count == 1 else "s"))
    return "%s: %d requirement lines not audited (editable/local/VCS)" % (name, count)


# #3271 (ruling D2): a stamped run by ANOTHER host is ours, so it is said, not
# halted on. `first_contact` prints the same sentence on stderr.
PRIOR_RUN = "this run started over an earlier %s run (%s) in .panopticon/"


def _text(value):
    return value if isinstance(value, str) and value else None


def image_line(image):
    """`meta.tools.image` as one line, or None."""
    if not isinstance(image, dict) or not _text(image.get("ref")):
        return None
    if not _text(image.get("id")):
        return "Tools image: %s not available; the tool scan was skipped" % image["ref"]
    digests = [d for d in image.get("repo_digests") or [] if _text(d)]
    registry = ("registry digest %s" % digests[0].rpartition("@")[2] if digests
                else "local build, no registry digest")
    code = _text(image.get("adapter_code"))
    return "Tools image: %s @ %s (%s); adapter code %s" % (
        image["ref"], image["id"], registry, code or "unrecorded")


def app_line(app):
    """One `meta.apps` row as one line, or None."""
    if not isinstance(app, dict) or not _text(app.get("name")):
        return None
    sha = _text(app.get("sha256"))
    line = "Host app: %s %s at %s (%s)" % (
        app["name"], _text(app.get("version")) or "(version unknown)",
        _text(app.get("path")) or "no trusted path",
        "sha256:%s" % sha if sha else "sha256 unknown")
    return line + ("; %s" % app["reason"] if _text(app.get("reason")) else "")


# #3651: where the review matrix came from. One `key: value` line of fixed words and hashes,
# nothing from the target, so it reads the same in both views and can move into a report
# header's text section unchanged. FRESH is the case two reports cannot be compared across.
MATRIX_ORIGINS = {
    "committed": "committed (reused: the config is in the reviewed commit, unmodified)",
    "working_tree": "working_tree (FRESH: the config is not in the reviewed commit; %s)",
    "unknown": "unknown (whether the config is in the reviewed commit could not be measured)",
}
MATRIX_DRAFTS = {"unchanged": "it is setup's last draft, unchanged",
                 "differs": "it is not setup's last draft"}
MATRIX_NO_DRAFT = "no setup draft is on record for this target"
MATRIX_COMPARABLE = "comparable only with runs on the same fingerprint"


def matrix_line(matrix):
    """`Matrix: origin=...; fingerprint=...; config=...`, or "" when the report carries no
    matrix block (one written before #3651)."""
    if not isinstance(matrix, dict):
        return ""
    origin = _text(matrix.get("origin")) or "unknown"
    origin = origin if origin in MATRIX_ORIGINS else "unknown"
    said = MATRIX_ORIGINS[origin]
    if origin == "working_tree":
        draft = matrix.get("setup_draft")
        said %= MATRIX_DRAFTS[draft] if isinstance(draft, str) and draft in MATRIX_DRAFTS \
            else MATRIX_NO_DRAFT
    parts = ["origin=" + said,
             "fingerprint=%s" % (_text(matrix.get("matrix_fingerprint")) or "unmeasured"),
             "config=%s" % (_text(matrix.get("config_sha256")) or "unrecorded")]
    if origin != "committed":
        parts.append(MATRIX_COMPARABLE)
    return "Matrix: " + "; ".join(parts)


def provenance_lines(meta):
    """The image line, one line per app, the prior run, then the matrix; [] when none of
    them was recorded."""
    if not isinstance(meta, dict):
        return []
    tools, apps = meta.get("tools"), meta.get("apps")
    tools = tools if isinstance(tools, dict) else {}
    apps = apps if isinstance(apps, list) else []
    prior = meta.get("prior_run")
    lines = [image_line(tools.get("image"))] + [app_line(app) for app in apps]
    if isinstance(prior, dict) and _text(prior.get("host")) and _text(prior.get("run_id")):
        lines.append("Prior run: " + PRIOR_RUN % (prior.get("host"), prior.get("run_id")))
    lines.append(matrix_line(meta.get("matrix")))
    return [line for line in lines if line]
