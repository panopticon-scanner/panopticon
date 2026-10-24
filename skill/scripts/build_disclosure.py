"""Human disclosures the report's two views share.

#3270 adds the provenance lines: the tools image a scan was dispatched by, and
every external app the run launched. They read `meta.tools.image` and
`meta.apps`, which synth has repaired; this module stays import-free so
html_report's flat import branch can load it.

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


def provenance_lines(meta):
    """The image line, then one line per app; [] when neither was recorded."""
    if not isinstance(meta, dict):
        return []
    tools, apps = meta.get("tools"), meta.get("apps")
    tools = tools if isinstance(tools, dict) else {}
    apps = apps if isinstance(apps, list) else []
    lines = [image_line(tools.get("image"))] + [app_line(app) for app in apps]
    return [line for line in lines if line]
