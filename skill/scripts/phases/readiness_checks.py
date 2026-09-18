"""The readiness phase's environment checks: what is on this machine.

Split out of `phases/readiness.py` (a pure move) so neither module sits on the
700-line ceiling. Every function here ANSWERS a question about the box --
Docker and the tools image, the Python packages the run imports, the host CLIs
on PATH -- and returns a row. Deciding what a row means, assembling the
artifact and rendering it stay in `readiness.py`, which is the only caller.

It LAUNCHES NOTHING of its own: `shutil.which` looks at the host CLIs, and the
docker probe goes through `setup_flow._check_docker`.

`DOCKER_RUNNER` below is a TEST-ONLY injection point and moved here with the
check that reads it. Its production value is `None` -- meaning "use
`setup_flow.DEFAULT_RUNNER`" -- and no module outside `tests/` may assign it: a
non-`None` value left in shipped code makes this checkpoint answer "ok" off a
fake without probing Docker at all, which is the one check gating every paid
dispatch. See DEVELOPMENT.md, "Test-only injection seams";
`tests/phases/test_readiness.py` asserts both halves, against THIS file.
"""
import importlib.util
import os
import shutil

import scripts.hosts as hosts
import scripts.setup_flow as setup_flow


# The repo root, resolved from `skill/`'s own location rather than from cwd:
# the remedy below names a `docker build` path, and the driver runs with cwd at
# the TARGET repo, which is emphatically not where the Dockerfile lives. Under
# the installed-flow substitution (#495) this resolves to whatever directory
# the skill was installed into, which is the correct answer there too.
_SKILL_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_REPO_ROOT = os.path.dirname(_SKILL_DIR)

TOOLS_IMAGE = "ghcr.io/panopticon-scanner/panopticon-tools:latest"

# Exact and paste-able, all three ways out in one line. `setup_flow`'s own
# tools-image detail points at DEVELOPMENT.md, which is the right register for
# a preflight report an operator reads at leisure and the wrong one for a
# refusal that just stopped a run: the remedy has to be runnable from the line
# it is printed on.
IMAGE_REMEDY = (
    "the panopticon-tools image is absent, so every scanner would produce "
    "nothing and every review panel would run without scanner evidence. "
    "Pull it: `docker pull %s && docker tag %s panopticon-tools:latest` -- "
    "or build it: `docker build -t panopticon-tools %s` -- or re-run with "
    "--no-tools to review without scanner evidence, which is disclosed in the "
    "report (meta.tools.panels_with_scanner_context and the tool coverage "
    "line)." % (TOOLS_IMAGE, TOOLS_IMAGE, _REPO_ROOT))

_NOT_APPLICABLE = "not applicable (--no-tools)"

# TEST-ONLY injection point; production value is None (see the module
# docstring). `None` means "use setup_flow's", which is `subprocess.run` in
# production and the suite's refusal under tests/conftest.py's autouse guard --
# so a test that wants a docker answer has to say so, and one that says nothing
# reaches nothing. Same construction, and the same reason, as the host-CLI
# launch seams in tests/test_host_launch_guard.py; this one is not a host CLI,
# so it is not spelled DEFAULT_RUNNER and does not belong in LAUNCH_SEAMS.
DOCKER_RUNNER = None

def _docker_checks(tools_flag):
    """The daemon + image rows, or two `ok: null` rows under `--no-tools`.

    Not merely skipped when tools are off: a row that vanishes is
    indistinguishable from a row that passed, and the artifact has to say which
    of the two happened on this run.
    """
    if tools_flag is False:
        return [("docker", None, _NOT_APPLICABLE),
                ("tools-image", None, _NOT_APPLICABLE)]
    runner = DOCKER_RUNNER if DOCKER_RUNNER is not None else setup_flow.DEFAULT_RUNNER
    rows = []
    for name, ok, detail in setup_flow._check_docker(runner):
        if name == "tools-image" and ok is False:
            detail = IMAGE_REMEDY
        rows.append((name, ok, detail))
    return rows

SESSION_REMEDY = (
    "not on PATH — install `%(binary)s`, or drive this host in session mode: "
    "`driver loop --host %(host)s --mode session`. `driver loop` picks headless "
    "whenever skill/scripts/runners/%(host)s.py exists, which is a fact about "
    "this repo and not about this machine, so it would resolve to headless here "
    "and find no binary")

# #1639 P15 I2: the Python packages a RUN needs, as (import name, pip name).
# Both are declared in `pyproject.toml`'s `[project] dependencies` and
# `tests/phases/test_readiness_verb.py` holds this tuple to that list, so the
# two cannot drift. Checked HERE, before the first paid dispatch, because
# neither failure is cheap where it actually lands: `jsonschema` is imported by
# the completion path's artifact validation, which is deliberately fail-closed,
# so an install without it does not quietly stop validating -- it exits
# `artifact invalid` after the whole review has been paid for. PyYAML is a hard
# import in discovery and takes the run down with a traceback.
RUNTIME_PACKAGES = (("yaml", "pyyaml"), ("jsonschema", "jsonschema"))

PACKAGES_REMEDY = "pip install %s (or `pip install -e .` in a checkout)"

def _installed(module):
    """Is `module` importable? A seam, so a test can state the machine.

    `find_spec` rather than `import`: this is a preflight, and importing a
    package for its side effects is not a read. It can raise on a broken
    parent package, which is itself a "not usable" answer.
    """
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _dependencies_row():
    """Gating: every package the run itself imports, by pip name."""
    missing = [pip for module, pip in RUNTIME_PACKAGES if not _installed(module)]
    checked = ", ".join(pip for _module, pip in RUNTIME_PACKAGES)
    return {"missing": missing, "ok": not missing,
            "detail": (PACKAGES_REMEDY % " ".join(missing)) if missing
                      else "%s installed" % checked}

def _cli_rows(host):
    """`shutil.which` and nothing else, for every host whose registry row names
    a headless CLI -- plus the SELECTED host always, even when it names none,
    because an operator who passed `--host generic` must not read three rows
    about hosts they did not ask about and none about the one they did.

    `host` is the RESOLVED host, never the raw flag: fix round 2's whole point
    is that a bare invocation still has one (`runio.resolve_host`), so there is
    always a selected row and this check is never vacuous.

    `binary` and `on_path` are null for a host that launches no CLI of ours:
    there is nothing to look for, which is a different answer from "looked and
    did not find it".

    Only the selected row can gate (F2), and only when it names a binary that
    is absent -- see SESSION_REMEDY. The others are informational: `driver
    loop` will not pick them, so their absence costs this run nothing."""
    names = set(hosts.driver_hosts())
    if hosts.spec(host) is not None:
        # A manifest may name a registered-but-unselectable host (`gemini`);
        # `orchestrate.loop` refuses that separately, and a row saying nothing
        # about the host this document is ABOUT would be worse than either.
        names.add(host)
    rows = []
    for name in sorted(names):
        binary = hosts.spec(name).cli_binary
        selected = name == host
        if not binary and not selected:
            continue                  # session-only, and not the one asked about
        found = shutil.which(binary) if binary else None
        rows.append({"host": name, "binary": binary or None,
                     "on_path": bool(found) if binary else None,
                     "path": found, "selected": selected,
                     "remedy": (SESSION_REMEDY % {"binary": binary, "host": name}
                                if selected and binary and not found else None)})
    rows.sort(key=lambda row: (not row["selected"], row["host"]))
    return rows


def _cli_gate(rows):
    """`False` when the selected host cannot be launched the way `driver loop`
    would launch it, else `True`.

    Never `None` (fix round 2, item 2): this row CAN fail, so when it does not
    it says `ok`, like every other gating row -- `--` is reserved for the three
    rows nothing is checked against, and a passing check wearing the token for
    "not checked" understates what was verified. Derived from the rows rather
    than stored beside them, so the JSON contract stays the list the brief
    specified."""
    return not any(row["remedy"] for row in rows)

def _tools_image_row():
    """The phase's own two docker rows and the phase's own remedy text, through
    the phase's own seam -- so the preflight and the checkpoint cannot tell an
    operator two different stories about one machine."""
    rows = {name: (ok, detail) for name, ok, detail in _docker_checks(None)}
    docker_ok, docker_detail = rows.get("docker", (False, "docker was not probed"))
    if not docker_ok:
        return {"docker": False, "image": False, "ok": False,
                "remedy": docker_detail}
    image_ok, image_detail = rows.get("tools-image", (False, IMAGE_REMEDY))
    # F7: `null`, not the string "ok". A field called `remedy` holding "ok"
    # rendered as `tools-image   ok   ok`, and read as a contract it claimed
    # there was a remedy to apply. The two booleans beside it already say what
    # was probed, so there is nothing for the healthy case to add.
    return {"docker": True, "image": bool(image_ok), "ok": bool(image_ok),
            "remedy": None if image_ok else image_detail}
