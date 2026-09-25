"""How to resume THIS run, as a command an operator can paste (#1623).

Split out of `outage.py` (#1732), which reached the 700-line package ceiling
when the loop grew its second stop rule. A cohesive piece with one subject and
no dependency on the rest of that module: it reads the loop's own `args` and
composes a string, and both pause messages (`HOST_OUTAGE`, `UNIFORM_FAILURE`)
end with what it returns.

`FailureTally.resume_command` still exists and is still how every caller
reaches this -- it holds the host and the args -- so nothing outside this
package changed. It calls `command()` below rather than being assigned from it
(layout rule 4: a package module may not re-export a sibling's name).
"""
import os
import shlex
import sys


# The flags a resume has to carry, in the order the parser declares them:
# (attribute, flag, kind). `value` prints the flag and its value, `flag` prints
# itself when set, `list` prints every value it holds.
#
# Two kinds of flag are here and one is deliberately not. The ANTI-DRIFT flags
# (`--security`, `--fail-on`, the scope selectors, ...) because the engine
# refuses a resume that changed one; and the per-invocation BOUNDS
# (`--max-budget-usd`, `--entry-timeout`, `--concurrency`, `--max-iterations`,
# `--max-turns`) because a copy-pasted resume that silently dropped them would
# run unbounded, which is the opposite of what an operator watching a quota
# outage wants. `--reset` is the one flag never carried: it would discard the
# very run this line exists to resume. `--host`, `--mode` and the review root
# are emitted ahead of the table, from the values the LOOP resolved rather
# than from whatever the operator did or did not type.
_RESUME_FLAGS = (
    ("security", "--security", "value"),
    ("fail_on", "--fail-on", "value"),
    ("severity", "--severity", "value"),
    ("gate_scope", "--gate-scope", "value"),
    ("diff_context", "--diff-context", "value"),
    ("tools", "--tools", "flag"),
    ("no_tools", "--no-tools", "flag"),
    ("online", "--online", "flag"),
    ("include_fixtures", "--include-fixtures", "flag"),
    ("allow_unenforced", "--allow-unenforced", "flag"),
    ("session_dir", "--session-dir", "value"),
    ("max_per_group", "--max-per-group", "value"),
    ("max_verify", "--max-verify", "value"),
    ("scope_file", "-f", "value"),
    ("scope_dir", "-d", "value"),
    ("scope_group", "-g", "value"),
    ("scope_changed", "-c", "flag"),
    ("scope_files", "--files", "list"),
    ("concurrency", "--concurrency", "value"),
    ("max_iterations", "--max-iterations", "value"),
    ("max_budget_usd", "--max-budget-usd", "value"),
    ("max_turns", "--max-turns", "value"),
    ("entry_timeout", "--entry-timeout", "value"),
    ("max_groups", "--max-groups", "value"),
)


def program():
    """How THIS process was invoked, as the head of a runnable command.

    Never the hard-coded `python3 skill/scripts/driver.py`: #495 says that
    spelling in the guide is a PLACEHOLDER for whatever directory the skill was
    installed to, so on an installed skill it names a path that does not exist.
    Read off `sys.argv[0]` when the driver really is what is running, and
    otherwise the abbreviated `driver` form every other runtime hint in the
    loop already prints (`_dispatch_exit`'s `driver persist <id>`).
    """
    argv0 = sys.argv[0] if sys.argv else ""
    return ("python3 %s" % shlex.quote(argv0)
            if os.path.basename(argv0) == "driver.py" else "driver")


def command(host, args):
    """The command that resumes this run, once whatever stopped it is fixed.

    Reconstructed from the loop's own `args`, so what it prints is what the
    operator ran: the review root (`target`, or the `--pr`/`--base` whose
    worktree IS the review root), the namespace, the `host` and mode the loop
    RESOLVED, and every flag in `_RESUME_FLAGS` that was set -- the anti-drift
    ones because the engine refuses a resume that changed one, the bounds
    because a resume that quietly dropped them would run unbounded. Quoted
    with `shlex`, so a path with a space in it survives the copy-paste.
    """
    cmd = [program(), "loop", shlex.quote(str(getattr(args, "target", None) or "."))]
    if getattr(args, "pr", None):
        cmd += ["--pr", str(args.pr)]
    elif getattr(args, "base", None):
        cmd += ["--base", shlex.quote(str(args.base))]
    if getattr(args, "setup", False):
        cmd.append("--setup")
    cmd += ["--host", str(host),
            "--mode", str(getattr(args, "mode", None) or "headless")]
    for attr, flag, kind in _RESUME_FLAGS:
        value = getattr(args, attr, None)
        if (value is None or (kind in ("flag", "list") and not value)
                or (kind == "value" and value == "")):
            continue
        if kind == "flag":
            cmd.append(flag)
        elif kind == "list":
            cmd += [flag] + [shlex.quote(str(v)) for v in value]
        else:
            cmd += [flag, shlex.quote(str(value))]
    return " ".join(cmd)
