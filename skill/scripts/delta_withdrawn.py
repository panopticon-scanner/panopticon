"""Delta review is withdrawn in 5.4 (#3735, owner ruling 2026-11-17).

Delta review is a review of a diff: `--pr`, `--changes` (`-c`), `--base`, and the
on-diff gate scope (`--gate-scope`). It was never calibrated or stress-tested, and
the five-gate review found a `--pr` run that passes, certified, with a new finding
on a changed line (#3731, #3732). Panopticon 5.4 is a whole-repository audit.

The delta code is still in the tree and is unreachable; it is deleted in 5.5
(#3736). Every way in is closed HERE, with one message:

- the driver's flags, on `run`, `loop`, `readiness` and `persist` (`driver.parse_cli`);
- a run folder that was started as a delta run and is resumed (`driver.main`);
- the two scripts the driver runs as children, when run by hand: `discovery.py`
  (which writes the hunk map) and `synthesize.py` (which reads it);
- a hunk map left in a run folder: the driver hands `synthesize.py` one only for a
  run whose manifest says it is a delta run (`phases/synthesize.py`), and no
  manifest the command line can write or resume says so.

No config key and no environment variable selects delta review. `gate_scope` in a
committed config stays a valid key and has no effect: with no diff there is nothing
for it to scope.
"""
MESSAGE = ("delta review is withdrawn in 5.4 (#3735): %s. Run a whole-repository review, or "
           "scope one with -f, -d, -g or --files. Delta review returns when it has been "
           "rebuilt and measured.")

# argparse dest -> the flag as typed, for the driver's `run`, `loop`, `readiness` and
# `persist`. `--diff-context` is the on-diff tolerance: it means nothing without a diff.
DRIVER_FLAGS = (("pr", "--pr"), ("scope_changed", "--changes (-c)"), ("base", "--base"),
                ("gate_scope", "--gate-scope"), ("diff_context", "--diff-context"))
# ...for `discovery.py --repo-scan`, which writes `diff-hunks.json`...
DISCOVERY_FLAGS = (("scope_changed", "--scope-changed"), ("base", "--base"),
                   ("pr_base", "--pr-base"), ("pr_worktree", "--pr-worktree"),
                   ("diff_context", "--diff-context"))
# ...and for `synthesize.py`, which reads it.
SYNTHESIZE_FLAGS = (("changes", "--changes (-c)"), ("diff_hunks", "--diff-hunks"),
                    ("diff_hunks_run_id", "--diff-hunks-run-id"),
                    ("gate_scope", "--gate-scope"), ("diff_context", "--diff-context"))


def given(args, flags):
    """The delta flags `args` carries, as typed. Each one's parser default is None (or
    False): a value is one the caller gave.

    By identity, not equality: `0 == False`, so `--pr 0` and `--diff-context 0` read as
    not given, and `driver run --pr 0` went on to `gh pr view 0` and a PR worktree
    (#3737 review F1)."""
    names = []
    for dest, name in flags:
        value = getattr(args, dest, None)
        if value is not None and value is not False:
            names.append(name)
    return names


def typed(parser, argv, flags):
    """`argv` parsed again with every delta flag's default cleared, so that a value is
    one the caller typed: `--gate-scope on-diff` is refused although it is the
    default. Call it after the real parse, which has already reported any error."""
    parser.set_defaults(**{dest: None for dest, _name in flags})
    return parser.parse_known_args(argv)[0]


def refusal(args, flags):
    """The message refusing `args`, or None when it asks for no delta review."""
    names = given(args, flags)
    if not names:
        return None
    return MESSAGE % ("%s %s refused" % (", ".join(names), "is" if len(names) == 1 else "are"))


def is_delta_run(manifest):
    """Was the run this manifest describes started as a delta review?"""
    if not isinstance(manifest, dict):
        return False
    scope = manifest.get("scope")
    return bool((isinstance(scope, dict) and scope.get("mode") == "changed")
                or manifest.get("base") or manifest.get("pr") is not None
                or manifest.get("pr_base") or manifest.get("worktree"))


def resumed_refusal(manifest):
    """The message refusing to resume `manifest`'s run, or None."""
    if not is_delta_run(manifest):
        return None
    return MESSAGE % ("this run folder was started as a delta review and cannot be resumed "
                      "(--reset discards it and starts a whole-repository run)")
