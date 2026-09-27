#!/usr/bin/env python3
"""What a claim may point at, and the root every advisor prompt pins. Stdlib-only.

A claim's `location.file` is panel/LLM-supplied and therefore steerable by
anything a reviewed repo commits, while an advisor's Read/Grep/Glob are
unconfined. #run8 ARC-F2A closed that channel on the driver's two advisor rounds
-- an escaping path becomes `REDACTED_CLAIM_PATH`, and the prompt pins the review
root the remaining relative paths resolve against. #1767 (run-14 ARC-3314534783)
found the SAME assembly a second time, in the CLI renderer
`dispatch.render_advisor_prompts` (`--render-advisor QUEUE`): there the claim
JSON went in verbatim and the root pinned was `os.getcwd()`. One implementation,
reached from both, is the fix; the copy is what the issue was.

Why a leaf, and why the confinement predicate lives HERE rather than in
`phases/runio` where it started: `dispatch` is imported by `runners/*`, and
layout rule 3 (tests/test_layout.py) forbids `runners/*` from reaching
`scripts.phases` -- so a `scripts.phases` import in this module, or in
`dispatch`, would put the phases package in every runner's import graph through
a back door no AST rule inspects. `scripts.safe_write` answered the same problem
the same way in #1735: a module that imports nothing of ours is reachable from
every side. `phases/runio._confined_to_root` and
`phases/verify_tools._confine_claim_location` keep their private names as
ALIASES of these functions (rule 4 leaves an alias of a definition from outside
the package legal and asks it to say why: the predicate's two call sites, both
in `phases/evidence_scope.py`, spell it with runio's name, and the
claim-confinement name is what `verify_tools._tool_verify_entry` and
tests/phases/test_verify.py call -- `phases/verify.py` calls this module
directly). tests/test_claim_scope.py pins both identities, so a second
implementation cannot appear behind either name.
"""
import os


REDACTED_CLAIM_PATH = "<redacted: location escapes review root>"

# ONE wording for the root pin, singular or plural: the per-finding advisor is
# handed one claim, the cell advisor a list. Both paragraphs are byte-for-byte
# what the driver pinned before this module existed (the goldens in
# tests/test_claim_scope.py), because the prompt an advisor reads must not
# change silently under a refactor.
_ROOT_PIN = ("Repo root: %s\nEvery relative path in the %s below resolves "
             "against this root -- read files THERE, never in your session's "
             "default checkout.\n\n")

_ARTIFACT_DIR = ".panopticon"


def confined_to_root(review_root, path):
    """True iff the claim path resolves inside review_root. An absolute path or a
    `../`-escape resolves outside and is rejected (#1096) -- the claim's
    location.file is LLM/panel-supplied (steerable by injection planted in the
    reviewed repo), so it must not be able to point a downstream advisor at files
    outside the review tree.

    #run7 ARC-F2A: resolve SYMLINKS (realpath), not just `..`/join (abspath). A
    committed in-tree symlink whose lexical path starts with root+sep (e.g.
    `src/evil -> /etc/passwd`) passed the old abspath check, then the backup
    advisor's unconfined Read followed it out of the repo. realpath on a
    non-existent tail resolves the existing prefix and appends the rest lexically,
    so a legitimate not-yet-written path still confines correctly."""
    if not isinstance(path, str) or not path:
        return False
    root = os.path.realpath(review_root)
    full = os.path.realpath(os.path.join(root, path))
    return full == root or full.startswith(root + os.sep)


def confine_claim_location(review_root, loc):
    """Return `loc` with an out-of-tree `location.file` neutralized.

    #run8 ARC-F2A: the verify claims JSON handed to the domain/tool advisor
    carries each finding's `location.file` VERBATIM, and the advisor's
    Read/Grep/Glob are unconfined -- so a path-traversal or committed-symlink
    location (e.g. `../../../.ssh/id_rsa`) planted by a redteam target would
    steer the advisor to read OUTSIDE review_root in every verify round.
    confined_to_root already guarded the derived backup file LIST but never this
    channel. A genuine review finding always cites an in-tree file, so redacting
    an escaping path both defuses the steer and signals the advisor the location
    is untrusted. Non-dict/absent locations pass through unchanged."""
    if not isinstance(loc, dict):
        return loc
    path = loc.get("file")
    if isinstance(path, str) and path and not confined_to_root(review_root, path):
        loc = dict(loc)
        loc["file"] = REDACTED_CLAIM_PATH
    return loc


def root_pin_paragraph(review_root, *, plural=False):
    """The `Repo root:` paragraph an advisor prompt opens with (#975).

    Advisors inherit the session cwd, never review_root or the `--pr` worktree,
    and a claim's `location` stays repo-relative on disk -- so without this
    header a relative location resolves against whichever checkout the host
    happened to start in. `plural` picks the claimS wording the cell advisor
    (a list of claims) uses; the default is the single-claim form. It is
    keyword-only: a bare `True` at a call site names neither the switch nor
    the noun it selects."""
    return _ROOT_PIN % (os.path.abspath(review_root),
                        "claims" if plural else "claim")


def review_root_of_artifact_path(path):
    """The review root an artifact path belongs to, or None when it is not one.

    The inverse of the driver's own artifact-path derivation: every run artifact
    lives under `<review_root>/.panopticon/` (flat for setup/report, else
    `runs/<tag>/`), so the root is the directory ABOVE that segment. This is the
    anchor `safe_write.confine_artifact_path` vets writes against and
    `phases/persist` places an incoming reply with, shared rather than copied a
    third time.

    None (not a cwd guess) when the path carries no `.panopticon` segment: a
    caller handed something that is not a run artifact, and a WRONG root is
    worse than a refusal -- it points an advisor at another checkout, which is
    the bug #1767 fixed. Callers refuse loudly on None."""
    parts = os.path.abspath(path).split(os.sep)
    if _ARTIFACT_DIR not in parts:
        return None
    return os.sep.join(parts[:parts.index(_ARTIFACT_DIR)]) or os.sep
