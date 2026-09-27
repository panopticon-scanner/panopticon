#!/usr/bin/env python3
"""Privacy and security sanitizers for text that ends up in public GitHub issues."""
import os
import re
import subprocess
import sys

# scrub() is the last sanitizer applied to text before it is posted to a PUBLIC
# GitHub issue, and it is the one sanitizer all FOUR public posters share:
# file_issues.py reads a report.json that synth/render.py already redacted, but
# file_fixmes.py (markdown FIXME doc), triage.py (JSONL ledger rows) and
# reconcile_apply.py (reconciliation comments on issues already filed) never pass
# through that path, so a secret in any of them went to GitHub verbatim.
# Redacting here makes coverage independent of which artifact a filer reads.
#
# The prefix scrub() strips is a DECISION, not an ambient fact -- see
# _normalized_root. A degenerate or foreign root publishes the operator's
# absolute paths, which is the one thing this module exists to prevent.
#
# Imported, not reimplemented: #run7 SEC-B2C made redact.py the single owner of
# the patterns, and a second list here would drift. Unconditional by design -- a
# scrub() that skipped redaction because an optional import failed would fail
# OPEN, silently, on the one path where that is least acceptable.
_SKILL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "skill")
if _SKILL not in sys.path:
    sys.path.insert(0, _SKILL)
import scripts.redact as _redact  # noqa: E402

_REPO_ROOT_CACHE = None
# A degenerate root is not a lesser evil than no root: '/' deletes every '/' in
# the text, and re.escape of what is left of it makes the bare-root substitution
# an empty-match pattern; a root from another checkout strips nothing at all.
_ROOT_REFUSAL = "; run the filer from the checkout or pass the root explicitly"


def _normalized_root(path, cause):
    """An absolute, realpath'd root with a trailing '/', or RuntimeError.

    realpath, not the path as handed over: `git rev-parse` reports the LOGICAL
    path the checkout was reached by, so a macOS /tmp checkout reports /tmp/...
    while a location resolved through realpath reads /private/tmp/... and the
    prefix matched nothing. A filesystem root (`dirname(p) == p`, on any
    platform) and a non-absolute root are refused rather than returned.
    """
    given = str(path)
    real = os.path.realpath(given)
    if not os.path.isabs(given) or os.path.dirname(real) == real:
        raise RuntimeError(cause + _ROOT_REFUSAL)
    return real + "/"


def _detect_repo_root():
    """The checkout's absolute, realpath'd root (trailing '/'), detected live.

    The cwd fallback stays -- a filer is run from the checkout by SOP -- but a
    cwd at the filesystem root is not a fallback, it is a silent text mangler,
    so it is refused loudly instead of returned.
    """
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"],  # nosec
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return _normalized_root(r.stdout.strip(),
                                    "git rev-parse reported an unusable repo root")
    except (subprocess.SubprocessError, OSError):
        pass
    return _normalized_root(os.getcwd(),
                            "git rev-parse failed and the cwd is the filesystem root")


def repo_root():
    """Cached dynamic repo root. A refused detection is never cached."""
    global _REPO_ROOT_CACHE
    if _REPO_ROOT_CACHE is None:
        _REPO_ROOT_CACHE = _detect_repo_root()
    return _REPO_ROOT_CACHE


def _resolved_root(root):
    """`None` means the cached detection; an explicit root is normalised alike."""
    if root is None:
        return repo_root()
    return _normalized_root(root, "the explicit repo root is not a usable checkout path")


def repo_relative(path, root=None):
    """Strip the repo-root prefix so a location is portable.

    `root` binds the prefix explicitly; `None` keeps the cached detection, so
    no existing filer has to change the way it calls this.
    """
    prefix = _resolved_root(root)
    p = str(path or "")
    return p[len(prefix):] if p.startswith(prefix) else p


def scrub(text, root=None):
    """Strip local paths AND mask secrets; issues are public and permanent.

    Reviewers cite absolute local paths, and reviewer/tool text can quote a real
    credential (#run12: gitleaks reported a live API key, and the report carried
    it verbatim). Both are unfixable once posted, so both are handled here.

    `root` binds the prefix a caller already knows -- a filer reading a report
    from another checkout -- instead of inheriting whatever the cwd detects;
    `None` keeps the cached detection.
    """
    prefix = _resolved_root(root)
    scrubbed = str(text).replace(prefix, "")
    scrubbed = re.sub(r"(?<![\w/-])%s(?![\w/-])" % re.escape(prefix.rstrip("/")),
                      "the repo root", scrubbed)
    return _redact.redact(scrubbed)


_MENTION_RE = re.compile(r"@(?=[A-Za-z0-9._-])")
_ISSUEREF_RE = re.compile(r"(?<![\w])#(?=\d)")
_REPO_ISSUEREF_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#(?=\d)")
# Keep ordinary identifiers and path components intact; punctuation may end a reference.
_GH_ISSUEREF_RE = re.compile(r"(?<![\w/.-])GH-(?=[0-9]+(?![\w/-]|\.[A-Za-z0-9]))")
_AUTOLINK_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9+.-]*://[^>]+)>")
_HTTP_RE = re.compile(r"\bhttps?://", re.IGNORECASE)
# GFM explicitly accepts underscore before www, although it is a word character.
_WWW_RE = re.compile(r"(?:\b|(?<=_))www\.(?=[A-Za-z0-9])", re.IGNORECASE)


def defang(text):
    """Make attacker-influenced finding text inert in a PUBLIC GitHub issue."""
    s = str(text or "")
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", s)
    s = _MENTION_RE.sub("@\u200b", s)
    s = _ISSUEREF_RE.sub("#\u200b", s)
    s = _GH_ISSUEREF_RE.sub("GH-\u200b", s)
    s = _REPO_ISSUEREF_RE.sub(lambda m: m.group(1) + "#\u200b", s)
    s = s.replace("](", "]\u200b(")
    s = s.replace("][", "]\u200b[")
    s = s.replace("]:", "]\u200b:")
    s = s.replace("![", "!\u200b[")
    s = _AUTOLINK_RE.sub(lambda m: "<\u200b" + m.group(1) + ">", s)
    s = _HTTP_RE.sub(lambda m: m.group(0)[0] + "\u200b" + m.group(0)[1:], s)
    s = _WWW_RE.sub(lambda m: m.group(0)[0] + "\u200b" + m.group(0)[1:], s)
    return s
