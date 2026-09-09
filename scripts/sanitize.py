#!/usr/bin/env python3
"""Privacy and security sanitizers for text that ends up in public GitHub issues."""
import os
import re
import subprocess
import sys

# scrub() is the last thing to touch text before it is posted to a PUBLIC GitHub
# issue, and it is the ONLY point all three filers share: file_issues.py reads a
# report.json that synth/render.py already redacted, but file_fixmes.py (markdown
# FIXME doc) and triage.py (JSONL ledger rows) never pass through that path, so a
# secret in either went to GitHub verbatim. Redacting here makes coverage
# independent of which artifact a filer happens to read.
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


def _detect_repo_root():
    """Absolute repo root (trailing '/') detected dynamically, not hardcoded."""
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"],  # nosec
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().rstrip("/") + "/"
    except (subprocess.SubprocessError, OSError):
        pass
    return os.getcwd().rstrip("/") + "/"


def repo_root():
    """Cached dynamic repo root."""
    global _REPO_ROOT_CACHE
    if _REPO_ROOT_CACHE is None:
        _REPO_ROOT_CACHE = _detect_repo_root()
    return _REPO_ROOT_CACHE


def repo_relative(path):
    """Strip the repo-root prefix so a location is portable."""
    root = repo_root()
    p = str(path or "")
    return p[len(root):] if p.startswith(root) else p


def scrub(text):
    """Strip local paths AND mask secrets; issues are public and permanent.

    Reviewers cite absolute local paths, and reviewer/tool text can quote a real
    credential (#run12: gitleaks reported a live API key, and the report carried
    it verbatim). Both are unfixable once posted, so both are handled here.
    """
    root = repo_root()
    scrubbed = str(text).replace(root, "")
    scrubbed = re.sub(r"(?<![\w/-])%s(?![\w/-])" % re.escape(root.rstrip("/")),
                      "the repo root", scrubbed)
    return _redact.redact(scrubbed)


_MENTION_RE = re.compile(r"@(?=[A-Za-z0-9._-])")
_ISSUEREF_RE = re.compile(r"(?<![\w])#(?=\d)")
_AUTOLINK_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9+.-]*://[^>]+)>")


def defang(text):
    """Make attacker-influenced finding text inert in a PUBLIC GitHub issue."""
    s = str(text or "")
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", s)
    s = _MENTION_RE.sub("@\u200b", s)
    s = _ISSUEREF_RE.sub("#\u200b", s)
    s = s.replace("](", "]\u200b(")
    s = s.replace("][", "]\u200b[")
    s = s.replace("]:", "]\u200b:")
    s = s.replace("![", "!\u200b[")
    s = _AUTOLINK_RE.sub(lambda m: "<\u200b" + m.group(1) + ">", s)
    s = re.sub(r"\bhttps://", "h\u200bttps://", s)
    s = re.sub(r"\bhttp://", "h\u200bttp://", s)
    return s
