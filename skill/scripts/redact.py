"""Single-source secret redaction for unambiguous credential formats.

The one owner of the redaction patterns shared by the driver (tool subprocess
output -> DriverError/status messages) and synthesize (reviewer finding text ->
the shareable report.json / report.html / X0X artifacts). Patterns are anchored
to token prefixes + lengths so they mask WELL-FORMED secrets, not prose that
merely mentions a token format (e.g. "a ghp_ token" is left untouched; a real
`ghp_<40 chars>` is masked). See #run7 SEC-B2C.

One rule is shape-only rather than prefix-anchored -- the UUID pattern -- because
a secret scanner's output quotes the secret without its `NAME=` context. See the
comment on that entry.
"""
import re

# (compiled pattern, replacement). Replacements use \1 back-refs where the match
# keeps a benign prefix (Bearer). Ordered generic->specific; each is independent.
_PATTERNS = [
    (re.compile(r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}"),
     "[REDACTED_TOKEN]"),                                   # GitHub PAT / OAuth
    (re.compile(r"sk-[A-Za-z0-9_-]{16,}"), "[REDACTED_KEY]"),  # OpenAI-style key
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._-]{16,}"), r"\1[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),   # AWS access-key id
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "[REDACTED_GOOGLE_KEY]"),  # Google API
    (re.compile(
        r"-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----",
        re.DOTALL), "[REDACTED_PRIVATE_KEY]"),                # PEM private key
    # Shape-only, and last: every rule above needs a prefix or an assignment to
    # anchor on, but a secret SCANNER reports the secret with that context
    # stripped (gitleaks emitted a leaked API key as a bare snippet, matching
    # nothing here), so shape is all that is left. Scoped to the hyphenated
    # 8-4-4-4-12 form: a bare-32-hex rule would swallow md5 sums and blob ids.
    # Measured against this repo before adding -- 0 UUIDs in tracked source, so
    # no legitimate identifier is masked. Runs last so Bearer/sk- keep their
    # more specific markers. See #run12 SEC.
    (re.compile(r"(?<![0-9A-Za-z])"
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
                r"(?![0-9A-Za-z])"), "[REDACTED_UUID]"),
]


def redact(text):
    """Mask unambiguous secret formats in a string. Returns '' for falsy input;
    coerces non-str via str()."""
    if not text:
        return ""
    out = str(text)
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    return out


def redact_tree(obj):
    """Return a copy of a JSON-ish structure with every string LEAF redacted.

    dicts and lists are rebuilt (the input is not mutated); non-string scalars
    (int/float/bool/None) pass through unchanged. Redaction runs per string
    leaf, so a multi-field structure can never let a pattern span two fields.
    Structured leaves (ids, codes, severities, file paths) do not match the
    anchored patterns, so walking the whole tree is safe.
    """
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_tree(v) for v in obj]
    if isinstance(obj, dict):
        return {k: redact_tree(v) for k, v in obj.items()}
    return obj
