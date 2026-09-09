"""Single-source secret redaction for unambiguous credential formats.

The one owner of the redaction patterns shared by the driver (tool subprocess
output -> DriverError/status messages) and synthesize (reviewer finding text ->
the shareable report.json / report.html / X0X artifacts). Patterns are anchored
to token prefixes + lengths so they mask WELL-FORMED secrets, not prose that
merely mentions a token format (e.g. "a ghp_ token" is left untouched; a real
`ghp_<40 chars>` is masked). See #run7 SEC-B2C.

Two rules are structural rather than prefix-anchored -- UUID and JWT -- because a
secret scanner's output quotes the secret without its `NAME=` context. See the
comments on those entries.

There is deliberately NO entropy, long-hex, or long-base64 rule. Measured across
run-12 finding text, tracked source, and the goldens: hex>=32 matched git SHAs
and content hashes, base64>=32 matched file paths, entropy>=4.0 matched URLs and
paths -- hundreds of distinct false positives each. This project's text is
saturated with the shapes a generic detector keys on, and a redactor mangles
silently, so a noisy one is worse than a narrow one. Every format here was
FP-measured against those three corpora before being added, and must stay at
zero -- with the measurement run through plain grep, never `git grep -E`, whose
POSIX ERE silently ignores \b. See tests/test_redact.py::TestRedactRejectsGenericDetection.
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
    (re.compile(r"xapp-[0-9]-[A-Za-z0-9-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), "[REDACTED_TOKEN]"),   # GitLab PAT
    (re.compile(r"npm_[A-Za-z0-9]{36}"), "[REDACTED_TOKEN]"),        # npm token
    (re.compile(r"hf_[A-Za-z0-9]{30,}"), "[REDACTED_TOKEN]"),        # HuggingFace
    (re.compile(r"pypi-[A-Za-z0-9_-]{32,}"), "[REDACTED_TOKEN]"),    # PyPI upload
    (re.compile(r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
     "[REDACTED_KEY]"),                                              # SendGrid
    (re.compile(r"dop_v1_[a-f0-9]{64}"), "[REDACTED_KEY]"),          # DigitalOcean
    (re.compile(r"[rs]k_(?:live|test)_[A-Za-z0-9]{20,}"),
     "[REDACTED_KEY]"),                                              # Stripe
    # Structure-anchored, not prefix-anchored: three base64url segments, the
    # first two starting eyJ (base64 of '{"'). Distinctive enough to be safe.
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "[REDACTED_JWT]"),
    (re.compile(
        r"-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----",
        re.DOTALL), "[REDACTED_PRIVATE_KEY]"),                # PEM private key
    # Shape-only, and last: every rule above needs a prefix or an assignment to
    # anchor on, but a secret SCANNER reports the secret with that context
    # stripped (gitleaks emitted a leaked API key as a bare snippet, matching
    # nothing here), so shape is all that is left. Scoped to the hyphenated
    # 8-4-4-4-12 form: a bare-32-hex rule would swallow md5 sums and blob ids.
    # Runs last so Bearer/sk- keep their more specific markers, and defers to
    # _mask_uuid for the one shape that is ambiguous. See #run12 SEC.
    (re.compile(r"(?<![0-9A-Za-z])"
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
                r"(?![0-9A-Za-z])"), lambda m: _mask_uuid(m)),
]

# A UUID is the only shape here that is genuinely ambiguous: it is as often an
# identifier as a secret. The goldens settle it -- gosec's SARIF carries 24 rule
# `guid`s and dependency-check 12 CVE `source`s, all benign, while the one real
# leaked key sits under `text`, a snippet field. A legitimate UUID is introduced
# by a key that NAMES it as an identifier; a leaked secret is not. So exempt the
# naming keys and mask everything else, which fails closed on any key not listed
# (including ones we have never seen).
#
# The first cut of this rule masked those guids, because the measurement behind
# it used `git grep -E '\b...'` and git grep's POSIX ERE does not honour \b --
# it reported 0 where plain grep finds 11. Never trust a zero from that.
_UUID_IDENTITY_KEYS = ("guid", "uuid", "instanceGuid", "correlationGuid",
                       "automationId", "source")
_UUID_IDENTITY_KEY = re.compile(
    r'"(?:%s)"\s*:\s*"$' % "|".join(_UUID_IDENTITY_KEYS))
_BARE_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _mask_uuid(m):
    """Mask a UUID unless it is the value of a self-declared identity key."""
    prefix = m.string[max(0, m.start() - 64):m.start()]
    return m.group(0) if _UUID_IDENTITY_KEY.search(prefix) else "[REDACTED_UUID]"



def redact(text):
    """Mask unambiguous secret formats in a string. Returns '' for falsy input;
    coerces non-str via str()."""
    if not text:
        return ""
    out = str(text)
    for pat, repl in _PATTERNS:
        out = pat.sub(repl, out)
    return out


def redact_tree(obj, _key=None):
    """Return a copy of a JSON-ish structure with every string LEAF redacted.

    dicts and lists are rebuilt (the input is not mutated); non-string scalars
    (int/float/bool/None) pass through unchanged. Redaction runs per string
    leaf, so a multi-field structure can never let a pattern span two fields.
    Structured leaves (ids, codes, severities, file paths) do not match the
    anchored patterns, so walking the whole tree is safe.

    The leaf's own key travels down with it: redacting a leaf in isolation
    throws away the one thing that distinguishes a SARIF `guid` from a leaked
    key, and _mask_uuid's textual lookbehind cannot see a key that is not in
    the string. The exemption is UUID-only -- a real token parked under an
    identity key is still masked.
    """
    if isinstance(obj, str):
        if _key in _UUID_IDENTITY_KEYS and _BARE_UUID.match(obj):
            return obj
        return redact(obj)
    if isinstance(obj, list):
        return [redact_tree(v, _key) for v in obj]
    if isinstance(obj, dict):
        return {k: redact_tree(v, k) for k, v in obj.items()}
    return obj
