"""Single-source secret redaction for unambiguous credential formats.

The one owner of the redaction patterns shared by the driver (tool subprocess
output -> DriverError/status messages) and synthesize (reviewer finding text ->
the shareable report.json / report.html / X0X artifacts). Patterns are anchored
to token prefixes + lengths so they mask WELL-FORMED secrets, not prose that
merely mentions a token format (e.g. "a ghp_ token" is left untouched; a real
`ghp_<40 chars>` is masked). See #run7 SEC-B2C.
Slack incoming webhooks use their vendor host and three credential-bearing
path segments as the anchor; the bare documentation prefix stays readable.

Three rules are structural rather than prefix-anchored -- UUID, JWT, and the
`scheme://user:password@host` URL userinfo -- because a secret scanner's output
quotes the secret without its `NAME=` context, and because a connection string
IS its own context. See the comments on those entries.

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
from collections.abc import Callable

# (compiled pattern, replacement). Replacements use \1 back-refs where the match
# keeps a benign prefix (Bearer). Ordered generic->specific; each is independent.
_PATTERNS: list[tuple[re.Pattern[str], str | Callable[[re.Match[str]], str]]] = [
    (re.compile(r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}"),
     "[REDACTED_TOKEN]"),                                   # GitHub PAT / OAuth
    (re.compile(r"sk-[A-Za-z0-9_-]{16,}"), "[REDACTED_KEY]"),  # OpenAI-style key
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._-]{16,}"), r"\1[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),   # AWS access-key id
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "[REDACTED_GOOGLE_KEY]"),  # Google API
    (re.compile(r"xapp-[0-9]-[A-Za-z0-9-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"https://hooks\.slack\.com/services/"
                + r"[A-Za-z0-9]{8,}/[A-Za-z0-9]{8,}/[A-Za-z0-9]{20,}"),
     "[REDACTED_SLACK_WEBHOOK]"),
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
    # Structure-anchored like the JWT above, and #1572's whole contribution: a
    # URL that carries a password in its userinfo (`scheme://user:pass@host`).
    # The finding's own example, and the one credential shape a reviewer is most
    # likely to quote verbatim while substantiating a finding -- a connection
    # string is evidence, not an aside. Any scheme, because the shape is the
    # anchor: postgres, jdbc:mysql, amqps, mongodb+srv, https-with-a-PAT.
    #
    # ONLY THE PASSWORD IS MASKED. `postgres://svc_reports:[REDACTED]@db.internal`
    # still says which credential leaked and where it points, which is the
    # difference between a finding an operator can act on and one they have to
    # re-derive. `scripts.tools.pip_audit._USERINFO` takes the whole userinfo
    # instead, and should: a dropped `--index-url` line has no locus worth
    # keeping, and it masks at the PRODUCER so no consumer has to remember to.
    # This is the backstop for everything that never passed through a producer.
    #
    # Every class excludes whitespace, `/`, `@` and both quote characters. The
    # quotes are what keep a match inside one JSON/XML field on the flat pass
    # (see TestOnlyThePemRuleMayCrossAQuote); `/` is what stops
    # `http://host:8080/u@v` -- a port and a path that happens to contain an `@`
    # -- from reading as a credential. FP-measured at zero over the whole repo
    # listing before it was added, and re-measured at zero after each widening;
    # see TestUrlCredentialShapeIsFpMeasured.
    #
    # The USER may be empty (R1-5). `redis://:pw@host` and `amqp://:guest@host`
    # are the documented forms for those two, not malformed ones, and a `+` on
    # the user class missed the whole shape -- the password is no less live for
    # having no account name beside it.
    #
    # The separator accepts `:\/\/` as well as `://` (R1-5), because this pass
    # runs FLAT over raw captures and a SARIF/JSON capture escapes the slashes
    # it was handed: the text reaching the redactor is literally
    # `postgres:\/\/u:pw@h`. Matching only the unescaped form left every
    # credential that arrived through a JSON tool report unmasked.
    #
    # The scheme is LENGTH-BOUNDED, and that is not cosmetic. `[A-Za-z0-9+.-]*`
    # before a literal `://` backtracks once per character of every alphanumeric
    # run in the document, which is O(n^2) on exactly the inputs this pass is
    # handed -- a 200 KB scanner capture, a PEM body quoted out of source. It
    # cost 0.2s on a 20 KB run of one letter and grows with the square; bounded,
    # the same input is 0.001s. 30 is above every scheme in the IANA registry;
    # a longer one simply does not match, which is the completeness limit.
    (re.compile(r"""([A-Za-z][A-Za-z0-9+.\-]{0,30}:(?:\\?/){2}[^\s/:@"']*:)[^\s/@"']+(@)"""),
     r"\1[REDACTED]\2"),
    # PEM private key. The body is BOUNDED two ways (#1639 P11), because it was
    # `.*?` under DOTALL -- the one rule here with nothing to stop it -- and a
    # raw scanner capture is where that bit: gitleaks quotes a truncated PEM
    # header line -- an RSA BEGIN marker with no END of its own (the committed
    # golden has one; the marker is not spelled out here because this file is
    # itself scanned, see #1578 fix round 2) -- so a flat pass over a document
    # ran from that snippet into a LATER result's END and collapsed every
    # result, rule id and
    # location in between into one token -- still valid JSON, so nothing
    # downstream noticed.
    #   `(?!-----BEGIN)` -- a match can never span two blocks, which is what
    #     that defect actually needed: an unterminated key stops at the next
    #     BEGIN instead of borrowing its END.
    #   `{1,16384}?`     -- and it can never run more than 16 KiB, so what a
    #     flat pass over a STRUCTURED document could swallow between two blocks
    #     is bounded. An RSA-4096 key is ~3.2 KiB; a body LONGER than the bound
    #     is not masked by this rule at all (no match, header included), which
    #     is the completeness limit this rule does have.
    # `[\s\S]` is DOTALL semantics without the flag, so the body crosses
    # newlines AND quotes. It must: a PEM embedded in C/Java/older-Python source
    # is written one double-quoted literal per line, and a `[^"]` bound (round 1
    # of this issue) silently stopped masking exactly that shape, publishing a
    # real key into report.json. Structure safety for a JSON capture comes from
    # PARSING (run_tools._redact_capture) and for the report from the per-leaf
    # walk below -- never from this character class.
    (re.compile(
        r"-----BEGIN[A-Z ]*PRIVATE KEY-----(?:(?!-----BEGIN)[\s\S]){1,16384}?"
        + r"-----END[A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # Shape-only, and last: every rule above needs a prefix or an assignment to
    # anchor on, but a secret SCANNER reports the secret with that context
    # stripped (gitleaks emitted a leaked API key as a bare snippet, matching
    # nothing here), so shape is all that is left. Scoped to the hyphenated
    # 8-4-4-4-12 form: a bare-32-hex rule would swallow md5 sums and blob ids.
    # Runs last so Bearer/sk- keep their more specific markers, and defers to
    # _mask_uuid for the one shape that is ambiguous. See #run12 SEC.
    (re.compile(r"(?<![0-9A-Za-z])"
                + r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                + r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
                + r"(?![0-9A-Za-z])"), lambda m: _mask_uuid(m)),
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


# Operator excerpts may discard the remainder of a capture; structured/general
# redaction above must preserve it. Bound work before scanning, never start at
# the tail: a key's opening delimiter may be far before the displayed suffix.
_DIAGNOSTIC_SCAN_LIMIT = 4 * 1024 * 1024
_DIAGNOSTIC_PEM = re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----")
_DIAGNOSTIC_PARTIAL_PEM = re.compile(r"-----BEGIN[A-Z -]*$")


def redact_diagnostic(text, limit: int, *, tail: bool = False) -> str:
    """Redact a bounded operator excerpt, then select its head or tail.

    Scan at most the first 4 MiB of characters, even for tail excerpts. A
    private-key header surviving complete-token redaction denotes an incomplete
    or overlong key: discard everything from it onward. Partial headers at the
    scan horizon are discarded too; no unscanned suffix is ever published.
    """
    if limit <= 0 or not text:
        return ""
    out = redact(str(text)[:_DIAGNOSTIC_SCAN_LIMIT])
    dangling = _DIAGNOSTIC_PEM.search(out) or _DIAGNOSTIC_PARTIAL_PEM.search(out)
    if dangling:
        out = out[:dangling.start()] + "[REDACTED_PRIVATE_KEY]"
    return out[-limit:] if tail else out[:limit]


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
