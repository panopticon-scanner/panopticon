"""Fixtures shared by the tests/synth/ modules (WS-0 S4): a canonical finding,
a cwd guard, an on-disk target and main()'s argument namespace.
"""
import contextlib
import os
import tempfile


SPLIT_FILE_MAX_BYTES = 1000

DEFAULT_TIMESTAMP = "2026-07-23T00:00:00Z"

@contextlib.contextmanager
def _chdir(path):
    prev = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(prev)

def _make_finding(**kw):
    base = {
        "id": "CD-001",
        "title": "t",
        "severity": "LOW",
        "confidence": "POSSIBLE",
        "panel": "code",
        "category": "structure",
        "location": {"file": "a.py", "line_start": 3},
    }
    base.update(kw)
    return base

@contextlib.contextmanager
def _target_with_files(groups, lines=100):
    """A real on-disk target for `groups`, so the letter grade is measurable.

    The grade keys on the health index, whose numerator is non-blank LoC across
    the reviewed files. A fixture pointing at files that do not exist has no LoC
    to measure and therefore no grade -- correct behaviour, but useless for a
    test that wants to assert a letter.
    """
    with tempfile.TemporaryDirectory() as d:
        for g in groups:
            for rel in g.get("files") or []:
                path = os.path.join(d, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("x = 1\n" * lines)
        yield d

def _agentic(fid="AG-001", sev="HIGH", **kw):
    f = {
        "id": fid,
        "title": "finding %s" % fid,
        "severity": sev,
        "confidence": "POSSIBLE",
        "panel": "security",
        "category": "injection",
        "location": {"file": "app.py", "line_start": 10},
        "provenance": {"discovered_by": "agent:panel_review", "confirmation_status": "UNVERIFIED"},
    }
    f.update(kw)
    return f

# Expected evidence.status once a verdict genuinely reaches apply_verdict,
# for an _agentic() (non-tool, non-reinforced) finding. Used by
# TestSeverityImmutability to prove its verdicts actually applied -- without
# this, a future queue_id-key regression (like the one fixed by #443) would
# make "severity/confidence unchanged" trivially true again, because nothing
# would have been applied at all.
_VERDICT_STATUS = {
    "REJECTED": "rejected",
    "NEEDS_MORE_INFO": "needs_more_info",
    "CONFIRMED": "advisor_confirmed",
}

def _cli_args(**kw):
    """An argparse.Namespace with every flag main() parses, at the parser's
    defaults, so the WS-0 S3 loaders see exactly the attribute set main() hands
    them. Override per test."""
    import argparse
    ns = dict(target="unknown", groups=None, security=None, fail_on=None,
              severity="all", changes=False, out=None, run_id=None, run_dir=None,
              html_out=None, compare=None, epss=False, tools_dir=None,
              tools_exclude=None, doc_paths=None, include_fixtures=False,
              emit_verify_queue=False, verdicts_dir=None, gate_unverified=False,
              max_verify=None, diff_hunks=None, diff_context=5, gate_scope="on-diff",
              files=[])
    ns.update(kw)
    return argparse.Namespace(**ns)
