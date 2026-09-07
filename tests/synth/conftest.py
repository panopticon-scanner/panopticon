"""tests/synth/ package fixtures (WS-0 S4).
"""
import pytest


@pytest.fixture(autouse=True)
def _isolate_cwd_from_stale_panopticon(tmp_path, monkeypatch):
    """Run every test in this module from an isolated cwd.

    Many tests call ``synthesize.main()`` without ``--run-dir``/``--groups``, so
    run_dir falls back to a cwd-relative ``.panopticon``. In a developer's real
    checkout that directory can hold a stale pre-5.1 flat ``tools-manifest.json``
    (no ``schema_version``), which synthesize's #17 guard correctly rejects with
    a loud ``sys.exit`` -- turning a stray local artifact into ~9 spurious test
    failures. Isolating the cwd makes the suite read only what each test writes
    (and stops the handful of relative-path tests from littering the repo root).
    Tests that manage their own cwd (``prev = os.getcwd()`` + restore) are
    unaffected -- they simply save/restore this tmp cwd; reference-data reads are
    ``__file__``-relative, so they don't depend on cwd.
    """
    monkeypatch.chdir(tmp_path)
