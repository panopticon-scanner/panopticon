"""Guards for the runner suites. Stdlib and pytest only.

R3-3: `runners/kimi.py` wraps SIGTERM while a run is armed and takes the
wrapper off on teardown. A test that prepares a Runner and never tears it
down -- or tears two down in the wrong order -- used to leak that wrapper
into every test after it, silently. This fixture snapshots the SIGTERM
handler before each test, puts it back afterwards so the NEXT test starts
clean, and then fails the test that leaked it.
"""
import signal

import pytest


@pytest.fixture(autouse=True)
def _sigterm_handler_is_restored():
    before = signal.getsignal(signal.SIGTERM)
    yield
    after = signal.getsignal(signal.SIGTERM)
    if after is not before:
        signal.signal(signal.SIGTERM, before)
    assert after is before, (
        "the test left a SIGTERM handler installed: %r (was %r); a prepared "
        "Runner must be torn down" % (after, before))
