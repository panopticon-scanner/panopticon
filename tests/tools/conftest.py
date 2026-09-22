"""Shared constants for the tools integration test sub-package."""
import os

# Define FIXTURE_ROOT for the tools sub-package so existing imports of the
# form ``from conftest import FIXTURE_ROOT`` resolve against this file.
FIXTURE_ROOT = os.environ.get(
    "FIXTURE_ROOT",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures"),
)

OK_SCAN_EXIT_CODES = (0, 1)  # 0 = clean exit, 1 = findings detected

# #1528: a binary on PATH is NOT the precondition these adapters actually have.
# Every one of them depends on an asset baked into panopticon-tools -- semgrep's
# vendored rules at /opt/semgrep-rules, bandit's SARIF formatter, trivy's and
# osv-scanner's offline databases, the Go toolchain gosec shells out to, the
# eslint plugin loaded by absolute path. Measured: on a dev host with semgrep
# and bandit installed the adapters exit 7 and 2 respectively, because the
# ASSETS are missing. So gate on the image, and say so.
TOOLS_IMAGE_MARKER = "/opt/panopticon/scripts"


def in_tools_image():
    return os.path.isdir(TOOLS_IMAGE_MARKER)


def scratch_cwd_recorder(calls, stdout=b"{}", stderr=b"", returncode=0):
    """A `subprocess.Popen` side_effect that records every scanner launch and,
    AT THE INSTANT OF LAUNCH, what the working directory it was handed looked
    like (#1877).

    The moment of launch is the only one that can answer the question: the
    adapter removes its scratch directory on the way out, so by the time the
    test inspects `call_args` the directory is already gone -- and what the
    scanner would have resolved its own config against is what was there when
    it started, not what is there afterwards.
    """
    from _test_helpers import FakePopen

    def _record(cmd, **kwargs):
        cwd = kwargs.get("cwd")
        existed = cwd is not None and os.path.isdir(cwd)
        calls.append({
            "argv": list(cmd),
            "cwd": cwd,
            "existed": existed,
            "entries": sorted(os.listdir(cwd)) if existed else None,
        })
        return FakePopen(stdout=stdout, stderr=stderr, returncode=returncode)

    return _record


def assert_scratch_cwd(case, record, target):
    """Pin one recorded launch as confined (#1877): the adapter NAMED its
    working directory, that directory existed and was EMPTY when the scanner
    started, it is not the target (nor inside it), and it did not outlive
    `invoke()`.

    `cwd=None` fails this deliberately: an unnamed cwd is inherited from the
    caller, which inside the tools container is the image's `WORKDIR /src` --
    the target mount itself.
    """
    cwd = record["cwd"]
    case.assertIsNotNone(cwd, "the adapter passed no cwd at all")
    case.assertTrue(record["existed"],
                    "the cwd %r did not exist when the scanner launched" % cwd)
    case.assertEqual(record["entries"], [],
                     "the scratch cwd was not empty at launch: %r"
                     % (record["entries"],))
    real_cwd = os.path.realpath(cwd)
    real_target = os.path.realpath(target)
    case.assertNotEqual(real_cwd, real_target)
    case.assertFalse(real_cwd.startswith(real_target + os.sep))
    case.assertFalse(os.path.exists(cwd), "the scratch cwd outlived invoke()")
