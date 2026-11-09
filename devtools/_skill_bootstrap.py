"""Put a checkout's `skill/` on sys.path for the dev tools (#3505).

A devtools CLI run by path (`python3 devtools/triage.py`) has `devtools/` at
sys.path[0] and imports panopticon code as `scripts.*`, which needs `skill/`.
Rather than edit sys.path itself, this runs that checkout's
`skill/scripts/_bootstrap.py`, so the mutation stays in one file (the guard in
tests/test_import_shape.py allows no other).

A CLI runs it by path inside its `if __name__ == "__main__":` block, so it
works under `python3 -P` too:

    if __name__ == "__main__":
        import runpy
        runpy.run_path(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                    "_skill_bootstrap.py"))

and `replay_report --repo` calls `install(repo)` to replay another checkout's
skill. Stdlib only, and `devtools/` stays where it is on sys.path, since the
tools here import each other flat.
"""
import importlib.util
import os

REPO = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def install(repo=REPO):
    """Run `<repo>/skill/scripts/_bootstrap.py`; return its SKILL directory."""
    path = os.path.join(repo, "skill", "scripts", "_bootstrap.py")
    spec = importlib.util.spec_from_file_location("_panopticon_skill_bootstrap", path)
    if spec is None or spec.loader is None or not os.path.isfile(path):
        raise SystemExit("%s has no skill/scripts/_bootstrap.py; it predates #3505" % repo)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)     # its __name__ is not scripts._bootstrap
    return module.SKILL


install()
