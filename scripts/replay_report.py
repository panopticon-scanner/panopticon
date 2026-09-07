#!/usr/bin/env python3
"""Replay a completed run's synthesis with the driver's own argv; diff two replays.

The behaviour-preservation oracle for the WS-0 refactor (spec §6.1): a move
or reshape PR is only clean when a replay on the branch is byte-for-byte the
replay on the base commit, for every reference run folder.

    python3 scripts/replay_report.py replay <review-root> <run-folder> <out-dir>
            [--manifest PATH] [--repo CHECKOUT]
    python3 scripts/replay_report.py diff <out-dir-a> <out-dir-b>

`replay` never touches the reference: it builds a scratch review root (a
symlink farm of <review-root>'s top-level entries plus a REAL `.panopticon/`
holding a copy of the manifest and a `runs/<tag>` symlink to <run-folder>),
calls `driver.synthesize_execute` with `_run_child` patched to record the
command instead of running it, then re-runs that recorded synthesize argv
with `--out` redirected into <out-dir>. cwd is the scratch root, so every
cwd-relative read (group files for the LOC count, `.panopticon` artifacts)
resolves exactly as the real run did, and every realpath check sees the
original files. It refuses to run when the folder lacks the artifacts the
phase would otherwise (re)write, and fails loudly if the folder's listing
changed afterwards.

The run folder may live anywhere under any name (an archive copy works);
it is paired with the manifest by run_id, not by folder name. A folder
replayed away from the absolute paths recorded in its dispatch plan (an
archive copy) deterministically exercises the path-mismatch integrity branch
on both sides of a diff; the scratch root is scrubbed to `<scratch>` in every
output so those replays still compare.

`--repo` points at the checkout whose skill/ should do the replay (default:
this file's own repo) -- use it to produce the base-commit replay from the
branch checkout before the tool exists on the base.

`diff` compares the parsed report, `_part2`, `-discarded` and `-x0x` files
of two out-dirs, masking `meta.timestamp` and the x0x `generated_at`, and
exits 1 on any difference -- including a key-order change, which the parsed
compare alone would forgive but the written bytes do not. The `.json.html`
rendering is compared as text with ISO timestamps masked. The out-dir files are named `<tag>-report*.json`
exactly like the driver's, so `diff <out-dir> <review-root>/.panopticon`
also shows the (informational, un-gated) drift from the historical report.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SUFFIXES = (".json", "_part2.json", "-discarded.json", "-x0x.json")
REQUIRED = ("dispatch-plan-driver.json", "out-file-hashes.json")
MASK = {".json": ("meta.timestamp",), "-x0x.json": ("generated_at",)}
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def _listing(folder):
    out = {}
    for d, _dirs, files in os.walk(folder):
        for f in files:
            p = os.path.join(d, f)
            st = os.lstat(p)
            out[os.path.relpath(p, folder)] = (st.st_size, st.st_mtime_ns)
    return out


def _folder_run_id(run_folder):
    """The run_id stamped into the folder's own artifacts (None if none carry one)."""
    for name in ("validate.json", "tools-manifest.json", "dispatch-request.json"):
        path = os.path.join(run_folder, name)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                return json.load(fh).get("run_id")
    return None

def _scrub_scratch(path, root):
    """Replace the scratch root (fresh per replay) with a stable token.

    A folder replayed away from its original absolute paths (an archive copy)
    trips the dispatch-plan path-mismatch branch, whose report lists the
    findings files by their scratch-root path; scrubbing keeps two such
    replays comparable."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if root in text:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text.replace(root, "<scratch>"))

def _scratch_root(tmp, review_root, manifest, tag, run_folder):
    root = os.path.join(tmp, "root")
    os.makedirs(os.path.join(root, ".panopticon", "runs"))
    for name in os.listdir(review_root):
        if name != ".panopticon":
            os.symlink(os.path.join(review_root, name), os.path.join(root, name))
    with open(os.path.join(root, ".panopticon", "run-manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    os.symlink(run_folder, os.path.join(root, ".panopticon", "runs", tag))
    return root


def replay(args):
    repo = os.path.abspath(args.repo or os.path.dirname(HERE))
    sys.path.insert(0, os.path.join(repo, "skill"))
    import scripts.driver as driver
    import scripts.run_manifest as run_manifest

    review_root = os.path.abspath(args.review_root)
    run_folder = os.path.abspath(args.run_folder)
    out_dir = os.path.abspath(args.out_dir)
    mpath = args.manifest or os.path.join(review_root, ".panopticon", "run-manifest.json")
    with open(mpath, encoding="utf-8") as fh:
        manifest = json.load(fh)
    tag = run_manifest.run_tag(manifest)
    folder_id = _folder_run_id(run_folder)
    if folder_id != manifest.get("run_id"):
        sys.exit(f"manifest run_id {manifest.get('run_id')!r} != run folder's {folder_id!r}")
    required = REQUIRED + (("usage.json",) if manifest.get("host", "claude") == "claude" else ())
    missing = [f for f in required if not os.path.isfile(os.path.join(run_folder, f))]
    if missing:
        sys.exit(f"{run_folder} lacks {missing}: synthesize_execute would write into it")
    before = _listing(run_folder)
    os.makedirs(out_dir, exist_ok=True)
    recorded = []

    def fake_run_child(cmd, review_root, phase, timeout=None):
        recorded.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with tempfile.TemporaryDirectory(prefix="replay-") as tmp:
        root = _scratch_root(tmp, review_root, manifest, tag, run_folder)
        with mock.patch("scripts.driver._run_child", new=fake_run_child):
            try:
                driver.synthesize_execute(root, manifest)
            except driver.DriverError:
                pass    # expected: the no-op child produced no report
        if not recorded or "synthesize.py" not in os.path.basename(recorded[-1][1]):
            sys.exit(f"driver did not build a synthesize command: {recorded}")
        cmd = recorded[-1]
        out_path = os.path.join(out_dir, f"{tag}-report.json")
        cmd[cmd.index("--out") + 1] = out_path
        # Pinned hash seed: set-ordered report keys (groups[].panel_grades
        # iterates VALID_PANELS, a set) otherwise reorder per process, which
        # the key-order check in `diff` would report as drift.
        env = dict(driver._child_env(), PYTHONHASHSEED="0")
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True,  # nosec B603
                              env=env)
        after = _listing(run_folder)
        for name in os.listdir(out_dir):
            if name.startswith(tag):
                _scrub_scratch(os.path.join(out_dir, name), root)
    with open(os.path.join(out_dir, "replay.json"), "w", encoding="utf-8") as fh:
        json.dump({"repo": repo, "review_root": review_root, "run_folder": run_folder,
                   "argv": [a.replace(root, "<scratch>") for a in cmd],
                   "returncode": proc.returncode}, fh, indent=2)
    with open(os.path.join(out_dir, "synthesize.stderr"), "w", encoding="utf-8") as fh:
        fh.write(proc.stderr or "")
    with open(os.path.join(out_dir, "synthesize.stdout"), "w", encoding="utf-8") as fh:
        fh.write(proc.stdout or "")
    if after != before:
        changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        sys.exit(f"REFERENCE RUN FOLDER MUTATED: {changed}")
    if not os.path.isfile(out_path):
        sys.exit(f"no report written (rc={proc.returncode}); see {out_dir}/synthesize.stderr")
    produced = sorted(f for f in os.listdir(out_dir) if f.startswith(tag))
    print(f"replayed {tag} (rc={proc.returncode}) -> {out_dir}: {produced}")
    return 0


def _mask(obj, dotted):
    node = obj
    parts = dotted.split(".")
    for k in parts[:-1]:
        if not isinstance(node, dict):
            return
        node = node.get(k)
    if isinstance(node, dict) and parts[-1] in node:
        node[parts[-1]] = "<masked>"


def _walk_diff(a, b, path, out, limit):
    if len(out) >= limit:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}.{k}: {'missing' if k not in a else 'extra'} on {'A' if k not in a else 'B'}")
            else:
                _walk_diff(a[k], b[k], f"{path}.{k}", out, limit)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: list length {len(a)} != {len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            _walk_diff(x, y, f"{path}[{i}]", out, limit)
    elif a != b:
        out.append(f"{path}: {json.dumps(a)[:80]} != {json.dumps(b)[:80]}")


def diff(args):
    a_dir, b_dir = os.path.abspath(args.a), os.path.abspath(args.b)
    stems = sorted({f[:-len(".json")] for f in os.listdir(a_dir) if f.endswith("-report.json")})
    if not stems:
        sys.exit(f"no <tag>-report.json in {a_dir}")
    problems = []
    for stem in stems:
        for suf in SUFFIXES:
            name = stem + suf
            pa, pb = os.path.join(a_dir, name), os.path.join(b_dir, name)
            if os.path.isfile(pa) != os.path.isfile(pb):
                problems.append(f"{name}: present on {'A' if os.path.isfile(pa) else 'B'} only")
                continue
            if not os.path.isfile(pa):
                continue
            with open(pa, encoding="utf-8") as fa, open(pb, encoding="utf-8") as fb:
                da, db = json.load(fa), json.load(fb)
            for dotted in MASK.get(suf, ()):
                _mask(da, dotted)
                _mask(db, dotted)
            found = []
            _walk_diff(da, db, name, found, args.limit)
            if not found and json.dumps(da) != json.dumps(db):
                # equal as objects, different on disk: key order is part of
                # the artifact (json.dump writes insertion order)
                found.append(f"{name}: KEY ORDER differs")
            problems.extend(found)
        html = stem + ".json.html"
        pa, pb = os.path.join(a_dir, html), os.path.join(b_dir, html)
        if os.path.isfile(pa) and os.path.isfile(pb):
            with open(pa, encoding="utf-8") as fa, open(pb, encoding="utf-8") as fb:
                ha, hb = (_TS_RE.sub("<ts>", fa.read()), _TS_RE.sub("<ts>", fb.read()))
            if ha != hb:
                problems.append(f"{html}: differs (ISO timestamps masked)")
        elif os.path.isfile(pa) != os.path.isfile(pb):
            problems.append(f"{html}: present on {'A' if os.path.isfile(pa) else 'B'} only")
    for line in problems:
        print(line)
    print(f"{'DIFFERENT' if problems else 'IDENTICAL'}: {len(problems)} difference(s) "
          f"across {len(stems)} report(s) ({a_dir} vs {b_dir})")
    return 1 if problems else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("replay", help="re-run synthesize on a completed run folder")
    r.add_argument("review_root")
    r.add_argument("run_folder")
    r.add_argument("out_dir")
    r.add_argument("--manifest", help="run-manifest.json (default: <review-root>/.panopticon/)")
    r.add_argument("--repo", help="checkout whose skill/ replays (default: this file's repo)")
    r.set_defaults(fn=replay)
    d = sub.add_parser("diff", help="compare two replay out-dirs")
    d.add_argument("a")
    d.add_argument("b")
    d.add_argument("--limit", type=int, default=50, help="max differences listed per file")
    d.set_defaults(fn=diff)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
