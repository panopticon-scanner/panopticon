#!/usr/bin/env python3
"""Replay a completed run's synthesis with the driver's own argv; diff two replays.

The behaviour-preservation oracle for the WS-0 refactor (spec §6.1): a move
or reshape PR is only clean when a replay on the branch is byte-for-byte the
replay on the base commit, for every reference run folder.

    python3 scripts/replay_report.py replay <review-root> <run-folder> <out-dir>
            [--manifest PATH] [--repo CHECKOUT] [--trust-archive]
    python3 scripts/replay_report.py diff <out-dir-a> <out-dir-b>

`replay` never touches the reference: it builds a scratch review root of
COPIES -- <review-root>'s top-level entries but `.git`, plus a REAL
`.panopticon/` holding the manifest and a copy of <run-folder> at `runs/<tag>`
(#3332: the artifact confinement refuses a linked `runs/<tag>`, and the LOC
count opens with no-follow, so a symlink farm read as 0 lines),
calls `phases.synthesize.synthesize_execute` with `_run_child` patched to record the
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
on both sides of a diff; the scratch root is scrubbed to `<scratch>` and the
out-dir to `<out>` in every output -- the report files and the captured
`synthesize.stdout` / `synthesize.stderr` alike -- so two replays compare
wherever they were written.

The scratch root is a new path, so the run's own stamp (#3271) can never
verify there; replay re-binds it under a throwaway key in its temp dir, never
the operator's. Without `--trust-archive` it does so only after first contact's
own read-only assessment verified <review-root>'s mark and manifest with this
machine's key -- a run of ours, replayed unmarked -- and refuses anything else.
`--trust-archive` skips that check for a foreign archive, reads no operator key,
says so on stderr and marks the report `meta.unverified_archive` (#3332).
Keep <out-dir> outside every tree's `.panopticon/`: the child's first contact
assesses the tree it writes into, and under the throwaway key none verifies.

`--repo` points at the checkout whose skill/ should do the replay (default:
this file's own repo) -- use it to produce the base-commit replay from the
branch checkout before the tool exists on the base.

`diff` compares the parsed report, every `_partN` either side wrote, `-discarded`, `-x0x`, and
`-x0x-failures` files of two out-dirs, masking `meta.timestamp` and the x0x `generated_at`, and
exits 1 on any difference -- including a key-order change, which the parsed
compare alone would forgive but the written bytes do not. The `.json.html`
rendering is compared as text with ISO timestamps masked, and the two
captured streams line by line (the first differing line is reported). The
out-dir files are named `<tag>-report*.json` exactly like the driver's, so
`diff <out-dir> <review-root>/.panopticon` also shows the (informational,
un-gated) drift from the historical report.
"""
import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SUFFIXES = (".json", "-discarded.json", "-x0x.json", "-x0x-failures.json")
_PART_RE = re.compile(r"_part([0-9]+)\.json\Z")


def _suffixes(stem, *folders):
    """SUFFIXES plus every `_partN.json` either folder holds for `stem` (#3256): the writer emits
    `_part2` .. `_partN`, so a report that grew or lost a part is a difference, not a blind spot."""
    parts = {int(m.group(1)) for folder in folders for name in os.listdir(folder)
             if name.startswith(stem) and (m := _PART_RE.fullmatch(name[len(stem):]))}
    return SUFFIXES[:1] + tuple("_part%d.json" % n for n in sorted(parts)) + SUFFIXES[1:]
STREAMS = ("synthesize.stdout", "synthesize.stderr")
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

def _scrub(text, root, out_dir):
    """Replace the two per-replay absolute paths with stable tokens.

    The scratch root (fresh per replay) reaches the outputs when a folder is
    replayed away from its original absolute paths (an archive copy): that
    trips the dispatch-plan path-mismatch branch, whose report lists the
    findings files by their scratch-root path. The out-dir reaches stdout
    through the `X0X artifact:` / `HTML artifact:` lines. Scrubbing both keeps
    two replays comparable wherever they were written."""
    return text.replace(root, "<scratch>").replace(out_dir, "<out>")


def _scrub_scratch(path, root, out_dir):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    scrubbed = _scrub(text, root, out_dir)
    if scrubbed != text:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(scrubbed)

def _copy_in(src, dst):
    """#3332: COPY, never link. A link inside a copied tree stays a link."""
    if os.path.isdir(src) and not os.path.islink(src):
        shutil.copytree(src, dst, symlinks=True)
    else:
        shutil.copy2(src, dst, follow_symlinks=False)

def _scratch_root(tmp, review_root, manifest, tag, run_folder, bind=None):
    root = os.path.join(tmp, "root")
    os.makedirs(root)
    for name in os.listdir(review_root):
        if name not in (".panopticon", ".git"):
            _copy_in(os.path.join(review_root, name), os.path.join(root, name))
    if bind is not None:
        bind(root, manifest)     # marks the still-absent `.panopticon/`, so before runs/
    os.makedirs(os.path.join(root, ".panopticon", "runs"), exist_ok=True)
    with open(os.path.join(root, ".panopticon", "run-manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    _copy_in(run_folder, os.path.join(root, ".panopticon", "runs", tag))
    return root


RECEIPT_DERIVED = ("replay: no output receipt in the archive's tools-manifest.json (#2070); derived "
                   "`outputs` from its `produced` on the copy")


def _derive_receipt(run_copy, tools_manifest):
    """#3386: give the COPY's tools manifest the output receipt its `produced` implies; True if so.

    Synthesis binds tool outputs only through `outputs`, and `output_receipt` accepts exactly the
    canonical output names of `produced`, so the receipt is a function of `produced`. A run folder
    without one replayed with no tool axis at all. Only a manifest that is an object with a
    well-formed `produced` and NO `outputs` key is touched; a malformed receipt, a malformed
    `produced` or an absent manifest is left for synthesis to refuse as before. The absence says
    nothing about the folder's age -- a removed receipt looks the same -- so the disclosure doesn't
    claim one."""
    path = os.path.join(run_copy, "tools-manifest.json")
    canonical = getattr(tools_manifest, "canonical_output_name", None)
    if canonical is None or os.path.islink(path) or not os.path.isfile(path):
        return False
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return False
    if not isinstance(doc, dict) or "outputs" in doc:
        return False
    produced = doc.get("produced")
    if not isinstance(produced, list) or not all(isinstance(t, str) and t for t in produced):
        return False
    doc["outputs"] = sorted(canonical(t) for t in produced)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    print(RECEIPT_DERIVED, file=sys.stderr, flush=True)
    return True


def _unverified(first_contact, review_root, manifest):
    """#3332: why <review-root> is NOT a verified run of this machine's, or None.
    First contact's own read-only assessment (no key or mark is written, and a
    missing key verifies nothing), and the manifest replayed must be the one it
    verified. Anything that could not be checked is unverified."""
    try:
        found = first_contact.assess_artifacts(review_root, read_only=True)
    except first_contact.FirstContactHalt as exc:
        return str(exc)
    if found.get("run-manifest.json") != manifest:
        return "%s holds no verified run manifest of this machine's matching it" % review_root
    return None


def _rebind(first_contact, root, manifest):
    """Stamp the scratch copy as ours under the throwaway key (#3332): the mark,
    then the manifest re-pointed at the copy, as an archive's review root was
    also its target."""
    original = manifest.get("review_root")
    for key in ("review_root", "target"):
        if manifest.get(key) == original:
            manifest[key] = os.path.abspath(root)
    first_contact._write_owner(os.path.join(root, ".panopticon"), root)
    first_contact.bind(root, manifest)


@contextlib.contextmanager
def _throwaway_state(tmp):
    """#3332: every stamp in a replay is signed and checked under a key that
    lives and dies in its temp dir -- the operator's state dir is never touched."""
    saved = os.environ.get("PANOPTICON_STATE_DIR")
    os.environ["PANOPTICON_STATE_DIR"] = os.path.join(tmp, "state")
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop("PANOPTICON_STATE_DIR", None)
        else:
            os.environ["PANOPTICON_STATE_DIR"] = saved


def _mark_unverified(path):
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    report.setdefault("meta", {})["unverified_archive"] = True
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(report, indent=2))


def replay(args):
    repo = os.path.abspath(args.repo or os.path.dirname(HERE))
    sys.path.insert(0, os.path.join(repo, "skill"))
    from scripts import hosts
    import scripts.first_contact as first_contact
    import scripts.phases.child as child_mod
    import scripts.phases.runio as runio
    import scripts.phases.synthesize as synthesize_phase
    import scripts.run_manifest as run_manifest
    import scripts.tools_manifest as tools_manifest

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
    trust = getattr(args, "trust_archive", False)
    if trust:
        print(f"replay: --trust-archive: {review_root}'s stamp is NOT verified; its copy is "
              "re-signed under a throwaway key and the report marked meta.unverified_archive",
              file=sys.stderr, flush=True)
    else:
        why = _unverified(first_contact, review_root, manifest)
        if why:
            sys.exit(f"replay: {review_root} is not a verified run of this machine's ({why}); "
                     "to replay a foreign archive anyway, pass --trust-archive (the report "
                     "is then marked meta.unverified_archive)")
    before = _listing(run_folder)
    os.makedirs(out_dir, exist_ok=True)
    recorded = []

    def fake_run_child(cmd, review_root, phase, timeout=None):
        recorded.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with tempfile.TemporaryDirectory(prefix="replay-") as tmp, _throwaway_state(tmp):
        root = _scratch_root(tmp, review_root, manifest, tag, run_folder,
                             bind=lambda r, m: _rebind(first_contact, r, m))
        receipt_derived = _derive_receipt(os.path.join(root, ".panopticon", "runs", tag),
                                          tools_manifest)
        # Match the phase's measured posture, including the deliberate absent-
        # host default. Read evidence through the scratch root so archived runs
        # use their own capability artifact, not the live checkout's latest run.
        collects_usage = (hosts.posture(manifest.get("host"), runio.host_evidence(root))
                          [hosts.USAGE_LEDGER] == hosts.PROVEN)
        required = REQUIRED + (("usage.json",) if collects_usage else ())
        missing = [f for f in required if not os.path.isfile(os.path.join(run_folder, f))]
        if missing:
            sys.exit(f"{run_folder} lacks {missing}: synthesize_execute would write into it")
        # #3226: what `driver.run` attaches per invocation. A replay dispatches nothing, so the
        # session-dispatch Bash gate has no launch to guard -- it must not refuse the oracle.
        manifest["dispatch_mode"] = "headless"
        with mock.patch("scripts.phases.child._run_child", new=fake_run_child):
            try:
                synthesize_phase.synthesize_execute(root, manifest)
            except runio.DriverError:
                pass    # expected: the no-op child produced no report
        if not recorded or "synthesize.py" not in os.path.basename(recorded[-1][1]):
            sys.exit(f"driver did not build a synthesize command: {recorded}")
        cmd = recorded[-1]
        out_path = os.path.join(out_dir, f"{tag}-report.json")
        cmd[cmd.index("--out") + 1] = out_path
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True,  # nosec B603
                              env=child_mod._child_env())
        after = _listing(run_folder)
        for name in os.listdir(out_dir):
            if name.startswith(tag):
                _scrub_scratch(os.path.join(out_dir, name), root, out_dir)
        if trust and os.path.isfile(out_path):
            _mark_unverified(out_path)
    with open(os.path.join(out_dir, "replay.json"), "w", encoding="utf-8") as fh:
        json.dump({"repo": repo, "review_root": review_root, "run_folder": run_folder,
                   "argv": [a.replace(root, "<scratch>") for a in cmd],
                   "returncode": proc.returncode, "receipt_derived": receipt_derived},
                  fh, indent=2)
    with open(os.path.join(out_dir, "synthesize.stderr"), "w", encoding="utf-8") as fh:
        fh.write(_scrub(proc.stderr or "", root, out_dir))
    with open(os.path.join(out_dir, "synthesize.stdout"), "w", encoding="utf-8") as fh:
        fh.write(_scrub(proc.stdout or "", root, out_dir))
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
        for suf in _suffixes(stem, a_dir, b_dir):
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
            found: list[str] = []
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
    for stream in STREAMS:
        pa, pb = os.path.join(a_dir, stream), os.path.join(b_dir, stream)
        if os.path.isfile(pa) != os.path.isfile(pb):
            problems.append(f"{stream}: present on {'A' if os.path.isfile(pa) else 'B'} only")
        elif os.path.isfile(pa):
            with open(pa, encoding="utf-8") as fa, open(pb, encoding="utf-8") as fb:
                la, lb = fa.read().splitlines(), fb.read().splitlines()
            if la != lb:
                first = next((i for i, (x, y) in enumerate(zip(la, lb)) if x != y),
                             min(len(la), len(lb)))
                problems.append(f"{stream}: differs at line {first + 1}")
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
    r.add_argument("--trust-archive", action="store_true",
                   help="replay a run whose stamp is not this machine's (a foreign archive); "
                        "the report is marked meta.unverified_archive (#3332)")
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
