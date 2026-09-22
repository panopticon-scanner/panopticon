#!/usr/bin/env python3
"""Materialize safe rule controls and verify an exact Semgrep JSON result set."""

import argparse
from collections import Counter
import json
from pathlib import Path


class ControlError(RuntimeError):
    pass


def _load(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ControlError("cannot read %s: %s" % (path, exc)) from exc
    if data.get("schema_version") != 1:
        raise ControlError("unsupported controls schema in %s" % path)
    return data


def materialize(controls_path, output_dir):
    controls = _load(controls_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    files = controls.get("files")
    if not isinstance(files, dict) or not files:
        raise ControlError("controls contain no source files")
    for name, source in files.items():
        if isinstance(source, list) and all(isinstance(line, str) for line in source):
            source = "\n".join(source) + "\n"
        if not isinstance(name, str) or Path(name).name != name or not isinstance(source, str):
            raise ControlError("invalid control source entry")
        (output_dir / name).write_text(source, encoding="utf-8")


def _record(item, control_root):
    check_id = item.get("check_id", "")
    try:
        path = Path(item["path"]).resolve().relative_to(control_root.resolve()).as_posix()
        line = item["start"]["line"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ControlError("malformed Semgrep result: %r" % item) from exc
    return check_id.rsplit(".", 1)[-1], path, line


def check(controls_path, control_root, result_path):
    controls = _load(controls_path)
    try:
        result = json.loads(Path(result_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ControlError("cannot read Semgrep results: %s" % exc) from exc
    if result.get("errors"):
        raise ControlError("Semgrep reported errors: %r" % result["errors"])
    expected = Counter(
        (item["rule_id"], item["path"], item["line"])
        for item in controls.get("expected", [])
    )
    actual = Counter(_record(item, Path(control_root)) for item in result.get("results", []))
    if actual != expected:
        missing = list((expected - actual).elements())
        unexpected = list((actual - expected).elements())
        raise ControlError(
            "Semgrep control result mismatch; missing=%r unexpected=%r"
            % (missing, unexpected)
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--controls", type=Path, default=Path(__file__).with_name("controls.json")
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    materialize_parser = subparsers.add_parser("materialize")
    materialize_parser.add_argument("output_dir", type=Path)
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("control_root", type=Path)
    check_parser.add_argument("result", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "materialize":
            materialize(args.controls, args.output_dir)
        else:
            check(args.controls, args.control_root, args.result)
    except ControlError as exc:
        parser.exit(1, "semgrep rule controls failed: %s\n" % exc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
