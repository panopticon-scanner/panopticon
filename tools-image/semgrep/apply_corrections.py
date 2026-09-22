#!/usr/bin/env python3
"""Install byte-pinned corrections into a vendored semgrep-rules tree."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile


class CorrectionError(RuntimeError):
    pass


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _inside(root, relative):
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise CorrectionError("correction path escapes rules root: %s" % relative) from exc
    return candidate


def _load_manifest(path):
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CorrectionError("cannot read correction manifest %s: %s" % (path, exc)) from exc
    if manifest.get("schema_version") != 1:
        raise CorrectionError("unsupported correction manifest schema")
    corrections = manifest.get("corrections")
    if not isinstance(corrections, list) or not corrections:
        raise CorrectionError("correction manifest has no corrections")
    return corrections


def apply_corrections(rules_root, manifest_path):
    """Validate the whole batch, then atomically replace each individual file."""
    rules_root = Path(rules_root)
    manifest_path = Path(manifest_path)
    prepared = []
    seen = set()
    for item in _load_manifest(manifest_path):
        try:
            relative = item["path"]
            source_sha = item["source_sha256"]
            replacement_relative = item["replacement"]
            corrected_sha = item["corrected_sha256"]
        except (KeyError, TypeError) as exc:
            raise CorrectionError("malformed correction entry") from exc
        if relative in seen:
            raise CorrectionError("duplicate correction path: %s" % relative)
        seen.add(relative)
        target = _inside(rules_root, relative)
        replacement = _inside(manifest_path.parent, replacement_relative)
        try:
            source_bytes = target.read_bytes()
            corrected_bytes = replacement.read_bytes()
        except OSError as exc:
            raise CorrectionError("cannot read correction input for %s: %s" % (relative, exc)) from exc
        actual_source_sha = _sha256(source_bytes)
        if actual_source_sha == corrected_sha:
            raise CorrectionError("%s is already corrected; review the Docker install path" % relative)
        if actual_source_sha != source_sha:
            raise CorrectionError(
                "source drift for %s: expected %s, got %s; review the pinned rules update"
                % (relative, source_sha, actual_source_sha)
            )
        actual_corrected_sha = _sha256(corrected_bytes)
        if actual_corrected_sha != corrected_sha:
            raise CorrectionError(
                "replacement drift for %s: expected %s, got %s"
                % (relative, corrected_sha, actual_corrected_sha)
            )
        prepared.append((relative, target, corrected_bytes, target.stat().st_mode))

    staged = []
    try:
        for relative, target, corrected_bytes, mode in prepared:
            handle = tempfile.NamedTemporaryFile(
                mode="wb", prefix=".%s." % target.name, dir=target.parent, delete=False
            )
            try:
                handle.write(corrected_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                handle.close()
            staged_path = Path(handle.name)
            os.chmod(staged_path, mode)
            staged.append((relative, staged_path, target))
        for _relative, staged_path, target in staged:
            os.replace(staged_path, target)
    finally:
        for _relative, staged_path, _target in staged:
            try:
                staged_path.unlink()
            except FileNotFoundError:
                pass
    return [relative for relative, _target, _bytes, _mode in prepared]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-root", required=True, type=Path)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).with_name("corrections.json"),
    )
    args = parser.parse_args(argv)
    try:
        corrected = apply_corrections(args.rules_root, args.manifest)
    except CorrectionError as exc:
        parser.exit(1, "semgrep rule correction failed: %s\n" % exc)
    print("corrected %d pinned Semgrep rule files" % len(corrected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
