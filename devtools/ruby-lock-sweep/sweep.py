"""Compare the Gemfile.lock reader with Bundler::LockfileParser on malformed variants.

Offline dev tool, not a test: generates lock TEXT, asks the reader (in-process) and
Bundler (one `ruby` child fed JSON lines) whether each parses, and prints every lock
the reader ACCEPTS that Bundler REJECTS -- the direction that reads better than the truth.
usage: sweep.py <checkout> [<file to write the accepted-but-rejected locks to>]
The Ruby to run is $RUBY, else /usr/bin/ruby (it must have Bundler).
"""
import importlib
import json
import os
import subprocess
import sys
import tempfile

WT = sys.argv[1]
BAD_OUT = sys.argv[2] if len(sys.argv) > 2 else None
RUBY = os.environ.get("RUBY") or "/usr/bin/ruby"
sys.path.insert(0, os.path.join(WT, "skill"))
fpa = importlib.import_module("scripts.first_party_advisory")

BASE = [
    "PATH", "  remote: gems/foo", "  specs:", "    foo (1.0)", "      rack (~> 2.2)", "      json", "",
    "GIT", "  remote: https://example.invalid/x.git", "  revision: abc123", "  specs:", "    x (0.1)", "",
    "GEM", "  remote: https://rubygems.org/", "  specs:", "    json (2.0)", "    rack (2.2.3)", "      webrick (>= 1.0, < 3)", "    webrick (1.8.1)", "",
    "PLATFORMS", "  ruby", "  x86_64-linux", "",
    "DEPENDENCIES", "  foo!", "  rack (~> 2.2)", "  x!", "  json", "",
    "RUBY VERSION", "   ruby 2.6.10p210", "",
    "BUNDLED WITH", "   1.17.2", "",
]
JUNK = ["potato", "=> 1", ">= potato", ">= 1, nonsense", ">= 1,", ", >= 1", ">= 1 < 2", "~> 2.2;", "",
        " ", "1..2", ".1", "1.", ">= 1.0-x", "true", "false", "nil", "!", "!!", "(", ")", "()", "(1)", "1)",
        "\x00", "\x1b", "\x7f", "\u200b", "\xe9", "\u0663", "x y", "x  y", "-", "--", "#", "# c", ":", "::", "a:b",
        "http://", "https://", "file:///x", "~", "..", "/", "//", "\\", "'", '"', "`", "$", "%", "&", "*", "+",
        ",", ";", "<", "=", ">", "?", "@", "[", "]", "^", "_", "{", "|", "}"]
REQS = ["~> 2.2", ">= 1.0, < 3", "= 1.0", "!= 1.5", ">= 1.0.0.rc1", ">=1,<2", "2.0", "> 0, <= 9", "1", ">= 0"]


def variants():
    seen = set()

    def emit(lines, why):
        text = "\n".join(lines) + "\n"
        if text not in seen:
            seen.add(text)
            yield why, text

    yield from emit(BASE, "base")
    for i, line in enumerate(BASE):
        if not line:
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.lstrip(" ")
        # drop, duplicate, re-indent
        yield from emit(BASE[:i] + BASE[i + 1:], "drop %d %r" % (i, line))
        yield from emit(BASE[:i] + [line, line] + BASE[i + 1:], "dup %d %r" % (i, line))
        for n in range(0, 9):
            if n != indent:
                yield from emit(BASE[:i] + [" " * n + body] + BASE[i + 1:], "indent %d->%d %r" % (indent, n, line))
        # append / prepend junk, replace value, replace parenthesised part
        for junk in JUNK:
            yield from emit(BASE[:i] + [line + junk] + BASE[i + 1:], "append %r to %r" % (junk, line))
            yield from emit(BASE[:i] + [line + " " + junk] + BASE[i + 1:], "append-sp %r to %r" % (junk, line))
            yield from emit(BASE[:i] + [" " * indent + junk + body] + BASE[i + 1:], "prepend %r to %r" % (junk, line))
            yield from emit(BASE[:i] + [" " * indent + junk] + BASE[i + 1:], "replace %r with %r" % (line, junk))
            if "(" in body:
                head = body[:body.index("(")]
                yield from emit(BASE[:i] + [" " * indent + head + "(" + junk + ")"] + BASE[i + 1:],
                                "parens %r in %r" % (junk, line))
            if ": " in body:
                key = body[:body.index(": ")]
                yield from emit(BASE[:i] + [" " * indent + key + ": " + junk] + BASE[i + 1:],
                                "value %r in %r" % (junk, line))
                yield from emit(BASE[:i] + [" " * indent + junk + ": " + body.split(": ", 1)[1]] + BASE[i + 1:],
                                "key %r in %r" % (junk, line))
        for req in REQS:
            if "(" in body:
                head = body[:body.index("(")]
                yield from emit(BASE[:i] + [" " * indent + head + "(" + req + ")"] + BASE[i + 1:], "req %r in %r" % (req, line))
        # insert junk lines after this one at each indent
        for junk in JUNK[:24] + ["rack (>= potato)", "rack (=> 1)", "rack!", "rack (1)!", "Remote: x", "remote: y",
                                 "specs:", "specs: x", "glob: *", "ref: main", "branch: b", "tag: v1", "submodules: true",
                                 "type: path", "foo (1.0)", "foo (1.0-java)", "FOO", "GEM", "PATH"]:
            for n in (0, 1, 2, 3, 4, 5, 6, 7, 8):
                yield from emit(BASE[:i + 1] + [" " * n + junk] + BASE[i + 1:], "insert %r@%d after %r" % (junk, n, line))
    # every junk character at every position of every line
    chars = ["\x00", "\x1b", "\x7f", "\u200b", "\u00e9", "\u0663", "\t", " ", "!", "(", ")", ",", "-", ".",
             ":", ";", "<", "=", ">", "~", "%", "[", "]", "#", "/", "\\", "'", '"', "@", "*", "+", "?", "^", "|"]
    for i, line in enumerate(BASE):
        for pos in range(len(line) + 1):
            for ch in chars:
                yield from emit(BASE[:i] + [line[:pos] + ch + line[pos:]] + BASE[i + 1:],
                                "char %r at %d of %r" % (ch, pos, line))
            if pos < len(line):
                yield from emit(BASE[:i] + [line[:pos] + line[pos + 1:]] + BASE[i + 1:],
                                "delete char %d of %r" % (pos, line))
    # a second shape: a plugin source, checksums, and a PATH source at the root
    other = ["PATH", "  remote: .", "  specs:", "    app (0.1)", "",
             "PLUGIN SOURCE", "  remote: https://example.invalid/p", "  type: custom", "  specs:", "    p (1.0)", "",
             "GEM", "  remote: https://rubygems.org/", "  remote: https://gems.example.invalid/", "  specs:",
             "    nokogiri (1.16.0-x86_64-linux)", "    rack (2.2.3)", "",
             "PLATFORMS", "  x86_64-linux", "",
             "DEPENDENCIES", "  app!", "  nokogiri (>= 1.0)", "",
             "CHECKSUMS", "  rack (2.2.3) sha256=abc", "",
             "BUNDLED WITH", "   2.5.6", ""]
    yield from emit(other, "other base")
    for i, line in enumerate(other):
        if not line:
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.lstrip(" ")
        yield from emit(other[:i] + other[i + 1:], "other drop %r" % line)
        yield from emit(other[:i] + [line, line] + other[i + 1:], "other dup %r" % line)
        for n in range(0, 9):
            if n != indent:
                yield from emit(other[:i] + [" " * n + body] + other[i + 1:], "other indent %d %r" % (n, line))
        for junk in JUNK:
            yield from emit(other[:i] + [line + junk] + other[i + 1:], "other append %r to %r" % (junk, line))
            yield from emit(other[:i] + [" " * indent + junk] + other[i + 1:], "other replace %r with %r" % (line, junk))
            if "(" in body:
                head = body[:body.index("(")]
                yield from emit(other[:i] + [" " * indent + head + "(" + junk + ")" + body[body.index(")") + 1:]]
                                + other[i + 1:], "other parens %r in %r" % (junk, line))
            if ": " in body:
                key = body[:body.index(": ")]
                yield from emit(other[:i] + [" " * indent + key + ": " + junk] + other[i + 1:],
                                "other value %r in %r" % (junk, line))
        for pos in range(len(line) + 1):
            for ch in chars:
                yield from emit(other[:i] + [line[:pos] + ch + line[pos:]] + other[i + 1:],
                                "other char %r at %d of %r" % (ch, pos, line))
    # line endings and trailing content
    yield from emit([line + " " for line in BASE], "trailing spaces")
    yield "crlf", "\r\n".join(BASE) + "\r\n"
    yield "no trailing newline", "\n".join(BASE)
    yield "bom", "\ufeff" + "\n".join(BASE) + "\n"


def reader_specs(text):
    """None when the reader refuses the lock, else {(name, version, kind)}."""
    try:
        sections = fpa._gem_lock_sections(text)
    except ValueError:
        return None
    return {(name, version, section.kind) for section in sections for name, version in section.specs}


def reader_accepts(text):
    return reader_specs(text) is not None


def main():
    jobs = list(variants())
    work = tempfile.mkdtemp(prefix="bundler-sweep-")
    open(os.path.join(work, "Gemfile"), "w").write("source 'https://rubygems.org'\n")
    env = {"PATH": "/usr/bin:/bin", "HOME": work, "BUNDLE_GEMFILE": os.path.join(work, "Gemfile"),
           "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"}
    feed = "".join(json.dumps({"id": i, "lock": text}) + "\n" for i, (_why, text) in enumerate(jobs))
    here = os.path.dirname(os.path.abspath(__file__))
    out = subprocess.run([RUBY, os.path.join(here, "bundler_parse.rb")], input=feed, cwd=work, env=env,
                         capture_output=True, text=True, timeout=600)
    answers = {}
    for line in out.stdout.splitlines():
        row = json.loads(line)
        answers[row["id"]] = row
    assert len(answers) == len(jobs), (len(answers), len(jobs), out.stderr[-400:])
    bad, strict, missed, both = [], 0, [], 0
    for i, (why, text) in enumerate(jobs):
        specs, theirs = reader_specs(text), answers[i]["ok"]
        ours = specs is not None
        if ours and not theirs:
            bad.append((why, answers[i].get("err")))
        elif theirs and not ours:
            strict += 1
        elif ours and theirs:
            both += 1
            # Bundler's view: name, version (platform re-joined), and whether the source is a Path.
            # By name, release and source kind: the platform is rendered differently by each side.
            seen = {(name, version, "local" if source == "Path" else "external")
                    for name, version, platform, source in answers[i]["specs"]}
            specs = {(name, version.partition("-")[0], kind) for name, version, kind in specs}
            if not seen <= specs:
                missed.append((why, sorted(seen - specs)[:3]))
    print("both accept: %d; Bundler saw a spec (or a kind) the reader did not: %d" % (both, len(missed)))
    for why, extra in missed[:12]:
        print("   MISSED %s -> %s" % (why[:110], extra))
    print("locks: %d; Bundler rejects: %d; reader accepts what Bundler rejects: %d; reader stricter: %d"
          % (len(jobs), sum(not a["ok"] for a in answers.values()), len(bad), strict))
    kinds = {}
    for why, err in bad:
        key = why.split(" ", 1)[0] + " | " + (err or "")[:60]
        kinds.setdefault(key, []).append(why)
    for key, items in sorted(kinds.items(), key=lambda kv: -len(kv[1])):
        print("%5d  %s\n         e.g. %s" % (len(items), key, items[0][:150]))
    if BAD_OUT:
        with open(BAD_OUT, "w", encoding="utf-8") as fh:
            json.dump(bad, fh, indent=0)


main()
