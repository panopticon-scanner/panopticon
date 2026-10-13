#!/usr/bin/env python3
"""Bounded argv adapters for download programs other than curl and wget."""
from dataclasses import dataclass
import os
import re

import shell_reader
from workflow_option_words import lifted


FETCHERS = ("aria2c", "axel", "fetch", "http", "https", "gh", "git", "pip", "pip3")


@dataclass(frozen=True)
class Transfer:
    """One adapter's answer before shell stdout routing is applied."""

    tool: str
    url: str | None = None
    dest: str | None = None
    stdout: bool = False
    tree: bool = False
    named: bool = False
    unread: bool = False


@dataclass
class _Scan:
    operands: list
    values: dict
    flags: set
    unread: bool = False


def _scan(args, short_values="", long_values=(), short_flags="", long_flags=()):
    """Split a bounded option grammar without treating option values as URLs."""
    answer = _Scan([], {}, set())
    i = 0
    while i < len(args):
        argument, i = args[i], i + 1
        if argument == "--":
            answer.operands.extend(args[i:])
            break
        if argument.startswith("--"):
            name, sep, inline = argument[2:].partition("=")
            if lifted(argument, 0, 2 + len(name)):
                answer.unread = True
                continue
            if name in long_values:
                value = (shell_reader.derived(inline, argument) if sep
                         else args[i] if i < len(args) else None)
                i += 0 if sep else 1
                answer.unread |= value is None
                answer.values.setdefault(name, []).append(value)
            elif name in long_flags:
                answer.flags.add(name)
                answer.unread |= bool(sep and inline not in ("true", "false"))
            else:
                answer.unread = True
            continue
        if argument.startswith("-") and argument != "-":
            j = 1
            while j < len(argument):
                if lifted(argument, j, j + 1):
                    answer.unread = True
                    break
                option, j = argument[j], j + 1
                if option in short_values:
                    value = (shell_reader.derived(argument[j:], argument) if argument[j:]
                             else args[i] if i < len(args) else None)
                    i += 0 if argument[j:] else 1
                    answer.unread |= value is None
                    answer.values.setdefault(option, []).append(value)
                    break
                if option in short_flags:
                    answer.flags.add(option)
                else:
                    answer.unread = True
            continue
        answer.operands.append(argument)
    return answer


def _last(scan, *names):
    found = [scan.values[name][-1] for name in names if scan.values.get(name)]
    return found[-1] if found else None


def _basename(url):
    if not url:
        return None
    name = os.path.basename(str(url).split("?", 1)[0].split("#", 1)[0].rstrip("/"))
    return shell_reader.derived(name, url) if name else None


def _join(directory, name):
    if not directory or directory == "." or not name or os.path.isabs(name):
        return name
    return shell_reader.derived(os.path.join(directory, name), directory, name)


def _unread(tool):
    return Transfer(tool, unread=True)


def _aria2(args):
    if any(word in ("-v", "--version", "-h") or str(word).startswith("--help")
           for word in args):
        return None
    if any(word in ("--dry-run", "--dry-run=true") for word in args):
        return None
    scan = _scan(
        args, "dijlosxk", {
            "dir", "input-file", "max-concurrent-downloads", "log", "out", "split",
            "max-connection-per-server", "min-split-size", "load-cookies", "save-cookies",
            "header", "user-agent", "referer", "checksum", "connect-timeout", "timeout",
            "retry-wait", "max-tries", "max-file-not-found", "lowest-speed-limit",
            "max-download-limit", "file-allocation", "interface", "all-proxy",
            "all-proxy-user", "all-proxy-passwd", "http-proxy", "http-proxy-user",
            "http-proxy-passwd", "https-proxy", "https-proxy-user", "https-proxy-passwd",
            "ftp-proxy", "ftp-proxy-user", "ftp-proxy-passwd", "select-file",
        }, "cVq", {
            "continue", "check-integrity", "quiet", "allow-overwrite", "auto-file-renaming",
            "force-sequential", "remote-time", "parameterized-uri", "content-disposition-default-utf8",
        },
    )
    if scan.unread or _last(scan, "i", "input-file") or not scan.operands:
        return _unread("aria2c")
    output = _last(scan, "o", "out")
    basenames = {_basename(url) for url in scan.operands}
    if not output and (None in basenames or len(basenames) != 1):
        return _unread("aria2c")
    dest = output or _basename(scan.operands[0])
    return Transfer("aria2c", scan.operands[0], _join(_last(scan, "d", "dir"), dest),
                    named=output is not None)


def _axel(args):
    scan = _scan(
        args, "snoHUT", {"max-speed", "num-connections", "max-redirect", "output", "header",
                          "user-agent", "timeout"},
        "SR46Nqvapkc hV".replace(" ", ""),
        {"search", "netrc", "ipv4", "ipv6", "no-proxy", "quiet", "verbose", "alternate",
         "percentage", "progress", "insecure", "no-clobber", "location-trusted", "no-netrc",
         "help", "version"},
    )
    if {"h", "V", "help", "version"} & scan.flags:
        return None
    if scan.unread or not scan.operands:
        return _unread("axel")
    output = _last(scan, "o", "output")
    dest = output or _basename(scan.operands[0])
    return Transfer("axel", scan.operands[0], dest, named=output is not None,
                    unread=dest is None)


def _fetch(args):
    scan = _scan(args, "BSTNowhcf", (), "146AFMPRUadlmnpqrsv", ())
    if "s" in scan.flags:
        return None
    if scan.unread or not scan.operands or len(scan.operands) != 1:
        return _unread("fetch")
    output = _last(scan, "o")
    dest = output or _basename(scan.operands[0])
    return Transfer("fetch", scan.operands[0], dest, stdout=output == "-",
                    named=output is not None, unread=dest is None)


_HTTP_VALUES = {
    "auth", "auth-type", "proxy", "session", "session-read-only", "output", "print",
    "pretty", "style", "format-options", "ssl", "cert", "cert-key", "timeout",
    "max-redirects", "max-headers", "boundary", "verify",
}
_HTTP_FLAGS = {
    "download", "continue", "body", "headers", "meta", "verbose", "quiet", "stream",
    "follow", "check-status", "ignore-stdin", "form", "multipart", "json", "offline",
    "compress", "all", "sorted", "unsorted", "raw", "help", "version",
}


def _http(tool, args):
    if "--help" in args or "--version" in args:
        return None
    scan = _scan(args, "aopsAP", _HTTP_VALUES, "dbhmvqSfcj", _HTTP_FLAGS)
    if "offline" in scan.flags:
        return None
    if scan.unread or not scan.operands:
        return _unread(tool)
    operands = list(scan.operands)
    if len(operands) > 1 and re.fullmatch(r"[A-Z]+", str(operands[0])):
        operands.pop(0)
    if not operands:
        return _unread(tool)
    output = _last(scan, "o", "output")
    return Transfer(tool, operands[0], output, stdout=output is None,
                    named=output is not None)


def _gh(args):
    if list(args[:2]) != ["release", "download"]:
        return None
    scan = _scan(args[2:], "ADORp", {"archive", "dir", "output", "pattern", "repo"},
                 "", {"allow-escape-sequences", "clobber", "skip-existing", "help"})
    if "help" in scan.flags:
        return None
    if scan.unread or len(scan.operands) > 1:
        return _unread("gh release download")
    output = _last(scan, "O", "output")
    pattern = _last(scan, "p", "pattern")
    directory = _last(scan, "D", "dir")
    if output is None:
        patterns = scan.values.get("p", []) + scan.values.get("pattern", [])
        if (len(patterns) != 1 or not pattern
                or shell_reader.has_substitution(pattern) or re.search(r"[*?[]", str(pattern))):
            return _unread("gh release download")
        output = _join(directory, pattern)
    url = pattern or (scan.operands[0] if scan.operands else _last(scan, "R", "repo"))
    return Transfer("gh release download", url, output, stdout=output == "-", named=True)


def _remote_repo(repository):
    text = str(repository)
    if shell_reader.has_substitution(repository):
        return True
    if text.startswith("file://") or text.startswith(("/", "./", "../", "~")):
        return False
    if re.match(r"(?:https?|ssh|git|ftps?)://", text):
        return True
    return "::" in text or bool(re.match(r"[^/]+:[^/]", text))


def _git(args):
    if not args or args[0] != "clone":
        return None
    scan = _scan(
        args[1:], "obucj", {
            "origin", "branch", "upload-pack", "config", "jobs", "template", "reference",
            "reference-if-able", "separate-git-dir", "depth", "shallow-since", "shallow-exclude",
            "filter", "server-option", "revision", "ref-format", "bundle-uri",
        }, "lsqnv46", {
            "local", "no-hardlinks", "shared", "dissociate", "quiet", "verbose", "progress",
            "no-checkout", "bare", "mirror", "single-branch", "no-single-branch", "no-tags",
            "checkout", "hardlinks", "recurse-submodules", "recursive", "no-recursive",
            "shallow-submodules", "remote-submodules", "sparse", "ipv4", "ipv6",
            "reject-shallow", "no-reject-shallow", "also-filter-submodules",
        },
    )
    if scan.unread or len(scan.operands) not in (1, 2):
        return _unread("git clone")
    repository = scan.operands[0]
    if not _remote_repo(repository):
        return None
    if {"n", "no-checkout", "bare", "mirror"} & scan.flags:
        return None
    dest = scan.operands[1] if len(scan.operands) == 2 else _basename(repository)
    if dest and str(dest).endswith(".git"):
        dest = shell_reader.derived(str(dest)[:-4], repository)
    return Transfer("git clone", repository, dest, tree=True, named=len(scan.operands) == 2,
                    unread=dest is None)


def _pip(tool, args):
    if not args or args[0] != "download":
        return None
    scan = _scan(
        args[1:], "crdif", {
            "constraint", "build-constraint", "requirement", "requirements-from-script", "dest",
            "index-url", "extra-index-url", "find-links", "src", "progress-bar", "platform",
            "python-version", "implementation", "abi", "group", "config-settings", "proxy",
            "timeout", "retries", "cert", "client-cert", "cache-dir", "log", "all-releases",
            "only-final", "no-binary", "only-binary", "refresh-package", "uploaded-prior-to",
            "python", "keyring-provider", "exists-action", "trusted-host", "use-feature",
            "use-deprecated", "resume-retries",
        }, "qvhV", {
            "no-deps", "only-deps", "require-hashes", "no-require-hashes", "no-build-isolation",
            "check-build-dependencies", "ignore-requires-python", "no-index", "pre",
            "prefer-binary", "no-clean", "debug", "isolated", "require-virtualenv", "no-input",
            "no-proxy-env", "no-cache-dir", "disable-pip-version-check", "no-color", "help",
            "version",
        },
    )
    if {"h", "V", "help", "version"} & scan.flags:
        return None
    if (scan.unread or len(scan.operands) != 1
            or any(scan.values.get(name) for name in
                   ("c", "constraint", "build-constraint", "r", "requirement",
                    "requirements-from-script", "group"))):
        return _unread(tool + " download")
    url = scan.operands[0]
    if not _remote_repo(url):
        return _unread(tool + " download")
    dest = _join(_last(scan, "d", "dest") or ".", _basename(url))
    return Transfer(tool + " download", url, dest, named=True, unread=dest is None)


def parse(tool, args):
    """Return a bounded transfer, None for a non-download command, or an unread transfer."""
    if tool == "aria2c":
        return _aria2(args)
    if tool == "axel":
        return _axel(args)
    if tool == "fetch":
        return _fetch(args)
    if tool in ("http", "https"):
        return _http(tool, args)
    if tool == "gh":
        return _gh(args)
    if tool == "git":
        return _git(args)
    if tool in ("pip", "pip3"):
        return _pip(tool, args)
    return None
