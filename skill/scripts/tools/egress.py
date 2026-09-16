"""Per-run egress containment for the ONLINE_ONLY adapters (#1645, SEC-C1A).

Every other scanner container gets `--network none`. The two ONLINE_ONLY
adapters got nothing in its place, so Docker attached them to its DEFAULT
BRIDGE -- every service reachable from the runner's network, private ones
included. `--online` decided WHETHER pip-audit/npm-audit ran; it never narrowed
where they could connect, and none of the container's other hardening (cap
drop, no-new-privileges, resource ceilings, read-only source mount) constrains
reachability.

So the online adapters get an egress path shaped like their job: a per-run
`--internal` network with no external route, and one forward-proxy sidecar
bridging it to the internet with a DENY-BY-DEFAULT allowlist of the advisory
endpoints those adapters actually call.

ONE TABLE. `ALLOWLIST` is read by the proxy config writer AND by the manifest
disclosure (`tools-manifest.json`'s `network`, which the report copies to
`meta.tools.network`), so what the artifact CLAIMS and what the proxy ENFORCES
are the same list by construction. A second copy is how those two drift.

WHY A PROXY AND NOT A FIREWALL RULE. The endpoints are CDN-fronted names whose
address sets change without notice, so an IP allowlist is either wrong or
enormous. A forward proxy filters on the name the client asked for -- including
the host in a `CONNECT`, which is all a proxy ever sees of an HTTPS request --
which is the axis the allowlist is actually written in.

NO REAL DOCKER RUNS IN THE TEST SUITE, so every claim about the proxy's
behaviour below is anchored to upstream documentation with a version rather
than to an observation: tinyproxy 1.11.3 (the Alpine v3.24 package inside the
pinned image), directives per `tinyproxy.conf(5)` at that tag.

OUT OF SCOPE, stated rather than assumed: rootless Docker and podman implement
`--internal` differently (podman's `--internal` historically blocked the
gateway rather than routing, and a rootless daemon's bridge is namespaced), so
this module's guarantee is stated for a standard rootful Docker daemon. On any
other runtime the disclosure still holds -- the manifest says what was done --
but the containment is that runtime's, not this one's.
"""
from __future__ import annotations

import os


# Adapter -> the advisory endpoints its argv actually reaches. Sorted, so the
# rendered filter file and the manifest's posture string are stable.
#
# pip-audit: `pip-audit --format=json --requirement <generated file>` resolves
#   what that file names through pip, which reads the simple index at
#   `pypi.org` and fetches distribution metadata from `files.pythonhosted.org`;
#   the default vulnerability service is PyPI's own JSON API (`pypi.org`).
#   `api.osv.dev` is pip-audit's other supported service
#   (`--vulnerability-service osv`); today's argv does not select it, and it is
#   listed because it is an ADVISORY endpoint -- the class this container is
#   supposed to be able to reach -- not because the allowlist is loose.
# npm-audit: `npm audit --json` posts the lockfile's package set to the bulk
#   advisory endpoint on `registry.npmjs.org`.
ALLOWLIST = {
    "pip-audit": ("api.osv.dev", "files.pythonhosted.org", "pypi.org"),
    "npm-audit": ("registry.npmjs.org",),
}

# The sidecar. Pinned BY DIGEST, not by tag: this is a third-party image pulled
# at scan time, and a tag would let the registry hand a later run a different
# proxy without anything in this repo changing. `kalaksi/tinyproxy:1.7`
# (2026-07-05, multi-arch amd64+arm64, ~6.5 MB) is Alpine 3.24.1 plus
# `apk add tinyproxy` -- tinyproxy 1.11.3-r0 -- and runs as uid 57981, not
# root. The digest is the OCI image INDEX digest, so one pin covers both
# architectures.
#
# Not in `scripts/bump_pins.py`: that script bumps the Dockerfile's
# curl-and-checksum artifacts (rustup today), and the repo's other image
# digests -- `ARG NVD_DATA_REF`, the `python:3.12-slim` base -- are BUILD-time
# `Dockerfile` pins that `docker build` resolves. This one is resolved by
# `docker run` on the operator's machine at scan time, so it lives beside the
# code that runs it. Bumping it is a deliberate edit here.
PROXY_IMAGE = ("docker.io/kalaksi/tinyproxy@sha256:"
               "8f9269b0b5b7b872b2fe8471299330c9fcf2ffb12eebdbb152feb7b9084f866a")
PROXY_PORT = 8888
HTTPS_PORT = 443

# Where the generated config is MOUNTED (the image's own `/etc/tinyproxy` is
# owned by the image user, so a file bind-mounted over it stays readable there
# whatever the host scratch directory's mode is).
PROXY_CONF = "/etc/tinyproxy/tinyproxy.conf"
PROXY_FILTER = "/etc/tinyproxy/filter"
PROXY_BIN = "/usr/bin/tinyproxy"

# Inactivity timeout and client ceiling for the sidecar. Two adapters, a
# handful of concurrent connections each.
PROXY_IDLE_TIMEOUT = 600
PROXY_MAX_CLIENTS = 16


def allowed_hosts(tools):
    """The sorted union of the allowlists of `tools` that have one."""
    hosts = set()
    for tool in tools:
        hosts.update(ALLOWLIST.get(tool, ()))
    return sorted(hosts)


def posture(tool):
    """`tool`'s manifest `network` value when it runs behind the proxy.

    Rendered from the same table the filter file is, so the artifact cannot
    claim an allowlist the proxy is not enforcing.
    """
    return "proxied:%s" % ",".join(ALLOWLIST[tool])


def render_config(subnet, hosts):
    """`(tinyproxy.conf, filter)` for a run whose adapters may reach `hosts`.

    Every directive is load-bearing and none is a default being restated:

    `Allow <subnet>` -- the sidecar is attached to the internal network AND to
      the bridge (that is what makes it a bridge), so without an ACL it is an
      open proxy to the allowlist for anything else on the host. `Allow`/`Deny`
      in tinyproxy.conf(5): "If there are no Allow or Deny lines, then all
      clients are allowed. Otherwise, the default action is to deny access." So
      this one line denies the bridge side.
    `ConnectPort 443` -- "If no ConnectPort line is found, then all ports are
      allowed", i.e. CONNECT could tunnel to any port on an allowlisted host.
    `FilterDefaultDeny Yes` -- "if set to No the Filter list acts as a
      blacklist, if set to Yes as a whitelist". `src/filter.c` at 1.11.3
      returns "filtered" for an unmatched host under this flag, and
      `src/reqs.c` runs the filter on `request->host`, which for a CONNECT is
      the tunnel's host -- so HTTPS is covered, not just plain HTTP.
    `FilterType fnmatch` -- the rules are matched with fnmatch(3) rather than
      as regular expressions. The entries are exact hostnames; under the
      default `bre` the same strings are regexes whose `.` matches any
      character, so `pypi.org` would also admit `pypixorg`. (`FilterExtended`
      is deprecated upstream in favour of `FilterType`; `FilterURLs` is
      documented as working "only in plain HTTP scenarios", which is not how
      an index is fetched.)

    No `LogFile` and no `Syslog`: `src/log.c` sends logging to stdout when no
    log file is named, which under `docker logs` is where an operator can read
    a refusal.
    """
    hosts = list(hosts)
    if not hosts:
        # A FilterDefaultDeny config with no rules denies every request, which
        # would read in the manifest as "proxied" while auditing nothing. A
        # caller with nothing to allow has no business starting a proxy.
        raise ValueError("refusing to render an egress proxy config with an "
                         "empty allowlist")
    conf = "\n".join([
        "# panopticon per-run egress allowlist (#1645) -- generated per run,",
        "# mounted read-only, deleted when the run's tool scan ends.",
        "# tinyproxy 1.11.3 (Alpine v3.24 package); tinyproxy.conf(5) at 1.11.3.",
        "Port %d" % PROXY_PORT,
        "Timeout %d" % PROXY_IDLE_TIMEOUT,
        "MaxClients %d" % PROXY_MAX_CLIENTS,
        "LogLevel Warning",
        "# Only this run's internal subnet may use the proxy at all; the",
        "# sidecar's bridge side (and the host) are denied by the same line.",
        "Allow %s" % subnet,
        "# CONNECT -- every HTTPS fetch -- reaches 443 and nothing else.",
        "ConnectPort %d" % HTTPS_PORT,
        "# Deny by default; the filter file below is the whole allowlist.",
        "FilterDefaultDeny Yes",
        "FilterType fnmatch",
        'Filter "%s"' % PROXY_FILTER,
        "",
    ])
    return conf, "".join("%s\n" % host for host in hosts)


def write_config(scratch, subnet, hosts):
    """Render the config into `scratch` and return `(conf_path, filter_path)`.

    Mode 0644 deliberately: the sidecar image runs as uid 57981 and a file
    inheriting mkdtemp's 0600 would be unreadable there -- tinyproxy would exit
    before it ever bound a port, turning a containment control into a silent
    scanner failure. The contents are an allowlist and a subnet, not a secret.

    These are CONTROLLER artifacts, not scanner captures: they are composed
    here from this module's own table, never from target text, and they are
    written to a scratch directory rather than into `.panopticon/tools/` so
    they can neither be mistaken for a capture by the ingest walk nor need a
    write path through `run_tools._redact_capture` (#1639 P11's choke point,
    which exists for bytes a scanner produced).
    """
    conf, filt = render_config(subnet, hosts)
    conf_path = os.path.join(scratch, "tinyproxy.conf")
    filter_path = os.path.join(scratch, "filter")
    for path, text in ((conf_path, conf), (filter_path, filt)):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(path, 0o644)
    return conf_path, filter_path
