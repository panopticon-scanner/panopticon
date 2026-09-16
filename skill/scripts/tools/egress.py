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

import contextlib
import ipaddress
import itertools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile


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


# --- the per-run session ----------------------------------------------------
#
# Names are prefixed rather than fixed so a leftover is recognisable, and the
# label is what the stale sweep filters on -- `docker container prune` removes
# only STOPPED containers and `docker network prune` only networks with nothing
# attached, so neither can reach a concurrently running scan's sidecar however
# the name matched. `SWEEP_AGE` keeps the sweep off anything recent for the
# same reason, belt and braces.
NETWORK_PREFIX = "panopticon-online-"
PROXY_PREFIX = "panopticon-proxy-"
EGRESS_LABEL = "panopticon-egress=1"
SWEEP_AGE = "1h"

# The sidecar is a plain workload -- a 6 MB proxy with two adapters talking to
# it -- so it gets its own ceilings rather than the scanners' (6g/4cpu), which
# are sized for an adversarial target driving a SAST parser.
PROXY_HARDENING = ["--cap-drop=ALL", "--security-opt=no-new-privileges"]
PROXY_LIMITS = ["--memory", "256m", "--memory-swap", "256m",
                "--cpus", "1", "--pids-limit", "64"]
# NOT applied: `--read-only`. tinyproxy with this config writes nothing (no
# LogFile, no PidFile), so a read-only rootfs would probably hold -- but
# "probably" is not a control, no real container runs in this suite, and the
# module this sits beside declined the same flag for the same reason rather
# than half-applying it.

# How long past the scan's own worst case the sidecar may live. The container
# is started under `timeout`, so a controller that dies without running its
# teardown leaves something that stops on its own and is then swept, instead of
# an orphan proxy running until the host reboots.
SIDECAR_SLACK = 120
DEFAULT_SIDECAR_SECONDS = 1800

# Control-plane calls are daemon round-trips, not scans.
CONTROL_TIMEOUT = 60

# `tools-manifest.json`'s `network` values for the two non-proxied outcomes.
# `UNAVAILABLE` is the fail-closed one: it carries its own reason, because
# `excluded_scope` is a list of NAMES (`security_gate` validates it as one) and
# has nowhere to put a why.
NO_NETWORK = "none"
EXCLUDED_PREFIX = "excluded:"
UNAVAILABLE = EXCLUDED_PREFIX + "online egress unavailable"


class _Unavailable(Exception):
    """Egress could not be established. The online adapters do not run."""


class Session:
    """What the run loop asks about each tool: may it run, and with what flags.

    An inactive session (no ONLINE_ONLY adapter selected) serves nobody and
    refuses nobody, so the loop's behaviour for every other tool is byte-
    identical to before this existed.
    """

    def __init__(self, network=None, proxy=None, tools=(), refused=()):
        self.network = network
        self.proxy = proxy
        self._tools = frozenset(tools)
        self._refused = frozenset(refused)

    def refuses(self, tool):
        """True when `tool` needed egress this run and could not be given it."""
        return tool in self._refused

    def serves(self, tool):
        """True when `tool` runs behind this session's proxy."""
        return tool in self._tools and bool(self.network and self.proxy)

    def flags_for(self, tool):
        """`tool`'s docker flags: the internal network and the proxy address.

        Exactly three environment variables, every one of them carrying its own
        value. `-e NAME` with no `=` is what forwards a HOST value into a
        container, and no scanner container has ever been given one -- these
        are composed here from the sidecar's address, not read from the
        environment. `NO_PROXY=` is explicitly empty so no destination bypasses
        the proxy; leaving it unset would let a `no_proxy` baked into an image
        punch a hole in the allowlist.
        """
        return ["--network", self.network,
                "-e", "HTTP_PROXY=%s" % self.proxy,
                "-e", "HTTPS_PROXY=%s" % self.proxy,
                "-e", "NO_PROXY="]

    def posture_for(self, tool):
        """`tool`'s `tools-manifest.json` `network` value."""
        return posture(tool)


@contextlib.contextmanager
def session(docker_bin, tools, runner, run_id=None, max_seconds=None):
    """A per-run internal network and allowlisting proxy for `tools`.

    Yields a `Session` in every case, including failure: an egress that cannot
    be established yields one that REFUSES the online adapters rather than
    letting them fall back to the bridge. That is the whole point -- the run
    loses a scanner and says so in the manifest, exactly like an absent one, so
    certification sees the gap instead of a container with unrestricted egress.

    Teardown is in `finally` and removes only what this call created, so an
    adapter that raises (or an operator who interrupts) leaves nothing behind.
    """
    online = sorted(set(tools) & set(ALLOWLIST))
    if not online:
        yield Session()
        return
    made = {"network": None, "proxy": None}
    scratch = tempfile.mkdtemp(prefix="pano-egress-")
    try:
        try:
            established = _establish(
                docker_bin, runner, _name_token(run_id), online, scratch, made,
                max_seconds or DEFAULT_SIDECAR_SECONDS)
        except _Unavailable as exc:
            print("online egress unavailable: %s; %s did not run and is "
                  "recorded in the tools manifest as excluded_scope"
                  % (exc, ", ".join(online)), file=sys.stderr)
            established = Session(refused=online)
        yield established
    finally:
        _teardown(docker_bin, runner, made)
        shutil.rmtree(scratch, ignore_errors=True)


def _establish(docker_bin, runner, token, online, scratch, made, max_seconds):
    """Bring up the network and the sidecar, or raise `_Unavailable`.

    Order matters. The sidecar is started on the BRIDGE and attached to the
    internal network second: a container's default route comes from a network
    that has one, and an `--internal` network deliberately does not, so
    starting there first and adding the bridge afterwards leaves the proxy's
    own egress to libnetwork's gateway election rather than to this code.
    """
    _sweep(docker_bin, runner)
    network, proxy = NETWORK_PREFIX + token, PROXY_PREFIX + token
    _require(runner, [docker_bin, "network", "create", "--internal",
                      "--label", EGRESS_LABEL, network],
             "could not create the run's internal network")
    made["network"] = network
    subnet, ip = _proxy_address(_require(
        runner, [docker_bin, "network", "inspect", network],
        "could not read the run's internal network back"))
    if not subnet:
        raise _Unavailable("the run's network reported no usable IPv4 subnet")
    conf, filt = write_config(scratch, subnet, allowed_hosts(online))
    _require(runner, [docker_bin, "run", "-d", "--rm", "--name", proxy,
                      "--label", EGRESS_LABEL, "--network", "bridge"]
             + PROXY_HARDENING + PROXY_LIMITS
             + ["-v", "%s:%s:ro" % (conf, PROXY_CONF),
                "-v", "%s:%s:ro" % (filt, PROXY_FILTER),
                PROXY_IMAGE, "timeout", str(max_seconds),
                PROXY_BIN, "-d", "-c", PROXY_CONF],
             "could not start the egress proxy sidecar")
    made["proxy"] = proxy
    _require(runner, [docker_bin, "network", "connect", "--ip", ip,
                      network, proxy],
             "could not attach the sidecar to the run's internal network")
    # The sidecar is `--rm`, so a config tinyproxy refused leaves NO container
    # for this to inspect and the call fails -- which is the answer wanted.
    # Without it a proxy that died on startup would show up as every online
    # adapter merely failing, instead of as an egress that was never there.
    state = _require(runner, [docker_bin, "inspect", "--format",
                              "{{.State.Running}}", proxy],
                     "could not read the egress sidecar's state")
    if state.strip().lower() != "true":
        raise _Unavailable("the egress sidecar is not running (state %r)"
                           % state.strip()[:40])
    return Session(network=network, proxy="http://%s:%d" % (ip, PROXY_PORT),
                   tools=online)


def _sweep(docker_bin, runner):
    """Remove what a crashed earlier run left behind. Best effort.

    `prune` rather than `ls` + `rm -f`: prune touches only stopped containers
    and unattached networks, so it cannot reach a scan running beside this one
    however the label matched. A daemon too old for either verb, or a prune
    that fails, is not a reason to refuse this run its egress.
    """
    for what in ("container", "network"):
        _control(runner, [docker_bin, what, "prune", "--force",
                          "--filter", "label=%s" % EGRESS_LABEL,
                          "--filter", "until=%s" % SWEEP_AGE])


def _teardown(docker_bin, runner, made):
    """Remove the sidecar and the network this session created."""
    if made.get("proxy"):
        _control(runner, [docker_bin, "rm", "-f", made["proxy"]])
    if made.get("network"):
        _control(runner, [docker_bin, "network", "rm", made["network"]])


def _name_token(run_id):
    """A docker-legal name suffix: the run id where there is one, plus enough
    randomness that two runs of the same id cannot collide."""
    base = re.sub(r"[^A-Za-z0-9_.-]", "-", str(run_id or ""))[:48].strip("-._")
    return "%s-%s" % (base or "run", os.urandom(4).hex())


def _proxy_address(inspected):
    """`(subnet, ip)` for the sidecar from `docker network inspect` output.

    The subnet is whatever the daemon's address pool handed out -- asking
    rather than pinning one is what keeps two concurrent runs, or a host whose
    RFC1918 space is already busy, from colliding on a hard-coded range. The
    address is the first host address that is neither the network's first
    (docker's gateway) nor whatever `Gateway` actually says.
    """
    try:
        configs = json.loads(inspected)[0]["IPAM"]["Config"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None, None
    for entry in configs or ():
        if not isinstance(entry, dict):
            continue
        try:
            net = ipaddress.ip_network(str(entry.get("Subnet")), strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.num_addresses < 4:
            continue
        gateway = str(entry.get("Gateway") or "")
        for host in itertools.islice(net.hosts(), 1, 4):
            if str(host) != gateway:
                return str(net), str(host)
    return None, None


def _require(runner, cmd, why):
    """`_control`, but a non-zero exit means egress is unavailable."""
    rc, out, err = _control(runner, cmd)
    if rc != 0:
        raise _Unavailable("%s (docker exited %s%s)"
                           % (why, rc, (": " + err[:200]) if err else ""))
    return out


def _control(runner, cmd, timeout=CONTROL_TIMEOUT):
    """One docker control-plane argv, through the SAME runner seam the scanner
    dispatches use -- so a test double sees, and can refuse, every docker call
    this module makes, and the suite still launches nothing.

    Accepts both shapes the seam returns: a live `Popen` (the production
    runner) and a `CompletedProcess`-like double, the same duck-typing
    `run_tools._capture_run` does at its own call site.
    """
    try:
        proc = runner(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      timeout=timeout)
        if hasattr(proc, "communicate"):
            try:
                out, err = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
            rc = proc.returncode
        else:
            out, err, rc = proc.stdout, proc.stderr, proc.returncode
    except Exception as exc:   # noqa: BLE001 -- a docker that will not run is
        return 127, "", str(exc)    # an unavailable egress, never a crashed scan
    return rc, _text(out), _text(err)


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value if isinstance(value, str) else ""
