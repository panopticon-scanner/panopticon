#!/usr/bin/env python3
"""Establish what a host actually delivers, as opposed to what it claims.

`hosts.py` is the table of claims and stays I/O-free. This module is where the
filesystem and subprocess live, so it is imported only by the driver's
pre-phase step and by setup -- never by `phases/*` on the hot path, and never
by `hosts.py` (that import would break the purity guard).

Every probe returns `(state, by, detail)`:

  state   one of hosts.PROVEN / hosts.REFUTED / hosts.UNKNOWN
  by      the probe id that produced it, or None when nothing ran
  detail  a sentence a human can act on, naming paths where paths matter

A probe that CANNOT RUN returns UNKNOWN with the reason -- never a guess, and
never `proven` by default. UNKNOWN and REFUTED are different answers: unknown
means nobody looked, refuted means we looked and the control is not there.
Confusing the two is the failure this whole spec exists to prevent.

No probe may touch live state. Anything that needs to arm, install or write
does it inside a `tempfile.TemporaryDirectory()`.
"""
import os

from scripts import dispatch, hosts

# The roles the DRIVER dispatches and therefore needs registered shells for.
# `advisor` is deliberately absent -- it is dispatched by the host, not the
# driver. Mirrors setup_flow._driver_roles, which trips loudly on drift.
DRIVER_ROLES = ("scout", "domain_panel", "domain_advisor")

REGISTERED_SHELL_TOOLS = "registered-shell-tools"


def _frontmatter_tools(path):
    """The `tools:` line of a registered shell as a list, or None.

    Deliberately a line scan rather than a YAML parse: the frontmatter is
    emitted by `dispatch.emit_host_agents` in a fixed shape, stdlib has no YAML,
    and a dependency here would violate the plan's stdlib-only constraint.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("tools:"):
                    return [t.strip() for t in line.split(":", 1)[1].split(",")
                            if t.strip()]
    except OSError:
        return None
    return None


def probe_registered_shell_tools(host, registration_dir=None):
    """Every driver role has a shell whose tools match its template exactly.

    `registration_dir` overrides the host's own, for fixtures only.
    """
    row = hosts.spec(host)
    if not row or not row.shell_format:
        return (hosts.UNKNOWN, None,
                "host %r registers no enforcement shells" % host)
    directory = registration_dir or row.registration_dir
    if not directory:
        return (hosts.UNKNOWN, None,
                "host %r has no registration directory" % host)
    faults, checked = [], 0
    for role in DRIVER_ROLES:
        role_file = dispatch.ROLE_FILES[role]
        path = os.path.join(directory,
                            dispatch.registered_agent_filename(host, role_file))
        if not os.path.isfile(path):
            faults.append("%s: no shell at %s" % (role, path))
            continue
        checked += 1
        policy = dispatch.load_template(role_file)[0]["tool_policy"]
        granted = _frontmatter_tools(path)
        if granted is None:
            faults.append("%s: shell has no `tools:` line" % role)
        elif granted != list(policy["allowed"]):
            faults.append("%s: shell grants %s, template allows %s"
                          % (role, granted, list(policy["allowed"])))
        elif set(granted) & set(policy["forbidden"] or []):
            faults.append("%s: shell grants a forbidden tool (%s)"
                          % (role, sorted(set(granted) & set(policy["forbidden"]))))
    if faults:
        return (hosts.REFUTED, REGISTERED_SHELL_TOOLS, "; ".join(faults))
    return (hosts.PROVEN, REGISTERED_SHELL_TOOLS,
            "%d/%d driver roles registered in %s; tools match their templates"
            % (checked, len(DRIVER_ROLES), directory))
