"""#1645: the egress allowlist table and the proxy config generated from it.

`--network none` is added for every adapter EXCEPT the `ONLINE_ONLY` ones, and
for those nothing took its place: Docker attached them to its default bridge,
i.e. everything reachable from the runner's network, private services included.
`--online` decided WHETHER pip-audit/npm-audit ran, never WHERE they could
connect.

This module covers the half that is pure data: one table mapping each online
adapter to the advisory endpoints its argv actually reaches, and the tinyproxy
configuration rendered from it. The table is read by BOTH the config writer and
the manifest disclosure, so what the report claims and what the proxy enforces
cannot drift -- and the drift is what a test can prove without a daemon.

No docker anywhere here: every assertion is over strings this module composes.
"""
import os
import re
import unittest

import scripts.tools.egress as egress
from scripts.tools import ONLINE_ONLY


class TestAllowlistTable(unittest.TestCase):
    """Ruling 4: one table, and every ONLINE_ONLY adapter has an entry."""

    def test_every_online_only_adapter_has_an_allowlist_entry(self):
        # An adapter admitted by --online with no entry here would either run
        # with an EMPTY allowlist (every request denied, a silent coverage
        # loss) or have to be let onto the bridge, which is the finding.
        self.assertEqual(set(egress.ALLOWLIST), set(ONLINE_ONLY))

    def test_the_table_names_no_adapter_that_is_not_online_only(self):
        # The other direction: an offline adapter with an entry here would
        # advertise an egress path it must never be given.
        self.assertEqual(set(egress.ALLOWLIST) - set(ONLINE_ONLY), set())

    def test_every_entry_is_a_bare_hostname(self):
        # The filter patterns are matched against the request host -- the whole
        # string, fnmatch-style. A scheme, a path, a port or a wildcard here
        # would either never match (silent coverage loss) or widen the
        # allowlist past the endpoint it names.
        bare = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
        offenders = [(tool, host) for tool, hosts in egress.ALLOWLIST.items()
                     for host in hosts if not bare.match(host)]
        self.assertEqual(offenders, [], "not a bare hostname: %s" % (offenders,))

    def test_pip_audit_reaches_the_python_index_and_nothing_else(self):
        self.assertEqual(egress.ALLOWLIST["pip-audit"],
                         ("api.osv.dev", "files.pythonhosted.org", "pypi.org"))

    def test_npm_audit_reaches_the_npm_registry_and_nothing_else(self):
        self.assertEqual(egress.ALLOWLIST["npm-audit"], ("registry.npmjs.org",))

    def test_allowed_hosts_is_the_sorted_union_of_the_selected_adapters(self):
        self.assertEqual(egress.allowed_hosts(["npm-audit", "pip-audit"]),
                         ["api.osv.dev", "files.pythonhosted.org",
                          "pypi.org", "registry.npmjs.org"])

    def test_allowed_hosts_ignores_an_adapter_with_no_entry(self):
        self.assertEqual(egress.allowed_hosts(["semgrep"]), [])

    def test_the_posture_string_names_the_allowlist_the_proxy_enforces(self):
        # The manifest's `network` value and the filter file are rendered from
        # the SAME table, which is the whole point of having one.
        self.assertEqual(egress.posture("npm-audit"),
                         "proxied:registry.npmjs.org")
        self.assertEqual(
            egress.posture("pip-audit"),
            "proxied:api.osv.dev,files.pythonhosted.org,pypi.org")


class TestProxyImagePin(unittest.TestCase):
    """The sidecar is a third-party image pulled at scan time; a tag would let
    the registry hand this run a different proxy tomorrow."""

    def test_the_proxy_image_is_pinned_by_digest(self):
        self.assertRegex(egress.PROXY_IMAGE,
                         r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")

    def test_the_pin_names_a_specific_repository(self):
        self.assertTrue(egress.PROXY_IMAGE.startswith("docker.io/kalaksi/tinyproxy@"),
                        egress.PROXY_IMAGE)


class TestRenderedConfig(unittest.TestCase):
    """The generated tinyproxy config, directive by directive.

    No real docker runs in this suite, so the configuration is asserted against
    tinyproxy 1.11.3's documented behaviour rather than observed: each
    directive below is quoted from `tinyproxy.conf(5)` at tag 1.11.3.
    """

    HOSTS = ["api.osv.dev", "pypi.org"]
    SUBNET = "172.28.0.0/16"

    def _render(self):
        return egress.render_config(self.SUBNET, self.HOSTS)

    def test_the_filter_list_is_exactly_the_allowlisted_hosts(self):
        _conf, filt = self._render()
        self.assertEqual([line for line in filt.splitlines() if line.strip()],
                         self.HOSTS)

    def test_the_filter_is_a_whitelist_not_a_blacklist(self):
        # tinyproxy.conf(5), FilterDefaultDeny: "if set to `No` the Filter list
        # acts as a blacklist, if set to `Yes` as a whitelist".
        conf, _filt = self._render()
        self.assertIn("FilterDefaultDeny Yes", conf)

    def test_the_filter_file_is_named_at_the_mount_point(self):
        conf, _filt = self._render()
        self.assertIn('Filter "%s"' % egress.PROXY_FILTER, conf)

    def test_patterns_are_matched_literally_not_as_regular_expressions(self):
        # FilterType fnmatch: `pypi.org` matches that host and nothing else.
        # Under the default `bre` the same string is a regex whose `.` matches
        # any character, so `pypixorg` would be allowed too.
        conf, _filt = self._render()
        self.assertIn("FilterType fnmatch", conf)

    def test_the_sidecar_accepts_only_the_run_internal_subnet(self):
        # tinyproxy.conf(5), Allow/Deny: "If there are no `Allow` or `Deny`
        # lines, then all clients are allowed. Otherwise, the default action is
        # to deny access." The sidecar sits on the bridge too, so without this
        # it would be an open proxy to the allowlist for anything on the host.
        conf, _filt = self._render()
        self.assertIn("Allow %s" % self.SUBNET, conf)

    def test_connect_is_confined_to_https(self):
        # ConnectPort: "If no `ConnectPort` line is found, then all ports are
        # allowed" -- i.e. CONNECT to any port on an allowlisted host.
        conf, _filt = self._render()
        self.assertIn("ConnectPort 443", conf)
        self.assertEqual(len(re.findall(r"^ConnectPort ", conf, re.M)), 1)

    def test_the_proxy_listens_on_the_documented_port(self):
        conf, _filt = self._render()
        self.assertIn("Port %d" % egress.PROXY_PORT, conf)

    def test_no_directive_is_indented_or_duplicated(self):
        conf, _filt = self._render()
        directives = [name for name, _sep, _rest in
                      (line.partition(" ") for line in conf.splitlines())
                      if name and not name.startswith("#")]
        self.assertEqual(sorted(directives), sorted(set(directives)),
                         "a repeated directive: tinyproxy takes the last one")
        self.assertEqual([d for d in directives if d != d.lstrip()], [])

    def test_an_empty_allowlist_is_refused_rather_than_rendered(self):
        # A config with FilterDefaultDeny and no rules denies everything, which
        # would read in the manifest as "proxied" while auditing nothing.
        with self.assertRaises(ValueError):
            egress.render_config(self.SUBNET, [])


class TestConfigFilesOnDisk(unittest.TestCase):
    """The two files are mounted into a container that runs as an unprivileged
    image user, and they are controller artifacts -- not captures."""

    def test_the_files_are_readable_by_the_image_user(self):
        # The sidecar image runs as uid 57981; a 0600 file from mkdtemp is
        # unreadable there and tinyproxy exits before it binds.
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        conf_path, filter_path = egress.write_config(d, "10.0.0.0/24",
                                                     ["pypi.org"])
        for path in (conf_path, filter_path):
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o644, path)

    def test_the_files_land_where_the_caller_asked_and_nowhere_else(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        paths = egress.write_config(d, "10.0.0.0/24", ["pypi.org"])
        for path in paths:
            self.assertEqual(os.path.dirname(path), d)


if __name__ == "__main__":
    unittest.main()
