"""L-3 (schemes/methods), L-9 (IPv6 literals), L-4 (username case), M-2 (numeric hosts vs arbiter)."""

from tests.e2e.harness import (ORIGIN_V6, Arbiter, Proxy, ProxyTestCase, http_request, raw_request,
                               requires_current, tunnel)


class SchemeTests(ProxyTestCase):  # E-L3
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.proxy = Proxy(policy={"version": 1, "principals": {"demo": [
            "https://example.com", "http://example.com", "http://example.com:443"]}}).start()
        cls.creds = ("demo", "demo-password")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()

    def test_non_http_schemes_denied(self):
        before = len(self.fx.http_origin.requests)
        for url in ("ftp://example.com:80/", "whois://example.com:80/", "gopher://example.com:80/",
                    "https://example.com/"):
            with self.subTest(url=url):
                r = http_request(self.proxy, url, self.creds)
                self.assertIn(r.status, {400, 403, 501}, r.raw_head)
        self.assertEqual(len(self.fx.http_origin.requests), before)

    def test_plain_http_and_connect_still_work(self):
        self.assertEqual(http_request(self.proxy, "http://example.com/", self.creds).status, 200)
        self.assertTrue(tunnel(self.proxy, "example.com:443", self.creds).established)


@requires_current("policy v2 method restrictions")
class MethodPolicyTests(ProxyTestCase):
    def test_method_restriction(self):
        policy = {"version": 2, "principals": {"demo": {"origins": [
            {"origin": "http://example.com", "methods": ["GET", "HEAD"]}]}}}
        with Proxy(policy=policy) as proxy:
            creds = ("demo", "demo-password")
            self.assertEqual(http_request(proxy, "http://example.com/", creds).status, 200)
            before = len(self.fx.http_origin.requests)
            r = http_request(proxy, "http://example.com/upload", creds, method="POST", body=b"secret" * 100)
            self.assertEqual(r.status, 403)
            self.assertEqual(len(self.fx.http_origin.requests), before)
            self.assertIn("method_not_allowed", [a.get("reason") for a in proxy.audit_records("decision")])


class IPv6LiteralTests(ProxyTestCase):  # E-L9
    def test_ipv6_literal_allowed_when_listed(self):
        policy = {"version": 1, "principals": {"demo": [f"https://[{ORIGIN_V6}]"]}}
        with Proxy(policy=policy) as proxy:
            result = tunnel(proxy, f"[{ORIGIN_V6}]:443", ("demo", "demo-password"), sni=None)
            self.assertTrue(result.established, f"{result} {proxy.diagnostics()[-1500:]}")

    def test_ipv6_literal_denied_when_not_listed(self):
        with Proxy(policy={"version": 1, "principals": {"demo": ["https://example.com"]}}) as proxy:
            self.assertFalse(tunnel(proxy, f"[{ORIGIN_V6}]:443", ("demo", "demo-password"), sni=None).established)


@requires_current("casesensitive on")
class UsernameCaseTests(ProxyTestCase):  # E-H2-10
    def test_usernames_are_case_sensitive(self):
        policy = {"version": 1, "principals": {"Demo": ["http://example.com"], "demo": []}}
        with Proxy(policy=policy, users={"Demo": "upper-pw", "demo": "lower-pw"}) as proxy:
            self.assertEqual(http_request(proxy, "http://example.com/", ("Demo", "upper-pw")).status, 200)
            self.assertEqual(http_request(proxy, "http://example.com/", ("demo", "lower-pw")).status, 403)
            self.assertEqual(http_request(proxy, "http://example.com/", ("DEMO", "upper-pw")).status, 407)


class NumericHostArbiterTests(ProxyTestCase):  # E-M2-01
    def test_numeric_hosts_never_reach_arbiter(self):
        arbiter = Arbiter(port=18081, respond=lambda req: (200, {"decision": "allow", "requestId": req.get("requestId")}))
        try:
            with Proxy(policy_url=arbiter.url) as proxy:
                creds = ("demo", "demo-password")
                for host in ("0xa9fea9fe", "169.254.43518", "2852039166", "127.1", "0177.0.0.1"):
                    with self.subTest(host=host):
                        self.assertFalse(tunnel(proxy, f"{host}:443", creds, sni=None).established)
                        self.assertNotEqual(http_request(proxy, f"http://{host}/", creds).status, 200)
                seen = [r.get("host") for r in arbiter.requests]
                for bad in ("0xa9fea9fe", "169.254.43518", "2852039166", "127.1", "0177.0.0.1"):
                    self.assertNotIn(bad, seen, f"arbiter was asked about ambiguous host {bad}")
                self.assertNotReached("169.254.169.254")
        finally:
            arbiter.close()
