"""Allowed destinations the proxy cannot use get a clear, attributable answer.

With SNI enforcement, Squid answers CONNECT with 200 before it connects upstream. Before this change
an allowed name that did not resolve made Squid write a plain-text 503 into the client's TLS
handshake, so clients saw "wrong version number" / SEC_E_INVALID_TOKEN with nothing pointing at the
cause. Now the destination check refuses it up front: the client gets the proxy's error certificate
(as for every other denial) with a 503 inside, and the access log says ``"destination":"unresolved"``.
"""

import time

from tests.e2e.harness import ORIGIN_V4, Proxy, ProxyTestCase, http_request, tunnel, unique

CREDS = ("demo", "demo-password")


class DestinationFeedbackTests(ProxyTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.fx.dns.set("internal-only.example", ["10.0.0.5"])
        cls.fx.dns.set("closed-port.example", ["93.184.215.17"])  # nothing listens there
        cls.unresolvable = unique("nxdomain") + ".example"
        origins = ["https://example.com", "https://internal-only.example", "https://closed-port.example",
                   f"https://{cls.unresolvable}", f"http://{cls.unresolvable}"]
        cls.proxy = Proxy(policy={"version": 1, "principals": {"demo": origins}}, users={"demo": CREDS[1]}).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()

    def records(self, url: str, **fields: str) -> list[dict]:
        deadline = time.monotonic() + 5  # Squid writes the record after answering
        while True:
            matches = [r for r in self.proxy.access_records()
                       if r.get("url") == url and all(r.get(k) == v for k, v in fields.items())]
            if matches or time.monotonic() > deadline:
                return matches
            time.sleep(0.1)

    def record(self, url: str) -> dict:
        matches = self.records(url)
        self.assertTrue(matches, f"no access log record for {url}")
        return matches[-1]

    def test_unresolvable_connect_gets_proxy_error_not_garbage(self):
        before = self.fx.tls_origin.connections
        result = tunnel(self.proxy, f"{self.unresolvable}:443", CREDS)
        self.assertEqual(result.outcome, "denied_in_tls", result)
        self.assertEqual(result.inner_status, 503, result)
        record = self.record(f"{self.unresolvable}:443")
        self.assertEqual((record["result"], record["destination"]), ("TCP_DENIED", "unresolved"), record)
        self.assertEqual(self.fx.tls_origin.connections, before)

    def test_unresolvable_plain_http_is_503(self):
        response = http_request(self.proxy, f"http://{self.unresolvable}/", CREDS)
        self.assertEqual(response.status, 503)
        self.assertEqual(self.record(f"http://{self.unresolvable}/")["destination"], "unresolved")

    def test_internal_address_is_forbidden(self):
        result = tunnel(self.proxy, "internal-only.example:443", CREDS)
        self.assertEqual((result.outcome, result.inner_status), ("denied_in_tls", 403), result)
        record = self.record("internal-only.example:443")
        self.assertEqual((record["result"], record["destination"]), ("TCP_DENIED", "forbidden"), record)

    def test_allowed_and_reachable_is_ok(self):
        result = tunnel(self.proxy, "example.com:443", CREDS)
        self.assertTrue(result.established, result)
        tunnels = self.records("example.com:443", result="TCP_TUNNEL")
        self.assertEqual(tunnels[-1]["destination"], "ok")
        self.assertEqual(tunnels[-1]["server"], ORIGIN_V4)

    def test_unreachable_destination_is_logged(self):
        # Connection failures happen after the splice; Squid can only close the connection. The
        # access log is the place to look: 503, the address tried, destination "ok" (it resolved).
        result = tunnel(self.proxy, "closed-port.example:443", CREDS)
        self.assertEqual(result.outcome, "terminated", result)
        records = self.records("closed-port.example:443", status="503")
        self.assertTrue(records, self.proxy.access_records()[-3:])
        self.assertEqual(records[-1]["server"], "93.184.215.17")

    def test_policy_denial_is_not_resolved(self):
        label = unique("not-allowed")
        result = tunnel(self.proxy, f"{label}.example:443", CREDS)
        self.assertEqual(result.outcome, "denied_in_tls", result)
        self.assertEqual(self.record(f"{label}.example:443")["destination"], "-")
        self.assertNoDNS(label)
