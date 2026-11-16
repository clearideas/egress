"""M-4: Squid hardening visible to sandboxes."""

import itertools
import subprocess

from tests.e2e.harness import PYTHON, Proxy, ProxyTestCase, http_request, raw_request, requires_current, tunnel

POLICY = {"version": 1, "principals": {"demo": ["http://example.com", "https://example.com"]}}


@requires_current("hardening directives")
class HardeningTests(ProxyTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.proxy = Proxy(policy=POLICY).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()

    def test_error_responses_do_not_disclose_version(self):  # E-M4-01
        for creds, url in ((None, "http://example.com/"), (("demo", "demo-password"), "http://denied.test/")):
            r = http_request(self.proxy, url, creds)
            with self.subTest(status=r.status):
                self.assertIn(r.status, {403, 407})
                blob = (r.raw_head + r.body.decode(errors="replace")).lower()
                self.assertNotRegex(blob, r"squid/\d")
                self.assertNotIn("x-squid-error", r.headers)
                self.assertNotIn("x-cache", r.headers)
                self.assertNotIn("squid", r.headers.get("server", ""))
                self.assertNotIn("via", r.headers)

    def test_malformed_header_rejected(self):  # E-M4-02
        before = len(self.fx.http_origin.requests)
        r = raw_request(self.proxy, b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nX-Bad : value\r\n"
                                    b"Proxy-Authorization: Basic ZGVtbzpkZW1vLXBhc3N3b3Jk\r\nConnection: close\r\n\r\n")
        self.assertEqual(r.status, 400, r.raw_head)
        self.assertEqual(len(self.fx.http_origin.requests), before)

    def test_whitespace_in_uri_rejected(self):
        r = raw_request(self.proxy, b"GET http://example.com/a b HTTP/1.1\r\nHost: example.com\r\n"
                                    b"Proxy-Authorization: Basic ZGVtbzpkZW1vLXBhc3N3b3Jk\r\nConnection: close\r\n\r\n")
        self.assertIn(r.status, {400, 403})

    def test_origin_does_not_see_proxy_headers(self):
        http_request(self.proxy, "http://example.com/hdr", ("demo", "demo-password"))
        headers = {k.lower() for k in self.fx.http_origin.requests[-1]["headers"]}
        self.assertFalse(headers & {"via", "x-forwarded-for", "proxy-authorization", "forwarded"}, headers)


@requires_current("renderer")
class ConfigVariantParseTests(ProxyTestCase):  # E-M4-03
    def test_every_variant_parses(self):
        for auth, tls, lb, ttl in itertools.product(("token", "htpasswd"), ("sni", "off"), ("", "10.30.0.1/32"),
                                                    ("0", "5")):
            env = {"EGRESS_TLS_ENFORCEMENT": tls, "EGRESS_DECISION_TTL": ttl}
            if lb:
                env["EGRESS_TRUSTED_PROXY_CIDRS"] = lb
            proxy = Proxy(policy=POLICY, auth=auth, env=env)
            proxy._write_inputs()
            base = proxy._base_env()
            subprocess.run([PYTHON, "-m", "clearideas_egress.render"], env=base, check=True,
                           capture_output=True)
            result = subprocess.run(["squid", "-k", "parse", "-f", str(proxy.run_dir / "run" / "squid.conf")],
                                    capture_output=True, text=True)
            with self.subTest(auth=auth, tls=tls, lb=lb, ttl=ttl):
                self.assertEqual(result.returncode, 0, result.stderr[-2000:])
                self.assertNotRegex(result.stderr, r"(?i)(FATAL|ERROR: |Bungled|unrecognized)")
