"""M-6: every decision is auditable; secrets never appear in logs."""

from tests.e2e.harness import Arbiter, Proxy, ProxyTestCase, http_request, requires_current, tunnel


@requires_current("structured logs")
class AuditTests(ProxyTestCase):
    def test_access_and_audit_records(self):  # E-M6-01
        policy = {"version": 1, "principals": {"demo": ["http://example.com", "https://example.com"]}}
        with Proxy(policy=policy) as proxy:
            http_request(proxy, "http://example.com/ok", ("demo", "demo-password"))
            http_request(proxy, "http://denied.test/", ("demo", "demo-password"))
            tunnel(proxy, "example.com:443", ("demo", "demo-password"))
            http_request(proxy, "http://example.com/", None)
            access = proxy.wait_for(lambda: len(proxy.access_records()) >= 4 and proxy.access_records())
            self.assertTrue(all("raw" not in r for r in access), "access log line is not valid JSON")
            by_url = {r["url"]: r for r in access}
            self.assertEqual(by_url["http://example.com/ok"]["decision"], "allowed")
            self.assertEqual(by_url["http://example.com/ok"]["principal"], "demo")
            self.assertEqual(by_url["http://denied.test/"]["decision"], "origin_not_allowed")
            self.assertEqual(by_url["http://denied.test/"]["result"], "TCP_DENIED")
            self.assertEqual(by_url["example.com:443"]["sni"], "example.com")
            audit = proxy.audit_records("decision")
            self.assertTrue({"allowed", "origin_not_allowed"} <= {a["reason"] for a in audit})
            for record in audit:
                self.assertTrue({"ts", "principal", "src", "method", "host", "port", "decision", "reason",
                                 "backend", "latency_ms"} <= set(record))

    def test_no_secrets_in_logs(self):  # E-M6-02
        arbiter = Arbiter(port=18098)
        token_file = None
        try:
            proxy = Proxy(policy_url=arbiter.url, users={"demo": "s3cret-demo-pw"})
            token_file = proxy.run_dir / "policy-token"
            token_file.write_text("arbiter-bearer-SECRET")
            proxy.extra_env["EGRESS_POLICY_TOKEN_FILE"] = str(token_file)
            with proxy:
                http_request(proxy, "http://example.com/", ("demo", "s3cret-demo-pw"))
                http_request(proxy, "http://example.com/", ("demo", "wrong-pw-SECRET"))
                self.assertEqual(arbiter.headers[-1].get("Authorization"), "Bearer arbiter-bearer-SECRET")
                for name in ("access.log", "audit.jsonl", "cache.log", "squid.stderr", "squid.stdout"):
                    path = proxy.run_dir / name
                    if path.exists():
                        text = path.read_text(errors="replace")
                        for secret in ("s3cret-demo-pw", "wrong-pw-SECRET", "arbiter-bearer-SECRET",
                                       "ZGVtbzpzM2NyZXQtZGVtby1wdw"):
                            self.assertNotIn(secret, text, f"{secret} leaked into {name}")
        finally:
            arbiter.close()
