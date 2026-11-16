"""H-2: per-sandbox, short-lived, source-bound identity; PROXY protocol; TLS to the proxy."""

import os
import signal
import subprocess
import time

from clearideas_egress.auth import mint_token

from tests.e2e.harness import (Arbiter, HAProxy, Proxy, ProxyTestCase, http_request, raw_request,
                               requires_current, tunnel)

POLICY = {"version": 1, "principals": {"sbx-1": ["https://example.com", "http://example.com"],
                                       "sbx-2": ["https://example.com", "http://example.com"]}}


@requires_current("token authentication")
class TokenAuthTests(ProxyTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.proxy = Proxy(policy=POLICY, auth="token", env={"EGRESS_CREDENTIALS_TTL": "2"}).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()

    def _get(self, creds, source=None):
        return http_request(self.proxy, "http://example.com/", creds, source=source).status

    def test_valid_token(self):  # E-H2-01
        self.assertEqual(self._get(self.proxy.credentials("sbx-1")), 200, self.proxy.diagnostics()[-2000:])
        self.assertTrue(tunnel(self.proxy, "example.com:443", self.proxy.credentials("sbx-1")).established)

    def test_expired_token(self):  # E-H2-02
        token = mint_token(self.proxy.key, "k1", "sbx-1", ["127.0.0.0/8", "10.20.0.0/16"], 60,
                           now=int(time.time()) - 3600)
        self.assertEqual(self._get(("sbx-1", token)), 407)
        self.assertIn("expired", {r.get("reason") for r in self.proxy.audit_records("auth")})

    def test_tampered_and_unknown_key(self):
        _, token = self.proxy.credentials("sbx-1")
        tampered = token[:-2] + ("AA" if not token.endswith("AA") else "BB")
        self.assertEqual(self._get(("sbx-1", tampered)), 407)
        other_key = mint_token(os.urandom(32), "k9", "sbx-1", ["10.20.0.0/16", "127.0.0.0/8"], 60)
        self.assertEqual(self._get(("sbx-1", other_key)), 407)
        reasons = {r.get("reason") for r in self.proxy.audit_records("auth")}
        self.assertTrue({"bad_signature", "unknown_key"} <= reasons, reasons)

    def test_token_for_other_principal(self):
        _, token = self.proxy.credentials("sbx-2")
        self.assertEqual(self._get(("sbx-1", token)), 407)

    def test_source_binding_and_cache_key(self):  # E-H2-03
        creds = self.proxy.credentials("sbx-1", src=["10.20.0.7/32"])
        self.assertEqual(self._get(creds, source="10.20.0.7"), 200)
        # Immediately replay the same, just-validated credential from another sandbox address.
        self.assertEqual(self._get(creds, source="10.20.0.8"), 407)
        self.assertIn("source_not_allowed", {r.get("reason") for r in self.proxy.audit_records("auth")})

    def test_secrets_not_logged(self):  # E-M6-02 (token mode)
        creds = self.proxy.credentials("sbx-1")
        self._get(creds)
        for name in ("access.log", "audit.jsonl", "cache.log", "squid.stderr"):
            path = self.proxy.run_dir / name
            if path.exists():
                self.assertNotIn(creds[1], path.read_text(errors="replace"), name)


@requires_current("token authentication")
class KeyRevocationTests(ProxyTestCase):
    def test_key_removal_revokes_within_ttl(self):  # E-H2-04
        with Proxy(policy=POLICY, auth="token", env={"EGRESS_CREDENTIALS_TTL": "2"}) as proxy:
            creds = proxy.credentials("sbx-1")
            self.assertEqual(http_request(proxy, "http://example.com/", creds).status, 200)
            (proxy.run_dir / "keys" / "k1.key").unlink()
            time.sleep(2 + 2 + 1)  # credentialsttl + key-ring refresh + margin
            self.assertEqual(http_request(proxy, "http://example.com/", creds).status, 407)
            # Revoking the last key must not take the proxy down: reconfigure Squid so it starts
            # new auth helpers (which now find no keys) and check it keeps refusing instead of
            # aborting ("helpers are crashing too rapidly"), as it did before helpers were made
            # to deny instead of exiting.
            pid = int((proxy.run_dir / "run" / "squid.pid").read_text().split()[0])
            os.kill(pid, signal.SIGHUP)
            time.sleep(2)
            for _ in range(10):
                self.assertEqual(http_request(proxy, "http://example.com/", creds).status, 407)
            self.assertTrue(proxy.alive(), proxy.diagnostics()[-1500:])
            self.assertNotIn("FATAL", (proxy.run_dir / "cache.log").read_text())


@requires_current("policy v2 sources")
class PolicySourceTests(ProxyTestCase):
    def test_policy_sources(self):  # E-H2-06
        policy = {"version": 2, "principals": {"demo": {"sources": ["10.20.0.7/32"],
                                                        "origins": ["http://example.com"]}}}
        with Proxy(policy=policy) as proxy:
            creds = ("demo", "demo-password")
            self.assertEqual(http_request(proxy, "http://example.com/", creds, source="10.20.0.7").status, 200)
            self.assertEqual(http_request(proxy, "http://example.com/", creds, source="10.20.0.8").status, 403)


@requires_current("htpasswd mode reload")
class HtpasswdReloadTests(ProxyTestCase):
    def test_add_user_with_reconfigure(self):  # E-H2-05
        policy = {"version": 1, "principals": {"demo": ["http://example.com"], "newuser": ["http://example.com"]}}
        with Proxy(policy=policy) as proxy:
            self.assertEqual(http_request(proxy, "http://example.com/", ("newuser", "new-pw")).status, 407)
            subprocess.run(["htpasswd", "-bB", str(proxy.run_dir / "passwd"), "newuser", "new-pw"], check=True,
                           capture_output=True)
            pid = int((proxy.run_dir / "run" / "squid.pid").read_text().split()[0])
            os.kill(pid, signal.SIGHUP)  # what `squid -k reconfigure` sends
            ok = proxy.wait_for(lambda: http_request(proxy, "http://example.com/", ("newuser", "new-pw")).status == 200,
                                timeout=10)
            self.assertTrue(ok)
            self.assertTrue(proxy.alive())


@requires_current("PROXY protocol")
class ProxyProtocolTests(ProxyTestCase):
    def test_real_client_ip_through_load_balancer(self):  # E-H2-07
        arbiter = Arbiter(port=18097)
        try:
            proxy = Proxy(policy_url=arbiter.url, auth="token", token_src=["10.20.0.7/32"],
                          env={"EGRESS_TRUSTED_PROXY_CIDRS": "10.30.0.1/32"})
            with proxy:
                lb = HAProxy(proxy.port)
                try:
                    proxy.endpoint = ("10.30.0.1", lb.port)
                    creds = proxy.credentials("sbx-1")
                    r = http_request(proxy, "http://example.com/", creds, source="10.20.0.7")
                    self.assertEqual(r.status, 200, proxy.diagnostics()[-2000:])
                    self.assertEqual(arbiter.requests[-1]["sourceIp"], "10.20.0.7")
                    # The token is bound to 10.20.0.7: the LB must not make every client look the same.
                    self.assertEqual(http_request(proxy, "http://example.com/", creds, source="10.20.0.8").status, 407)
                    self.assertNotIn("10.30.0.1", [a.get("sourceIp") for a in arbiter.requests])
                finally:
                    lb.close()
                    proxy.endpoint = None
                # E-H2-08: direct connections without a PROXY header are rejected
                r = http_request(proxy, "http://example.com/", proxy.credentials("sbx-1"), source="10.20.0.7")
                self.assertNotEqual(r.status, 200)
                # E-H2-09: a client cannot forge a PROXY header (untrusted source)
                forged = (b"PROXY TCP4 10.20.0.7 10.20.0.1 40000 3128\r\n"
                          b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                self.assertNotEqual(raw_request(proxy, forged, source="10.20.0.8").status, 200)
        finally:
            arbiter.close()

    def test_tls_to_proxy_via_terminating_load_balancer(self):  # E-H2-11
        cert, key = self.fx.pki.issue("egress-lb", ["IP:10.30.0.1", "DNS:egress.test"])
        proxy = Proxy(policy=POLICY, auth="token", token_src=["10.20.0.7/32"],
                      env={"EGRESS_TRUSTED_PROXY_CIDRS": "10.30.0.1/32"})
        with proxy:
            lb = HAProxy(proxy.port, tls=(cert, key))
            try:
                user, token = proxy.credentials("sbx-1")
                result = subprocess.run(
                    ["curl", "-sS", "-o", "-", "-w", "\\n%{http_code}", "--max-time", "10",
                     "--interface", "10.20.0.7",
                     "--proxy", f"https://10.30.0.1:{lb.port}", "--proxy-cacert", str(self.fx.pki.ca),
                     "--proxy-user", f"{user}:{token}", "--cacert", str(self.fx.pki.ca),
                     "--resolve", "example.com:443:93.184.215.14", "https://example.com/"],
                    capture_output=True, text=True)
                self.assertTrue(result.stdout.strip().endswith("200"), result.stdout + result.stderr)
                self.assertIn("sni=example.com", result.stdout)
            finally:
                lb.close()
