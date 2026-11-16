"""Credential injection: the proxy holds provider API keys; the sandbox only has a placeholder."""

import json
import time

from tests.e2e.harness import (Arbiter, Proxy, ProxyTestCase, http_request, requires_current, signed_request,
                               tunnel)
from tests.e2e.test_signed_headers import PROFILE_ENV, RUN, arbiter_for

CREDS = ("demo", "demo-password")
SECRET_A = "sk-test-REAL-aaaa+/bbbb=="      # includes base64 characters on purpose
SECRET_B = "sk-proj-REAL-bbbb_cccc-dddd"
POLICY = {"version": 1, "principals": {"demo": ["https://example.com", "https://other.example", "http://example.com"]}}


def header_values(request: dict, name: str) -> list[str]:
    return [value for key, value in request["headers"] if key.lower() == name.lower()]


class CredentialProxy:
    """Helper to build a proxy with a credentials file and secret files."""

    def __init__(self, *, mode="origination", env=None, policy=POLICY, auth="htpasswd", policy_url=None):
        self.proxy = Proxy(policy=None if policy_url else policy, policy_url=policy_url, auth=auth,
                           env={"EGRESS_MODE": mode, **(env or {})})
        run = self.proxy.run_dir
        (run / "secret-a").write_text(SECRET_A + "\n")
        (run / "secret-b").write_text(SECRET_B)
        rules = {"version": 1, "rules": [
            {"id": "example", "origin": "https://example.com", "header": "x-api-key", "value": "{secret}",
             "secretFile": str(run / "secret-a"), "stripHeaders": ["authorization"]},
            {"id": "other-bearer", "origin": "https://other.example", "header": "Authorization",
             "value": "Bearer {secret}", "secretFile": str(run / "secret-b"), "rejectQueryParams": ["key"]},
        ]}
        (run / "credentials.json").write_text(json.dumps(rules))
        self.proxy.extra_env["EGRESS_CREDENTIALS_FILE"] = str(run / "credentials.json")


@requires_current("credential injection")
class CredentialInjectionTests(ProxyTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.wrapper = CredentialProxy(env={"EGRESS_MODE": "both"})
        cls.proxy = cls.wrapper.proxy.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()

    def last(self, origin):
        return origin.requests[-1]

    def test_placeholder_replaced_and_other_auth_stripped(self):
        r = http_request(self.proxy, "https://example.com/v1/messages", CREDS, method="POST", body=b"{}",
                         extra_headers="x-api-key: sandbox-placeholder\r\nAuthorization: Bearer attacker-token\r\n")
        self.assertEqual(r.status, 200, self.proxy.diagnostics()[-2000:])
        request = self.last(self.fx.tls_origin)
        self.assertEqual(header_values(request, "x-api-key"), [SECRET_A])
        self.assertEqual(header_values(request, "authorization"), [])

    def test_sandbox_cannot_substitute_its_own_key(self):
        http_request(self.proxy, "https://example.com/v1/files", CREDS, method="POST", body=b"exfil",
                     extra_headers="x-api-key: sk-ATTACKER-key\r\nX-Api-Key: sk-ATTACKER-2\r\n")
        self.assertEqual(header_values(self.last(self.fx.tls_origin), "x-api-key"), [SECRET_A])

    def test_missing_placeholder_still_injected(self):
        http_request(self.proxy, "https://example.com/v1/models", CREDS)
        self.assertEqual(header_values(self.last(self.fx.tls_origin), "x-api-key"), [SECRET_A])

    def test_bearer_template(self):
        r = http_request(self.proxy, "https://other.example/v1/chat", CREDS,
                         extra_headers="Authorization: Bearer placeholder\r\n")
        self.assertEqual(r.status, 200)
        self.assertEqual(header_values(self.last(self.fx.tls_origin2), "authorization"), [f"Bearer {SECRET_B}"])

    def test_query_parameter_credentials_refused(self):
        before = len(self.fx.tls_origin2.requests)
        r = http_request(self.proxy, "https://other.example/v1/chat?alt=json&KEY=attacker-key", CREDS)
        self.assertEqual(r.status, 403)
        self.assertEqual(len(self.fx.tls_origin2.requests), before)
        self.assertIn("credential_query_param", [a["reason"] for a in self.proxy.audit_records("request_check")])

    def test_connect_to_managed_origin_refused(self):
        result = tunnel(self.proxy, "example.com:443", CREDS)
        self.assertFalse(result.established, result)
        self.assertIn("credential_requires_origination",
                      [a["reason"] for a in self.proxy.audit_records("request_check")])

    def test_unmanaged_requests_untouched(self):
        http_request(self.proxy, "http://example.com/plain", CREDS, extra_headers="x-api-key: keep-me\r\n")
        self.assertEqual(self.fx.http_origin.requests[-1]["headers"].get("x-api-key"), "keep-me")

    def test_secrets_never_logged(self):
        http_request(self.proxy, "https://example.com/v1/messages", CREDS)
        http_request(self.proxy, "https://other.example/v1/chat", CREDS)
        time.sleep(0.3)
        for name in ("access.log", "audit.jsonl", "cache.log", "squid.stderr", "squid.stdout"):
            text = (self.proxy.run_dir / name).read_text(errors="replace") if (self.proxy.run_dir / name).exists() else ""
            for secret in (SECRET_A, SECRET_B, "REAL-"):
                self.assertNotIn(secret, text, f"secret leaked into {name}")
        self.assertNotIn("reserved for Squid use", (self.proxy.run_dir / "cache.log").read_text())
        self.assertNotIn(SECRET_A, (self.proxy.run_dir / "run" / "squid.conf").read_text())
        audit = [a for a in self.proxy.audit_records("request_check") if a.get("credential")]
        self.assertTrue(audit and {a["credential"] for a in audit} <= {"example", "other-bearer"})


@requires_current("credential injection")
class CredentialLifecycleTests(ProxyTestCase):
    def test_rotation_and_missing_secret(self):
        wrapper = CredentialProxy()
        with wrapper.proxy as proxy:
            http_request(proxy, "https://example.com/a", CREDS)
            self.assertEqual(header_values(self.fx.tls_origin.requests[-1], "x-api-key"), [SECRET_A])
            (proxy.run_dir / "secret-a").write_text("sk-test-ROTATED-0001")
            time.sleep(2.5)
            http_request(proxy, "https://example.com/b", CREDS)
            self.assertEqual(header_values(self.fx.tls_origin.requests[-1], "x-api-key"), ["sk-test-ROTATED-0001"])
            (proxy.run_dir / "secret-a").unlink()
            time.sleep(2.5)
            before = len(self.fx.tls_origin.requests)
            r = http_request(proxy, "https://example.com/c", CREDS)
            self.assertEqual(r.status, 503)  # temporary (e.g. mid-rotation): clients retry
            self.assertEqual(r.headers.get("retry-after"), "1")
            self.assertEqual(len(self.fx.tls_origin.requests), before)
            self.assertIn("credential_unavailable", [a["reason"] for a in proxy.audit_records("request_check")])

    def test_injection_survives_decision_cache(self):
        wrapper = CredentialProxy(env={"EGRESS_DECISION_TTL": "30"})
        with wrapper.proxy as proxy:
            for path in ("/same", "/same", "/same"):
                http_request(proxy, f"https://example.com{path}", CREDS)
                self.assertEqual(header_values(self.fx.tls_origin.requests[-1], "x-api-key"), [SECRET_A])

    def test_connect_mode_rejects_credentials_file(self):
        wrapper = CredentialProxy(mode="connect")
        with self.assertRaises(RuntimeError) as caught:
            wrapper.proxy.start()
        self.assertIn("EGRESS_CREDENTIALS_FILE requires", str(caught.exception))

    def test_with_signed_headers(self):
        """The egress-helper pattern: signed identity + policy API + injected provider key."""
        arbiter = Arbiter(port=18210, respond=arbiter_for(allowed_hosts=("example.com",)))
        try:
            wrapper = CredentialProxy(auth="signed-headers", policy_url=arbiter.url,
                                      env={**PROFILE_ENV, "EGRESS_MAX_CONN_PER_CLIENT": "0"})
            with wrapper.proxy as proxy:
                r = signed_request(proxy, "POST", "https://example.com/v1/messages", identity=RUN,
                                   body=b"{}", extra="x-api-key: placeholder\r\n")
                self.assertEqual(r.status, 200, proxy.diagnostics()[-2000:])
                request = self.fx.tls_origin.requests[-1]
                self.assertEqual(header_values(request, "x-api-key"), [SECRET_A])
                self.assertFalse([k for k, _ in request["headers"] if k.lower().startswith("x-acme")])
        finally:
            arbiter.close()
