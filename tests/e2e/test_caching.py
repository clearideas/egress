"""Decision caching is on by default (300 s per principal + origin); per-request checks still run."""

import time

from tests.e2e.harness import Arbiter, Proxy, ProxyTestCase, http_request, requires_current, signed_request
from tests.e2e.test_credentials import SECRET_A, CredentialProxy, header_values
from tests.e2e.test_signed_headers import PROFILE_ENV, RUN, arbiter_for, origin_proxy

CREDS = ("demo", "demo-password")


def counting_arbiter(port, allow=True, scope=None, methods=None, ttl=None, latency=0.0):
    state = {"allow": allow, "down": False}

    def respond(req):
        if latency:
            time.sleep(latency)
        if state["down"]:
            return 503, {"error": "unavailable"}
        answer = {"decision": "allow" if state["allow"] else "deny", "requestId": req["requestId"]}
        for key, value in (("scope", scope), ("methods", methods), ("ttl", ttl)):
            if value is not None:
                answer[key] = value(req) if callable(value) else value
        return 200, answer

    arbiter = Arbiter(port=port, respond=respond)
    arbiter.state = state
    return arbiter


@requires_current("decision caching defaults")
class DecisionCachingTests(ProxyTestCase):
    def test_origin_scope_caches_per_origin_not_per_path(self):
        arbiter = counting_arbiter(18500)
        try:
            with Proxy(policy_url=arbiter.url, env={"EGRESS_DECISION_SCOPE": "origin"}) as proxy:
                for i in range(20):
                    self.assertEqual(http_request(proxy, f"http://example.com/v1/files/{i}", CREDS).status, 200)
                self.assertEqual(len(arbiter.requests), 1, "one decision should cover the origin")
                self.assertNotIn("path", arbiter.requests[0])
                # A different method or origin is a different decision.
                http_request(proxy, "http://example.com/v1/files", CREDS, method="POST", body=b"x")
                http_request(proxy, "http://other.example/", CREDS)
                self.assertEqual(len(arbiter.requests), 3)
        finally:
            arbiter.close()

    def test_request_scope_decides_per_path(self):
        arbiter = counting_arbiter(18501)
        try:
            with Proxy(policy_url=arbiter.url, env={"EGRESS_DECISION_SCOPE": "request"}) as proxy:
                for i in range(5):
                    http_request(proxy, f"http://example.com/p/{i}?q=secret", CREDS)
                self.assertEqual(len(arbiter.requests), 5)
                self.assertEqual(arbiter.requests[0]["path"], "/p/0")  # query withheld
        finally:
            arbiter.close()

    def test_cached_allow_survives_api_outage_until_expiry(self):
        arbiter = counting_arbiter(18502, scope="http://example.com/")
        try:
            with Proxy(policy_url=arbiter.url, env={"EGRESS_POLICY_RETRIES": "1"}) as proxy:
                self.assertEqual(http_request(proxy, "http://example.com/a", CREDS).status, 200)
                arbiter.state["down"] = True
                self.assertEqual(http_request(proxy, "http://example.com/b", CREDS).status, 200)  # cached
                self.assertEqual(http_request(proxy, "http://other.example/", CREDS).status, 503)  # new decision
        finally:
            arbiter.close()

    def test_kill_switch_revokes_despite_cached_allow(self):
        arbiter = counting_arbiter(18503)
        try:
            proxy = Proxy(policy_url=arbiter.url)
            revoked = proxy.run_dir / "revoked"
            revoked.write_text("# empty\n")
            proxy.extra_env["EGRESS_REVOKED_FILE"] = str(revoked)
            with proxy:
                self.assertEqual(http_request(proxy, "http://example.com/", CREDS).status, 200)
                revoked.write_text("principal=demo\n")
                time.sleep(2.5)
                calls = len(arbiter.requests)
                r = http_request(proxy, "http://example.com/", CREDS)
                self.assertEqual(r.status, 403)
                self.assertEqual(len(arbiter.requests), calls, "the kill switch must not need the policy API")
                self.assertIn("revoked", [a["reason"] for a in proxy.audit_records("request_check")])
                revoked.write_text("")
                time.sleep(2.5)
                self.assertEqual(http_request(proxy, "http://example.com/", CREDS).status, 200)
        finally:
            arbiter.close()

    def test_kill_switch_by_identity_attribute_in_signed_mode(self):
        arbiter = Arbiter(port=18504, respond=arbiter_for())
        try:
            proxy = origin_proxy(arbiter)
            revoked = proxy.run_dir / "revoked"
            revoked.write_text("")
            proxy.extra_env["EGRESS_REVOKED_FILE"] = str(revoked)
            with proxy:
                self.assertEqual(signed_request(proxy, "GET", "https://example.com/", identity=RUN).status, 200)
                revoked.write_text(f"runnerAuthId={RUN['runnerAuthId']}\n")
                time.sleep(2.5)
                self.assertEqual(signed_request(proxy, "GET", "https://example.com/", identity=RUN).status, 403)
        finally:
            arbiter.close()

    def test_denials_expire_quickly(self):
        arbiter = counting_arbiter(18505, allow=False)
        try:
            with Proxy(policy_url=arbiter.url) as proxy:
                self.assertEqual(http_request(proxy, "http://example.com/", CREDS).status, 403)
                arbiter.state["allow"] = True  # access granted
                time.sleep(6.5)  # negative TTL 5 s + stamp granularity
                self.assertEqual(http_request(proxy, "http://example.com/", CREDS).status, 200)
        finally:
            arbiter.close()

    def test_credentials_applied_per_request_under_cache(self):
        wrapper = CredentialProxy()
        with wrapper.proxy as proxy:
            self.assertEqual(http_request(proxy, "https://other.example/v1/chat", CREDS).status, 200)  # cached allow
            self.assertEqual(http_request(proxy, "https://other.example/v1/chat?key=attacker", CREDS).status, 403)
            http_request(proxy, "https://example.com/a", CREDS)
            self.assertEqual(header_values(self.fx.tls_origin.requests[-1], "x-api-key"), [SECRET_A])
            (proxy.run_dir / "secret-a").write_text("sk-test-ROTATED-0002")
            time.sleep(2.5)
            http_request(proxy, "https://example.com/b", CREDS)  # decision still cached; key rotated
            self.assertEqual(header_values(self.fx.tls_origin.requests[-1], "x-api-key"), ["sk-test-ROTATED-0002"])


@requires_current("api-scoped approvals")
class ApiScopedApprovalTests(ProxyTestCase):
    """Default EGRESS_DECISION_SCOPE=api: the policy API sees the full URL and scopes its allow."""

    def test_prefix_scope(self):
        arbiter = counting_arbiter(18510, scope="http://example.com/v1")
        try:
            with Proxy(policy_url=arbiter.url, env={"EGRESS_HELPER_CHILDREN": "1"}) as proxy:
                self.assertEqual(http_request(proxy, "http://example.com/v1/files/2390423480?key=x", CREDS).status, 200)
                self.assertEqual(arbiter.requests[0]["url"], "http://example.com/v1/files/2390423480")
                for i in range(10):
                    self.assertEqual(http_request(proxy, f"http://example.com/v1/files/{i}", CREDS).status, 200)
                self.assertEqual(len(arbiter.requests), 1)
                http_request(proxy, "http://example.com/v1evil", CREDS)   # not under /v1
                http_request(proxy, "http://example.com/v2/x", CREDS)
                self.assertEqual([r["path"] for r in arbiter.requests[1:]], ["/v1evil", "/v2/x"])
        finally:
            arbiter.close()

    def test_exact_scope_and_methods(self):
        arbiter = counting_arbiter(18511, scope=lambda req: req["url"])
        try:
            with Proxy(policy_url=arbiter.url, env={"EGRESS_HELPER_CHILDREN": "1"}) as proxy:
                http_request(proxy, "http://example.com/v1/files/2390423480", CREDS)
                http_request(proxy, "http://example.com/v1/files/2390423480/content", CREDS)  # beneath: covered
                self.assertEqual(len(arbiter.requests), 1)
                http_request(proxy, "http://example.com/v1/files/1", CREDS)  # sibling: asked
                http_request(proxy, "http://example.com/v1/files/2390423480", CREDS, method="DELETE")  # other method
                self.assertEqual(len(arbiter.requests), 3)
        finally:
            arbiter.close()

    def test_api_ttl_shortens(self):
        arbiter = counting_arbiter(18512, scope="http://example.com/", ttl=1)
        try:
            with Proxy(policy_url=arbiter.url, env={"EGRESS_HELPER_CHILDREN": "1"}) as proxy:
                http_request(proxy, "http://example.com/a", CREDS)
                http_request(proxy, "http://example.com/b", CREDS)
                self.assertEqual(len(arbiter.requests), 1)
                time.sleep(1.5)
                http_request(proxy, "http://example.com/c", CREDS)
                self.assertEqual(len(arbiter.requests), 2)
        finally:
            arbiter.close()

    def test_dot_segments_refused_without_api_call(self):
        arbiter = counting_arbiter(18513, scope="http://example.com/")
        try:
            with Proxy(policy_url=arbiter.url) as proxy:
                before = len(self.fx.http_origin.requests)
                for path in ("/v1/%2e%2e/admin", "/v1/%2E%2e/%2e%2e/etc"):
                    self.assertEqual(http_request(proxy, f"http://example.com{path}", CREDS).status, 403)
                self.assertEqual(arbiter.requests, [])
                self.assertEqual(len(self.fx.http_origin.requests), before)
        finally:
            arbiter.close()

    def test_burst_at_run_start_shares_one_call(self):
        arbiter = counting_arbiter(18514, scope="http://example.com/v1", latency=0.5)
        try:
            with Proxy(policy_url=arbiter.url) as proxy:
                import threading
                results = []
                threads = [threading.Thread(target=lambda i=i: results.append(
                    http_request(proxy, f"http://example.com/v1/item/{i}", CREDS).status)) for i in range(100)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                self.assertEqual(results, [200] * 100)
                # one call per policy-helper process at most (default 4)
                self.assertLessEqual(len(arbiter.requests), 4, len(arbiter.requests))
        finally:
            arbiter.close()
