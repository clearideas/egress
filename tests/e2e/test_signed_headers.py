"""Signed per-request identity headers + proxy-originated TLS (the sandbox egress-helper model).

The sandbox sends plain HTTP (absolute-form https:// URLs) with identity headers signed
by a per-run key; the proxy verifies the signature against the actual destination, asks
the policy API (which checks the run is still active), strips the identity headers and
originates TLS itself. Most tests use a three-attribute custom profile (X-Acme-* headers)
to prove the scheme is configuration, not code; one test covers the default profile.
"""

import socket
import time

from clearideas_egress.signing import derive_run_key

from tests.e2e.harness import (PROXY_IP, Arbiter, Proxy, ProxyTestCase, RedisServer, connect, http_request,
                               raw_request, requires_current, signed_headers, signed_request, tunnel, unique)

PROFILE_ENV = {"EGRESS_SIGNED_IDENTITY": "jobId=X-Acme-Job-Id,runnerId=X-Acme-Runner-Id,runnerAuthId=X-Acme-Runner-Auth-Id",
               "EGRESS_SIGNED_PRINCIPAL": "runnerId", "EGRESS_SIGNED_HEADER_PREFIX": "X-Acme-"}
RUN = {"jobId": "job-7f3a", "runnerId": "runner-42", "runnerAuthId": "auth-9c1e"}
OTHER_RUN = {"jobId": "job-8b2d", "runnerId": "runner-43", "runnerAuthId": "auth-0d2f"}


def arbiter_for(allowed_hosts=("example.com",), inactive=()):
    def respond(req):
        identity = req.get("identity") or {}
        if identity.get("runnerAuthId") in inactive:
            return 200, {"decision": "deny", "reason": "run_inactive", "requestId": req["requestId"]}
        allowed = req["host"] in allowed_hosts
        return 200, {"decision": "allow" if allowed else "deny", "requestId": req["requestId"]}
    return respond


def origin_proxy(arbiter, **env):
    settings = {"EGRESS_MODE": "origination", "EGRESS_MAX_CONN_PER_CLIENT": "0", **PROFILE_ENV}
    settings.update(env)
    return Proxy(policy_url=arbiter.url, auth="signed-headers", env=settings)


@requires_current("signed-header identity")
class SignedOriginationTests(ProxyTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.arbiter = Arbiter(port=18200, respond=arbiter_for(inactive=("auth-ended",)))
        cls.proxy = origin_proxy(cls.arbiter).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()
        cls.arbiter.close()

    def reasons(self):
        return [r["reason"] for r in self.proxy.audit_records("signature")]

    def test_valid_request_end_to_end(self):
        url = "https://example.com/v1/messages?beta=true&key=SECRET-QUERY"
        r = signed_request(self.proxy, "POST", url, identity=RUN, body=b'{"model":"x"}')
        self.assertEqual(r.status, 200, self.proxy.diagnostics()[-2000:])
        self.assertIn(b"sni=example.com", r.body)  # the proxy originated TLS to the real origin
        # The arbiter received the verified identity, the real scheme and the path without its query.
        request = self.arbiter.requests[-1]
        self.assertEqual(request["identity"], RUN)
        self.assertEqual((request["method"], request["scheme"], request["host"], request["port"]),
                         ("POST", "https", "example.com", 443))
        self.assertEqual(request["url"], "https://example.com/v1/messages")  # full URL, query withheld
        self.assertEqual(request["principal"], "runner-42")
        # Logs name the runner and never contain the query string.
        access = self.proxy.wait_for(lambda: [a for a in self.proxy.access_records()
                                              if a.get("method") == "POST" and a.get("status") == "200"
                                              and "v1%2Fmessages" in a.get("url", "").replace("/", "%2F")])
        self.assertEqual(access[-1]["principal"], "runner-42")
        for name in ("access.log", "audit.jsonl", "cache.log"):
            self.assertNotIn("SECRET-QUERY", (self.proxy.run_dir / name).read_text(errors="replace"), name)

    def test_identity_headers_are_stripped_upstream(self):
        # The TLS origin echoes nothing about headers, so use the plain HTTP origin to inspect them.
        r = signed_request(self.proxy, "GET", "http://example.com/inspect", identity=RUN)
        self.assertEqual(r.status, 200)
        seen = {k.lower() for k in self.fx.http_origin.requests[-1]["headers"]}
        self.assertFalse({h for h in seen if h.startswith("x-acme")}, seen)

    def test_connect_is_refused_in_origination_mode(self):
        headers = signed_headers(self.proxy, "CONNECT", "example.com:443", identity=RUN)
        extra = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        r = raw_request(self.proxy, f"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n{extra}\r\n".encode())
        self.assertEqual(r.status, 403)

    def test_tampering_is_rejected(self):
        url = "https://example.com/v1/messages"
        cases = {}
        good = signed_headers(self.proxy, "POST", url, identity=RUN)
        sig = good["X-Acme-Signature"]
        cases["bad_signature"] = {**good, "X-Acme-Signature": sig[:-3] + ("AAA" if not sig.endswith("AAA") else "BBB")}
        cases["bad_signature "] = {**good, "X-Acme-Job-Id": "job-other"}  # claim another job
        cases["bad_signature  "] = {**good, "X-Acme-Runner-Auth-Id": OTHER_RUN["runnerAuthId"]}
        other_key = derive_run_key(self.proxy.signing_key, OTHER_RUN)
        cases["bad_signature   "] = signed_headers(self.proxy, "POST", url, identity=RUN, run_key=other_key)
        cases["unknown_key"] = signed_headers(self.proxy, "POST", url, identity=RUN, kid="m9")
        cases["stale_timestamp"] = signed_headers(self.proxy, "POST", url, identity=RUN, timestamp=int(time.time()) - 120)
        cases["stale_timestamp "] = signed_headers(self.proxy, "POST", url, identity=RUN, timestamp=int(time.time()) + 120)
        cases["missing_header"] = {k: v for k, v in good.items() if k != "X-Acme-Nonce"}
        cases["malformed_signature"] = {**good, "X-Acme-Signature": "v2." + sig[3:]}
        before = len(self.arbiter.requests)
        for expected, headers in cases.items():
            with self.subTest(case=expected.strip()):
                r = signed_request(self.proxy, "POST", url, headers)
                self.assertEqual(r.status, 403)
                self.assertEqual(self.reasons()[-1], expected.strip())
        self.assertEqual(len(self.arbiter.requests), before, "unverified requests must not reach the policy API")

    def test_duplicate_identity_header_rejected(self):
        url = "https://example.com/v1/messages"
        headers = signed_headers(self.proxy, "GET", url, identity=RUN)
        r = signed_request(self.proxy, "GET", url, headers, extra="X-Acme-Runner-Id: runner-evil\r\n")
        self.assertEqual(r.status, 403)
        self.assertEqual(self.reasons()[-1], "invalid_identity")

    def test_signature_is_bound_to_the_destination(self):
        signed_for = signed_headers(self.proxy, "POST", "https://example.com/v1/messages", identity=RUN)
        for method, url in [("POST", "https://example.com/v1/files"),      # other path
                            ("POST", "https://example.com/v1/messages?x"),  # other query
                            ("GET", "https://example.com/v1/messages"),     # other method
                            ("POST", "http://example.com/v1/messages"),     # other scheme
                            ("POST", "https://other.example/v1/messages"),  # other host
                            ("POST", "https://example.com:8443/v1/messages")]:
            with self.subTest(method=method, url=url):
                r = signed_request(self.proxy, method, url, dict(signed_for))
                self.assertEqual(r.status, 403)
        self.assertTrue(all(reason == "bad_signature" for reason in self.reasons()[-5:]), self.reasons()[-6:])

    def test_unsigned_requests_never_resolve_names(self):  # C-1 holds in this mode
        label = unique("signed-c1")
        r = http_request(self.proxy, f"https://{label}.attacker.test/", None)
        self.assertEqual(r.status, 403)
        forged = signed_headers(self.proxy, "GET", f"https://{label}.attacker.test/", identity=RUN,
                                run_key=b"\x00" * 32)
        self.assertEqual(signed_request(self.proxy, "GET", f"https://{label}.attacker.test/", forged).status, 403)
        self.assertNoDNS(label)

    def test_finished_run_is_denied_by_policy_api(self):
        ended = {"jobId": "job-done", "runnerId": "runner-done", "runnerAuthId": "auth-ended"}
        r = signed_request(self.proxy, "GET", "https://example.com/", identity=ended)
        self.assertEqual(r.status, 403)
        self.assertEqual(self.arbiter.requests[-1]["identity"]["runnerAuthId"], "auth-ended")
        self.assertIn("arbiter:run_inactive", [a["reason"] for a in self.proxy.audit_records("decision")])

    def test_sandbox_supplied_authorization_passes_through(self):
        # Provider API keys currently live in the sandbox; they are forwarded unchanged (never logged).
        r = signed_request(self.proxy, "GET", "http://example.com/auth-check", identity=RUN,
                           extra="Authorization: Bearer sk-sandbox-key\r\n")
        self.assertEqual(r.status, 200)
        self.assertEqual(self.fx.http_origin.requests[-1]["headers"].get("Authorization"), "Bearer sk-sandbox-key")
        for name in ("access.log", "audit.jsonl", "cache.log"):
            self.assertNotIn("sk-sandbox-key", (self.proxy.run_dir / name).read_text(errors="replace"))

    def test_many_connections_from_one_gateway_address(self):
        # Tunnel deployments: every sandbox shares the gateway's source address (maxconn disabled).
        held = []
        try:
            for _ in range(80):
                s = socket.create_connection((PROXY_IP, self.proxy.port), timeout=5)
                held.append(s)
            r = signed_request(self.proxy, "GET", "https://example.com/", identity=RUN)
            self.assertEqual(r.status, 200)
        finally:
            for s in held:
                s.close()

    def test_request_body_limit_applies(self):
        with origin_proxy(self.arbiter, EGRESS_REQUEST_BODY_MAX_SIZE="64 KB") as proxy:
            r = signed_request(proxy, "POST", "https://example.com/upload", identity=RUN, body=b"x" * 200_000)
            self.assertEqual(r.status, 413)


@requires_current("signed-header identity")
class ReplayTests(ProxyTestCase):
    URL = "https://example.com/v1/messages"

    def test_without_nonce_store_only_identical_replay_is_possible(self):
        arbiter = Arbiter(port=18201, respond=arbiter_for())
        try:
            with origin_proxy(arbiter) as proxy:
                headers = signed_headers(proxy, "POST", self.URL, identity=RUN)
                self.assertEqual(signed_request(proxy, "POST", self.URL, dict(headers)).status, 200)
                # Documented: without Redis an identical request can be repeated inside the window...
                self.assertEqual(signed_request(proxy, "POST", self.URL, dict(headers)).status, 200)
                # ...but never redirected anywhere else.
                self.assertEqual(signed_request(proxy, "POST", "https://example.com/v1/files", dict(headers)).status, 403)
        finally:
            arbiter.close()

    def test_redis_blocks_replay_across_replicas(self):
        arbiter = Arbiter(port=18202, respond=arbiter_for())
        redis = RedisServer()
        try:
            env = {"EGRESS_NONCE_REDIS_URL": redis.url}
            with origin_proxy(arbiter, **env) as replica_a, origin_proxy(arbiter, **env) as replica_b:
                replica_b.signing_key = replica_a.signing_key  # same master key on every replica
                (replica_b.run_dir / "signing" / "m1.key").write_bytes(
                    (replica_a.run_dir / "signing" / "m1.key").read_bytes())
                headers = signed_headers(replica_a, "POST", self.URL, identity=RUN)
                self.assertEqual(signed_request(replica_a, "POST", self.URL, dict(headers)).status, 200)
                time.sleep(2.5)  # let replica B's key ring pick up the shared master key
                self.assertEqual(signed_request(replica_a, "POST", self.URL, dict(headers)).status, 403)  # replay: final
                self.assertEqual(signed_request(replica_b, "POST", self.URL, dict(headers)).status, 403)
                self.assertIn("nonce_replayed", [r["reason"] for r in replica_b.audit_records("signature")])
                # Fresh nonces keep working on both replicas.
                self.assertEqual(signed_request(replica_b, "POST", self.URL, identity=RUN).status, 200)
                # Redis down: fail closed, as a retryable 503.
                redis.stop()
                self.assertEqual(signed_request(replica_a, "POST", self.URL, identity=RUN).status, 503)
                self.assertIn("nonce_store_error", [r["reason"] for r in replica_a.audit_records("signature")])
        finally:
            arbiter.close()
            if redis.process.poll() is None:
                redis.stop()


@requires_current("signed-header identity")
class DecisionCacheWithSignaturesTests(ProxyTestCase):
    def test_cache_never_skips_signature_verification(self):
        arbiter = Arbiter(port=18203, respond=arbiter_for())
        try:
            with origin_proxy(arbiter, EGRESS_DECISION_TTL="30") as proxy:
                for _ in range(5):
                    self.assertEqual(signed_request(proxy, "GET", "https://example.com/a", identity=RUN).status, 200)
                self.assertEqual(len(arbiter.requests), 1, "allow decision should be cached per run and destination")
                forged = signed_headers(proxy, "GET", "https://example.com/a", identity=RUN, run_key=b"\x01" * 32)
                self.assertEqual(signed_request(proxy, "GET", "https://example.com/a", forged).status, 403)
                # A different run is never served from another run's cached decision.
                signed_request(proxy, "GET", "https://example.com/a", identity=OTHER_RUN)
                self.assertEqual(arbiter.requests[-1]["identity"]["runnerId"], OTHER_RUN["runnerId"])
        finally:
            arbiter.close()


@requires_current("upstream TLS verification")
class UpstreamTLSTests(ProxyTestCase):
    def test_untrusted_and_mismatched_certificates(self):
        arbiter = Arbiter(port=18204, respond=arbiter_for(allowed_hosts=("example.com", "mismatch.test")))
        self.fx.dns.set("mismatch.test", ["93.184.215.14"])  # origin presents an example.com certificate
        try:
            with origin_proxy(arbiter) as proxy:
                self.assertEqual(signed_request(proxy, "GET", "https://mismatch.test/", identity=RUN).status, 503)
            proxy = origin_proxy(arbiter)
            proxy.extra_env["EGRESS_UPSTREAM_CA_FILE"] = ""  # system trust only: the test CA is unknown
            with proxy:
                self.assertEqual(signed_request(proxy, "GET", "https://example.com/", identity=RUN).status, 503)
        finally:
            arbiter.close()


@requires_current("signed-header identity")
class IdentityModeIsolationTests(ProxyTestCase):
    def test_token_mode_ignores_identity_headers(self):
        arbiter = Arbiter(port=18205)
        try:
            proxy = Proxy(policy_url=arbiter.url, auth="token", env={"EGRESS_MODE": "origination", **PROFILE_ENV})
            with proxy:
                forged = signed_headers(proxy, "GET", "https://example.com/", identity=OTHER_RUN, run_key=b"\x02" * 32)
                extra = "".join(f"{k}: {v}\r\n" for k, v in forged.items())
                r = http_request(proxy, "https://example.com/", proxy.credentials("sbx-1"), extra_headers=extra)
                self.assertEqual(r.status, 200)
                self.assertEqual(arbiter.requests[-1]["principal"], "sbx-1")
                self.assertNotIn("identity", arbiter.requests[-1])
        finally:
            arbiter.close()


@requires_current("signed-header identity")
class SignedConnectTests(ProxyTestCase):
    """EGRESS_MODE=both: signed CONNECT (headers on the CONNECT request) with SNI enforcement."""

    def test_signed_connect(self):
        arbiter = Arbiter(port=18206, respond=arbiter_for())
        try:
            with origin_proxy(arbiter, EGRESS_MODE="both") as proxy:
                headers = signed_headers(proxy, "CONNECT", "example.com:443", identity=RUN)
                extra = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                sock = socket.create_connection((PROXY_IP, proxy.port), timeout=10)
                sock.sendall(f"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n{extra}\r\n".encode())
                self.assertIn(b" 200 ", sock.recv(4096))
                import ssl
                tls = ssl.create_default_context(cafile=str(self.fx.pki.ca)).wrap_socket(sock, server_hostname="example.com")
                tls.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                self.assertIn(b"sni=example.com", tls.recv(4096) + tls.recv(4096))
                tls.close()
                self.assertEqual(arbiter.requests[-1]["method"], "CONNECT")
                # Unsigned CONNECT is refused; fronting through a signed CONNECT is terminated.
                self.assertFalse(tunnel(proxy, "example.com:443", None).established)
                sock = socket.create_connection((PROXY_IP, proxy.port), timeout=10)
                sock.sendall(f"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n"
                             f"{''.join(f'{k}: {v}{chr(13)}{chr(10)}' for k, v in signed_headers(proxy, 'CONNECT', 'example.com:443', identity=RUN).items())}\r\n".encode())
                self.assertIn(b" 200 ", sock.recv(4096))
                with self.assertRaises(Exception):
                    ssl.create_default_context(cafile=str(self.fx.pki.ca)).wrap_socket(sock, server_hostname="fronted.test").recv(1)
                sock.close()
        finally:
            arbiter.close()


@requires_current("signed-header identity")
class DefaultProfileTests(ProxyTestCase):
    """Out of the box: a single runId attribute in X-Egress-Run-Id."""

    def test_default_profile(self):
        arbiter = Arbiter(port=18207, respond=arbiter_for())
        try:
            with Proxy(policy_url=arbiter.url, auth="signed-headers", env={"EGRESS_MODE": "origination"}) as proxy:
                headers = signed_headers(proxy, "GET", "https://example.com/", {"runId": "run-123"})
                self.assertEqual(set(headers), {"X-Egress-Run-Id", "X-Egress-Timestamp", "X-Egress-Nonce",
                                                "X-Egress-Signature"})
                self.assertEqual(signed_request(proxy, "GET", "https://example.com/", headers).status, 200)
                self.assertEqual(arbiter.requests[-1]["identity"], {"runId": "run-123"})
                self.assertEqual(arbiter.requests[-1]["principal"], "run-123")
                self.assertNotIn("reserved for Squid use", (proxy.run_dir / "cache.log").read_text())
        finally:
            arbiter.close()
