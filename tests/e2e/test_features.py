"""Operational features: monitor (health, readiness, metrics), drain, WebSocket, hot reload, correlation."""

import json
import os
import re
import signal
import socket
import threading
import time

from tests.e2e.harness import (PROXY_IP, Arbiter, Proxy, ProxyTestCase, _auth_header, http_request,
                               requires_current, signed_request)
from tests.e2e.test_signed_headers import RUN, arbiter_for, origin_proxy

CREDS = ("demo", "demo-password")
POLICY = {"version": 2, "principals": {"demo": {"origins": [
    "http://example.com", "https://example.com", {"origin": "http://stream.example", "websocket": True},
    "http://other.example"]}}}


def metric(text: str, name: str, **labels) -> float | None:
    for line in text.splitlines():
        if not line.startswith(name):
            continue
        match = re.match(r"([a-zA-Z_:]+)(\{(.*)\})? (\S+)$", line)
        if not match or match.group(1) != name:
            continue
        found = dict(re.findall(r'(\w+)="([^"]*)"', match.group(3) or ""))
        if all(found.get(k) == v for k, v in labels.items()):
            return float(match.group(4))
    return None


@requires_current("monitor")
class MonitorTests(ProxyTestCase):
    def test_health_readiness_and_metrics(self):
        with Proxy(policy=POLICY, monitor=True, env={"EGRESS_MODE": "both"}) as proxy:
            self.assertEqual(proxy.monitor_get("/livez")[0], 200)
            status, body = proxy.monitor_get("/readyz")
            self.assertEqual(status, 200, body)
            for i in range(5):
                http_request(proxy, f"http://example.com/x/{i}", CREDS)
            http_request(proxy, "http://denied.example/", CREDS)
            time.sleep(2.5)  # helper snapshot interval
            status, text = proxy.monitor_get("/metrics")
            self.assertEqual(status, 200)
            self.assertEqual(metric(text, "egress_squid_up"), 1)
            self.assertEqual(metric(text, "egress_decisions_total", decision="allow", reason="allowed", source="backend"), 1)
            self.assertEqual(metric(text, "egress_decisions_total", decision="allow", reason="approved_cached",
                                    source="approval"), 4)
            self.assertEqual(metric(text, "egress_decisions_total", decision="deny", reason="origin_not_allowed",
                                     source="backend"), 1)
            self.assertGreaterEqual(metric(text, "egress_squid_client_requests_total") or 0, 6)
            self.assertIsNotNone(metric(text, "egress_helper_pool_requests_total", helper="egress_policy"))
            self.assertIsNotNone(metric(text, "egress_squid_file_descriptors", state="max"))
            self.assertIsNotNone(metric(text, "egress_policy_decision_seconds_count", backend="file"))
            self.assertEqual(metric(text, "egress_approval_cache_hits_total"), 4)
            self.assertEqual(metric(text, "egress_ready"), 1)
            # Low cardinality: no principals or destinations in metrics.
            self.assertNotIn("demo", text)
            self.assertNotIn("example.com", text)

    def test_ready_during_policy_api_outage(self):
        with Proxy(policy_url="http://127.0.0.1:18799/decide", monitor=True, env={"EGRESS_POLICY_RETRIES": "0"}) as proxy:
            self.assertEqual(http_request(proxy, "http://example.com/", CREDS).status, 503)
            status, body = proxy.monitor_get("/readyz")
            self.assertEqual(status, 200, "an API outage must not make the replica unready: " + body)

    def test_not_ready_when_helpers_misconfigured(self):
        proxy = Proxy(policy=POLICY, monitor=True)
        with proxy:
            (proxy.run_dir / "policy.json").write_text("{ broken")
            os.kill(proxy.squid_pid(), signal.SIGHUP)  # new helpers start with an unusable policy
            time.sleep(3)
            self.assertEqual(http_request(proxy, "http://example.com/new", CREDS).status, 503)
            time.sleep(2.5)
            status, body = proxy.monitor_get("/readyz")
            self.assertEqual(status, 503)
            self.assertIn("helper_misconfigured:acl", body)


@requires_current("graceful drain")
class DrainTests(ProxyTestCase):
    def test_sigterm_drains_active_streams(self):
        with Proxy(policy=POLICY, monitor=True, env={"EGRESS_DRAIN_SECONDS": "8"}) as proxy:
            sock = socket.create_connection((PROXY_IP, proxy.port), timeout=15)
            sock.sendall(f"GET http://stream.example/sse HTTP/1.1\r\nHost: stream.example\r\n{_auth_header(CREDS)}\r\n".encode())
            received, done = [], threading.Event()

            def reader():
                buffer = b""
                while True:
                    try:
                        data = sock.recv(4096)
                    except OSError:
                        break
                    if not data:
                        break
                    buffer += data
                    received[:] = re.findall(rb"token\d", buffer)
                    if b"0\r\n\r\n" in buffer:
                        break
                done.set()

            threading.Thread(target=reader, daemon=True).start()
            time.sleep(1.0)
            # What "tini -g" does on pod termination: SIGTERM to Squid and the monitor.
            os.kill(proxy.squid_pid(), signal.SIGTERM)
            os.kill(proxy.monitor_pid(), signal.SIGTERM)
            time.sleep(0.5)
            status, body = proxy.monitor_get("/readyz")
            self.assertEqual(status, 503)
            self.assertIn("draining", body)
            with self.assertRaises(OSError):
                socket.create_connection((PROXY_IP, proxy.port), timeout=2)
            self.assertTrue(done.wait(10))
            self.assertEqual(len(received), 6, "the in-flight stream must complete during the drain")
            sock.close()


@requires_current("websocket")
class WebSocketTests(ProxyTestCase):
    def _upgrade(self, proxy, host):
        sock = socket.create_connection((PROXY_IP, proxy.port), timeout=5)
        sock.sendall(f"GET http://{host}/ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
                     f"{_auth_header(CREDS)}\r\n".encode())
        head = sock.recv(4096)
        return sock, head

    def test_websocket_only_where_policy_allows(self):
        with Proxy(policy=POLICY, env={"EGRESS_MODE": "origination"}) as proxy:
            sock, head = self._upgrade(proxy, "stream.example")
            self.assertTrue(head.startswith(b"HTTP/1.1 101"), head)
            sock.sendall(b"frame-1")
            self.assertEqual(sock.recv(100), b"ECHO:frame-1")
            sock.close()
        policy = {"version": 2, "principals": {"demo": {"origins": ["http://stream.example"]}}}
        with Proxy(policy=policy, env={"EGRESS_MODE": "origination"}) as proxy:
            before = len(self.fx.stream.upgrades)
            sock, head = self._upgrade(proxy, "stream.example")
            self.assertNotIn(b" 101 ", head.split(b"\r\n")[0])
            self.assertEqual(len(self.fx.stream.upgrades), before, "upgrade must not reach the origin")
            sock.close()


@requires_current("policy hot reload")
class HotReloadTests(ProxyTestCase):
    def test_policy_file_reload_and_last_good(self):
        policy = {"version": 1, "principals": {"demo": ["http://example.com"]}}
        with Proxy(policy=policy, monitor=True, env={"EGRESS_DECISION_TTL": "2", "EGRESS_DECISION_NEGATIVE_TTL": "0"}) as proxy:
            self.assertEqual(http_request(proxy, "http://other.example/", CREDS).status, 403)
            path = proxy.run_dir / "policy.json"
            path.write_text(json.dumps({"version": 1, "principals": {"demo": ["http://other.example"]}}))
            time.sleep(4)
            self.assertEqual(http_request(proxy, "http://other.example/", CREDS).status, 200)
            self.assertEqual(http_request(proxy, "http://example.com/", CREDS).status, 403)  # removed
            path.write_text("{ not json")
            time.sleep(3)
            self.assertEqual(http_request(proxy, "http://other.example/again", CREDS).status, 200)  # last good kept
            time.sleep(2.5)
            _, text = proxy.monitor_get("/metrics")
            self.assertGreaterEqual(metric(text, "egress_config_reloads_total", file="policy", result="ok") or 0, 1)
            self.assertGreaterEqual(metric(text, "egress_config_reloads_total", file="policy", result="error") or 0, 1)
            events = [(a["result"]) for a in proxy.audit_records("config_reload")]
            self.assertIn("ok", events)
            self.assertIn("error", events)
            self.assertEqual(proxy.monitor_get("/readyz")[0], 200)  # a bad edit does not take the replica out


@requires_current("log correlation")
class CorrelationTests(ProxyTestCase):
    def test_decision_id_links_access_audit_and_api(self):
        arbiter = Arbiter(port=18700, respond=lambda req: (200, {"decision": "allow", "requestId": req["requestId"],
                                                                 "scope": "http://example.com/"}))
        try:
            with Proxy(policy_url=arbiter.url) as proxy:
                http_request(proxy, "http://example.com/a", CREDS)
                http_request(proxy, "http://example.com/b", CREDS)  # served by the stored approval
                request_id = arbiter.requests[0]["requestId"]
                access = proxy.wait_for(lambda: [r for r in proxy.access_records() if r.get("method") == "GET"]
                                        if len([r for r in proxy.access_records() if r.get("method") == "GET"]) >= 2 else None)
                self.assertEqual([r["decision_id"] for r in access], [request_id, request_id])
                self.assertEqual({r["instance"] for r in access}, {proxy.name})
                self.assertTrue(all(r["xaction"].isdigit() for r in access))
                audit = proxy.audit_records("decision")
                self.assertEqual(audit[0]["decision_id"], request_id)
                self.assertEqual(audit[0]["instance"], proxy.name)
        finally:
            arbiter.close()

    def test_xaction_in_per_request_checks(self):
        arbiter = Arbiter(port=18701, respond=arbiter_for())
        try:
            with origin_proxy(arbiter) as proxy:
                signed_request(proxy, "GET", "https://example.com/", identity=RUN)
                access = proxy.wait_for(lambda: [r for r in proxy.access_records() if r.get("method") == "GET"])
                signature = proxy.audit_records("signature")[-1]
                self.assertEqual(signature["xaction"], access[-1]["xaction"])
        finally:
            arbiter.close()
