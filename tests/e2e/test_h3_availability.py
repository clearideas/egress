"""H-3: one tenant or a degraded arbiter must not deny service to everyone else."""

import itertools
import statistics
import subprocess
import time

from tests.e2e.harness import PROXY_IP, PYTHON, Arbiter, Proxy, ProxyTestCase, connect, requires_current, tunnel

USERS = {"victim": "victim-pw", "attacker": "attacker-pw"}


def allow_example(req):
    allowed = req.get("host") == "example.com"
    return 200, {"decision": "allow" if allowed else "deny", "requestId": req.get("requestId")}


FLOOD_SCRIPT = r"""
import base64, os, socket, sys, threading, time
host, port, source, width = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
auth = base64.b64encode(b"attacker:attacker-pw").decode()
sent = 0
lock = threading.Lock()
def run():
    global sent
    while True:
        try:
            s = socket.socket(); s.settimeout(5); s.bind((source, 0)); s.connect((host, port))
            target = os.urandom(4).hex() + ".attacker.test:443"
            s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
            s.recv(256); s.close()
        except OSError:
            time.sleep(0.01)
        with lock:
            sent += 1
for _ in range(width):
    threading.Thread(target=run, daemon=True).start()
while True:
    time.sleep(0.5)
    with lock:
        print(sent, flush=True)
"""


class Flood:
    """Keeps ``width`` concurrent CONNECTs from the attacker in flight (separate process)."""

    def __init__(self, proxy: Proxy, width: int, source: str) -> None:
        self.args = [PROXY_IP, str(proxy.port), source, str(width)]
        self.sent = 0

    def __enter__(self):
        self.process = subprocess.Popen([PYTHON, "-c", FLOOD_SCRIPT, *self.args],
                                        stdout=subprocess.PIPE, text=True)
        time.sleep(1.5)  # let the flood saturate
        return self

    def __exit__(self, *exc):
        self.process.kill()
        output, _ = self.process.communicate(timeout=10)
        counts = [int(line) for line in output.split() if line.isdigit()]
        self.sent = counts[-1] if counts else 0


class NoisyNeighbourTests(ProxyTestCase):
    def test_victim_unaffected_by_flood(self):  # E-H3-01 (regression of the reproduced attack)
        arbiter = Arbiter(port=18090, latency=0.3, respond=allow_example)
        try:
            with Proxy(policy_url=arbiter.url, users=USERS) as proxy:
                with Flood(proxy, width=150, source="10.20.0.7") as flood:
                    latencies, outcomes = [], []
                    for _ in range(20):
                        started = time.monotonic()
                        status, sock = connect(proxy, "example.com:443", ("victim", "victim-pw"), source="10.20.0.8")
                        latencies.append(time.monotonic() - started)
                        outcomes.append(status)
                        if sock:
                            sock.close()
                        time.sleep(0.05)
                self.assertGreater(flood.sent, 300, "flood did not generate load")
                self.assertNotIn(407, outcomes, f"valid credentials answered 407 under load: {outcomes}")
                self.assertEqual(outcomes.count(200), 20, f"victim outcomes under flood: {outcomes}")
                p95 = statistics.quantiles(latencies, n=20)[-1]
                # One arbiter round trip is 0.3 s; the bound leaves headroom for loaded CI hosts (the
                # unfixed proxy answered 407 or stalled for many seconds).
                self.assertLess(p95, 2.0, f"victim p95 latency {p95:.2f}s")
                self.assertTrue(proxy.alive())
        finally:
            arbiter.close()


@requires_current("bounded deadline and fail-fast")
class DegradedArbiterTests(ProxyTestCase):
    def test_blackholed_arbiter_fails_fast(self):  # E-H3-02
        arbiter = Arbiter(port=18091, latency=30, respond=allow_example)
        try:
            with Proxy(policy_url=arbiter.url, users=USERS, env={"EGRESS_POLICY_TIMEOUT": "1.0"}) as proxy:
                durations, statuses = [], []
                for _ in range(5):
                    started = time.monotonic()
                    result = tunnel(proxy, "example.com:443", ("victim", "victim-pw"))
                    durations.append(time.monotonic() - started)
                    statuses.append(result.outcome)
                self.assertTrue(all(outcome != "established" for outcome in statuses))
                self.assertLess(max(durations), 2.5, durations)
                reasons = {r.get("reason") for r in proxy.audit_records("decision")}
                self.assertIn("backend_timeout", reasons)
                self.assertTrue(proxy.alive())
        finally:
            arbiter.close()

    def test_arbiter_down(self):
        with Proxy(policy_url="http://127.0.0.1:18099/decide", users=USERS) as proxy:
            started = time.monotonic()
            result = tunnel(proxy, "example.com:443", ("victim", "victim-pw"))
            self.assertFalse(result.established)
            self.assertLess(time.monotonic() - started, 2.5)
            self.assertIn("backend_error", {r.get("reason") for r in proxy.audit_records("decision")})

    def test_garbage_responses_deny(self):  # E-H3-03
        # Cycled, because the proxy retries 5xx answers (a retry gets the next bad answer).
        responses = itertools.cycle([(500, {"decision": "allow"}), (200, b"not json"), (200, {"decision": True}),
                                     (200, {"decision": "allow", "requestId": "wrong"}), (302, {"decision": "allow"}),
                                     (200, b"{" * 5000)])
        arbiter = Arbiter(port=18092, respond=lambda req: next(responses))
        try:
            with Proxy(policy_url=arbiter.url, users=USERS) as proxy:
                for _ in range(6):
                    self.assertFalse(tunnel(proxy, "example.com:443", ("victim", "victim-pw")).established)
                reasons = [r.get("reason") for r in proxy.audit_records("decision")]
                self.assertTrue(all(reason in {"backend_error", "backend_denied"} for reason in reasons), reasons)
                decisions = [r.get("decision") for r in proxy.access_records() if r.get("method") == "CONNECT"]
                self.assertTrue(decisions and all(d.startswith("backend_") for d in decisions), decisions)
        finally:
            arbiter.close()

    def test_keep_alive_reuses_connections(self):
        arbiter = Arbiter(port=18093, respond=allow_example)
        try:
            with Proxy(policy_url=arbiter.url, users=USERS,
                       env={"EGRESS_HELPER_CHILDREN": "1", "EGRESS_DECISION_TTL": "0"}) as proxy:
                for _ in range(30):
                    status, sock = connect(proxy, "example.com:443", ("victim", "victim-pw"))
                    self.assertEqual(status, 200)
                    sock.close()
                self.assertEqual(len(arbiter.requests), 30)
                self.assertLessEqual(arbiter.connections, 3, "policy client is not reusing connections")
        finally:
            arbiter.close()


@requires_current("configurable decision cache")
class DecisionCacheTests(ProxyTestCase):
    """Decision caching is opt-in (EGRESS_DECISION_TTL) for bursty workloads."""

    def test_default_caches_and_zero_disables(self):
        arbiter = Arbiter(port=18094, respond=allow_example)
        try:
            with Proxy(policy_url=arbiter.url, users=USERS) as proxy:
                for _ in range(5):
                    connect(proxy, "example.com:443", ("victim", "victim-pw"))[1].close()
                self.assertEqual(len(arbiter.requests), 1)
            with Proxy(policy_url=arbiter.url, users=USERS, env={"EGRESS_DECISION_TTL": "0"}) as proxy:
                for _ in range(5):
                    connect(proxy, "example.com:443", ("victim", "victim-pw"))[1].close()
                self.assertEqual(len(arbiter.requests), 6)
        finally:
            arbiter.close()

    def test_positive_ttl_absorbs_bursts_and_bounds_revocation(self):  # E-H3-04
        state = {"allow": True}

        def respond(req):
            return 200, {"decision": "allow" if state["allow"] else "deny", "requestId": req.get("requestId")}

        arbiter = Arbiter(port=18095, respond=respond)
        try:
            with Proxy(policy_url=arbiter.url, users=USERS, env={"EGRESS_DECISION_TTL": "3"}) as proxy:
                for _ in range(20):
                    status, sock = connect(proxy, "example.com:443", ("victim", "victim-pw"))
                    self.assertEqual(status, 200)
                    sock.close()
                self.assertLessEqual(len(arbiter.requests), 2, "burst was not absorbed by the decision cache")
                # cache key includes the principal: another principal is evaluated separately
                connect(proxy, "example.com:443", ("attacker", "attacker-pw"))[1].close()
                self.assertTrue(any(r.get("principal") == "attacker" for r in arbiter.requests))
                state["allow"] = False  # revoke
                # Squid stamps cache entries in whole seconds: the revocation bound is TTL + ~1 s.
                time.sleep(3 + 2)
                self.assertFalse(tunnel(proxy, "example.com:443", ("victim", "victim-pw")).established,
                                 "revocation not effective after the TTL")
        finally:
            arbiter.close()

    def test_negative_ttl_absorbs_denied_floods(self):
        arbiter = Arbiter(port=18096, respond=allow_example)
        try:
            with Proxy(policy_url=arbiter.url, users=USERS, env={"EGRESS_DECISION_NEGATIVE_TTL": "30"}) as proxy:
                for _ in range(15):
                    tunnel(proxy, "denied.attacker.test:443", ("attacker", "attacker-pw"))
                self.assertLessEqual(len([r for r in arbiter.requests if r.get("host") == "denied.attacker.test"]), 2)
        finally:
            arbiter.close()
