"""Bursty workloads must be slowed down, never silently lost.

Production history this reproduces: with a slow policy API under burst load, an 8 s
timeout and no retries caused timeouts and lost requests. Here the proxy merges
identical decisions, queues bursts, retries transient API failures, waits for slow
answers within its budget, and answers what it still cannot decide with 503 +
Retry-After (which clients retry) instead of 403.
"""

import collections
import threading
import time

from tests.e2e.harness import Arbiter, Proxy, ProxyTestCase, http_request, requires_current, open_proxy

CREDS = ("demo", "demo-password")


class CapacityArbiter:
    """Policy API with limited capacity (``capacity`` concurrent requests of ``latency`` s each)."""

    def __init__(self, port: int, capacity: int = 10, latency: float = 0.2, fail_first: int = 0) -> None:
        self.sem = threading.Semaphore(capacity)
        self.latency = latency
        self.fail_first = fail_first
        self.attempts: collections.Counter = collections.Counter()
        self.lock = threading.Lock()

        def respond(req):
            with self.lock:
                self.attempts[req["requestId"]] += 1
                attempt = self.attempts[req["requestId"]]
            if attempt <= self.fail_first:
                return 503, {"error": "overloaded"}
            with self.sem:
                time.sleep(self.latency)
            return 200, {"decision": "allow", "requestId": req["requestId"]}

        self.arbiter = Arbiter(port=port, respond=respond)

    def close(self) -> None:
        self.arbiter.close()


def burst(proxy, count, paths, timeout=60):
    results = []
    lock = threading.Lock()

    def one(index):
        started = time.monotonic()
        r = http_request(proxy, f"http://example.com{paths[index % len(paths)]}", CREDS, timeout=timeout)
        with lock:
            results.append((r.status, time.monotonic() - started, r.headers.get("retry-after")))

    threads = [threading.Thread(target=one, args=(i,)) for i in range(count)]
    started = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results, time.monotonic() - started


@requires_current("burst handling")
class BurstTests(ProxyTestCase):
    def test_burst_of_distinct_requests_is_not_lost(self):
        api = CapacityArbiter(18300, capacity=10, latency=0.2)
        try:
            # Uncached, per-path decisions: every request needs the API (worst case for bursts).
            with Proxy(policy_url=api.arbiter.url,
                       env={"EGRESS_DECISION_TTL": "0", "EGRESS_DECISION_SCOPE": "request"}) as proxy:
                results, elapsed = burst(proxy, 200, [f"/v1/item/{i}" for i in range(200)])
                statuses = collections.Counter(status for status, _, _ in results)
                self.assertEqual(statuses, {200: 200}, f"{statuses} in {elapsed:.1f}s")
                self.assertEqual(len(api.attempts), 200)
                self.assertLess(elapsed, 15)
        finally:
            api.close()

    def test_identical_concurrent_decisions_are_merged(self):
        api = CapacityArbiter(18301, capacity=10, latency=0.3)
        try:
            with Proxy(policy_url=api.arbiter.url) as proxy:
                results, elapsed = burst(proxy, 100, ["/v1/messages"])
                self.assertEqual(collections.Counter(s for s, _, _ in results), {200: 100})
                self.assertLessEqual(len(api.attempts), 3, "identical decisions were not merged")
                self.assertLess(max(d for _, d, _ in results), 5, "merged requests waited too long")
        finally:
            api.close()

    def test_transient_api_failures_are_retried(self):
        api = CapacityArbiter(18302, capacity=10, latency=0.05, fail_first=2)
        try:
            with Proxy(policy_url=api.arbiter.url,
                       env={"EGRESS_DECISION_TTL": "0", "EGRESS_DECISION_SCOPE": "request"}) as proxy:
                results, _ = burst(proxy, 20, [f"/r/{i}" for i in range(20)])
                self.assertEqual(collections.Counter(s for s, _, _ in results), {200: 20})
                self.assertTrue(all(count == 3 for count in api.attempts.values()), api.attempts)
        finally:
            api.close()

    def test_slow_api_within_budget_succeeds(self):
        """The production incident: the API takes ~8 s under load. Default budget: 15 s."""
        api = CapacityArbiter(18303, capacity=50, latency=8.0)
        try:
            with Proxy(policy_url=api.arbiter.url,
                       env={"EGRESS_DECISION_TTL": "0", "EGRESS_DECISION_SCOPE": "request"}) as proxy:
                results, elapsed = burst(proxy, 20, [f"/slow/{i}" for i in range(20)], timeout=30)
                self.assertEqual(collections.Counter(s for s, _, _ in results), {200: 20})
                self.assertTrue(all(count == 1 for count in api.attempts.values()),
                                "slow answers must not be abandoned and re-sent")
        finally:
            api.close()

    def test_unavailable_api_answers_retryable_503(self):
        with Proxy(policy_url="http://127.0.0.1:18399/decide") as proxy:
            started = time.monotonic()
            r = http_request(proxy, "http://example.com/", CREDS)
            self.assertEqual(r.status, 503, r.raw_head)
            self.assertEqual(r.headers.get("retry-after"), "1")
            self.assertLess(time.monotonic() - started, 3)

    def test_policy_denial_stays_403(self):
        arbiter = Arbiter(port=18305, respond=lambda req: (200, {"decision": "deny", "requestId": req["requestId"]}))
        try:
            with Proxy(policy_url=arbiter.url) as proxy:
                r = http_request(proxy, "http://example.com/", CREDS)
                self.assertEqual(r.status, 403)
                self.assertIsNone(r.headers.get("retry-after"))
        finally:
            arbiter.close()

    def test_connection_limit_answers_503(self):
        api = CapacityArbiter(18306)
        try:
            with Proxy(policy_url=api.arbiter.url, env={"EGRESS_MAX_CONN_PER_CLIENT": "2"}) as proxy:
                held = [open_proxy(proxy), open_proxy(proxy)]
                try:
                    time.sleep(0.2)
                    r = http_request(proxy, "http://example.com/", CREDS)
                    self.assertEqual(r.status, 503, r.raw_head)
                    self.assertEqual(r.headers.get("retry-after"), "1")
                finally:
                    for sock in held:
                        sock.close()
        finally:
            api.close()

    def test_rate_limit_answers_429(self):
        api = CapacityArbiter(18307, latency=0.01)
        try:
            with Proxy(policy_url=api.arbiter.url, env={"EGRESS_RATE_LIMIT": "1/2", "EGRESS_HELPER_CHILDREN": "1",
                                                                    "EGRESS_DECISION_TTL": "0", "EGRESS_DECISION_SCOPE": "request"}) as proxy:
                statuses = [http_request(proxy, f"http://example.com/rl/{i}", CREDS).status for i in range(6)]
                self.assertIn(429, statuses)
                self.assertNotIn(403, statuses)
        finally:
            api.close()
