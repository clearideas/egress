import re
import threading
import time
import unittest

from clearideas_egress.approvals import ApprovalCache, ambiguous_path, covers, parse_scope
from clearideas_egress.audit import AuditLog
from clearideas_egress.cli import AclHandler
from clearideas_egress.limits import PrincipalConcurrency
from clearideas_egress.policy import ACLRequest, Decision, compile_file_policy


def req(path="/v1/files/2390423480", method="GET", host="server.example", principal="run-1", port=443):
    return ACLRequest(principal, "10.0.0.1", method, host, port, scheme="https", path=path)


class MatchingTests(unittest.TestCase):
    def test_segment_boundaries(self):
        self.assertTrue(covers("/v1", "/v1"))
        self.assertTrue(covers("/v1", "/v1/files/1"))
        self.assertTrue(covers("/v1", "/v1?x=1"))
        self.assertFalse(covers("/v1", "/v1evil"))
        self.assertFalse(covers("/v1", "/v1-admin/x"))
        self.assertFalse(covers("/v1/files/2390423480", "/v1/files/23904234801"))
        self.assertTrue(covers("/v1/files/2390423480", "/v1/files/2390423480/content"))
        self.assertTrue(covers("/", "/anything"))

    def test_ambiguous_paths_never_covered(self):
        for path in ["/v1/../admin", "/v1/%2e%2e/admin", "/v1/.%2E/admin", "/v1/./x", "/v1/files%2F..%2Fadmin",
                     "/v1\\..\\admin", "/v1//x", "/v1/%5cx"]:
            with self.subTest(path=path):
                self.assertFalse(covers("/v1", path))
        self.assertTrue(ambiguous_path("/v1/../admin"))
        self.assertTrue(ambiguous_path("/v1/%2E%2e"))
        self.assertFalse(ambiguous_path("/v1/.../x"))
        self.assertFalse(ambiguous_path("/v1/files.json?x=../"))  # query ignored

    def test_scope_validation(self):
        r = req()
        self.assertEqual(parse_scope("https://server.example/v1", r), "/v1")
        self.assertEqual(parse_scope("https://SERVER.example:443/v1/", r), "/v1")
        self.assertEqual(parse_scope("https://server.example", r), "/")
        self.assertEqual(parse_scope("https://server.example/v1/files/2390423480", r), "/v1/files/2390423480")
        for bad in ["https://other.example/v1", "http://server.example/v1", "https://server.example:8443/v1",
                    "https://server.example/v2", "https://server.example/v1?x=1", "https://u:p@server.example/v1",
                    "https://server.example/v1/../", "https://server.example/v1evil", "not a url", "/v1"]:
            with self.subTest(bad=bad):
                self.assertIsNone(parse_scope(bad, r))


class CacheTests(unittest.TestCase):
    def test_store_lookup_methods_and_expiry(self):
        cache = ApprovalCache(max_ttl=300)
        cache.store(req(), "/v1", frozenset({"GET"}), 300, {})
        self.assertIsNotNone(cache.lookup(req("/v1/other"))[0])
        self.assertIsNone(cache.lookup(req("/v1/other", method="POST"))[0])
        self.assertIsNone(cache.lookup(req("/v2"))[0])
        self.assertIsNone(cache.lookup(req("/v1", principal="run-2"))[0])   # per principal
        self.assertIsNone(cache.lookup(req("/v1", host="other.example"))[0])  # per origin
        cache.store(req(), "/v2", None, 0.05, {})                          # any method, short ttl
        self.assertIsNotNone(cache.lookup(req("/v2/x", method="DELETE"))[0])
        time.sleep(0.1)
        self.assertIsNone(cache.lookup(req("/v2/x"))[0])

    def test_ttl_can_only_shorten(self):
        cache = ApprovalCache(max_ttl=1)
        cache.store(req(), "/v1", None, 3600, {})
        self.assertLessEqual(cache.lookup(req())[0].expires - time.monotonic(), 1.01)

    def test_forget(self):
        cache = ApprovalCache(max_ttl=300)
        cache.store(req(), "/v1", None, 300, {})
        cache.store(req(), "/v2", None, 300, {})
        cache.forget(req("/v1/x"))
        self.assertIsNone(cache.lookup(req("/v1/y"))[0])
        self.assertIsNotNone(cache.lookup(req("/v2/y"))[0])


class ScriptedBackend:
    supports_deadline = True

    def __init__(self, answers, delay=0.0):
        self.answers = answers  # callable(request) -> Decision
        self.calls = []
        self.delay = delay
        self.lock = threading.Lock()

    def decide(self, request, deadline=None):
        with self.lock:
            self.calls.append(request.path)
        if self.delay:
            time.sleep(self.delay)
        return self.answers(request)


class _Clean:
    """Strips the per-decision ID annotation so answers can be compared as strings."""

    def __init__(self, handler):
        self.handler = handler

    def __call__(self, fields):
        return re.sub(r" egress_decision_=[0-9a-f]+", "", self.handler(fields))


def handler_for(backend, ttl=300, grace=10):
    return _Clean(AclHandler(backend, "http", AuditLog(None), PrincipalConcurrency(32), None, layout="v2",
                             scope="request", approvals=ApprovalCache(max_ttl=ttl, grace_percent=grace)))


def fields(path, method="GET", principal="run-1"):
    return [principal, "10.0.0.1", method, "https", "server.example", "443", path, "-", "-"]


class HandlerTests(unittest.TestCase):
    def test_cache_hits_carry_the_original_decision_id(self):
        backend = ScriptedBackend(lambda r: Decision(True, "allowed", scope="https://server.example/v1",
                                                     decision_id="abc123"))
        handler = AclHandler(backend, "http", AuditLog(None), PrincipalConcurrency(32), None, layout="v2",
                             scope="request", approvals=ApprovalCache(max_ttl=300))
        self.assertEqual(handler(fields("/v1/a")), "OK log=allowed egress_decision_=abc123")
        self.assertEqual(handler(fields("/v1/b")), "OK log=approved_cached egress_decision_=abc123")

    def test_api_scope_covers_later_requests(self):
        backend = ScriptedBackend(lambda r: Decision(True, "allowed", scope="https://server.example/v1"))
        handler = handler_for(backend)
        self.assertEqual(handler(fields("/v1/files/2390423480")), "OK log=allowed")
        for i in range(10):
            self.assertEqual(handler(fields(f"/v1/files/{i}")), "OK log=approved_cached")
        self.assertEqual(handler(fields("/v1evil")), "OK log=allowed")  # not covered: asked again
        self.assertEqual(backend.calls, ["/v1/files/2390423480", "/v1evil"])

    def test_no_scope_covers_request_url_and_below(self):
        backend = ScriptedBackend(lambda r: Decision(True, "allowed"))
        handler = handler_for(backend)
        handler(fields("/v1/files/2390423480"))
        self.assertEqual(handler(fields("/v1/files/2390423480/content")), "OK log=approved_cached")
        handler(fields("/v1/files/999"))
        self.assertEqual(len(backend.calls), 2)

    def test_methods_scope(self):
        backend = ScriptedBackend(lambda r: Decision(True, "allowed", scope="https://server.example/v1"))
        handler = handler_for(backend)
        handler(fields("/v1/a"))
        handler(fields("/v1/b", method="POST"))  # GET approval does not cover POST
        self.assertEqual(len(backend.calls), 2)
        backend2 = ScriptedBackend(lambda r: Decision(True, "allowed", scope="https://server.example/v1",
                                                      scope_methods=frozenset({"GET", "POST"})))
        handler2 = handler_for(backend2)
        handler2(fields("/v1/a"))
        self.assertEqual(handler2(fields("/v1/b", method="POST")), "OK log=approved_cached")
        self.assertEqual(len(backend2.calls), 1)

    def test_scope_for_another_origin_is_ignored(self):
        backend = ScriptedBackend(lambda r: Decision(True, "allowed", scope="https://evil.example/"))
        handler = handler_for(backend)
        handler(fields("/v1/a"))
        handler(fields("/v1/b"))  # the invalid scope fell back to the request URL only
        self.assertEqual(len(backend.calls), 2)

    def test_dot_segments_refused_without_backend_call(self):
        backend = ScriptedBackend(lambda r: Decision(True, "allowed", scope="https://server.example/"))
        handler = handler_for(backend)
        self.assertEqual(handler(fields("/v1/%2e%2e/admin")), "ERR log=ambiguous_path")
        self.assertEqual(backend.calls, [])

    def test_api_ttl_shortens(self):
        backend = ScriptedBackend(lambda r: Decision(True, "allowed", scope="https://server.example/v1", scope_ttl=0))
        handler = handler_for(backend)
        handler(fields("/v1/a"))
        handler(fields("/v1/a"))
        self.assertEqual(len(backend.calls), 2)  # ttl 0: never reused

    def test_burst_single_flight(self):
        backend = ScriptedBackend(lambda r: Decision(True, "allowed", scope="https://server.example/v1"), delay=0.3)
        handler = handler_for(backend)
        results = []
        threads = [threading.Thread(target=lambda i=i: results.append(handler(fields(f"/v1/item/{i}"))))
                   for i in range(50)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(sorted(set(results)), ["OK log=allowed", "OK log=approved_cached"])

    def test_refresh_ahead_and_revocation(self):
        state = {"allow": True}
        backend = ScriptedBackend(lambda r: Decision(True, "allowed", scope="https://server.example/v1")
                                  if state["allow"] else Decision.deny("backend_denied"))
        handler = handler_for(backend, ttl=1, grace=50)
        handler(fields("/v1/a"))
        time.sleep(0.6)  # inside the grace window
        state["allow"] = False
        self.assertEqual(handler(fields("/v1/a")), "OK log=approved_cached")  # served, refresh started
        time.sleep(0.2)
        self.assertEqual(handler(fields("/v1/a")), "ERR log=backend_denied")  # refresh revoked the approval

    def test_file_policy_scope_is_origin_wide(self):
        policy = compile_file_policy({"version": 2, "principals": {"run-1": {"origins": [
            {"origin": "https://server.example", "methods": ["GET"]}]}}})

        class Counting:
            supports_deadline = False
            calls = 0

            def decide(self, request):
                Counting.calls += 1
                return policy.decide(request)

        handler = handler_for(Counting())
        handler(fields("/a"))
        self.assertEqual(handler(fields("/b/c")), "OK log=approved_cached")
        self.assertEqual(handler(fields("/b", method="POST")), "ERR log=method_not_allowed")
        self.assertEqual(Counting.calls, 2)


if __name__ == "__main__":
    unittest.main()
