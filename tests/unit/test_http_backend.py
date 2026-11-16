import http.server
import json
import os
import socket
import socketserver
import threading
import time
import unittest
from unittest import mock

from clearideas_egress import ACLRequest, HTTPPolicy, PolicyError, decide

REQUEST = ACLRequest("alice", "192.0.2.10", "CONNECT", "example.com", 443)


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass  # resets caused by deliberate deadline aborts are expected


def serve(handler_factory):
    server = _Server(("127.0.0.1", 0), handler_factory)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/decide"


def stop(server):
    server.shutdown()
    server.server_close()


def json_handler(respond, counter=None, log=None):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            if counter is not None:
                counter.append(1)
            super().setup()

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if log is not None:
                log.append((body, dict(self.headers)))
            status, payload = respond(body)
            data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    return Handler


def echo_allow(body):
    return 200, {"decision": "allow", "requestId": body["requestId"]}


class ValidationTests(unittest.TestCase):
    def test_rejects_unprotected_remote_endpoint(self):
        for url, token in [("http://policy.example/authorize", "secret"), ("http://localhost/authorize", None),
                           ("https://policy.example/authorize", None), ("https://u:p@policy.example/", "t"),
                           ("https://policy.example/#frag", "t")]:
            with self.subTest(url=url), self.assertRaises(PolicyError):
                HTTPPolicy(url, token=token)

    def test_rejects_bad_options(self):
        for kwargs in [{"timeout_seconds": 0}, {"timeout_seconds": True}, {"timeout_seconds": 121},
                       {"retries": -1}, {"retries": 11}, {"attempt_timeout": 0}, {"attempt_timeout": 20, "timeout_seconds": 10},
                       {"token": "a b"}, {"token": "x\n"}, {"max_in_flight": 0},
                       {"client_cert_file": "/c.pem"}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(PolicyError):
                HTTPPolicy("https://policy.example/", **{"token": "t", **kwargs})
        with self.assertRaises(PolicyError):
            HTTPPolicy("http://127.0.0.1:1/", ca_file="/ca.pem")


class DecisionTests(unittest.TestCase):
    def test_request_payload_and_explicit_allow(self):
        log = []
        server, url = serve(json_handler(echo_allow, log=log))
        try:
            policy = HTTPPolicy(url, token="secret")
            decision = decide(REQUEST, policy)
            self.assertTrue(decision.allowed, decision)
            body, headers = log[0]
            self.assertEqual(headers["Authorization"], "Bearer secret")
            self.assertEqual({k: body[k] for k in ("version", "principal", "sourceIp", "method", "scheme", "host", "port")},
                             {"version": 2, "principal": "alice", "sourceIp": "192.0.2.10", "method": "CONNECT",
                              "scheme": "https", "host": "example.com", "port": 443})
            self.assertRegex(body["requestId"], r"^[0-9a-f]{32}$")
        finally:
            stop(server)

    def test_only_explicit_allow(self):
        cases = [
            (200, {"decision": True}, "backend_denied"),
            (200, {"decision": "deny"}, "backend_denied"),
            (200, {"decision": "deny", "reason": "quota_exceeded"}, "arbiter:quota_exceeded"),
            (200, {"decision": "deny", "reason": "Bad Reason!"}, "backend_denied"),
            (200, {}, "backend_denied"),
            (200, b"invalid-json", "backend_error"),
            (200, b"[" * 10000, "backend_error"),
            (200, b"", "backend_error"),
            (500, {"decision": "allow"}, "backend_error"),
            (302, {"decision": "allow"}, "backend_error"),
            (200, {"decision": "allow", "requestId": "not-mine"}, "backend_error"),
            (200, b"{\"decision\":\"allow\",\"pad\":\"" + b"x" * 70000 + b"\"}", "backend_error"),
        ]
        for status, payload, reason in cases:
            server, url = serve(json_handler(lambda body, s=status, p=payload: (s, p)))
            try:
                with self.subTest(status=status, payload=str(payload)[:40]):
                    self.assertEqual(decide(REQUEST, HTTPPolicy(url)).reason, reason)
            finally:
                stop(server)

    def test_url_and_scope_fields(self):
        log = []
        server, url = serve(json_handler(lambda b: (200, {"decision": "allow", "requestId": b["requestId"],
                                                          "scope": "https://api.example.com/v1",
                                                          "methods": ["GET", "POST"], "ttl": 60}), log=log))
        try:
            request = ACLRequest("alice", "192.0.2.10", "GET", "api.example.com", 443, scheme="https",
                                 path="/v1/files/2390423480?key=SECRET")
            decision = decide(request, HTTPPolicy(url))
            self.assertEqual((decision.scope, decision.scope_methods, decision.scope_ttl),
                             ("https://api.example.com/v1", frozenset({"GET", "POST"}), 60.0))
            body = log[0][0]
            self.assertEqual(body["url"], "https://api.example.com/v1/files/2390423480")
            self.assertNotIn("SECRET", json.dumps(body))
            odd = ACLRequest("alice", "192.0.2.10", "GET", "2001:db8::1", 8443, scheme="https", path="/x")
            decide(odd, HTTPPolicy(url))
            self.assertEqual(log[1][0]["url"], "https://[2001:db8::1]:8443/x")
        finally:
            stop(server)

    def test_request_id_required_mode(self):
        server, url = serve(json_handler(lambda body: (200, {"decision": "allow"})))
        try:
            self.assertTrue(decide(REQUEST, HTTPPolicy(url)).allowed)
            self.assertEqual(decide(REQUEST, HTTPPolicy(url, require_request_id=True)).reason, "backend_error")
        finally:
            stop(server)

    def test_allow_non_tls_only_for_connect(self):
        server, url = serve(json_handler(lambda b: (200, {"decision": "allow", "requestId": b["requestId"],
                                                          "allowNonTls": True})))
        try:
            policy = HTTPPolicy(url)
            self.assertEqual(decide(REQUEST, policy).annotations, {"egress_tls_": "optional"})
            get = ACLRequest("alice", "192.0.2.10", "GET", "example.com", 80)
            self.assertEqual(decide(get, policy).annotations, {})
        finally:
            stop(server)


class DeadlineTests(unittest.TestCase):
    def test_slow_drip_body_bounded_by_deadline(self):  # review H-3 (the original repro)
        class Drip(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(65536)
                body = b'{"decision":"allow"}'
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body))
                try:
                    for byte in body:
                        time.sleep(0.3)
                        self.request.sendall(bytes([byte]))
                except OSError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Drip)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            policy = HTTPPolicy(f"http://127.0.0.1:{server.server_address[1]}/", timeout_seconds=1.0)
            started = time.monotonic()
            decision = decide(REQUEST, policy)
            elapsed = time.monotonic() - started
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason, "backend_timeout")
            self.assertLess(elapsed, 1.3)
        finally:
            stop(server)

    def test_slow_headers_bounded(self):
        class SlowHeaders(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(65536)
                try:
                    for _ in range(50):
                        self.request.sendall(b"X")
                        time.sleep(0.2)
                except OSError:
                    pass

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SlowHeaders)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            policy = HTTPPolicy(f"http://127.0.0.1:{server.server_address[1]}/", timeout_seconds=0.8)
            started = time.monotonic()
            self.assertEqual(decide(REQUEST, policy).reason, "backend_timeout")
            self.assertLess(time.monotonic() - started, 1.1)
        finally:
            stop(server)

    def test_dns_hang_bounded(self):
        real = socket.getaddrinfo

        def hanging(host, *args, **kwargs):
            if host == "policy.hang.example":
                time.sleep(3)
            return real(host, *args, **kwargs)

        with mock.patch("socket.getaddrinfo", hanging):
            policy = HTTPPolicy("https://policy.hang.example/decide", token="t", timeout_seconds=0.5)
            started = time.monotonic()
            self.assertEqual(decide(REQUEST, policy).reason, "backend_timeout")
            self.assertLess(time.monotonic() - started, 0.8)

    def test_saturation_waits_then_proceeds(self):
        release = threading.Event()

        def blocking(body):
            release.wait(5)
            return echo_allow(body)

        server, url = serve(json_handler(blocking))
        try:
            policy = HTTPPolicy(url, max_in_flight=2, timeout_seconds=5)
            results = []
            threads = [threading.Thread(target=lambda: results.append(decide(REQUEST, policy).reason)) for _ in range(2)]
            for thread in threads:
                thread.start()
            time.sleep(0.3)
            # With no slot free before the caller's deadline: saturated.
            started = time.monotonic()
            self.assertEqual(decide(REQUEST, policy, deadline=time.monotonic() + 0.3).reason, "backend_saturated")
            self.assertLess(time.monotonic() - started, 0.6)
            # With budget left, a burst waits for a slot instead of failing.
            waiter = []
            t = threading.Thread(target=lambda: waiter.append(decide(REQUEST, policy).reason))
            t.start()
            time.sleep(0.2)
            release.set()
            for thread in threads + [t]:
                thread.join()
            self.assertEqual(results + waiter, ["allowed"] * 3)
        finally:
            stop(server)


class RetryTests(unittest.TestCase):
    def sequence_server(self, responses, latency=0.0):
        """Serve the given (status, payload, headers) responses in order, then allow."""
        log = []
        responses = list(responses)

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                log.append((time.monotonic(), body["requestId"]))
                if latency:
                    time.sleep(latency)
                status, payload, headers = responses.pop(0) if responses else (200, None, {})
                if payload is None:
                    payload = {"decision": "allow", "requestId": body["requestId"]}
                data = json.dumps(payload).encode()
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        server, url = serve(Handler)
        self.addCleanup(stop, server)
        return url, log

    def test_transient_errors_are_retried_with_same_request_id(self):
        url, log = self.sequence_server([(503, {}, {}), (502, {}, {}), (500, {}, {})])
        policy = HTTPPolicy(url)
        decision = decide(REQUEST, policy)
        self.assertTrue(decision.allowed, decision)
        self.assertEqual(len(log), 4)
        self.assertEqual(len({request_id for _, request_id in log}), 1)
        self.assertEqual(policy.retries_total, 3)

    def test_retry_after_is_honored(self):
        url, log = self.sequence_server([(429, {}, {"Retry-After": "1"})])
        self.assertTrue(decide(REQUEST, HTTPPolicy(url)).allowed)
        self.assertGreaterEqual(log[1][0] - log[0][0], 0.95)

    def test_retries_exhausted(self):
        url, log = self.sequence_server([(503, {}, {})] * 10)
        self.assertEqual(decide(REQUEST, HTTPPolicy(url, retries=2)).reason, "backend_error")
        self.assertEqual(len(log), 3)

    def test_non_retryable_status_not_retried(self):
        for status in (400, 401, 403, 404):
            url, log = self.sequence_server([(status, {}, {})])
            with self.subTest(status=status):
                self.assertEqual(decide(REQUEST, HTTPPolicy(url)).reason, "backend_error")
                self.assertEqual(len(log), 1)

    def test_explicit_deny_not_retried(self):
        url, log = self.sequence_server([(200, {"decision": "deny"}, {})])
        self.assertEqual(decide(REQUEST, HTTPPolicy(url)).reason, "backend_denied")
        self.assertEqual(len(log), 1)

    def test_connection_refused_retried_quickly(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        policy = HTTPPolicy(f"http://127.0.0.1:{port}/")
        started = time.monotonic()
        self.assertEqual(decide(REQUEST, policy).reason, "backend_error")
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(policy.attempts_total, 4)

    def test_slow_answer_is_waited_for_not_abandoned(self):
        # An overloaded API that answers in 2 s: wait (one attempt), do not abandon and resend.
        url, log = self.sequence_server([], latency=2.0)
        started = time.monotonic()
        self.assertTrue(decide(REQUEST, HTTPPolicy(url, timeout_seconds=5)).allowed)
        self.assertGreaterEqual(time.monotonic() - started, 1.9)
        self.assertEqual(len(log), 1)

    def test_attempt_timeout_retries_slow_attempts(self):
        url, log = self.sequence_server([], latency=1.0)
        policy = HTTPPolicy(url, timeout_seconds=2.5, attempt_timeout=0.4, retries=5)
        started = time.monotonic()
        self.assertEqual(decide(REQUEST, policy).reason, "backend_timeout")
        self.assertLess(time.monotonic() - started, 2.8)
        self.assertGreater(len(log), 1)

    def test_caller_deadline_caps_retries(self):
        url, log = self.sequence_server([(503, {}, {"Retry-After": "2"})] * 5)
        started = time.monotonic()
        self.assertEqual(decide(REQUEST, HTTPPolicy(url), deadline=time.monotonic() + 1.0).reason, "backend_error")
        self.assertLess(time.monotonic() - started, 1.2)
        self.assertEqual(len(log), 1)  # a 2 s Retry-After does not fit in the remaining budget


class TransportTests(unittest.TestCase):
    def test_keep_alive_reuse(self):
        connections = []
        server, url = serve(json_handler(echo_allow, counter=connections))
        try:
            policy = HTTPPolicy(url)
            for _ in range(25):
                self.assertTrue(decide(REQUEST, policy).allowed)
            self.assertEqual(len(connections), 1)
            self.assertEqual(policy.connections_opened, 1)
        finally:
            stop(server)

    def test_recovers_when_server_closes_pooled_connection(self):
        server, url = serve(json_handler(echo_allow))
        policy = HTTPPolicy(url)
        self.assertTrue(decide(REQUEST, policy).allowed)
        port = server.server_address[1]
        stop(server)
        time.sleep(0.1)
        server2 = _Server(("127.0.0.1", port), json_handler(echo_allow))
        threading.Thread(target=server2.serve_forever, daemon=True).start()
        try:
            self.assertTrue(decide(REQUEST, policy).allowed)
        finally:
            stop(server2)

    def test_proxy_environment_ignored(self):  # review M-1 (the original repro)
        spy_hits = []

        class Spy(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                spy_hits.append(self.requestline)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"decision":"allow"}')

            def log_message(self, *args):
                pass

        spy, spy_url = serve(Spy)
        real, url = serve(json_handler(echo_allow))
        proxy = spy_url.rsplit("/", 1)[0]
        try:
            with mock.patch.dict(os.environ, {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "ALL_PROXY": proxy,
                                              "http_proxy": proxy, "NO_PROXY": "", "no_proxy": ""}):
                self.assertTrue(decide(REQUEST, HTTPPolicy(url, token="s3cret")).allowed)
            self.assertEqual(spy_hits, [])
        finally:
            stop(spy)
            stop(real)


if __name__ == "__main__":
    unittest.main()
