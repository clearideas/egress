"""M-5: bounds on exfiltration volume and duration.

Upload *rate* shaping is intentionally not tested here: Squid 6 client_delay_pools
did not throttle request bodies (verified during remediation), so rate limits
belong at the network layer. See docs/OPERATIONS.md.
"""

import time
import unittest

from tests.e2e.harness import Proxy, ProxyTestCase, connect, http_request, requires_current, tunnel

POLICY = {"version": 2, "principals": {"demo": {"origins": [
    "http://example.com", "https://example.com", {"origin": "https://echo.example", "allowNonTls": True}]}}}
CREDS = ("demo", "demo-password")


def _closed_after(sock, limit: float) -> float | None:
    """Seconds until the proxy closes an idle socket, or None if still open after ``limit``."""
    sock.settimeout(limit)
    started = time.monotonic()
    try:
        data = sock.recv(1)
    except OSError:
        return None
    return time.monotonic() - started if data == b"" else None


@requires_current("limits")
class LimitTests(ProxyTestCase):
    def test_request_body_limit(self):  # E-M5-01
        with Proxy(policy=POLICY, env={"EGRESS_REQUEST_BODY_MAX_SIZE": "64 KB"}) as proxy:
            before = len(self.fx.http_origin.requests)
            r = http_request(proxy, "http://example.com/upload", CREDS, method="POST", body=b"x" * 200_000)
            self.assertEqual(r.status, 413, r.raw_head)
            self.assertEqual(len(self.fx.http_origin.requests), before)
            ok = http_request(proxy, "http://example.com/upload", CREDS, method="POST", body=b"x" * 1000)
            self.assertEqual(ok.status, 200)

    def test_connect_without_client_hello_is_closed(self):
        with Proxy(policy=POLICY, env={"EGRESS_REQUEST_TIMEOUT": "2"}) as proxy:
            status, sock = connect(proxy, "example.com:443", CREDS)
            self.assertEqual(status, 200)
            closed = _closed_after(sock, 10)
            sock.close()
            self.assertIsNotNone(closed, "pre-ClientHello tunnel never closed")
            self.assertLess(closed, 5)

    def test_idle_tunnel_closed_at_read_timeout(self):  # E-M5-03
        with Proxy(policy=POLICY, env={"EGRESS_READ_TIMEOUT": "2"}) as proxy:
            status, sock = connect(proxy, "echo.example:443", CREDS)
            self.assertEqual(status, 200)
            sock.sendall(b"ping")
            self.assertEqual(sock.recv(4), b"ping")
            closed = _closed_after(sock, 10)
            sock.close()
            self.assertIsNotNone(closed)
            self.assertLess(closed, 4.5)

    @unittest.expectedFailure
    def test_active_tunnel_closed_at_client_lifetime(self):  # E-M5-02
        """KNOWN LIMITATION (verified on Squid 6.14): client_lifetime does not end an *active*
        CONNECT tunnel, so revocation applies to new tunnels only and an active tunnel lives
        until either side closes it. Documented in docs/OPERATIONS.md. If this test starts
        passing, Squid has begun enforcing the bound: update the docs and drop the marker."""
        with Proxy(policy=POLICY, env={"EGRESS_CLIENT_LIFETIME": "4", "EGRESS_READ_TIMEOUT": "60"}) as proxy:
            status, sock = connect(proxy, "echo.example:443", CREDS)
            self.assertEqual(status, 200)
            started = time.monotonic()
            alive_for = None
            try:
                while time.monotonic() - started < 15:
                    sock.sendall(b"x")
                    if sock.recv(1) != b"x":
                        break
                    time.sleep(0.25)
            except OSError:
                pass
            alive_for = time.monotonic() - started
            sock.close()
            self.assertLess(alive_for, 8, f"active tunnel outlived client_lifetime: {alive_for:.1f}s")
            self.assertGreater(alive_for, 3)

    def test_max_connections_per_client(self):  # E-M5-04
        with Proxy(policy=POLICY, env={"EGRESS_MAX_CONN_PER_CLIENT": "3"}) as proxy:
            held = []
            try:
                for _ in range(3):
                    status, sock = connect(proxy, "echo.example:443", CREDS, source="10.20.0.7")
                    self.assertEqual(status, 200)
                    held.append(sock)
                self.assertFalse(tunnel(proxy, "example.com:443", CREDS, source="10.20.0.7").established)
                self.assertTrue(tunnel(proxy, "example.com:443", CREDS, source="10.20.0.8").established,
                                "other clients must be unaffected")
            finally:
                for sock in held:
                    sock.close()
