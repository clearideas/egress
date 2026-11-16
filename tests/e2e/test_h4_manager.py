"""H-4: the Squid cache manager must not be reachable by tenants."""

import base64
import socket
import time

from tests.e2e.harness import PROXY_IP, Proxy, ProxyTestCase, raw_request

MANAGER_MARKERS = (b"Squid Object Cache", b"Connection information", b"Cached Usernames", b"username ",
                   b"Start Time", b"Cache Clients")


class CacheManagerTests(ProxyTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.proxy = Proxy(policy={"version": 1, "principals": {
            "demo": ["https://example.com", "http://example.com"], "bob": ["https://example.com"]}},
            users={"demo": "demo-password", "bob": "bob-password"}).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()

    def _auth(self, user="demo", password="demo-password") -> str:
        return "Proxy-Authorization: Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() + "\r\n"

    def _assert_no_manager(self, request: str) -> None:
        response = raw_request(self.proxy, request.encode())
        if "cache_object://" in request:
            self.assertNotEqual(response.status, 200, f"{request!r} -> {response.raw_head}")
        for marker in MANAGER_MARKERS:
            self.assertNotIn(marker, response.body)

    def test_manager_url_forms(self):  # E-H4-01..08
        a = self._auth()
        forms = [
            f"GET cache_object://example.com/info HTTP/1.1\r\nHost: example.com\r\n{a}Connection: close\r\n\r\n",
            f"GET cache_object://example.com:80/active_requests HTTP/1.1\r\nHost: example.com\r\n{a}Connection: close\r\n\r\n",
            f"GET cache_object://example.com:443/menu HTTP/1.1\r\nHost: example.com\r\n{a}Connection: close\r\n\r\n",
            f"GET http://example.com/squid-internal-mgr/info HTTP/1.1\r\nHost: example.com\r\n{a}Connection: close\r\n\r\n",
            f"GET http://{PROXY_IP}:{self.proxy.port}/squid-internal-mgr/info HTTP/1.1\r\nHost: {PROXY_IP}:{self.proxy.port}\r\n{a}Connection: close\r\n\r\n",
            f"GET /squid-internal-mgr/info HTTP/1.1\r\nHost: egress\r\n{a}Connection: close\r\n\r\n",
            f"GET /squid-internal-mgr/info HTTP/1.1\r\nHost: egress:{self.proxy.port}\r\nConnection: close\r\n\r\n",
            "GET cache_object://example.com:80/active_requests HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        ]
        for request in forms:
            with self.subTest(request=request.splitlines()[0]):
                self._assert_no_manager(request)

    def test_no_cross_tenant_disclosure(self):  # E-H4-09
        bob = socket.create_connection((PROXY_IP, self.proxy.port), timeout=5)
        try:
            bob.sendall(f"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n{self._auth('bob', 'bob-password')}\r\n".encode())
            bob.recv(1024)
            time.sleep(0.3)
            for action in ("active_requests", "username_cache", "client_list"):
                response = raw_request(self.proxy, (f"GET cache_object://example.com:80/{action} HTTP/1.1\r\n"
                                                    f"Host: example.com\r\n{self._auth()}Connection: close\r\n\r\n").encode())
                with self.subTest(action=action):
                    self.assertNotIn(b"bob", response.body)
                    self.assertNotEqual(response.status, 200)
        finally:
            bob.close()
