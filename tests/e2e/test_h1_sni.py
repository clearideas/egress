"""H-1: CONNECT tunnels must carry TLS whose SNI names the authorized host."""

import ssl
import time

from tests.e2e.harness import (ORIGIN2_V4, Arbiter, Proxy, ProxyTestCase, connect, requires_current, tunnel)

CREDS = ("demo", "demo-password")
POLICY = {"version": 2, "principals": {"demo": {"origins": [
    "https://example.com",
    f"https://{ORIGIN2_V4}",
    {"origin": "https://other.example", "allowNonTls": True},
]}}}


def fragmented_tls_get(sock, sni: str, cafile, chunk: int = 7, delay: float = 0.01) -> str:
    """TLS over ``sock`` with the ClientHello split into tiny TCP writes."""
    context = ssl.create_default_context(cafile=str(cafile))
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_hostname=sni)
    first = True
    while True:
        try:
            tls.do_handshake()
            break
        except ssl.SSLWantReadError:
            data = outgoing.read()
            if first:
                for i in range(0, len(data), chunk):
                    sock.sendall(data[i:i + chunk])
                    time.sleep(delay)
                first = False
            elif data:
                sock.sendall(data)
            received = sock.recv(65536)
            if not received:
                raise ConnectionError("closed during handshake")
            incoming.write(received)
    tls.write(f"GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode())
    sock.sendall(outgoing.read())
    body = b""
    while True:
        try:
            body += tls.read(65536)
        except ssl.SSLWantReadError:
            received = sock.recv(65536)
            if not received:
                break
            incoming.write(received)
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            break
    return body.decode(errors="replace")


@requires_current("SNI enforcement")
class SNIEnforcementTests(ProxyTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.proxy = Proxy(policy=POLICY).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()

    def test_matching_sni_is_spliced(self):  # E-H1-01
        result = tunnel(self.proxy, "example.com:443", CREDS)
        self.assertTrue(result.established, result)
        self.assertIn("sni=example.com", result.body)

    def test_domain_fronting_is_terminated(self):  # E-H1-02
        hellos_before = list(self.fx.tls_origin.hellos)
        result = tunnel(self.proxy, "example.com:443", CREDS, sni="fronted.test")
        self.assertEqual(result.outcome, "terminated", result)
        time.sleep(0.2)
        self.assertNotIn("fronted.test", self.fx.tls_origin.hellos[len(hellos_before):])
        self.assertIn("sni_mismatch", [r.get("reason") for r in self.proxy.audit_records("tls_check")])

    def test_non_tls_is_terminated(self):  # E-H1-03
        raw_before = len(self.fx.tls_origin.raw_connections)
        result = tunnel(self.proxy, "example.com:443", CREDS, payload=b"SSH-2.0-OpenSSH_9.6\r\n")
        self.assertEqual(result.outcome, "terminated", result)
        time.sleep(0.2)
        self.assertEqual(len(self.fx.tls_origin.raw_connections), raw_before)

    def test_allow_non_tls_origin(self):  # E-H1-04
        raw_before = len(self.fx.tls_origin2.raw_connections)
        tunnel(self.proxy, "other.example:443", CREDS, payload=b"SSH-2.0-OpenSSH_9.6\r\n")
        got = self.proxy.wait_for(lambda: self.fx.tls_origin2.raw_connections[raw_before:])
        self.assertTrue(got and got[0].startswith(b"SSH-2.0"), got)

    def test_missing_sni_to_hostname_is_terminated(self):  # E-H1-05
        result = tunnel(self.proxy, "example.com:443", CREDS, sni=None)
        self.assertEqual(result.outcome, "terminated", result)
        self.assertIn("sni_missing", [r.get("reason") for r in self.proxy.audit_records("tls_check")])

    def test_ip_literal_without_sni(self):  # E-H1-06
        result = tunnel(self.proxy, f"{ORIGIN2_V4}:443", CREDS, sni=None)
        self.assertTrue(result.established, result)

    def test_ip_literal_with_hostname_sni_is_terminated(self):
        result = tunnel(self.proxy, f"{ORIGIN2_V4}:443", CREDS, sni="other.example")
        self.assertEqual(result.outcome, "terminated", result)

    def test_sni_case_insensitive(self):  # E-H1-07
        result = tunnel(self.proxy, "EXAMPLE.com:443", CREDS, sni="example.COM")
        self.assertTrue(result.established, result)

    def test_fragmented_client_hello(self):  # E-H1-08
        status, sock = connect(self.proxy, "example.com:443", CREDS)
        self.assertEqual(status, 200)
        try:
            body = fragmented_tls_get(sock, "example.com", self.fx.pki.ca)
        finally:
            sock.close()
        self.assertIn("sni=example.com", body)

    def test_fragmented_fronting_still_terminated(self):
        status, sock = connect(self.proxy, "example.com:443", CREDS)
        self.assertEqual(status, 200)
        with self.assertRaises((ConnectionError, ssl.SSLError, OSError)):
            try:
                fragmented_tls_get(sock, "fronted.test", self.fx.pki.ca)
            finally:
                sock.close()

    def test_access_log_records_sni(self):
        tunnel(self.proxy, "example.com:443", CREDS)
        records = self.proxy.wait_for(lambda: [r for r in self.proxy.access_records()
                                               if r.get("sni") == "example.com" and r.get("result") == "TCP_TUNNEL"])
        self.assertTrue(records)


@requires_current("arbiter allowNonTls")
class ArbiterNonTLSTests(ProxyTestCase):
    def test_arbiter_can_mark_origin_non_tls(self):
        def respond(req):
            return 200, {"decision": "allow", "requestId": req["requestId"],
                         "allowNonTls": req["host"] == "other.example"}
        arbiter = Arbiter(port=18082, respond=respond)
        try:
            with Proxy(policy_url=arbiter.url) as proxy:
                before = len(self.fx.tls_origin2.raw_connections)
                tunnel(proxy, "other.example:443", CREDS, payload=b"SSH-2.0-test\r\n")
                self.assertTrue(proxy.wait_for(lambda: self.fx.tls_origin2.raw_connections[before:]))
                raw_before = len(self.fx.tls_origin.raw_connections)
                result = tunnel(proxy, "example.com:443", CREDS, payload=b"SSH-2.0-test\r\n")
                self.assertEqual(result.outcome, "terminated")
                self.assertEqual(len(self.fx.tls_origin.raw_connections), raw_before)
        finally:
            arbiter.close()


class LegacyModeTests(ProxyTestCase):
    """Documents what EGRESS_TLS_ENFORCEMENT=off (and the baseline) permit."""

    def test_fronting_possible_without_enforcement(self):
        env = {} if False else {"EGRESS_TLS_ENFORCEMENT": "off"}
        with Proxy(policy={"version": 1, "principals": {"demo": ["https://example.com"]}}, env=env) as proxy:
            result = tunnel(proxy, "example.com:443", CREDS, sni="fronted.test")
            self.assertTrue(result.established, "without SNI enforcement fronting is expected to work")
