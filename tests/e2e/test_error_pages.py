"""The proxy's own refusals are readable: error pages, the X-Egress-Error header, and the error CA.

With EGRESS_ERROR_CA_* set, a sandbox that trusts the error CA sees a refused HTTPS request as a
clean HTTP error from the proxy (the certificate is minted for the requested host only to deliver
that error). The security properties checked here: allowed tunnels are never decrypted, SNI
violations still get no certificate at all, nothing more is served on a connection after the error,
and a destination cannot impersonate a proxy refusal.
"""

import base64
import socket
import ssl
import subprocess
import time

from tests.e2e.harness import PROXY_IP, Proxy, ProxyTestCase, http_request, tunnel, unique

CREDS = ("demo", "demo-password")
POLICY = {"version": 1, "principals": {"demo": ["https://example.com", "http://example.com"]}}


def make_ca(directory, name="egress error CA", days=30, ca=True):
    constraints = "critical,CA:TRUE,pathlen:0" if ca else "critical,CA:FALSE"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", str(directory / "error-ca.key"), "-out", str(directory / "error-ca.pem"),
                    "-days", str(days), "-subj", f"/CN={name}", "-addext", f"basicConstraints={constraints}",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign"], check=True, capture_output=True)
    return directory / "error-ca.pem", directory / "error-ca.key"


def connect_tls(proxy, host, context, *, request=b"", sni=None):
    """CONNECT, then TLS with ``context``; returns (tls socket, peer cert dict) or raises."""
    sock = socket.create_connection((PROXY_IP, proxy.port), timeout=10)
    sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nProxy-Authorization: Basic ".encode()
                 + base64.b64encode(":".join(CREDS).encode()) + b"\r\n\r\n")
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("proxy closed before answering CONNECT")
        head += chunk
    assert head.startswith(b"HTTP/1.1 200"), head
    try:
        return context.wrap_socket(sock, server_hostname=sni or host)
    except BaseException:
        sock.close()
        raise


def read_all(tls):
    data = b""
    try:
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            data += chunk
    except (ssl.SSLError, OSError):
        pass
    finally:
        tls.close()
    return data


def parse(data: bytes):
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    fields = {}
    for line in body.decode(errors="replace").splitlines():
        if ": " in line and not line.startswith("<"):
            key, value = line.split(": ", 1)
            fields[key.strip()] = value.strip()
    return int(lines[0].split()[1]), headers, fields, body


class ErrorCATests(ProxyTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.unresolvable = unique("nx-ca") + ".example"
        policy = {"version": 1, "principals": {"demo": POLICY["principals"]["demo"] + [f"https://{cls.unresolvable}"]}}
        cls.proxy = Proxy(policy=policy)
        cls.ca_cert, cls.ca_key = make_ca(cls.proxy.run_dir)
        cls.proxy.extra_env.update({"EGRESS_ERROR_CA_CERT_FILE": str(cls.ca_cert),
                                    "EGRESS_ERROR_CA_KEY_FILE": str(cls.ca_key)})
        cls.proxy.start()
        cls.trusting = ssl.create_default_context(cafile=str(cls.ca_cert))  # a sandbox that trusts the error CA

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proxy.stop()

    def test_denied_connect_is_a_clean_403(self):
        host = unique("refused") + ".example"
        tls = connect_tls(self.proxy, host, self.trusting)
        cert = tls.getpeercert()
        self.assertEqual(cert["subjectAltName"], (("DNS", host),))
        self.assertEqual(dict(x[0] for x in cert["issuer"])["commonName"], "egress error CA")
        tls.sendall(f"GET /x HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        status, headers, fields, _ = parse(read_all(tls))
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("x-egress-error"), "denied")
        self.assertEqual((fields["code"], fields["reason"]), ("denied", "origin_not_allowed"))
        self.assertNoDNS(host.split(".")[0])
        records = [r for r in self.proxy.access_records() if r.get("url") == f"{host}:443"]
        self.assertEqual(records[-1]["decision_id"], fields["decision_id"])

    def test_unresolvable_is_a_clean_503(self):
        tls = connect_tls(self.proxy, self.unresolvable, self.trusting)
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {self.unresolvable}\r\n\r\n".encode())
        status, headers, fields, _ = parse(read_all(tls))
        self.assertEqual(status, 503)
        self.assertEqual(headers.get("x-egress-error"), "unavailable")
        self.assertEqual((fields["code"], fields["destination"]), ("unresolved", "unresolved"))

    def test_allowed_tunnel_is_never_decrypted(self):
        before = len(self.fx.tls_origin.requests)
        # A client that trusts only the error CA must fail: the proxy never presents a minted
        # certificate for an allowed destination, so the peer is the real origin.
        with self.assertRaises(ssl.SSLCertVerificationError):
            connect_tls(self.proxy, "example.com", self.trusting)
        result = tunnel(self.proxy, "example.com:443", CREDS)
        self.assertTrue(result.established, result)
        self.assertIn("sni=example.com", result.body)
        self.assertEqual(len(self.fx.tls_origin.requests), before + 1)

    def test_one_bundle_serves_allowed_and_refused(self):
        """The documented sandbox setup: public roots *plus* the error CA in one trust bundle."""
        bundle = self.proxy.run_dir / "bundle.pem"
        bundle.write_text(self.fx.pki.ca.read_text() + self.ca_cert.read_text())  # "public roots" + error CA
        context = ssl.create_default_context(cafile=str(bundle))
        tls = connect_tls(self.proxy, "example.com", context)
        self.assertEqual(dict(x[0] for x in tls.getpeercert()["subject"])["commonName"], "example.com")
        tls.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        self.assertIn("tls origin", read_all(tls).decode(errors="replace"))
        refused = connect_tls(self.proxy, unique("bundle") + ".example", context)
        refused.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        status, headers, _, _ = parse(read_all(refused))
        self.assertEqual((status, headers.get("x-egress-error")), (403, "denied"))

    def test_sni_mismatch_gets_no_certificate(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
        with self.assertRaises((ssl.SSLError, OSError)):
            connect_tls(self.proxy, "example.com", context, sni="fronted.example")

    def test_nothing_more_is_served_after_the_error(self):
        before = (len(self.fx.tls_origin.requests), len(self.fx.http_origin.requests))
        host = unique("pipelined") + ".example"
        tls = connect_tls(self.proxy, host, self.trusting)
        # Pipeline a follow-up that the proxy must not act on (an allowed URL, absolute form).
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
                    "GET http://example.com/smuggled HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    "GET https://example.com/smuggled HTTP/1.1\r\nHost: example.com\r\n\r\n".encode())
        data = read_all(tls)
        self.assertEqual(data.count(b"HTTP/1.1 "), 1, data[:500])
        time.sleep(0.5)
        self.assertEqual((len(self.fx.tls_origin.requests), len(self.fx.http_origin.requests)), before)

    def test_plain_http_refusal_is_marked_and_destinations_cannot_forge_it(self):
        denied = http_request(self.proxy, f"http://{unique('plain')}.example/", CREDS)
        self.assertEqual(denied.status, 403)
        self.assertEqual(denied.headers.get("x-egress-error"), "denied")
        self.assertIn(b"code: denied", denied.body)
        allowed = http_request(self.proxy, "http://example.com/ok", CREDS)
        self.assertEqual(allowed.status, 200)
        self.assertNotIn("x-egress-error", allowed.headers)
        forged = http_request(self.proxy, "http://example.com/forge-egress-error", CREDS)
        self.assertEqual(forged.status, 403)  # the origin's own 403 ...
        self.assertNotIn("x-egress-error", forged.headers)  # ... without the proxy's marker

    def test_error_pages_do_not_name_the_product(self):
        denied = http_request(self.proxy, f"http://{unique('plain')}.example/", CREDS)
        self.assertNotIn(b"squid", denied.body.lower())
        self.assertNotIn("x-squid-error", denied.headers)


class ErrorCAConfigurationTests(ProxyTestCase):
    def test_startup_refuses_a_non_ca_certificate(self):
        proxy = Proxy(policy=POLICY)
        cert, key = make_ca(proxy.run_dir, ca=False)
        proxy.extra_env.update({"EGRESS_ERROR_CA_CERT_FILE": str(cert), "EGRESS_ERROR_CA_KEY_FILE": str(key)})
        with self.assertRaisesRegex(RuntimeError, "CA certificate"):
            proxy.start()

    def test_without_error_ca_denials_use_the_proxy_port_certificate(self):
        with Proxy(policy=POLICY) as proxy:
            result = tunnel(proxy, f"{unique('noca')}.example:443", CREDS)
            self.assertEqual((result.outcome, result.inner_status), ("denied_in_tls", 403), result)
            self.assertIn("code: denied", result.body)
