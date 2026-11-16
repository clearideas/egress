"""E2E harness: fixtures and a Squid launcher for tests running inside tests/e2e/run.sh.

Everything runs in a private network namespace with no route out. Tests assert on
*evidence*: the DNS query log, origin/listener connection logs, the arbiter request
log, Squid's access log and the helper audit log, not only on status codes.
"""

from __future__ import annotations

import base64
import http.server
import ipaddress
import itertools
import json
import os
import shutil
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
import unittest
from dataclasses import dataclass, field
from pathlib import Path

WORK = Path(os.environ.get("EGRESS_E2E_WORK", "/nonexistent"))
REPO = Path(os.environ.get("EGRESS_E2E_REPO", Path(__file__).resolve().parents[2]))
TARGET = os.environ.get("EGRESS_E2E_TARGET", "current")
BASELINE_DIR = Path(os.environ.get("EGRESS_E2E_BASELINE_DIR", "/nonexistent"))
IN_SANDBOX = "EGRESS_E2E_WORK" in os.environ
PYTHON = sys.executable

# Where Squid and its helpers run:
#   "bwrap"     (default) a nested bubblewrap sandbox as uid 1000, no capabilities, read-only root;
#   "container" directly, inside a test container built from the production image
#               (tests/docker/e2e.sh), as EGRESS_E2E_RUN_AS (the image's unprivileged user), using
#               the package *installed in the image*.
RUNTIME = os.environ.get("EGRESS_E2E_RUNTIME", "bwrap")
RUN_AS = os.environ.get("EGRESS_E2E_RUN_AS") or None


def _run_as_ids():
    if RUNTIME != "container" or not RUN_AS or os.geteuid() != 0:
        return None
    import pwd
    entry = pwd.getpwnam(RUN_AS)
    return entry.pw_uid, entry.pw_gid


def can_run_unprivileged() -> bool:
    """True when Squid and the entrypoint run as a non-root user in this runtime."""
    return RUNTIME == "bwrap" or _run_as_ids() is not None or os.geteuid() != 0 or bool(shutil.which("bwrap"))

PROXY_IP = "10.20.0.1"  # the proxy listens on all addresses; clients use this one
ORIGIN_V4 = "93.184.215.14"
ORIGIN2_V4 = "93.184.215.15"
ORIGIN_V6 = "2606:2800:220:1::14"
ECHO_V4 = "93.184.215.16"  # raw TCP echo on :443 ("echo.example"), for tunnel lifetime tests
INTERNAL_TARGETS = {
    # name -> address the proxy must never reach
    "imds.test": "169.254.169.254",
    "oci-imds.test": "192.0.0.192",
    "azure-wire.test": "168.63.129.16",
    "rfc1918.test": "10.0.0.5",
    "rfc1918-172.test": "172.16.0.9",
    "rfc1918-192.test": "192.168.1.9",
    "cgnat.test": "100.100.100.200",
    "bench.test": "198.18.0.1",
    "nat64-imds.test": "64:ff9b::a9fe:a9fe",
    "sixtofour.test": "2002:a9fe:a9fe::1",
    "teredo.test": "2001:0:a9fe:a9fe::1",
    "aws-imds-v6.test": "fd00:ec2::254",
}


def baseline() -> bool:
    return TARGET == "baseline"


def requires_current(reason: str = "feature added by the remediation"):
    """Skip in baseline mode: the pre-remediation code cannot express this scenario."""
    return unittest.skipIf(baseline(), reason)


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)


# ---------------------------------------------------------------------------
# PKI
# ---------------------------------------------------------------------------


class PKI:
    def __init__(self, directory: Path) -> None:
        self.dir = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.ca = directory / "ca.pem"
        _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(directory / "ca.key"),
              "-out", str(self.ca), "-days", "2", "-subj", "/CN=Egress E2E CA",
              "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign"])

    def issue(self, name: str, sans: list[str], *, client: bool = False) -> tuple[Path, Path]:
        key, csr, cert = self.dir / f"{name}.key", self.dir / f"{name}.csr", self.dir / f"{name}.pem"
        if cert.exists():
            return cert, key
        _run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr),
              "-subj", f"/CN={name}"])
        ext = self.dir / f"{name}.ext"
        usage = "clientAuth" if client else "serverAuth"
        ext.write_text(f"subjectAltName={','.join(sans)}\nextendedKeyUsage={usage}\n")
        _run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(self.ca), "-CAkey", str(self.dir / "ca.key"),
              "-CAcreateserial", "-out", str(cert), "-days", "2", "-extfile", str(ext)])
        return cert, key


# ---------------------------------------------------------------------------
# DNS stub
# ---------------------------------------------------------------------------


class DNSStub:
    """Authoritative-ish stub on 127.0.0.53:53 that logs every query.

    ``zone`` maps a name to a list of addresses, or to a list of lists that is
    cycled per query (for rebinding tests). TTL is configurable per name.
    """

    def __init__(self) -> None:
        self.zone: dict[str, list] = {}
        self.ttl: dict[str, int] = {}
        self.queries: list[tuple[str, int]] = []
        self._cycle: dict[str, itertools.cycle] = {}
        self._lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.53", 53))
        threading.Thread(target=self._serve, daemon=True).start()

    def set(self, name: str, addresses: list, ttl: int = 60) -> None:
        with self._lock:
            self.zone[name.lower()] = addresses
            self.ttl[name.lower()] = ttl
            self._cycle.pop(name.lower(), None)

    def set_sequence(self, name: str, answers: list[list[str]], ttl: int = 0) -> None:
        with self._lock:
            self.zone[name.lower()] = answers
            self.ttl[name.lower()] = ttl
            self._cycle[name.lower()] = itertools.cycle(answers)

    def queried(self, fragment: str) -> list[tuple[str, int]]:
        fragment = fragment.lower()
        with self._lock:
            return [q for q in self.queries if fragment in q[0]]

    def _answer_for(self, name: str) -> list[str] | None:
        with self._lock:
            if name in self._cycle:
                return next(self._cycle[name])
            return self.zone.get(name)

    def _serve(self) -> None:
        while True:
            data, addr = self.sock.recvfrom(4096)
            try:
                tid = struct.unpack(">H", data[:2])[0]
                i, labels = 12, []
                while data[i]:
                    labels.append(data[i + 1:i + 1 + data[i]].decode("ascii", "replace"))
                    i += 1 + data[i]
                qtype = struct.unpack(">H", data[i + 1:i + 3])[0]
                question = data[12:i + 5]
                name = ".".join(labels).lower()
                with self._lock:
                    self.queries.append((name, qtype))
                    ttl = self.ttl.get(name, 60)
                answer = self._answer_for(name)
                addresses = [ipaddress.ip_address(a) for a in (answer or [])]
                wanted = [a for a in addresses if (qtype == 1 and a.version == 4) or (qtype == 28 and a.version == 6)]
                records = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, ttl, len(a.packed)) + a.packed
                                   for a in wanted)
                rcode = 0 if answer is not None else 3
                self.sock.sendto(struct.pack(">HHHHHH", tid, 0x8180 | rcode, 1, len(wanted), 0, 0)
                                 + question + records, addr)
            except Exception:
                continue


# ---------------------------------------------------------------------------
# Origins and listeners
# ---------------------------------------------------------------------------


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 1024  # the default backlog (5) drops connections during burst tests


class HTTPOrigin:
    """Plain HTTP origin that records requests (method, path, host header, body size)."""

    def __init__(self, address: str, port: int = 80) -> None:
        self.requests: list[dict] = []
        origin = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                received = 0
                while received < length:
                    chunk = self.rfile.read(min(65536, length - received))
                    if not chunk:
                        break
                    received += len(chunk)
                origin.requests.append({"method": self.command, "path": self.path, "host": self.headers.get("Host"),
                                        "body_bytes": received, "headers": dict(self.headers)})
                body = f"origin {address} {self.command} {self.path}\n".encode()
                forged = "forge-egress-error" in self.path  # an origin impersonating a proxy refusal
                self.send_response(403 if forged else 200)
                if forged:
                    self.send_header("X-Egress-Error", "denied")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = _handle

            def log_message(self, *args) -> None:
                pass

        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        server_class = type("S", (_ThreadingHTTPServer,), {"address_family": family})
        self.server = server_class((address, port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


class TLSOrigin:
    """TLS origin on one address serving several names; records the SNI of every ClientHello
    and any bytes received on connections that never complete a TLS handshake."""

    def __init__(self, address: str, pki: PKI, names: list[str], port: int = 443) -> None:
        self.hellos: list[str | None] = []
        self.raw_connections: list[bytes] = []
        self.requests: list[dict] = []  # {"line", "headers": [(name, value), ...], "body_bytes"}
        self.connections = 0
        contexts = {}
        for name in names:
            cert, key = pki.issue(name, [f"DNS:{name}"])
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            contexts[name] = ctx
        default = contexts[names[0]]

        def sni_callback(sock, server_name, _ctx):
            self.hellos.append(server_name)
            sock.egress_sni = server_name
            if server_name in contexts:
                sock.context = contexts[server_name]

        for ctx in contexts.values():
            ctx.sni_callback = sni_callback
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((address, port))
        self.listener.listen(256)

        def handle(conn: socket.socket) -> None:
            self.connections += 1
            tls = None
            try:
                conn.settimeout(5)
                first = conn.recv(5, socket.MSG_PEEK)
                if not first or first[0] != 0x16:  # not a TLS handshake record
                    self.raw_connections.append(conn.recv(4096))
                    conn.close()
                    return
                tls = default.wrap_socket(conn, server_side=True)
                request = b""
                while b"\r\n\r\n" not in request:  # read the complete request (headers + body)
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    request += chunk
                head, _, body = request.partition(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1])
                while len(body) < length:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    body += chunk
                lines = head.decode("latin-1").split("\r\n")
                self.requests.append({"line": lines[0], "body_bytes": len(body),
                                      "headers": [tuple(x.strip() for x in l.split(":", 1)) for l in lines[1:] if ":" in l]})
                body = f"tls origin {address} sni={getattr(tls, 'egress_sni', None)}\n".encode()
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
                tls.close()
            except Exception:
                for sock in (tls, conn):
                    try:
                        if sock is not None:
                            sock.close()
                    except OSError:
                        pass

        def serve() -> None:
            while True:
                conn, _ = self.listener.accept()
                threading.Thread(target=handle, args=(conn,), daemon=True).start()

        threading.Thread(target=serve, daemon=True).start()


class EchoServer:
    """Raw TCP echo (keeps tunnels open as long as the proxy allows)."""

    def __init__(self, address: str, port: int = 443) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((address, port))
        self.sock.listen(64)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            conn, _ = self.sock.accept()
            threading.Thread(target=self._echo, args=(conn,), daemon=True).start()

    @staticmethod
    def _echo(conn: socket.socket) -> None:
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()


class StreamOrigin:
    """Plain-HTTP origin on ``address``:80 serving SSE (``/sse``) and a WebSocket echo (Upgrade)."""

    def __init__(self, address: str, events: int = 6, gap: float = 0.5) -> None:
        self.events, self.gap = events, gap
        self.upgrades: list[bytes] = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((address, 80))
        self.sock.listen(128)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            conn, _ = self.sock.accept()
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                request += chunk
            head = request.split(b"\r\n\r\n", 1)[0].lower()
            if b"upgrade: websocket" in head:
                self.upgrades.append(head)
                conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                             b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(b"ECHO:" + data)
            elif b" /sse" in head.split(b"\r\n", 1)[0]:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
                for index in range(self.events):
                    event = f"data: token{index}\n\n".encode()
                    conn.sendall(b"%x\r\n%s\r\n" % (len(event), event))
                    time.sleep(self.gap)
                conn.sendall(b"0\r\n\r\n")
            else:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nno-upgrade")
        except OSError:
            pass
        finally:
            conn.close()


class Listener:
    """Records every TCP connection attempt to an address (for 'must never reach' checks)."""

    def __init__(self, address: str, ports=(80, 443)) -> None:
        self.address = address
        self.hits: list[int] = []
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        for port in ports:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((address, port))
            sock.listen(64)
            threading.Thread(target=self._serve, args=(sock, port), daemon=True).start()

    def _serve(self, sock: socket.socket, port: int) -> None:
        while True:
            conn, _ = sock.accept()
            self.hits.append(port)
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nINTERNAL")
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Policy arbiter stub
# ---------------------------------------------------------------------------


class Arbiter:
    """Programmable policy API. ``respond(request_json) -> (status, body_dict|bytes)``."""

    def __init__(self, *, port: int, tls: tuple[Path, Path] | None = None, client_ca: Path | None = None,
                 latency: float = 0.0, respond=None) -> None:
        self.requests: list[dict] = []
        self.headers: list[dict] = []
        self.connections = 0
        self.latency = latency
        self.respond = respond or (lambda req: (200, {"decision": "allow", "requestId": req.get("requestId")}))
        arbiter = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            wbufsize = -1  # one write per response (avoids Nagle/delayed-ACK stalls on keep-alive)

            def setup(self) -> None:
                arbiter.connections += 1
                self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                super().setup()

            def do_POST(self) -> None:
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                try:
                    request = json.loads(raw)
                except ValueError:
                    request = {}
                arbiter.requests.append(request)
                arbiter.headers.append(dict(self.headers))
                if arbiter.latency:
                    time.sleep(arbiter.latency)
                status, body = arbiter.respond(request)
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    pass

            def log_message(self, *args) -> None:
                pass

        self.server = _ThreadingHTTPServer(("127.0.0.1", port), Handler)
        if tls is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*tls)
            if client_ca is not None:
                context.load_verify_locations(client_ca)
                context.verify_mode = ssl.CERT_REQUIRED
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.url = f"{'https' if tls else 'http'}://127.0.0.1:{port}/decide"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# ---------------------------------------------------------------------------
# Shared fixture set (started once per test process)
# ---------------------------------------------------------------------------


@dataclass
class Fixtures:
    pki: PKI
    dns: DNSStub
    http_origin: HTTPOrigin
    http_origin2: HTTPOrigin
    tls_origin: TLSOrigin
    tls_origin2: TLSOrigin
    tls_origin_v6: TLSOrigin
    echo: "EchoServer"
    stream: "StreamOrigin"
    internal: dict[str, Listener] = field(default_factory=dict)


_FIXTURES: Fixtures | None = None
_FIXTURE_LOCK = threading.Lock()


def fixtures() -> Fixtures:
    global _FIXTURES
    with _FIXTURE_LOCK:
        if _FIXTURES is None:
            if not IN_SANDBOX:
                raise unittest.SkipTest("E2E tests must run via tests/e2e/run.sh")
            pki = PKI(WORK / "pki")
            dns = DNSStub()
            dns.set("example.com", [ORIGIN_V4])
            dns.set("fronted.test", [ORIGIN_V4])
            dns.set("other.example", [ORIGIN2_V4])
            dns.set("v6only.example", [ORIGIN_V6])
            dns.set("echo.example", [ECHO_V4])
            dns.set("stream.example", [ECHO_V4])
            for name, address in INTERNAL_TARGETS.items():
                dns.set(name, [address])
            dns.set("mixed.test", [ORIGIN_V4, "169.254.169.254"])
            f = Fixtures(
                pki=pki,
                dns=dns,
                http_origin=HTTPOrigin(ORIGIN_V4),
                http_origin2=HTTPOrigin(ORIGIN2_V4),
                tls_origin=TLSOrigin(ORIGIN_V4, pki, ["example.com", "fronted.test"]),
                tls_origin2=TLSOrigin(ORIGIN2_V4, pki, ["other.example"]),
                tls_origin_v6=TLSOrigin(ORIGIN_V6, pki, ["v6only.example"]),
                echo=EchoServer(ECHO_V4),
                stream=StreamOrigin(ECHO_V4),
            )
            for address in set(INTERNAL_TARGETS.values()):
                f.internal[address] = Listener(address)
            _FIXTURES = f
        return _FIXTURES


# ---------------------------------------------------------------------------
# Squid launcher
# ---------------------------------------------------------------------------

_PORTS = itertools.count(3200)
_NAMES = itertools.count(1)


def _ncsa_path() -> str:
    for candidate in ("/usr/lib/squid/basic_ncsa_auth", "/usr/lib64/squid/basic_ncsa_auth",
                      "/usr/libexec/squid/basic_ncsa_auth"):
        if os.path.exists(candidate):
            return candidate
    raise RuntimeError("basic_ncsa_auth missing from toolchain")


class Proxy:
    """One Squid instance configured through EGRESS_* settings (or the baseline template)."""

    def __init__(self, *, policy: dict | None = None, policy_url: str | None = None, auth: str = "htpasswd",
                 users: dict[str, str] | None = None, env: dict[str, str] | None = None,
                 token_src: list[str] | None = None, entrypoint: bool = False, mutate_config=None,
                 monitor: bool = False) -> None:
        self.fx = fixtures()
        self.name = f"proxy{next(_NAMES)}"
        self.port = next(_PORTS)
        self.run_dir = WORK / self.name
        self.run_dir.mkdir(parents=True)
        os.chmod(self.run_dir, 0o777)
        self.policy = policy
        self.policy_url = policy_url
        self.auth = auth
        self.users = users or {"demo": "demo-password"}
        self.extra_env = env or {}
        self.token_src = token_src or ["127.0.0.0/8", "10.20.0.0/16"]
        self.entrypoint = entrypoint
        self.mutate_config = mutate_config  # test-only hook to simulate a broken configuration
        self.monitor = monitor
        self.monitor_port = self.port + 20000
        self.monitor_process: subprocess.Popen | None = None
        self.process: subprocess.Popen | None = None
        self.key = os.urandom(32)
        self.kid = "k1"
        self.signing_key = os.urandom(32)  # master key for signed-header mode
        self.signing_kid = "m1"

    # -- credentials ------------------------------------------------------

    def credentials(self, principal: str, *, src: list[str] | None = None, ttl: int = 300) -> tuple[str, str]:
        if self.auth == "token":
            from clearideas_egress.auth import mint_token
            return principal, mint_token(self.key, self.kid, principal, src or self.token_src, ttl)
        return principal, self.users[principal]

    # -- lifecycle ----------------------------------------------------------

    def _base_env(self) -> dict[str, str]:
        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            # container runtime: the package installed in the image (override only to simulate locally)
            "PYTHONPATH": str(REPO / "src") if RUNTIME == "bwrap" else os.environ.get("EGRESS_E2E_PACKAGE_PATH", ""),
            "PYTHONDONTWRITEBYTECODE": "1",
            "EGRESS_PYTHON": PYTHON,
            "EGRESS_RUN_DIR": str(self.run_dir / "run"),
            "EGRESS_LISTEN_PORT": str(self.port),
            "EGRESS_DNS_NAMESERVERS": "127.0.0.53",
            "EGRESS_ACCESS_LOG": f"stdio:{self.run_dir}/access.log",
            "EGRESS_CACHE_LOG": f"{self.run_dir}/cache.log",
            "EGRESS_AUDIT_LOG": f"{self.run_dir}/audit.jsonl",
            "EGRESS_SQUID_EXTRA_CONF": f"{self.run_dir}/harness.conf",
            "EGRESS_AUTH_MODE": self.auth,
            "EGRESS_ADMIN_PORT": str(self.port + 10000),
            "EGRESS_INSTANCE_ID": self.name,
            "EGRESS_DRAIN_SECONDS": "3",
        }
        if self.policy is not None:
            env["EGRESS_POLICY_FILE"] = str(self.run_dir / "policy.json")
        else:
            env["EGRESS_POLICY_URL"] = self.policy_url or ""
        if self.auth == "token":
            env["EGRESS_AUTH_KEYS_DIR"] = str(self.run_dir / "keys")
        elif self.auth == "signed-headers":
            env["EGRESS_SIGNING_KEYS_DIR"] = str(self.run_dir / "signing")
        else:
            env["EGRESS_HTPASSWD_FILE"] = str(self.run_dir / "passwd")
        env["EGRESS_UPSTREAM_CA_FILE"] = str(self.fx.pki.ca)
        env.update(self.extra_env)
        return env

    def _write_inputs(self) -> None:
        if self.policy is not None:
            (self.run_dir / "policy.json").write_text(json.dumps(self.policy))
        passwd = self.run_dir / "passwd"
        passwd.write_text("")
        for user, password in self.users.items():
            _run(["htpasswd", "-bB", str(passwd), user, password])
        keys = self.run_dir / "keys"
        keys.mkdir(exist_ok=True)
        (keys / f"{self.kid}.key").write_text(base64.b64encode(self.key).decode())
        signing = self.run_dir / "signing"
        signing.mkdir(exist_ok=True)
        (signing / f"{self.signing_kid}.key").write_text(base64.b64encode(self.signing_key).decode())
        (self.run_dir / "harness.conf").write_text(
            "# E2E harness only: ignore the host's /etc/hosts\nhosts_file none\n")

    def _baseline_config(self, env: dict[str, str]) -> Path:
        template = (BASELINE_DIR / "docker" / "squid.conf.template").read_text()
        config = (template.replace("__BASIC_AUTH_HELPER__", _ncsa_path())
                  .replace("/etc/squid/passwd", str(self.run_dir / "passwd"))
                  .replace("stdio:/var/log/squid/access.log", f"stdio:{self.run_dir}/access.log")
                  .replace("/usr/local/bin/clearideas-egress-acl", f"{PYTHON} -m clearideas_egress")
                  .replace("http_port 3128", f"http_port {self.port}"))
        config += (f"\n# E2E harness overrides\npid_filename {self.run_dir}/squid.pid\ncache_log {self.run_dir}/cache.log\n"
                   f"coredump_dir {self.run_dir}\ndns_nameservers 127.0.0.53\nhosts_file none\npinger_enable off\n"
                   "shutdown_lifetime 1 seconds\n")
        path = self.run_dir / "squid.conf"
        path.write_text(config)
        env["PYTHONPATH"] = str(BASELINE_DIR / "src")
        return path

    def _launch(self, argv: list[str], env: dict[str, str], stdout, stderr) -> subprocess.Popen:
        """Start a proxy-side process (Squid, renderer, monitor, entrypoint) in the configured runtime."""
        simulated = RUNTIME == "container" and os.geteuid() == 0 and _run_as_ids() is None
        if RUNTIME == "bwrap" or simulated:
            # (simulated: a local dry run of the container runtime inside the bwrap sandbox, where there is
            # no second uid to demote to — drop to uid 1000 the same way the bwrap runtime does)
            command = ["bwrap", "--ro-bind", "/", "/", "--bind", str(self.run_dir), str(self.run_dir),
                       "--dev", "/dev", "--proc", "/proc", "--unshare-user", "--uid", "1000", "--gid", "1000",
                       "--cap-drop", "ALL", "--die-with-parent", "--new-session", "--clearenv"]
            for key, value in env.items():
                command += ["--setenv", key, value]
            return subprocess.Popen(command + argv, stdout=stdout, stderr=stderr)
        ids = _run_as_ids()

        def demote() -> None:
            if ids is not None:
                os.setgroups([])
                os.setgid(ids[1])
                os.setuid(ids[0])

        clean_env = {key: value for key, value in env.items() if value != ""}
        return subprocess.Popen(argv, env=clean_env, stdout=stdout, stderr=stderr, preexec_fn=demote,
                                start_new_session=True)

    def _prepare_ownership(self) -> None:
        """In the container runtime, hand the run directory to the unprivileged proxy user."""
        ids = _run_as_ids()
        if ids is None:
            return
        for path in [self.run_dir, *self.run_dir.rglob("*")]:
            os.chown(path, *ids)

    def start(self) -> "Proxy":
        self._write_inputs()
        self._prepare_ownership()
        env = self._base_env()
        if baseline():
            config = self._baseline_config(env)
            argv = ["squid", "-N", "-f", str(config)]
        elif self.entrypoint:
            entrypoint = "/usr/local/bin/egress-entrypoint" if RUNTIME == "container" and \
                os.path.exists("/usr/local/bin/egress-entrypoint") else str(REPO / "docker" / "entrypoint.sh")
            argv = ["/bin/sh"] + (["-x"] if os.environ.get("EGRESS_E2E_TRACE") else []) + [entrypoint]
        else:
            render = self._launch([PYTHON, "-m", "clearideas_egress.render"], env, subprocess.PIPE, subprocess.PIPE)
            out, err = render.communicate(timeout=60)
            if render.returncode != 0:
                raise RuntimeError(f"render failed: {err.decode(errors='replace')}")
            if self.mutate_config is not None:
                conf = self.run_dir / "run" / "squid.conf"
                conf.write_text(self.mutate_config(conf.read_text()))
            argv = ["squid", "-N", "-f", str(self.run_dir / "run" / "squid.conf")]
        self.stderr_path = self.run_dir / "squid.stderr"
        with open(self.run_dir / "squid.stdout", "wb") as out, open(self.stderr_path, "wb") as err:
            self.process = self._launch(argv, env, out, err)
        if self.monitor and not self.entrypoint:
            monitor_env = {**env, "EGRESS_MONITOR_PORT": str(self.monitor_port), "EGRESS_MONITOR_ADDRESS": "127.0.0.1"}
            with open(self.run_dir / "monitor.log", "wb") as log:
                self.monitor_process = self._launch([PYTHON, "-m", "clearideas_egress", "monitor"], monitor_env, log, log)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"squid exited early: {self.diagnostics()}")
            try:
                socket.create_connection((PROXY_IP, self.port), timeout=0.2).close()
                time.sleep(0.3)  # let helpers spawn
                return self
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"squid did not start: {self.diagnostics()}")

    def stop(self) -> None:
        for process in (self.monitor_process, self.process):
            if process is None:
                continue
            if RUNTIME != "bwrap":
                try:
                    os.killpg(process.pid, signal.SIGKILL)  # Squid and its helpers share the session
                except (ProcessLookupError, PermissionError):
                    pass
            if process.poll() is None:
                process.send_signal(signal.SIGKILL)
            process.wait(timeout=10)

    def squid_pid(self) -> int:
        return int((self.run_dir / "run" / "squid.pid").read_text().split()[0])

    def monitor_pid(self) -> int:
        """PID of the monitor process itself (not its bwrap wrapper)."""
        if RUNTIME == "container" and self.monitor_process is not None:
            return self.monitor_process.pid
        marker = f"EGRESS_MONITOR_PORT={self.monitor_port}".encode()
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                if b"clearideas_egress\0monitor" in (entry / "cmdline").read_bytes() and \
                        marker in (entry / "environ").read_bytes():
                    return int(entry.name)
            except OSError:
                continue
        raise RuntimeError("monitor process not found")

    def monitor_get(self, path: str) -> tuple[int, str]:
        import http.client
        for _ in range(50):
            try:
                connection = http.client.HTTPConnection("127.0.0.1", self.monitor_port, timeout=5)
                connection.request("GET", path)
                response = connection.getresponse()
                return response.status, response.read().decode()
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("monitor not reachable")

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def __enter__(self) -> "Proxy":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- evidence -------------------------------------------------------------

    def diagnostics(self) -> str:
        parts = []
        for name in ("squid.stderr", "cache.log"):
            path = self.run_dir / name
            if path.exists():
                parts.append(f"--- {name}\n" + path.read_text(errors="replace")[-4000:])
        return "\n".join(parts)

    def access_records(self) -> list[dict]:
        path = self.run_dir / "access.log"
        if not path.exists():
            return []
        records = []
        for line in path.read_text(errors="replace").splitlines():
            try:
                records.append(json.loads(line))
            except ValueError:
                records.append({"raw": line})
        return records

    def audit_records(self, event: str | None = None) -> list[dict]:
        path = self.run_dir / "audit.jsonl"
        if not path.exists():
            return []
        records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        return [r for r in records if event is None or r.get("event") == event]

    def wait_for(self, predicate, timeout: float = 5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.05)
        return predicate()


class HAProxy:
    """TCP load balancer in front of Squid, speaking PROXY protocol v2 to it.

    ``tls`` = (cert, key) terminates TLS from clients (an HTTPS proxy endpoint).
    """

    _ports = itertools.count(18500)

    def __init__(self, backend_port: int, *, tls: tuple[Path, Path] | None = None, send_proxy: bool = True) -> None:
        self.port = next(self._ports)
        self.dir = WORK / f"haproxy{self.port}"
        self.dir.mkdir()
        bind = f"bind 10.30.0.1:{self.port}"
        if tls is not None:
            bundle = self.dir / "bundle.pem"
            bundle.write_text(Path(tls[0]).read_text() + Path(tls[1]).read_text())
            bind += f" ssl crt {bundle}"
        proxy_opt = " send-proxy-v2" if send_proxy else ""
        (self.dir / "haproxy.cfg").write_text(
            "global\n  maxconn 4000\n"
            "defaults\n  mode tcp\n  timeout connect 5s\n  timeout client 60s\n  timeout server 60s\n"
            f"frontend fe\n  {bind}\n  default_backend be\n"
            f"backend be\n  server squid {PROXY_IP}:{backend_port}{proxy_opt} source 10.30.0.1\n")
        with open(self.dir / "stderr", "wb") as stderr:
            self.process = subprocess.Popen(["haproxy", "-db", "-f", str(self.dir / "haproxy.cfg")],
                                            stdout=subprocess.DEVNULL, stderr=stderr)
        for _ in range(100):
            try:
                socket.create_connection(("10.30.0.1", self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)

    def close(self) -> None:
        self.process.kill()
        self.process.wait(timeout=5)


class RedisServer:
    """redis-server on a loopback port for cluster-wide nonce tests."""

    _ports = itertools.count(16390)

    def __init__(self) -> None:
        self.port = next(self._ports)
        self.dir = WORK / f"redis{self.port}"
        self.dir.mkdir()
        self.url = f"redis://127.0.0.1:{self.port}/0"
        self.start()

    def start(self) -> None:
        self.process = subprocess.Popen(
            ["redis-server", "--port", str(self.port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no",
             "--dir", str(self.dir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("redis did not start")

    def stop(self) -> None:
        self.process.kill()
        self.process.wait(timeout=5)


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


@dataclass
class Response:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes
    raw_head: str = ""


def _auth_header(credentials: tuple[str, str] | None) -> str:
    if credentials is None:
        return ""
    token = base64.b64encode(f"{credentials[0]}:{credentials[1]}".encode()).decode()
    return f"Proxy-Authorization: Basic {token}\r\n"


def open_proxy(proxy: Proxy, source: str | None = None, timeout: float = 10.0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if source:
            sock.bind((source, 0))
        sock.connect(getattr(proxy, "endpoint", None) or (PROXY_IP, proxy.port))
    except OSError:
        sock.close()
        raise
    return sock


def _read_head(sock: socket.socket) -> tuple[str, bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    return head.decode("latin-1"), rest


def _parse_head(head: str) -> tuple[int, str, dict[str, str]]:
    lines = head.split("\r\n")
    parts = lines[0].split(" ", 2) if lines and lines[0] else ["", "0", ""]
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        status = 0
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, parts[2] if len(parts) > 2 else "", headers


def raw_request(proxy: Proxy, data: bytes, *, source: str | None = None, timeout: float = 10.0) -> Response:
    try:
        sock = open_proxy(proxy, source, timeout)
    except OSError as error:
        return Response(0, type(error).__name__, {}, b"")
    try:
        sock.sendall(data)
        head, rest = _read_head(sock)
        status, reason, headers = _parse_head(head)
        body = rest
        length = headers.get("content-length")
        try:
            if length is not None:
                while len(body) < int(length):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    body += chunk
            elif status and headers.get("transfer-encoding", "").lower() == "chunked" or headers.get("connection") == "close":
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    body += chunk
        except (socket.timeout, OSError):
            pass
        return Response(status, reason, headers, body, head)
    except (socket.timeout, ConnectionError) as error:
        return Response(0, type(error).__name__, {}, b"")
    finally:
        sock.close()


def http_request(proxy: Proxy, url: str, credentials: tuple[str, str] | None, *, method: str = "GET",
                 body: bytes = b"", source: str | None = None, extra_headers: str = "", timeout: float = 10.0) -> Response:
    host = url.split("://", 1)[1].split("/", 1)[0]
    data = (f"{method} {url} HTTP/1.1\r\nHost: {host}\r\n{_auth_header(credentials)}{extra_headers}"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    return raw_request(proxy, data, source=source, timeout=timeout)


def connect(proxy: Proxy, target: str, credentials: tuple[str, str] | None, *, source: str | None = None,
            timeout: float = 10.0) -> tuple[int, socket.socket | None]:
    """Send CONNECT target; returns (status, socket-if-established)."""
    try:
        sock = open_proxy(proxy, source, timeout)
    except OSError:
        return 0, None
    try:
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{_auth_header(credentials)}\r\n".encode())
        head, _ = _read_head(sock)
    except (socket.timeout, OSError):
        sock.close()
        return 0, None
    status, _, _ = _parse_head(head)
    if status != 200:
        sock.close()
        return status, None
    return status, sock


def tls_get(sock: socket.socket, sni: str | None, cafile: Path, *, verify_name: str | None = None) -> str:
    """TLS handshake over an established tunnel and a GET; returns the body or raises."""
    context = ssl.create_default_context(cafile=str(cafile))
    if sni is None:
        context.check_hostname = False
    tls = context.wrap_socket(sock, server_hostname=sni)
    tls.sendall(f"GET / HTTP/1.1\r\nHost: {verify_name or sni or 'x'}\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while True:
        chunk = tls.recv(65536)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace").split("\r\n\r\n", 1)[-1]


@dataclass
class TunnelResult:
    """Classified outcome of CONNECT + TLS through the proxy.

    outcome:
      ``refused``      CONNECT answered with a non-200 status (``status``)
      ``denied_in_tls`` CONNECT got 200, but the TLS peer was the proxy's own port
                        certificate delivering an error (Squid "delayed error");
                        ``inner_status`` holds the HTTP status inside TLS
      ``terminated``   CONNECT got 200, but the proxy closed the connection during
                        the TLS handshake (SNI/TLS policy violation)
      ``established``  TLS completed with a certificate that is not the proxy's,
                        i.e. the tunnel reached an origin; ``body`` is the response
    """

    outcome: str
    status: int
    inner_status: int = 0
    body: str = ""
    error: str = ""

    @property
    def established(self) -> bool:
        return self.outcome == "established"


def _proxy_port_cert_der(proxy: "Proxy") -> bytes | None:
    path = proxy.run_dir / "run" / "tls-port.pem"
    if not path.exists():
        return None
    return ssl.PEM_cert_to_DER_cert(path.read_text())


def tunnel(proxy: "Proxy", target: str, credentials: tuple[str, str] | None, *, sni: str | None = "",
           source: str | None = None, payload: bytes | None = None, timeout: float = 10.0) -> TunnelResult:
    """CONNECT to ``target`` and attempt TLS with ``sni`` (default: the target host; None: no SNI).

    With ``payload`` set, raw bytes are sent instead of a TLS ClientHello.
    """
    status, sock = connect(proxy, target, credentials, source=source, timeout=timeout)
    if status != 200 or sock is None:
        return TunnelResult("refused", status)
    host = target.rsplit(":", 1)[0].strip("[]")
    if sni == "":
        sni = host
    try:
        if payload is not None:
            sock.sendall(payload)
            data = b""
            try:
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, OSError):
                pass
            if not data:
                return TunnelResult("terminated", status)
            return TunnelResult("established", status, body=data.decode(errors="replace"))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            tls = context.wrap_socket(sock, server_hostname=sni)
        except (ssl.SSLError, OSError) as error:
            return TunnelResult("terminated", status, error=f"{type(error).__name__}: {error}")
        peer = tls.getpeercert(binary_form=True)
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {sni or host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        try:
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                data += chunk
        except (ssl.SSLError, OSError):
            pass
        tls.close()
        head, _, body = data.decode(errors="replace").partition("\r\n\r\n")
        inner_status, _, _ = _parse_head(head)
        if peer is not None and peer == _proxy_port_cert_der(proxy):
            return TunnelResult("denied_in_tls", status, inner_status=inner_status, body=body)
        return TunnelResult("established", status, inner_status=inner_status, body=body)
    finally:
        sock.close()


def signing_profile(proxy: "Proxy"):
    from clearideas_egress.signing import SigningProfile
    return SigningProfile.from_env(proxy.extra_env)


def signed_headers(proxy: "Proxy", method: str, url: str, identity: dict[str, str] | None = None, *,
                   run_key: bytes | None = None, timestamp: int | None = None, nonce: str | None = None,
                   kid: str | None = None) -> dict[str, str]:
    """Headers the sandbox egress helper would add (library reference signer)."""
    from clearideas_egress.signing import Destination, derive_run_key, sign_request
    profile = signing_profile(proxy)
    identity = identity or {profile.attributes[0]: "run-1"}
    ordered = {name: identity[name] for name in profile.attributes}
    key = run_key if run_key is not None else derive_run_key(proxy.signing_key, ordered)
    if method == "CONNECT":
        host, port = url.rsplit(":", 1)
        destination = Destination.build("CONNECT", "", host.strip("[]"), port, "")
    else:
        scheme, rest = url.split("://", 1)
        authority, _, path = rest.partition("/")
        host, _, port = authority.partition(":")
        destination = Destination.build(method, scheme, host, port or (443 if scheme == "https" else 80), "/" + path)
    return sign_request(key, kid or proxy.signing_kid, profile, ordered, destination, timestamp=timestamp, nonce=nonce)


def signed_request(proxy: "Proxy", method: str, url: str, headers: dict[str, str] | None = None, *,
                   body: bytes = b"", extra: str = "", source: str | None = None, timeout: float = 10.0,
                   **sign_kwargs) -> Response:
    headers = headers if headers is not None else signed_headers(proxy, method, url, **sign_kwargs)
    header_text = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    return http_request(proxy, url, None, method=method, body=body, source=source,
                        extra_headers=header_text + extra, timeout=timeout)


def unique(label: str) -> str:
    return f"{label}-{os.urandom(4).hex()}"


class ProxyTestCase(unittest.TestCase):
    """Base class: one fixture set per process, helpers for common assertions."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.fx = fixtures()

    def assertNoDNS(self, fragment: str) -> None:
        time.sleep(0.2)
        queries = self.fx.dns.queried(fragment)
        self.assertEqual(queries, [], f"proxy resolved a name it should not have: {queries}")

    def assertNotReached(self, address: str) -> None:
        time.sleep(0.2)
        self.assertEqual(self.fx.internal[address].hits, [], f"proxy connected to internal address {address}")
