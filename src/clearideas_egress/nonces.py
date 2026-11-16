"""Cluster-wide nonce replay protection backed by Redis (standard library only).

Each signed request carries a nonce. With several proxy replicas behind a load
balancer, a replayed request can land on a different replica, so nonces must be
remembered in a store shared by all replicas. ``claim()`` runs the atomic Redis
command ``SET <key> 1 NX PX <ttl>``: the first claim of a nonce succeeds and every
later claim of the same nonce fails, on any replica, until the entry expires (at
least twice the accepted clock skew, so no replay fits inside the window).

If Redis is unavailable the caller must deny (fail closed).
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import threading
import urllib.parse


class NonceStoreError(RuntimeError):
    pass


class RedisNonceStore:
    def __init__(self, url: str, *, timeout_seconds: float = 0.25, ca_file: str | None = None,
                 prefix: str = "clearideas-egress:nonce:") -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("redis", "rediss") or not parsed.hostname:
            raise ValueError("nonce store URL must be redis://[user:password@]host:port/db or rediss://...")
        self.host = parsed.hostname
        self.port = parsed.port or 6379
        self.username = urllib.parse.unquote(parsed.username) if parsed.username else None
        self.password = urllib.parse.unquote(parsed.password) if parsed.password else None
        db = (parsed.path or "/0").lstrip("/") or "0"
        if not db.isdigit():
            raise ValueError("Redis database must be a number")
        self.db = int(db)
        self.timeout = timeout_seconds
        self.prefix = prefix
        self._tls: ssl.SSLContext | None = None
        if parsed.scheme == "rediss":
            self._tls = ssl.create_default_context(cafile=ca_file)
        self._local = threading.local()

    # -- RESP ---------------------------------------------------------------

    @staticmethod
    def _encode(*parts: str | bytes) -> bytes:
        out = [b"*%d\r\n" % len(parts)]
        for part in parts:
            data = part.encode("utf-8") if isinstance(part, str) else part
            out.append(b"$%d\r\n%s\r\n" % (len(data), data))
        return b"".join(out)

    @staticmethod
    def _read_reply(stream) -> object:
        line = stream.readline(65536)
        if not line.endswith(b"\r\n"):
            raise NonceStoreError("connection closed")
        kind, body = line[:1], line[1:-2]
        if kind == b"+":
            return body.decode()
        if kind == b"-":
            raise NonceStoreError(f"redis error: {body.decode(errors='replace')[:100]}")
        if kind == b":":
            return int(body)
        if kind == b"$":
            length = int(body)
            if length < 0:
                return None
            data = stream.read(length + 2)
            return data[:-2]
        raise NonceStoreError("unexpected reply")

    def _connect(self):
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self._tls is not None:
            sock = self._tls.wrap_socket(sock, server_hostname=self.host)
        sock.settimeout(self.timeout)
        stream = sock.makefile("rb")
        try:
            if self.password is not None:
                auth = ("AUTH", self.username, self.password) if self.username else ("AUTH", self.password)
                sock.sendall(self._encode(*auth))
                self._read_reply(stream)
            if self.db:
                sock.sendall(self._encode("SELECT", str(self.db)))
                self._read_reply(stream)
        except BaseException:
            stream.close()
            sock.close()
            raise
        return sock, stream

    def _command(self, *parts: str) -> object:
        for attempt in (0, 1):
            connection = getattr(self._local, "connection", None)
            try:
                if connection is None:
                    connection = self._connect()
                    self._local.connection = connection
                sock, stream = connection
                sock.sendall(self._encode(*parts))
                return self._read_reply(stream)
            except NonceStoreError as error:
                if "redis error" in str(error):
                    raise
                self._drop()
                if attempt:
                    raise
            except (OSError, ValueError) as error:
                self._drop()
                if attempt:
                    raise NonceStoreError(f"redis unavailable: {type(error).__name__}") from error
        raise NonceStoreError("redis unavailable")

    def _drop(self) -> None:
        connection = getattr(self._local, "connection", None)
        self._local.connection = None
        if connection is not None:
            for part in (connection[1], connection[0]):  # the reader holds the socket open too
                try:
                    part.close()
                except OSError:
                    pass

    def close(self) -> None:
        """Close this thread's connection (others close when their threads end)."""
        self._drop()

    # -- API ----------------------------------------------------------------

    def claim(self, scope: str, nonce: str, ttl_ms: int) -> bool:
        """True if this (scope, nonce) was never seen before; False for a replay."""
        digest = hashlib.sha256(f"{scope}\n{nonce}".encode("utf-8")).hexdigest()
        reply = self._command("SET", self.prefix + digest, "1", "NX", "PX", str(int(ttl_ms)))
        return reply == "OK"

    def ping(self) -> bool:
        return self._command("PING") == "PONG"
