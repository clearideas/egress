"""HTTP(S) policy-arbiter backend.

Design constraints (see the security review, H-3 / M-1 / L-6):

* **Overall deadline.** Every decision completes within ``timeout_seconds`` of wall
  time (default 15 s), covering waiting for capacity, DNS, connect, TLS, retries
  and the response. When it passes, the waiting side shuts the socket down so a
  slow-drip server cannot pin a worker, and the decision is ``backend_timeout``.
  Slow answers are waited for (no per-attempt cutoff unless ``attempt_timeout``
  is set): abandoning and re-sending work to an overloaded API makes it slower.
* **Retries.** Connection failures and HTTP 429/500/502/503/504 are retried up to
  ``retries`` times (default 3) with exponential backoff and full jitter, honoring
  ``Retry-After``, all inside the deadline. Every attempt carries the same
  ``requestId`` so the API can de-duplicate.
* **Bounded concurrency.** At most ``max_in_flight`` calls run at once; further
  calls wait for a slot until the deadline (``backend_saturated`` after that).
* **Keep-alive.** Connections are pooled and reused, avoiding a TCP+TLS handshake
  per decision.
* **No proxies.** ``http.client`` never consults ``HTTP(S)_PROXY`` environment
  variables, so the bearer token and decisions cannot be diverted.
* **Explicit allow only.** HTTP 200 with ``{"decision": "allow"}`` (and a matching
  ``requestId`` when one is echoed or required) is the only allow.
"""

from __future__ import annotations

import concurrent.futures
import http.client
import json
import queue
import random
import re
import socket
import ssl
import threading
import time
import urllib.parse
import uuid
import weakref
from typing import Callable

from .policy import (
    ALLOWED,
    BACKEND_DENIED,
    BACKEND_ERROR,
    BACKEND_SATURATED,
    BACKEND_TIMEOUT,
    TLS_OPTIONAL_NOTE,
    ACLRequest,
    Decision,
    PolicyError,
    WEBSOCKET_NOTE,
    normalize_host,
)
import dataclasses

MAX_RESPONSE_BYTES = 65536
_METHOD = re.compile(r"^[A-Z]{1,20}$")
RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
BACKOFF_BASE_SECONDS = 0.1
BACKOFF_CAP_SECONDS = 2.0
_ARBITER_REASON = re.compile(r"^[a-z0-9_.-]{1,64}$")

# transport(body, headers, deadline_monotonic, abort_holder) -> (status, body_bytes, retry_after_seconds | None)
Transport = Callable[[bytes, dict, float, "_AbortHolder"], "tuple[int, bytes, float | None]"]


def _shutdown(executor: concurrent.futures.Executor, idle: queue.Queue) -> None:
    executor.shutdown(wait=False, cancel_futures=True)
    while True:
        try:
            idle.get_nowait().close()
        except queue.Empty:
            break


class _AbortHolder:
    """Lets the waiting thread abort the socket a worker is blocked on."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._connection: http.client.HTTPConnection | None = None
        self.aborted = False

    def attach(self, connection: http.client.HTTPConnection | None) -> None:
        with self._lock:
            self._connection = connection
            if self.aborted:
                self._shutdown()

    def abort(self) -> None:
        with self._lock:
            self.aborted = True
            self._shutdown()

    def _shutdown(self) -> None:
        connection = self._connection
        sock = getattr(connection, "sock", None) if connection is not None else None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class HTTPPolicy:
    """POST each decision to a policy arbiter; never cache approvals here."""

    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        timeout_seconds: float = 15.0,
        attempt_timeout: float | None = None,
        retries: int = 3,
        ca_file: str | None = None,
        client_cert_file: str | None = None,
        client_key_file: str | None = None,
        max_in_flight: int = 64,
        require_request_id: bool = False,
        transport: Transport | None = None,
    ) -> None:
        try:
            parsed = urllib.parse.urlsplit(url)
            host = normalize_host(parsed.hostname or "")
            # Cleartext only to literal loopback addresses; a DNS name such as
            # "localhost" could be remapped.
            loopback = host in {"127.0.0.1", "::1"}
            if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
                raise PolicyError("policy API must use HTTPS or local loopback HTTP")
            if host is None or parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise PolicyError("invalid policy API URL")
            if not loopback and not token:
                raise PolicyError("remote policy API requires a bearer token")
            if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 120:
                raise PolicyError("invalid policy API timeout")
            if attempt_timeout is not None and (isinstance(attempt_timeout, bool) or
                                                not isinstance(attempt_timeout, (int, float)) or
                                                not 0 < attempt_timeout <= timeout_seconds):
                raise PolicyError("invalid policy API attempt timeout")
            if isinstance(retries, bool) or not isinstance(retries, int) or not 0 <= retries <= 10:
                raise PolicyError("invalid policy API retries")
            if token is not None and (not token or any(ord(c) < 33 or ord(c) > 126 for c in token)):
                raise PolicyError("invalid bearer token")
            if not isinstance(max_in_flight, int) or not 1 <= max_in_flight <= 1024:
                raise PolicyError("invalid max_in_flight")
            if (client_cert_file is None) != (client_key_file is None):
                raise PolicyError("client certificate and key must be configured together")
            port = parsed.port
        except (TypeError, ValueError) as error:
            if isinstance(error, PolicyError):
                raise
            raise PolicyError("invalid policy API URL") from error

        self.url = url
        self.token = token
        self.timeout_seconds = float(timeout_seconds)
        self.attempt_timeout = float(attempt_timeout) if attempt_timeout is not None else None
        self.retries = retries
        self.require_request_id = require_request_id
        self.supports_deadline = True  # decide() accepts a caller deadline (see policy.decide)
        self.attempts_total = 0  # observable for tests/metrics
        self.retries_total = 0
        self._scheme = parsed.scheme
        self._host = parsed.hostname or ""
        self._port = port or (443 if parsed.scheme == "https" else 80)
        self._path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        self._ssl_context: ssl.SSLContext | None = None
        if parsed.scheme == "https":
            context = ssl.create_default_context(cafile=ca_file)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if client_cert_file:
                context.load_cert_chain(client_cert_file, client_key_file)
            self._ssl_context = context
        elif ca_file or client_cert_file:
            raise PolicyError("CA and client certificates require an https:// policy API")
        self._transport = transport or self._http_transport
        self._slots = threading.BoundedSemaphore(max_in_flight)
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_in_flight, thread_name_prefix="egress-policy"
        )
        self._idle: "queue.LifoQueue[http.client.HTTPConnection]" = queue.LifoQueue()
        self.connections_opened = 0  # observable for tests/metrics
        # Close pooled keep-alive connections even if close() is never called.
        self._finalizer = weakref.finalize(self, _shutdown, self._executor, self._idle)

    # -- transport ---------------------------------------------------------

    def _new_connection(self, timeout: float) -> http.client.HTTPConnection:
        self.connections_opened += 1
        if self._ssl_context is not None:
            return http.client.HTTPSConnection(self._host, self._port, timeout=timeout, context=self._ssl_context)
        return http.client.HTTPConnection(self._host, self._port, timeout=timeout)

    def _http_transport(self, body: bytes, headers: dict, deadline: float,
                        holder: _AbortHolder) -> tuple[int, bytes, float | None]:
        try:
            connection = self._idle.get_nowait()
            reused = True
        except queue.Empty:
            connection = self._new_connection(max(deadline - time.monotonic(), 0.001))
            reused = False
        holder.attach(connection)
        try:
            status, payload, reusable, retry_after = self._exchange(connection, body, headers, deadline)
        except (OSError, http.client.HTTPException):
            connection.close()
            if not reused or holder.aborted or time.monotonic() >= deadline:
                raise
            # A pooled keep-alive connection may have been closed by the server; retry once fresh.
            connection = self._new_connection(max(deadline - time.monotonic(), 0.001))
            holder.attach(connection)
            try:
                status, payload, reusable, retry_after = self._exchange(connection, body, headers, deadline)
            except (OSError, http.client.HTTPException):
                connection.close()
                raise
        holder.attach(None)
        if reusable and not holder.aborted:
            self._idle.put(connection)
        else:
            connection.close()
        return status, payload, retry_after

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("policy API deadline exceeded")
        return remaining

    @staticmethod
    def _retry_after(response) -> float | None:
        value = response.getheader("Retry-After")
        if value and value.strip().isdigit():
            return float(min(int(value.strip()), 60))
        return None

    def _exchange(self, connection, body: bytes, headers: dict, deadline: float) -> tuple[int, bytes, bool, float | None]:
        connection.timeout = self._remaining(deadline)
        if connection.sock is None:
            connection.connect()
        connection.sock.settimeout(self._remaining(deadline))
        connection.request("POST", self._path, body=body, headers=headers)
        connection.sock.settimeout(self._remaining(deadline))
        response = connection.getresponse()
        length = response.getheader("Content-Length")
        retry_after = self._retry_after(response)
        if length is not None and (not length.isdigit() or int(length) > MAX_RESPONSE_BYTES):
            response.close()
            return response.status, b"", False, retry_after
        chunks = []
        total = 0
        while True:
            if connection.sock is not None:
                connection.sock.settimeout(self._remaining(deadline))
            chunk = response.read1(16384) if hasattr(response, "read1") else response.read(16384)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                response.close()
                return response.status, b"", False, retry_after
            chunks.append(chunk)
        reusable = not response.will_close
        return response.status, b"".join(chunks), reusable, retry_after

    # -- decision ----------------------------------------------------------

    def _payload(self, request: ACLRequest, request_id: str) -> bytes:
        payload = {
            "version": 2,
            "requestId": request_id,
            "principal": request.principal,
            "sourceIp": request.source_ip,
            "method": request.method,
            "scheme": request.effective_scheme,
            "host": request.host,
            "port": request.port,
        }
        if request.path is not None:
            # Query strings are withheld: some APIs carry credentials there (e.g. ?key=...).
            path = request.path.split("?", 1)[0]
            default_port = 443 if request.effective_scheme == "https" else 80
            host = f"[{request.host}]" if ":" in request.host else request.host
            authority = host if request.port == default_port else f"{host}:{request.port}"
            payload["path"] = path
            payload["url"] = f"{request.effective_scheme}://{authority}{path}"
        if request.attributes:
            payload["identity"] = dict(request.attributes)
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def _interpret(self, request: ACLRequest, request_id: str, status: int, raw: bytes) -> Decision:
        if status != 200 or not raw or len(raw) > MAX_RESPONSE_BYTES:
            return Decision.deny(BACKEND_ERROR)
        try:
            payload = json.loads(raw)
        except (ValueError, RecursionError):
            return Decision.deny(BACKEND_ERROR)
        if not isinstance(payload, dict):
            return Decision.deny(BACKEND_ERROR)
        echoed = payload.get("requestId")
        if echoed is not None and echoed != request_id:
            return Decision.deny(BACKEND_ERROR)
        if echoed is None and self.require_request_id:
            return Decision.deny(BACKEND_ERROR)
        reason = payload.get("reason")
        if payload.get("decision") != "allow":
            if isinstance(reason, str) and _ARBITER_REASON.fullmatch(reason):
                return Decision.deny(f"arbiter:{reason}")
            return Decision.deny(BACKEND_DENIED)
        annotations = {TLS_OPTIONAL_NOTE: "optional"} if payload.get("allowNonTls") is True and request.method == "CONNECT" else {}
        if payload.get("websocket") is True and request.method == "GET":
            annotations[WEBSOCKET_NOTE] = "yes"
        scope = payload.get("scope") if isinstance(payload.get("scope"), str) else None
        methods = payload.get("methods")
        scope_methods = None
        if isinstance(methods, list) and methods and all(isinstance(m, str) and _METHOD.fullmatch(m) for m in methods):
            scope_methods = frozenset(methods)
        ttl = payload.get("ttl")
        scope_ttl = float(ttl) if isinstance(ttl, int) and not isinstance(ttl, bool) and ttl >= 0 else None
        return Decision(True, ALLOWED, annotations, scope=scope, scope_methods=scope_methods, scope_ttl=scope_ttl)

    def _attempt(self, body: bytes, headers: dict, attempt_deadline: float):
        """One HTTP exchange. Returns ("ok", status, raw, retry_after) | ("timeout",) | ("error",) | ("saturated",)."""
        remaining = attempt_deadline - time.monotonic()
        if remaining <= 0:
            return ("timeout",)
        if not self._slots.acquire(timeout=remaining):
            return ("saturated",)
        holder = _AbortHolder()

        def run():
            try:
                return self._transport(body, headers, attempt_deadline, holder)
            finally:
                self._slots.release()

        self.attempts_total += 1
        try:
            future = self._executor.submit(run)
        except RuntimeError:
            self._slots.release()
            return ("error",)
        try:
            result = future.result(timeout=max(attempt_deadline - time.monotonic(), 0))
        except concurrent.futures.TimeoutError:  # also the builtin TimeoutError on 3.11+
            holder.abort()
            return ("timeout",)
        except Exception:
            return ("timeout",) if time.monotonic() >= attempt_deadline else ("error",)
        status, raw, *rest = result
        return ("ok", status, raw, rest[0] if rest else None)

    def _backoff(self, attempt: int, retry_after: float | None, deadline: float) -> bool:
        """Sleep before the next attempt; False if no time is left for another attempt."""
        delay = retry_after if retry_after is not None else random.uniform(
            0, min(BACKOFF_CAP_SECONDS, BACKOFF_BASE_SECONDS * (2 ** attempt)))
        if time.monotonic() + delay >= deadline:
            return False
        time.sleep(delay)
        return True

    def decide(self, request: ACLRequest, deadline: float | None = None) -> Decision:
        request_id = uuid.uuid4().hex  # the same ID on every retry, so the API can de-duplicate
        decision = self._decide(request, deadline, request_id)
        return dataclasses.replace(decision, decision_id=request_id)

    def _decide(self, request: ACLRequest, deadline: float | None, request_id: str) -> Decision:
        now = time.monotonic()
        deadline = min(deadline, now + self.timeout_seconds) if deadline is not None else now + self.timeout_seconds
        body = self._payload(request, request_id)
        headers = {"Content-Type": "application/json", "Accept": "application/json", "Connection": "keep-alive"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        reason = BACKEND_TIMEOUT
        for attempt in range(self.retries + 1):
            if attempt:
                self.retries_total += 1
            attempt_deadline = deadline if self.attempt_timeout is None else min(
                deadline, time.monotonic() + self.attempt_timeout)
            outcome = self._attempt(body, headers, attempt_deadline)
            kind = outcome[0]
            if kind == "saturated":
                return Decision.deny(BACKEND_SATURATED)
            if kind == "ok":
                _, status, raw, retry_after = outcome
                if status not in RETRYABLE_STATUS:
                    return self._interpret(request, request_id, status, raw)
                reason = BACKEND_ERROR
            else:
                reason = BACKEND_TIMEOUT if kind == "timeout" else BACKEND_ERROR
                retry_after = None
            if time.monotonic() >= deadline or attempt == self.retries:
                break
            if not self._backoff(attempt, retry_after, deadline):
                break
        return Decision.deny(reason)

    def __call__(self, request: ACLRequest) -> bool:
        return self.decide(request).allowed

    def close(self) -> None:
        self._finalizer()
