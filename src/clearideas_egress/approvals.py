"""Scoped approval cache: the policy backend decides how broadly an allow applies.

The policy API sees the full request URL (without the query string) and may answer
with a **scope**, a URL prefix on the same origin::

    {"decision": "allow", "scope": "https://api.example.com/v1", "methods": ["GET", "POST"], "ttl": 300}

Until the approval expires, later requests from the same principal/identity/source
whose URL falls under the scope, with a listed method, are allowed without asking
again. Matching is on path-segment boundaries: ``/v1`` covers ``/v1`` and ``/v1/...``
but not ``/v1evil``. Without ``scope`` an allow covers only that exact URL; without
``methods``, only the request's method. ``ttl`` can shorten, never extend,
``EGRESS_DECISION_TTL``.

Paths that could be interpreted differently by the proxy and the origin are never
matched against stored approvals (they always go to the backend): encoded slashes or
backslashes, backslashes, empty segments. Dot segments (``/../``, ``%2e%2e``) are
refused outright by :func:`ambiguous_path`.
"""

from __future__ import annotations

import re
import threading
import time
import urllib.parse
from collections import OrderedDict
from dataclasses import dataclass

from .policy import ACLRequest, normalize_host

_DOT_SEGMENT = re.compile(r"(^|/)(\.|%2e){1,2}(/|$)", re.IGNORECASE)
_UNSAFE_FOR_PREFIX = re.compile(r"%2f|%5c|\\|//", re.IGNORECASE)
MAX_KEYS = 50_000
MAX_PREFIXES_PER_KEY = 64


def ambiguous_path(path: str) -> bool:
    """True for paths containing dot segments, raw or percent-encoded (refused outright)."""
    return bool(_DOT_SEGMENT.search(path.split("?", 1)[0]))


def _path_only(path: str) -> str:
    return path.split("?", 1)[0] or "/"


def covers(prefix: str, path: str) -> bool:
    """Segment-boundary prefix match of a normalized scope prefix against a request path."""
    path = _path_only(path)
    if _UNSAFE_FOR_PREFIX.search(path) or ambiguous_path(path):
        return False
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def parse_scope(scope: str, request: ACLRequest) -> str | None:
    """Return the normalized path prefix of ``scope`` if it is valid for ``request``, else None."""
    if not isinstance(scope, str) or not scope or any(ord(c) < 33 or ord(c) > 126 for c in scope):
        return None
    try:
        parsed = urllib.parse.urlsplit(scope)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or parsed.query or parsed.fragment or parsed.username or parsed.password:
        return None
    if parsed.scheme != request.effective_scheme:
        return None
    if normalize_host(parsed.hostname or "") != request.host:
        return None
    if (port or (443 if parsed.scheme == "https" else 80)) != request.port:
        return None
    prefix = parsed.path or "/"
    if not prefix.startswith("/") or _UNSAFE_FOR_PREFIX.search(prefix) or ambiguous_path(prefix):
        return None
    if len(prefix) > 1:
        prefix = prefix.rstrip("/") or "/"
    if request.path is not None and not covers(prefix, request.path):
        return None  # the scope must include the request it approves
    return prefix


@dataclass(frozen=True)
class Approval:
    prefix: str
    methods: frozenset[str] | None  # None: any method
    expires: float
    refresh_at: float
    annotations: tuple[tuple[str, str], ...]


def approval_key(request: ACLRequest) -> tuple:
    return (request.principal, request.source_ip, tuple(sorted(request.attributes.items())),
            request.effective_scheme, request.host, request.port)


class ApprovalCache:
    def __init__(self, *, max_ttl: float, grace_percent: int = 10) -> None:
        self.max_ttl = max_ttl
        self.grace = max(0, min(grace_percent, 99)) / 100.0
        self._entries: "OrderedDict[tuple, list[Approval]]" = OrderedDict()
        self._inflight: dict[tuple, threading.Event] = {}
        self._refreshing: set[tuple] = set()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def lookup(self, request: ACLRequest) -> tuple[Approval | None, bool]:
        """Return (approval, needs_refresh) for a request, or (None, False)."""
        if request.method != "CONNECT" and request.path is None:
            return None, False
        key = approval_key(request)
        now = time.monotonic()
        with self._lock:
            approvals = self._entries.get(key)
            if not approvals:
                self.misses += 1
                return None, False
            live = [a for a in approvals if a.expires > now]
            if len(live) != len(approvals):
                if live:
                    self._entries[key] = live
                else:
                    del self._entries[key]
            for approval in live:
                if approval.methods is not None and request.method not in approval.methods:
                    continue
                if request.method == "CONNECT" or covers(approval.prefix, request.path or "/"):
                    self._entries.move_to_end(key)
                    self.hits += 1
                    return approval, now >= approval.refresh_at
            self.misses += 1
            return None, False

    def store(self, request: ACLRequest, prefix: str, methods: frozenset[str] | None, ttl: float,
              annotations: dict[str, str]) -> None:
        ttl = min(ttl, self.max_ttl)
        if ttl <= 0:
            return
        now = time.monotonic()
        approval = Approval(prefix, methods, now + ttl, now + ttl * (1 - self.grace), tuple(sorted(annotations.items())))
        key = approval_key(request)
        with self._lock:
            approvals = [a for a in self._entries.get(key, []) if a.expires > now
                         and not (a.prefix == prefix and a.methods == methods)]
            approvals.append(approval)
            self._entries[key] = approvals[-MAX_PREFIXES_PER_KEY:]
            self._entries.move_to_end(key)
            while len(self._entries) > MAX_KEYS:
                self._entries.popitem(last=False)

    def forget(self, request: ACLRequest) -> None:
        """Drop approvals covering this request (e.g. the backend now denies it)."""
        key = approval_key(request)
        with self._lock:
            approvals = self._entries.get(key)
            if not approvals:
                return
            keep = [a for a in approvals if not (
                (a.methods is None or request.method in a.methods) and
                (request.method == "CONNECT" or covers(a.prefix, request.path or "/")))]
            if keep:
                self._entries[key] = keep
            else:
                del self._entries[key]

    # -- single flight ------------------------------------------------------------

    def begin(self, request: ACLRequest) -> tuple[bool, threading.Event]:
        """Leader/follower for concurrent misses of one principal + origin + method."""
        key = approval_key(request) + (request.method,)
        with self._lock:
            event = self._inflight.get(key)
            if event is not None:
                return False, event
            event = threading.Event()
            self._inflight[key] = event
            return True, event

    def end(self, request: ACLRequest) -> None:
        key = approval_key(request) + (request.method,)
        with self._lock:
            event = self._inflight.pop(key, None)
        if event is not None:
            event.set()

    def start_refresh(self, request: ACLRequest) -> bool:
        key = approval_key(request) + (request.method, request.path)
        with self._lock:
            if key in self._refreshing:
                return False
            self._refreshing.add(key)
            return True

    def end_refresh(self, request: ACLRequest) -> None:
        key = approval_key(request) + (request.method, request.path)
        with self._lock:
            self._refreshing.discard(key)
