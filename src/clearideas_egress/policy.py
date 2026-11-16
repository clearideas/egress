"""Fail-closed policy core: request parsing, host normalization, file policy, decisions.

Everything here is deliberately strict. Ambiguous input is rejected rather than
interpreted, because an egress proxy is the last line of defense and any
difference between how this module and Squid (or the operating system resolver)
interpret a destination is a potential bypass.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping


class PolicyError(ValueError):
    """Invalid policy or policy backend configuration."""


# ---------------------------------------------------------------------------
# Requests and decisions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ACLRequest:
    principal: str
    source_ip: str
    method: str
    host: str
    port: int
    # Real URL scheme when Squid provides it ("https"/"http"); None for CONNECT or legacy callers.
    scheme: str | None = None
    # Request target path+query exactly as sent (proxied HTTP only); None for CONNECT.
    path: str | None = None
    # Verified identity attributes (e.g. jobId/runnerId/runnerAuthId), passed to policy backends.
    attributes: Mapping[str, str] = field(default_factory=dict)

    @property
    def effective_scheme(self) -> str:
        if self.method == "CONNECT":
            return "https"
        return self.scheme or "http"


@dataclass(frozen=True)
class Decision:
    """Outcome of a policy evaluation.

    ``reason`` is a short machine-readable code that ends up in the audit log and
    in Squid's access log (``%ea``). ``annotations`` are returned to Squid as
    ``key=value`` pairs; they can only *relax* the TLS check for an origin that
    the policy explicitly marked ``allowNonTls``.
    """

    allowed: bool
    reason: str
    annotations: Mapping[str, str] = field(default_factory=dict)
    # How broadly an allow may be reused (see approvals.py). ``scope``: a URL prefix on the
    # request's origin, or "/" for the whole origin; None means the request URL itself.
    scope: str | None = None
    scope_methods: frozenset[str] | None = None  # None: only the request's method
    scope_any_method: bool = False
    scope_ttl: float | None = None  # seconds; can only shorten EGRESS_DECISION_TTL
    # Correlates the access log, the audit log and the policy API (the API's requestId).
    decision_id: str | None = None

    @classmethod
    def allow(cls, reason: str = "allowed", **annotations: str) -> "Decision":
        return cls(True, reason, dict(annotations))

    @classmethod
    def deny(cls, reason: str) -> "Decision":
        return cls(False, reason)


# Reason codes (stable; referenced by docs and log consumers).
ALLOWED = "allowed"
INVALID_REQUEST = "invalid_request"
UNKNOWN_PRINCIPAL = "unknown_principal"
SOURCE_NOT_ALLOWED = "source_not_allowed"
ORIGIN_NOT_ALLOWED = "origin_not_allowed"
METHOD_NOT_ALLOWED = "method_not_allowed"
BACKEND_DENIED = "backend_denied"
BACKEND_ERROR = "backend_error"
BACKEND_TIMEOUT = "backend_timeout"
BACKEND_SATURATED = "backend_saturated"
RATE_LIMITED = "rate_limited"

# Denials caused by a temporary condition rather than by policy. Squid answers them with
# 503 (or 429 for rate limiting) plus Retry-After, so clients and SDKs retry automatically.
RETRYABLE_REASONS = {
    BACKEND_ERROR: "503", BACKEND_TIMEOUT: "503", BACKEND_SATURATED: "503", RATE_LIMITED: "429",
    "nonce_store_error": "503", "credential_unavailable": "503", "helper_misconfigured": "503",
}
RETRY_NOTE = "egress_retry_"

WEBSOCKET_NOTE = "egress_ws_"  # Squid annotation; "yes" allows an HTTP Upgrade to WebSocket
DECISION_NOTE = "egress_decision_"  # Squid annotation carrying the decision ID
TLS_OPTIONAL_NOTE = "egress_tls_"  # Squid annotation (custom names must end with "_"); "optional" relaxes SNI checks


# ---------------------------------------------------------------------------
# Host normalization
# ---------------------------------------------------------------------------

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_METHOD = re.compile(r"^[A-Z]{1,20}$")
_PORT = re.compile(r"^[0-9]{1,5}$")
# A final label that the C resolver / Squid / WHATWG URL parser would treat as
# (part of) an IPv4 address: decimal, octal (leading 0) or 0x-hex digits.
_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$")


def _is_ascii(value: str) -> bool:
    return all(ord(char) < 128 for char in value)


def normalize_host(value: str, *, allow_unicode: bool = True) -> str | None:
    """Return a canonical DNS name or IP literal, rejecting ambiguous input.

    * IP literals are returned in canonical ``ipaddress`` form (IPv6 without brackets).
    * DNS names are lower-cased, a single trailing dot is removed, labels must be
      LDH, and names whose last label is numeric (``127.1``, ``0x7f000001``,
      ``2130706433``) are rejected because resolvers interpret them as IPv4.
    * Punycode (``xn--``) labels must round-trip, so malformed A-labels are rejected.
    * With ``allow_unicode=False`` (used for policy files) non-ASCII input is
      rejected instead of being mapped with IDNA 2003, whose mappings (``ß``->``ss``,
      dropped joiners) can silently change which domain is meant.
    """
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    if any(char in value for char in "/?#@%\\") or any(char.isspace() or ord(char) < 32 for char in value):
        return None
    host = value[:-1] if value.endswith(".") else value
    bracketed = host.startswith("[") and host.endswith("]")
    if bracketed:
        host = host[1:-1]
    elif "[" in host or "]" in host:
        return None
    if not _is_ascii(host) and not allow_unicode:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if bracketed and address.version != 6:
            return None
        if address.version == 6 and address.scope_id:
            return None
        return str(address)
    if bracketed or ":" in host:
        return None
    try:
        ascii_host = host.encode("idna").decode("ascii").lower() if not _is_ascii(host) else host.lower()
    except UnicodeError:
        return None
    if not ascii_host or len(ascii_host) > 253:
        return None
    labels = ascii_host.split(".")
    if not all(0 < len(label) <= 63 and _LABEL.fullmatch(label) for label in labels):
        return None
    if _NUMERIC_LABEL.fullmatch(labels[-1]):
        return None
    for label in labels:
        if label.startswith("xn--"):
            try:
                if label.encode("ascii").decode("idna").encode("idna").decode("ascii").lower() != label:
                    return None
            except UnicodeError:
                return None
    return ascii_host


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Squid external ACL line parsing
# ---------------------------------------------------------------------------


def decode_field(raw: str) -> str | None:
    """Undo Squid's default URL quoting of external ACL fields exactly once.

    Returns ``None`` when the decoded value is unsafe (control characters, a
    remaining ``%`` that could be decoded a second time, or invalid UTF-8).
    """
    if not raw or any(ord(char) < 33 or ord(char) == 127 for char in raw):
        return None
    if "%" in raw:
        if re.search(r"%(?![0-9A-Fa-f]{2})", raw):
            return None
        try:
            value = urllib.parse.unquote(raw, encoding="utf-8", errors="strict")
        except UnicodeDecodeError:
            return None
    else:
        value = raw
    if "%" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value


def valid_principal(principal: str) -> bool:
    return (
        bool(principal)
        and principal != "-"
        and len(principal) <= 256
        and not any(char.isspace() or char in "|%" or ord(char) < 32 or ord(char) == 127 for char in principal)
    )


def parse_fields(fields: list[str]) -> ACLRequest | None:
    """Build a request from the five decoded-or-raw ``%ul %>a %METHOD %DST %PORT`` fields."""
    if len(fields) != 5:
        return None
    decoded = [decode_field(item) for item in fields]
    if any(item is None for item in decoded):
        return None
    principal, source_ip, method, raw_host, raw_port = decoded  # type: ignore[misc]
    if not valid_principal(principal) or not _METHOD.fullmatch(method) or not _PORT.fullmatch(raw_port):
        return None
    try:
        source = ipaddress.ip_address(source_ip)
    except ValueError:
        return None
    host = normalize_host(raw_host)
    port = int(raw_port)
    if host is None or not 1 <= port <= 65535:
        return None
    return ACLRequest(principal, str(source), method, host, port)


def parse_acl_line(line: str) -> ACLRequest | None:
    """Parse Squid's ``%ul %>a %METHOD %DST %PORT`` external ACL line (no channel ID)."""
    if not isinstance(line, str):
        return None
    parts = line.strip().split(" ")
    # Squid appends a '-' placeholder when the `acl ... external` line has no arguments.
    if len(parts) == 6 and parts[-1] == "-":
        parts.pop()
    return parse_fields(parts)


# ---------------------------------------------------------------------------
# File policy (versions 1 and 2)
# ---------------------------------------------------------------------------

Origin = tuple[str, str, int]


@dataclass(frozen=True)
class OriginRule:
    methods: frozenset[str] | None = None  # None: any method. CONNECT cannot be method-checked.
    allow_non_tls: bool = False  # https origins only
    websocket: bool = False  # allow HTTP Upgrade to WebSocket (proxy-originated TLS / plain HTTP)


@dataclass(frozen=True)
class PrincipalRule:
    sources: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] | None
    origins: Mapping[Origin, OriginRule]

    def source_allowed(self, source_ip: str) -> bool:
        if self.sources is None:
            return True
        address = ipaddress.ip_address(source_ip)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return any(address.version == network.version and address in network for network in self.sources)


def _origin(value: object) -> Origin:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PolicyError("policy origin must be a URL string")
    if not _is_ascii(value):
        raise PolicyError(
            f"policy origin {value!r} must be ASCII; write internationalized names as A-labels (xn--...)"
        )
    if "?" in value or "#" in value:
        raise PolicyError("policy origin cannot contain a query or fragment")
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise PolicyError("policy origin must use HTTP or HTTPS")
        if parsed.username is not None or parsed.password is not None or parsed.path not in {"", "/"}:
            raise PolicyError("policy origin cannot contain credentials or a path")
        host = normalize_host(parsed.hostname or "", allow_unicode=False)
        port = parsed.port
        if port is None:
            if parsed.netloc.endswith(":"):
                raise PolicyError("policy origin has an empty port")
            port = 443 if parsed.scheme == "https" else 80
    except ValueError as error:
        if isinstance(error, PolicyError):
            raise
        raise PolicyError("invalid policy origin") from error
    if host is None or not 1 <= port <= 65535:
        raise PolicyError(f"invalid policy origin host or port: {value!r}")
    return parsed.scheme, host, port


def _origin_entry(entry: object, version: int) -> tuple[Origin, OriginRule]:
    if version == 1 or isinstance(entry, str):
        return _origin(entry), OriginRule()
    if not isinstance(entry, dict) or set(entry) - {"origin", "methods", "allowNonTls", "websocket"}:
        raise PolicyError("origin entry must be a string or an object with origin/methods/allowNonTls/websocket")
    origin = _origin(entry.get("origin"))
    methods = entry.get("methods")
    if methods is not None:
        if not isinstance(methods, list) or not methods or not all(
            isinstance(m, str) and _METHOD.fullmatch(m) and m != "CONNECT" for m in methods
        ):
            raise PolicyError("methods must be a non-empty list of upper-case HTTP methods")
        methods = frozenset(methods)
    allow_non_tls = entry.get("allowNonTls", False)
    if type(allow_non_tls) is not bool:
        raise PolicyError("allowNonTls must be a boolean")
    if allow_non_tls and origin[0] != "https":
        raise PolicyError("allowNonTls only applies to https:// (CONNECT) origins")
    websocket = entry.get("websocket", False)
    if type(websocket) is not bool:
        raise PolicyError("websocket must be a boolean")
    if websocket and methods is not None and "GET" not in methods:
        raise PolicyError("websocket requires GET to be allowed")
    return origin, OriginRule(methods, allow_non_tls, websocket)


def _sources(value: object) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] | None:
    if value is None:
        return None
    if not isinstance(value, list) or not value:
        raise PolicyError("sources must be a non-empty list of CIDRs")
    networks = []
    for item in value:
        if not isinstance(item, str):
            raise PolicyError("sources must be CIDR strings")
        try:
            networks.append(ipaddress.ip_network(item, strict=True))
        except ValueError as error:
            raise PolicyError(f"invalid source CIDR {item!r}") from error
    return tuple(networks)


@dataclass(frozen=True)
class FilePolicy:
    """Immutable exact-origin allowlist keyed by authenticated proxy principal."""

    principals: Mapping[str, PrincipalRule]

    def decide(self, request: ACLRequest) -> Decision:
        rule = self.principals.get(request.principal)
        if rule is None:
            return Decision.deny(UNKNOWN_PRINCIPAL)
        if not rule.source_allowed(request.source_ip):
            return Decision.deny(SOURCE_NOT_ALLOWED)
        origin_rule = rule.origins.get((request.effective_scheme, request.host, request.port))
        if origin_rule is None:
            return Decision.deny(ORIGIN_NOT_ALLOWED)
        # A method restriction cannot be enforced on a CONNECT tunnel, so it refuses CONNECT.
        if origin_rule.methods is not None and request.method not in origin_rule.methods:
            return Decision.deny(METHOD_NOT_ALLOWED)
        # File rules are per origin: the allow covers the whole origin for the allowed methods.
        annotations = {TLS_OPTIONAL_NOTE: "optional"} if origin_rule.allow_non_tls else {}
        if origin_rule.websocket:
            annotations[WEBSOCKET_NOTE] = "yes"
        return Decision(True, ALLOWED, annotations, scope="/", scope_methods=origin_rule.methods,
                        scope_any_method=origin_rule.methods is None)

    def __call__(self, request: ACLRequest) -> bool:
        return self.decide(request).allowed


def compile_file_policy(document: object) -> FilePolicy:
    if not isinstance(document, dict) or type(document.get("version")) is not int or document["version"] not in (1, 2):
        raise PolicyError("policy must have version 1 or 2")
    version = document["version"]
    if set(document) - {"version", "principals"}:
        raise PolicyError("unknown top-level policy keys")
    principals = document.get("principals")
    if not isinstance(principals, dict):
        raise PolicyError("policy must have a principals object")
    compiled: dict[str, PrincipalRule] = {}
    for principal, spec in principals.items():
        if not isinstance(principal, str) or not valid_principal(principal) or principal != principal.strip():
            raise PolicyError(f"invalid principal name {principal!r}")
        if version == 1 or isinstance(spec, list):
            if version == 2:
                raise PolicyError("version 2 principals must be objects with an origins list")
            if not isinstance(spec, list):
                raise PolicyError("invalid principal or origin list")
            sources, entries = None, spec
        else:
            if not isinstance(spec, dict) or set(spec) - {"sources", "origins"}:
                raise PolicyError("principal must be an object with sources/origins")
            sources, entries = _sources(spec.get("sources")), spec.get("origins")
            if not isinstance(entries, list):
                raise PolicyError("principal origins must be a list")
        origins: dict[Origin, OriginRule] = {}
        for entry in entries:
            origin, rule = _origin_entry(entry, version)
            if origin in origins and origins[origin] != rule:
                raise PolicyError(f"conflicting rules for origin {origin!r} of principal {principal!r}")
            origins[origin] = rule
        compiled[principal] = PrincipalRule(sources, origins)
    return FilePolicy(compiled)


def _reject_duplicate_keys(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON key {key!r} in policy")
        result[key] = value
    return result


def load_policy_document(text: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise PolicyError(f"policy is not valid JSON: {error}") from error


def load_file_policy(path: str | Path) -> FilePolicy:
    return compile_file_policy(load_policy_document(Path(path).read_text(encoding="utf-8")))


class ReloadingFilePolicy:
    """A policy file that is re-read when it changes (checked every ``refresh_seconds``).

    A changed file is validated before it replaces the current policy; an invalid edit
    or a missing file keeps the last good policy and is reported through ``on_reload``.
    """

    def __init__(self, path: str | Path, *, refresh_seconds: float = 2.0, on_reload=None) -> None:
        import os
        import threading
        self._os = os
        self.path = Path(path)
        self.refresh_seconds = refresh_seconds
        self.on_reload = on_reload  # callable(result: "ok" | "error", detail: str)
        self._lock = threading.Lock()
        self._checked = 0.0
        stat = os.stat(self.path)
        self._policy = load_file_policy(self.path)  # startup: errors propagate
        self._stamp = (stat.st_mtime_ns, stat.st_size, stat.st_ino)

    def _maybe_reload(self) -> None:
        import time
        now = time.monotonic()
        with self._lock:
            if now - self._checked < self.refresh_seconds:
                return
            self._checked = now
            try:
                stat = self._os.stat(self.path)
                stamp = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
                if stamp == self._stamp:
                    return
                policy = load_file_policy(self.path)
            except (OSError, PolicyError) as error:
                if self.on_reload is not None and getattr(self, "_last_error", None) != str(error):
                    self.on_reload("error", str(error))
                self._last_error = str(error)
                return
            self._policy, self._stamp, self._last_error = policy, stamp, None
        if self.on_reload is not None:
            self.on_reload("ok", str(self.path))

    @property
    def policy(self) -> FilePolicy:
        self._maybe_reload()
        return self._policy

    def decide(self, request: ACLRequest) -> Decision:
        return self.policy.decide(request)

    def __call__(self, request: ACLRequest) -> bool:
        return self.decide(request).allowed


# ---------------------------------------------------------------------------
# Authorization entry points
# ---------------------------------------------------------------------------

Backend = Callable[[ACLRequest], object]


def _valid_request(request: object) -> bool:
    if not isinstance(request, ACLRequest) or not valid_principal(request.principal):
        return False
    if not isinstance(request.method, str) or not _METHOD.fullmatch(request.method):
        return False
    if normalize_host(request.host) != request.host or not isinstance(request.port, int) or not 1 <= request.port <= 65535:
        return False
    try:
        ipaddress.ip_address(request.source_ip)
    except (TypeError, ValueError):
        return False
    return True


def decide(request: ACLRequest | None, backend: Backend, deadline: float | None = None) -> Decision:
    """Evaluate ``request``; only a valid request and an explicit allow can allow egress.

    Backends may return a :class:`Decision` or (legacy) the boolean ``True``.
    Anything else, including exceptions, denies. ``deadline`` (``time.monotonic()``
    based) is passed to backends that declare ``supports_deadline``.
    """
    if not _valid_request(request):
        return Decision.deny(INVALID_REQUEST)
    try:
        decide_method = getattr(backend, "decide", None)
        if callable(decide_method) and deadline is not None and getattr(backend, "supports_deadline", False):
            result = decide_method(request, deadline=deadline)
        else:
            result = decide_method(request) if callable(decide_method) else backend(request)  # type: ignore[arg-type]
    except Exception:  # Backends must never turn a failed lookup into an allow.
        return Decision.deny(BACKEND_ERROR)
    if isinstance(result, Decision):
        return result if isinstance(result.allowed, bool) else Decision.deny(BACKEND_ERROR)
    if result is True:
        return Decision.allow(ALLOWED)
    return Decision.deny(BACKEND_DENIED)


def authorize(request: ACLRequest | None, backend: Backend) -> bool:
    """Only a valid request and an explicit allow may allow egress."""
    return decide(request, backend).allowed
