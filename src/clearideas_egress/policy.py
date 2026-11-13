"""Small policy core that can also be imported by a private Python adapter."""

from __future__ import annotations

import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping


class PolicyError(ValueError):
    """Invalid policy or policy backend configuration."""


@dataclass(frozen=True)
class ACLRequest:
    principal: str
    source_ip: str
    method: str
    host: str
    port: int


_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
_METHOD = re.compile(r"^[A-Z]+$")


def normalize_host(value: str) -> str | None:
    """Return a canonical DNS name or IP literal, rejecting ambiguous input."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    if any(char in value for char in "/?#@%\\") or any(char.isspace() for char in value):
        return None
    host = value[:-1] if value.endswith(".") else value
    bracketed = host.startswith("[") and host.endswith("]")
    if bracketed:
        host = host[1:-1]
    elif "[" in host or "]" in host:
        return None
    try:
        address = ipaddress.ip_address(host)
        if bracketed and address.version != 6:
            return None
        return str(address)
    except ValueError:
        pass
    if bracketed or ":" in host:
        return None
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not ascii_host or len(ascii_host) > 253:
        return None
    if not all(0 < len(label) <= 63 and _LABEL.fullmatch(label) for label in ascii_host.split(".")):
        return None
    return ascii_host


def parse_acl_line(line: str) -> ACLRequest | None:
    """Parse Squid's `%ul %>a %METHOD %DST %PORT` external ACL line."""
    if not isinstance(line, str):
        return None
    parts = line.strip().split()
    # Squid may append a '-' placeholder for an empty external ACL argument.
    if len(parts) == 6 and parts[-1] == "-":
        parts.pop()
    if len(parts) != 5:
        return None
    principal, source_ip, method, raw_host, raw_port = parts
    host = normalize_host(raw_host)
    if not principal or principal == "-" or "|" in principal or not _METHOD.fullmatch(method):
        return None
    try:
        ipaddress.ip_address(source_ip)
        port = int(raw_port) if raw_port.isdecimal() else 0
    except ValueError:
        return None
    if host is None or not 1 <= port <= 65535:
        return None
    return ACLRequest(principal, source_ip, method, host, port)


def _origin(value: str) -> tuple[str, str, int]:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PolicyError("policy origin must be a URL string")
    if "?" in value or "#" in value:
        raise PolicyError("policy origin cannot contain a query or fragment")
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise PolicyError("policy origin must use HTTP or HTTPS")
        if parsed.username is not None or parsed.password is not None or parsed.path not in {"", "/"}:
            raise PolicyError("policy origin cannot contain credentials or a path")
        host = normalize_host(parsed.hostname or "")
        port = parsed.port
        if port is None:
            if parsed.netloc.endswith(":"):
                raise PolicyError("policy origin has an empty port")
            port = 443 if parsed.scheme == "https" else 80
    except ValueError as error:
        raise PolicyError("invalid policy origin") from error
    if host is None or not 1 <= port <= 65535:
        raise PolicyError("invalid policy origin host or port")
    return parsed.scheme, host, port


@dataclass(frozen=True)
class FilePolicy:
    """Immutable exact-origin allowlist keyed by authenticated proxy principal."""

    principals: Mapping[str, frozenset[tuple[str, str, int]]]

    def __call__(self, request: ACLRequest) -> bool:
        scheme = "https" if request.method == "CONNECT" else "http"
        return (scheme, request.host, request.port) in self.principals.get(request.principal, frozenset())


def compile_file_policy(document: object) -> FilePolicy:
    if not isinstance(document, dict) or document.get("version") != 1 or type(document.get("version")) is not int:
        raise PolicyError("policy must have version 1")
    principals = document.get("principals")
    if not isinstance(principals, dict):
        raise PolicyError("policy must have a principals object")
    compiled: dict[str, frozenset[tuple[str, str, int]]] = {}
    for principal, origins in principals.items():
        if not isinstance(principal, str) or not principal or principal != principal.strip() or any(
            char.isspace() or char == "|" for char in principal
        ) or not isinstance(origins, list):
            raise PolicyError("invalid principal or origin list")
        compiled[principal] = frozenset(_origin(origin) for origin in origins)
    return FilePolicy(compiled)


def load_file_policy(path: str | Path) -> FilePolicy:
    return compile_file_policy(json.loads(Path(path).read_text(encoding="utf-8")))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class HTTPPolicy:
    """POST each decision to a generic policy service; do not cache approvals."""

    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        timeout_seconds: float = 2.0,
        opener: object | None = None,
    ) -> None:
        try:
            parsed = urllib.parse.urlsplit(url)
            host = normalize_host(parsed.hostname or "")
            # Permit cleartext policy calls only to literal loopback addresses;
            # a DNS name such as localhost could be remapped unexpectedly.
            loopback = host in {"127.0.0.1", "::1"}
            if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
                raise PolicyError("policy API must use HTTPS or local loopback HTTP")
            if host is None or parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise PolicyError("invalid policy API URL")
            if not loopback and not token:
                raise PolicyError("remote policy API requires a bearer token")
            if not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 60:
                raise PolicyError("invalid policy API timeout")
            if token is not None and (not token or "\n" in token or "\r" in token):
                raise PolicyError("invalid bearer token")
            _ = parsed.port
        except (TypeError, ValueError) as error:
            if isinstance(error, PolicyError):
                raise
            raise PolicyError("invalid policy API URL") from error
        self.url = url
        self.token = token
        self.timeout_seconds = timeout_seconds
        self.opener = opener or urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )

    def __call__(self, request: ACLRequest) -> bool:
        body = json.dumps({
            "principal": request.principal,
            "sourceIp": request.source_ip,
            "method": request.method,
            "host": request.host,
            "port": request.port,
        }, separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        outgoing = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        with self.opener.open(outgoing, timeout=self.timeout_seconds) as response:
            if response.status != 200:
                return False
            raw = response.read(65537)
            if len(raw) > 65536:
                return False
            payload = json.loads(raw)
            return isinstance(payload, dict) and payload.get("decision") == "allow"


def authorize(request: ACLRequest | None, backend: Callable[[ACLRequest], object]) -> bool:
    """Only a valid request and an explicit Boolean True may allow egress."""
    if not isinstance(request, ACLRequest) or not request.principal or not _METHOD.fullmatch(request.method):
        return False
    if normalize_host(request.host) != request.host or not 1 <= request.port <= 65535:
        return False
    try:
        ipaddress.ip_address(request.source_ip)
        return backend(request) is True
    except Exception:  # Backends must never turn a failed lookup into an allow.
        return False
