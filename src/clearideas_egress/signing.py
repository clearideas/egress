"""Per-request signed identity headers (signature scheme v1).

For deployments where an egress helper inside the sandbox forwards the sandbox's
traffic to the proxy (often over a tunnel, where every sandbox shares one source
address). Identity rests on a **per-run key**, a **signature over each request that
includes its destination**, and the policy API's check that the run is still
active. The full specification, with test vectors, is in
docs/INTEGRATION.md#signed-request-headers-v1.

Identity is a configurable, ordered set of attributes, each carried in its own
header (``EGRESS_SIGNED_IDENTITY``), for example ``runId=X-Egress-Run-Id`` (the
default) or ``tenantId=X-Acme-Tenant,runId=X-Acme-Run``. One attribute is the
principal (``EGRESS_SIGNED_PRINCIPAL``, default: the first). The timestamp, nonce
and signature headers share a prefix (``EGRESS_SIGNED_HEADER_PREFIX``, default
``X-Egress-``).

Keys
----
Master keys (``<kid>.key``, >= 32 random bytes) are shared by the control plane and
the proxies. For each run the control plane derives::

    run_key = HMAC-SHA256(master_key, "egress-run-key/v1" + "\\n" + "name1=value1" + "\\n" + "name2=value2" ...)

(attributes in configured order) and gives ``run_key`` and ``kid`` to the sandbox.
The proxy re-derives it, so verification is stateless.

Canonical request
-----------------
``signature = HMAC-SHA256(run_key, canonical)`` with these lines joined by ``\\n``::

    EGRESS-SIG-V1
    <METHOD>
    <scheme>             "https"/"http"; "" for CONNECT
    <host>               lower case, no trailing dot, IDN A-labels, IPv6 without brackets
    <port>               decimal, always explicit
    <path>               path and query exactly as sent; "" for CONNECT
    <name1>=<value1>     one line per identity attribute, configured order
    ...
    <timestamp>          unix seconds
    <nonce>              16-64 chars [A-Za-z0-9_-]

Signature header value: ``v1.<kid>.<base64url(signature), unpadded>``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import time
from dataclasses import dataclass
from typing import Mapping

from .policy import normalize_host

SCHEME_VERSION = "v1"
CANONICAL_PREFIX = "EGRESS-SIG-V1"
KEY_DERIVATION_LABEL = "egress-run-key/v1"

DEFAULT_IDENTITY = "runId=X-Egress-Run-Id"
DEFAULT_HEADER_PREFIX = "X-Egress-"

_ATTRIBUTE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,31}$")
_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_RESERVED_HEADERS = {"host", "connection", "content-length", "transfer-encoding", "proxy-authorization",
                     "proxy-connection", "upgrade", "te", "trailer", "keep-alive", "authorization", "cookie"}
_VALUE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
_TIMESTAMP = re.compile(r"^[0-9]{1,12}$")
_KID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_SIG = re.compile(r"^[A-Za-z0-9_-]{43}$")  # 32 bytes, base64url, unpadded
_METHOD = re.compile(r"^[A-Z]{1,20}$")
_PORT = re.compile(r"^[0-9]{1,5}$")
_PATH = re.compile(r"^/[\x21-\x7e]{0,8191}$")  # request target as sent; no whitespace
MAX_ATTRIBUTES = 8


class SignatureError(ValueError):
    """Rejected signature; ``reason`` is a stable, log-safe code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def valid_identity_value(value: object) -> bool:
    return isinstance(value, str) and bool(_VALUE.fullmatch(value))


@dataclass(frozen=True)
class SigningProfile:
    """Which headers carry the identity, and how they map to identity attributes."""

    identity: tuple[tuple[str, str], ...] = (("runId", "X-Egress-Run-Id"),)  # (attribute, header)
    principal: str = "runId"
    timestamp_header: str = "X-Egress-Timestamp"
    nonce_header: str = "X-Egress-Nonce"
    signature_header: str = "X-Egress-Signature"

    @classmethod
    def parse(cls, identity: str | None = None, principal: str | None = None,
              header_prefix: str | None = None) -> "SigningProfile":
        spec = (identity or DEFAULT_IDENTITY).strip()
        pairs: list[tuple[str, str]] = []
        for item in spec.split(","):
            name, sep, header = item.strip().partition("=")
            if not sep or not _ATTRIBUTE.fullmatch(name) or not _HEADER.fullmatch(header):
                raise ValueError("EGRESS_SIGNED_IDENTITY must look like 'attr=Header-Name,attr2=Header-Two'")
            pairs.append((name, header))
        if not 1 <= len(pairs) <= MAX_ATTRIBUTES:
            raise ValueError(f"EGRESS_SIGNED_IDENTITY needs 1-{MAX_ATTRIBUTES} attributes")
        prefix = DEFAULT_HEADER_PREFIX if header_prefix is None else header_prefix
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,40}", prefix or "-"):
            raise ValueError("EGRESS_SIGNED_HEADER_PREFIX must be a header-name prefix such as 'X-Egress-'")
        profile = cls(tuple(pairs), principal or pairs[0][0], f"{prefix}Timestamp", f"{prefix}Nonce",
                      f"{prefix}Signature")
        names = [name for name, _ in pairs]
        headers = [header.lower() for header in profile.all_headers]
        if len(set(names)) != len(names) or len(set(headers)) != len(headers):
            raise ValueError("identity attributes and headers must be unique")
        if profile.principal not in names:
            raise ValueError("EGRESS_SIGNED_PRINCIPAL must be one of the identity attributes")
        if set(headers) & _RESERVED_HEADERS:
            raise ValueError("identity headers cannot reuse standard HTTP/proxy header names")
        return profile

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "SigningProfile":
        env = os.environ if env is None else env
        return cls.parse(env.get("EGRESS_SIGNED_IDENTITY") or None, env.get("EGRESS_SIGNED_PRINCIPAL") or None,
                         env.get("EGRESS_SIGNED_HEADER_PREFIX") if env.get("EGRESS_SIGNED_HEADER_PREFIX") else None)

    @property
    def attributes(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.identity)

    @property
    def identity_headers(self) -> tuple[str, ...]:
        return tuple(header for _, header in self.identity)

    @property
    def all_headers(self) -> tuple[str, ...]:
        return self.identity_headers + (self.timestamp_header, self.nonce_header, self.signature_header)

    def validate_identity(self, identity: Mapping[str, str]) -> dict[str, str]:
        if set(identity) != set(self.attributes) or not all(valid_identity_value(v) for v in identity.values()):
            raise SignatureError("invalid_identity")
        return {name: identity[name] for name in self.attributes}


def encode_identity(identity: Mapping[str, str]) -> str:
    """Compact form used in Squid annotations: ``name=value,name=value``."""
    return ",".join(f"{name}={value}" for name, value in identity.items())


def decode_identity(text: str) -> dict[str, str] | None:
    if not text or text == "-":
        return None
    result: dict[str, str] = {}
    for item in text.split(","):
        name, sep, value = item.partition("=")
        if not sep or not _ATTRIBUTE.fullmatch(name) or not valid_identity_value(value) or name in result:
            return None
        result[name] = value
    return result if 1 <= len(result) <= MAX_ATTRIBUTES else None


@dataclass(frozen=True)
class Destination:
    method: str
    scheme: str  # "https"/"http", or "" for CONNECT
    host: str
    port: int
    path: str  # "" for CONNECT

    @classmethod
    def build(cls, method: str, scheme: str, host: str, port: int | str, path: str) -> "Destination":
        if not _METHOD.fullmatch(method or ""):
            raise SignatureError("invalid_destination")
        normalized = normalize_host(host)
        if normalized is None:
            raise SignatureError("invalid_destination")
        port_text = str(port)
        if not _PORT.fullmatch(port_text) or not 1 <= int(port_text) <= 65535:
            raise SignatureError("invalid_destination")
        if method == "CONNECT":
            if scheme not in ("", "-") or path not in ("", "-"):
                raise SignatureError("invalid_destination")
            return cls(method, "", normalized, int(port_text), "")
        if scheme not in ("http", "https") or not _PATH.fullmatch(path or ""):
            raise SignatureError("invalid_destination")
        return cls(method, scheme, normalized, int(port_text), path)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as error:
        raise SignatureError("malformed_signature") from error


def _identity_lines(identity: Mapping[str, str]) -> list[str]:
    return [f"{name}={value}" for name, value in identity.items()]


def derive_run_key(master_key: bytes, identity: Mapping[str, str]) -> bytes:
    if not identity or not all(_ATTRIBUTE.fullmatch(n) and valid_identity_value(v) for n, v in identity.items()):
        raise SignatureError("invalid_identity")
    message = "\n".join([KEY_DERIVATION_LABEL, *_identity_lines(identity)])
    return hmac.new(master_key, message.encode("ascii"), hashlib.sha256).digest()


def canonical_string(destination: Destination, identity: Mapping[str, str], timestamp: str, nonce: str) -> str:
    return "\n".join([CANONICAL_PREFIX, destination.method, destination.scheme, destination.host,
                      str(destination.port), destination.path, *_identity_lines(identity), timestamp, nonce])


def sign_request(run_key: bytes, kid: str, profile: SigningProfile, identity: Mapping[str, str],
                 destination: Destination, *, timestamp: int | None = None, nonce: str | None = None) -> dict[str, str]:
    """Headers an egress helper adds to one request (reference implementation)."""
    if not _KID.fullmatch(kid):
        raise ValueError("invalid kid")
    ordered = profile.validate_identity(identity)
    ts = str(int(time.time()) if timestamp is None else int(timestamp))
    nonce = nonce or _b64url(os.urandom(18))
    if not _NONCE.fullmatch(nonce):
        raise ValueError("invalid nonce")
    signature = hmac.new(run_key, canonical_string(destination, ordered, ts, nonce).encode("utf-8"),
                         hashlib.sha256).digest()
    headers = {header: ordered[name] for name, header in profile.identity}
    headers[profile.timestamp_header] = ts
    headers[profile.nonce_header] = nonce
    headers[profile.signature_header] = f"{SCHEME_VERSION}.{kid}.{_b64url(signature)}"
    return headers


@dataclass(frozen=True)
class VerifiedRequest:
    identity: Mapping[str, str]
    principal: str
    destination: Destination
    timestamp: int
    nonce: str
    kid: str


def verify_request(headers: Mapping[str, str | None], destination: Destination, master_keys,
                   profile: SigningProfile = SigningProfile(), *, max_skew_seconds: int = 30,
                   now: float | None = None) -> VerifiedRequest:
    """Verify one request's signed headers against its actual destination.

    ``headers`` maps header names (as in ``profile``) to values; ``master_keys`` needs
    ``get(kid) -> bytes | None``. Values outside their strict character sets (including
    the ``,`` Squid inserts when a header is repeated) are rejected.
    """
    values = {name: headers.get(name) for name in profile.all_headers}
    if any(value in (None, "", "-") for value in values.values()):
        raise SignatureError("missing_header")
    identity = {name: values[header] for name, header in profile.identity}
    if not all(valid_identity_value(value) for value in identity.values()):
        raise SignatureError("invalid_identity")
    timestamp, nonce = values[profile.timestamp_header], values[profile.nonce_header]
    if not _TIMESTAMP.fullmatch(timestamp) or not _NONCE.fullmatch(nonce):  # type: ignore[arg-type]
        raise SignatureError("malformed_header")
    parts = values[profile.signature_header].split(".")  # type: ignore[union-attr]
    if len(parts) != 3 or parts[0] != SCHEME_VERSION or not _KID.fullmatch(parts[1]) or not _SIG.fullmatch(parts[2]):
        raise SignatureError("malformed_signature")
    _, kid, encoded = parts
    current = time.time() if now is None else now
    if abs(current - int(timestamp)) > max_skew_seconds:  # type: ignore[arg-type]
        raise SignatureError("stale_timestamp")
    master = master_keys.get(kid)
    if master is None:
        raise SignatureError("unknown_key")
    expected = hmac.new(derive_run_key(master, identity),
                        canonical_string(destination, identity, timestamp, nonce).encode("utf-8"),  # type: ignore[arg-type]
                        hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(encoded)):
        raise SignatureError("bad_signature")
    return VerifiedRequest(identity, identity[profile.principal], destination, int(timestamp), nonce, kid)  # type: ignore[arg-type]
