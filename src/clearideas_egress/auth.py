"""Short-lived, source-bound sandbox credentials for Squid Basic authentication.

The sandbox orchestrator mints a token per sandbox and hands it to the sandbox as
its proxy password (``http://<principal>:<token>@egress:3128``). The token is

    v1.<kid>.<base64url(JSON claims)>.<base64url(HMAC-SHA256(key, "v1.<kid>.<claims>"))>

with claims::

    {"sub": "<principal>", "src": ["10.20.0.7/32"], "iat": 1700000000, "exp": 1700000900}

Squid passes the client address to this helper through
``auth_param basic key_extras "%>a"``. The helper accepts the credential only if
the signature verifies with a current key, the token is within its validity
window, ``sub`` equals the Basic username, and the client address is inside one
of the ``src`` networks. Because ``key_extras`` is also part of Squid's
credential-cache key, a cached approval cannot be reused from another address.

Keys live in ``EGRESS_AUTH_KEYS_DIR`` as ``<kid>.key`` files containing at least
32 random bytes, base64 encoded. Adding a file introduces a key; deleting it
revokes every token signed with it (bounded by Squid's ``credentialsttl``). The
directory is re-read automatically.

Commands::

    clearideas-egress-auth                       # Squid helper (reads stdin)
    clearideas-egress-auth --concurrent          # with auth_param ... concurrency=N
    clearideas-egress-token --key-file K --kid KID --sub sbx-1 --src 10.0.0.7/32 --ttl 900
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from pathlib import Path

from .audit import AuditLog
from .metrics import METRICS, start_from_env
from .policy import valid_principal

TOKEN_VERSION = "v1"
MAX_TOKEN_LENGTH = 4096
MIN_KEY_BYTES = 32
MAX_TTL_SECONDS = 24 * 3600
CLOCK_SKEW_SECONDS = 30
_KID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class TokenError(ValueError):
    """Token rejected; ``reason`` is a stable code safe to log (never contains the token)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    if not _B64URL.fullmatch(text):
        raise TokenError("malformed")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as error:
        raise TokenError("malformed") from error


def decode_key(text: str) -> bytes:
    text = text.strip()
    try:
        key = base64.b64decode(text, altchars=b"-_", validate=False) if text else b""
    except (binascii.Error, ValueError) as error:
        raise ValueError("key must be base64") from error
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"key must decode to at least {MIN_KEY_BYTES} bytes")
    return key


def mint_token(key: bytes, kid: str, sub: str, src: list[str], ttl_seconds: int, *, now: int | None = None) -> str:
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"key must be at least {MIN_KEY_BYTES} bytes")
    if not _KID.fullmatch(kid):
        raise ValueError("kid must match [A-Za-z0-9_-]{1,32}")
    if not valid_principal(sub):
        raise ValueError("invalid principal")
    if not src:
        raise ValueError("at least one source CIDR is required")
    networks = [str(ipaddress.ip_network(item, strict=True)) for item in src]
    if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise ValueError(f"ttl must be between 1 and {MAX_TTL_SECONDS} seconds")
    issued = int(time.time()) if now is None else int(now)
    claims = {"sub": sub, "src": networks, "iat": issued, "exp": issued + int(ttl_seconds)}
    payload = _b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{TOKEN_VERSION}.{kid}.{payload}".encode("ascii")
    signature = _b64url_encode(hmac.new(key, signing_input, hashlib.sha256).digest())
    return f"{TOKEN_VERSION}.{kid}.{payload}.{signature}"


class KeyRing:
    """``<kid>.key`` files in a directory, reloaded when the directory changes."""

    def __init__(self, directory: str | Path, *, refresh_seconds: float = 2.0, require_keys: bool = True) -> None:
        """``require_keys=False`` is for long-running helpers: an empty or missing directory
        then denies everything instead of failing to start. (Squid aborts entirely when
        helpers keep failing to start, so revoking the last key must not crash helpers.)"""
        self.directory = Path(directory)
        self.refresh_seconds = refresh_seconds
        self._keys: dict[str, bytes] = {}
        self._signature: tuple | None = None
        self._checked = 0.0
        self._lock = threading.Lock()
        try:
            self._load(force=True)
        except OSError:
            if require_keys:
                raise
        if not self._keys and require_keys:
            raise ValueError(f"no valid <kid>.key files in {self.directory}")

    def __len__(self) -> int:
        return len(self._keys)

    def _snapshot(self) -> tuple:
        entries = []
        if not self.directory.is_dir():
            return ()
        for path in sorted(self.directory.glob("*.key")):
            try:
                stat = path.stat()
            except OSError:
                continue
            entries.append((path.name, stat.st_mtime_ns, stat.st_size))
        return tuple(entries)

    def _load(self, *, force: bool = False) -> None:
        snapshot = self._snapshot()
        if not force and snapshot == self._signature:
            return
        keys: dict[str, bytes] = {}
        for name, _, _ in snapshot:
            kid = name[: -len(".key")]
            if not _KID.fullmatch(kid):
                continue
            try:
                keys[kid] = decode_key((self.directory / name).read_text(encoding="ascii"))
            except (OSError, ValueError, UnicodeDecodeError):
                continue
        self._keys = keys
        self._signature = snapshot

    def get(self, kid: str) -> bytes | None:
        now = time.monotonic()
        with self._lock:
            if now - self._checked >= self.refresh_seconds:
                self._checked = now
                try:
                    self._load()
                except OSError:
                    self._keys = {}  # directory vanished: fail closed
            return self._keys.get(kid)


def verify_token(token: str, username: str, client_ip: str | None, keys: KeyRing, *,
                 require_source: bool = True, now: float | None = None) -> dict:
    """Return the claims of a valid token or raise :class:`TokenError`."""
    if not token or len(token) > MAX_TOKEN_LENGTH:
        raise TokenError("malformed")
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != TOKEN_VERSION:
        raise TokenError("malformed")
    _, kid, payload, signature = parts
    if not _KID.fullmatch(kid):
        raise TokenError("malformed")
    key = keys.get(kid)
    if key is None:
        raise TokenError("unknown_key")
    expected = hmac.new(key, f"{TOKEN_VERSION}.{kid}.{payload}".encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64url_decode(signature)):
        raise TokenError("bad_signature")
    try:
        claims = json.loads(_b64url_decode(payload))
    except ValueError as error:
        raise TokenError("malformed") from error
    if not isinstance(claims, dict):
        raise TokenError("malformed")
    sub, exp, iat, src = claims.get("sub"), claims.get("exp"), claims.get("iat"), claims.get("src")
    if not isinstance(sub, str) or type(exp) is not int or type(iat) is not int:
        raise TokenError("malformed")
    current = time.time() if now is None else now
    if exp - iat > MAX_TTL_SECONDS:
        raise TokenError("ttl_too_long")
    if current > exp + CLOCK_SKEW_SECONDS:
        raise TokenError("expired")
    if current + CLOCK_SKEW_SECONDS < iat:
        raise TokenError("not_yet_valid")
    if not hmac.compare_digest(sub.encode("utf-8"), username.encode("utf-8")):
        raise TokenError("subject_mismatch")
    if src is None:
        if require_source:
            raise TokenError("source_required")
    else:
        if not isinstance(src, list) or not src or not all(isinstance(item, str) for item in src):
            raise TokenError("malformed")
        try:
            networks = [ipaddress.ip_network(item, strict=True) for item in src]
            address = ipaddress.ip_address(client_ip or "")
        except ValueError as error:
            raise TokenError("source_not_allowed") from error
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if not any(address.version == network.version and address in network for network in networks):
            raise TokenError("source_not_allowed")
    return claims


class BasicAuthHelper:
    """Squid Basic auth helper: ``[channel] username password [client-ip]`` per line."""

    def __init__(self, keys: KeyRing, audit: AuditLog, *, require_source: bool = True) -> None:
        self.keys = keys
        self.audit = audit
        self.require_source = require_source

    def check(self, fields: list[str]) -> str:
        if len(fields) not in (2, 3):
            return "BH message=invalid_request"
        try:
            username = urllib.parse.unquote(fields[0], errors="strict")
            password = urllib.parse.unquote(fields[1], errors="strict")
        except UnicodeDecodeError:
            return "ERR"
        client_ip = urllib.parse.unquote(fields[2]) if len(fields) == 3 and fields[2] != "-" else None
        if not valid_principal(username):
            self.audit.emit("auth", principal=None, src=client_ip, result="deny", reason="invalid_username")
            return "ERR"
        try:
            claims = verify_token(password, username, client_ip, self.keys, require_source=self.require_source)
        except TokenError as error:
            METRICS.inc("egress_auth_total", {"decision": "deny", "reason": error.reason})
            self.audit.emit("auth", principal=username, src=client_ip, result="deny", reason=error.reason)
            return "ERR"
        METRICS.inc("egress_auth_total", {"decision": "allow", "reason": "token_valid"})
        self.audit.emit("auth", principal=username, src=client_ip, result="allow", reason="token_valid",
                        token_exp=claims["exp"])
        return "OK"


def _serve(helper: BasicAuthHelper, concurrent: bool) -> int:
    lock = threading.Lock()
    for raw in sys.stdin.buffer:
        channel = None
        try:
            fields = raw.decode("ascii").rstrip("\r\n").split(" ")
            if concurrent:
                channel = fields.pop(0)
                if not channel.isdigit():
                    continue
            answer = helper.check(fields)
        except Exception:
            answer = "BH message=helper_error"
        with lock:
            sys.stdout.write(f"{channel} {answer}\n" if channel is not None else f"{answer}\n")
            sys.stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="clearideas-egress-auth")
    parser.add_argument("--concurrent", action="store_true")
    args = parser.parse_args(argv)
    directory = os.environ.get("EGRESS_AUTH_KEYS_DIR") or "/nonexistent"
    audit = AuditLog.from_setting(os.environ.get("EGRESS_AUDIT_LOG"))
    # Never exit on configuration problems at runtime: Squid aborts when helpers keep failing
    # to start. With no usable keys every credential is refused (fail closed, stay up).
    keys = KeyRing(directory, require_keys=False)
    if not len(keys):
        print(f"egress auth: no valid <kid>.key files in {directory}; refusing all credentials", file=sys.stderr)
    require_source = os.environ.get("EGRESS_AUTH_REQUIRE_SOURCE", "true").lower() not in {"0", "false", "no", "off"}
    start_from_env("auth", [lambda registry: registry.set("egress_auth_keys_loaded", len(keys))])
    return _serve(BasicAuthHelper(keys, audit, require_source=require_source), args.concurrent)


def mint_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="clearideas-egress-token", description="Mint a sandbox proxy token.")
    parser.add_argument("--key-file", required=True)
    parser.add_argument("--kid", required=True)
    parser.add_argument("--sub", required=True, help="principal (proxy username)")
    parser.add_argument("--src", action="append", required=True, help="allowed client CIDR (repeatable)")
    parser.add_argument("--ttl", type=int, default=900, help="lifetime in seconds (default 900)")
    args = parser.parse_args(argv)
    try:
        key = decode_key(Path(args.key_file).read_text(encoding="ascii"))
        print(mint_token(key, args.kid, args.sub, args.src, args.ttl))
    except (OSError, ValueError) as error:
        print(f"cannot mint token: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
