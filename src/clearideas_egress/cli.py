"""Squid external ACL helper (``clearideas-egress-acl``).

Protocol
--------
Squid writes one request per line and reads one response per line. With
``concurrency=N`` on the ``external_acl_type`` line (and ``--concurrent`` here)
every line starts with a numeric channel ID that is echoed back, and responses
may be returned out of order.

Modes
-----
``--mode=acl`` (default)
    Fields ``%ul %>a %METHOD %DST %PORT`` (legacy layout). Consults the configured
    policy (``EGRESS_POLICY_FILE`` or ``EGRESS_POLICY_URL``).
``--mode=acl --fields=v2 --identity=auth|signed``
    Fields ``%un %>a %>rm %>rs %>rd %>rP %>rp %note{egress_principal_} %note{egress_identity_}``.
    The two notes are set only by the ``signed`` ACL after it verified the request
    (clients cannot set annotations). With ``--identity=auth`` the principal is the
    proxy-authenticated user; with ``--identity=signed`` it is the verified principal.
    ``--scope=api``: the backend's answer says how broadly an allow applies (a URL prefix
    and methods, see approvals.py); the helper keeps those approvals. ``--scope=origin``:
    the path is omitted and Squid caches one decision per identity, method and origin.
    ``--scope=request``: Squid caches per exact path.
``--mode=request``
    Fields ``%un %>rm %>rs %>rd %>rP %>rp %note{egress_principal_} %note{egress_identity_}``.
    Local per-request checks that must never be cached: the revocation list
    (``EGRESS_REVOKED_FILE``) and credential injection (``EGRESS_CREDENTIALS_FILE``:
    annotations with the provider key, credential query parameters, CONNECT refusal).
``--mode=sni``
    Fields ``%un %>a %DST %PORT %ssl::>sni``. Local check, no backend call: the TLS
    SNI must name the host the CONNECT was authorized for.
``--mode=signed``
    Fields ``%>rm %>rs %>rd %>rP %>rp``, the signed headers of the configured profile
    (identity headers, timestamp, nonce, signature) and ``%note{clt_conn_tag}``.
    Verifies the signature against the request's actual destination and, with a Redis
    nonce store, that the nonce is new. Returns the verified identity as annotations.
    For CONNECT it also tags the client connection with the identity and authorized
    destination, because Squid re-checks access for peeked TLS tunnels on an internal
    request that carries no client headers.

Responses are ``OK``/``ERR``/``BH`` plus ``log=<reason>`` (``%ea`` in the access log)
and annotations. Custom annotation names end with ``_`` (Squid reserves the rest and
logs their values). Every malformed line, backend failure or internal error produces
a non-OK answer; the helper never exits because of a bad line.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import os
import re
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Callable

from .audit import AuditLog
from .auth import KeyRing
import uuid

from .approvals import ApprovalCache, ambiguous_path, parse_scope
from .metrics import METRICS, reason_label, start_from_env
from .credentials import CredentialInjector
from .revocation import RevocationList
from .http_backend import HTTPPolicy
from .limits import PrincipalConcurrency, TokenBucketLimiter
from .nonces import NonceStoreError, RedisNonceStore
from .policy import (
    DECISION_NOTE,
    ReloadingFilePolicy,
    BACKEND_SATURATED,
    INVALID_REQUEST,
    RATE_LIMITED,
    RETRY_NOTE,
    RETRYABLE_REASONS,
    ACLRequest,
    Decision,
    PolicyError,
    decide,
    decode_field,
    is_ip_literal,
    load_file_policy,
    normalize_host,
    parse_fields,
    valid_principal,
)
from .signing import (
    Destination,
    SignatureError,
    SigningProfile,
    decode_identity,
    encode_identity,
    valid_identity_value,
    verify_request,
)

MAX_LINE_BYTES = 16384
NOTE_PRINCIPAL = "egress_principal_"
NOTE_IDENTITY = "egress_identity_"
CONNECT_TAG_PREFIX = "egress-connect"
_REQUEST_PATH = re.compile(r"^/[\x21-\x7e]{0,8191}$")


def _env_secret(name: str) -> str | None:
    """Read ``NAME_FILE`` (preferred) or ``NAME`` from the environment."""
    path = os.environ.get(f"{name}_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return os.environ.get(name) or None


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    return float(value) if value else default


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    return int(value) if value else default


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def build_backend():
    file_path = os.environ.get("EGRESS_POLICY_FILE")
    url = os.environ.get("EGRESS_POLICY_URL")
    if bool(file_path) == bool(url):
        raise ValueError("set exactly one of EGRESS_POLICY_FILE or EGRESS_POLICY_URL")
    if file_path:
        def on_reload(result: str, detail: str) -> None:
            METRICS.inc("egress_config_reloads_total", {"file": "policy", "result": result})
            AuditLog.from_setting(os.environ.get("EGRESS_AUDIT_LOG")).emit(
                "config_reload", file="policy", result=result, detail=detail[:300])

        return ReloadingFilePolicy(file_path, on_reload=on_reload), "file"
    return (
        HTTPPolicy(
            url,
            token=_env_secret("EGRESS_POLICY_TOKEN"),
            timeout_seconds=_env_float("EGRESS_POLICY_TIMEOUT", 15.0),
            attempt_timeout=_env_float("EGRESS_POLICY_ATTEMPT_TIMEOUT", 0.0) or None,
            retries=_env_int("EGRESS_POLICY_RETRIES", 3),
            ca_file=os.environ.get("EGRESS_POLICY_CA_FILE") or None,
            client_cert_file=os.environ.get("EGRESS_POLICY_CLIENT_CERT_FILE") or None,
            client_key_file=os.environ.get("EGRESS_POLICY_CLIENT_KEY_FILE") or None,
            max_in_flight=_env_int("EGRESS_POLICY_MAX_IN_FLIGHT", 64),
            require_request_id=_env_bool("EGRESS_POLICY_REQUIRE_REQUEST_ID"),
        ),
        "http",
    )


def _deny_line(reason: str) -> str:
    """ERR answer; temporary conditions carry the retry annotation (Squid then answers 503/429)."""
    retry = RETRYABLE_REASONS.get(reason)
    return f"ERR log={reason} {RETRY_NOTE}={retry}" if retry else f"ERR log={reason}"


def _format(result: str, decision: Decision) -> str:
    if result == "ERR":
        parts = [_deny_line(decision.reason)]
    else:
        parts = [result, f"log={decision.reason}"]
    parts.extend(f"{key}={value}" for key, value in sorted(decision.annotations.items()))
    return " ".join(parts)


def _strip_query(path: str | None) -> str | None:
    return path.split("?", 1)[0] if path else None


# ---------------------------------------------------------------------------
# Policy decision
# ---------------------------------------------------------------------------


def parse_v2_fields(fields: list[str], identity_mode: str, scope: str = "request") -> ACLRequest | None:
    """``%un %>a %>rm %>rs %>rd %>rP [%>rp] %note{egress_principal_} %note{egress_identity_}``.

    With ``scope="origin"`` the path field is absent (it is not part of the cached decision).
    """
    expected = 9 if scope == "request" else 8
    if len(fields) == expected + 1 and fields[-1] == "-":
        fields = fields[:-1]
    if len(fields) != expected:
        return None
    if scope != "request":
        fields = fields[:6] + ["-" if fields[2] == "CONNECT" else "/"] + fields[6:]
    user, source, method, scheme, raw_host, port, path, note_principal, note_identity = fields
    if method == "CONNECT":
        # "authority_form" is Squid's internal re-check of a peeked tunnel.
        if scheme not in ("-", "authority_form") or path != "-":
            return None
        scheme_value, path_value = None, None
    else:
        if scheme not in ("http", "https") or not _REQUEST_PATH.fullmatch(path):
            return None
        scheme_value, path_value = scheme, path
    if identity_mode == "signed":
        identity = decode_identity(note_identity)
        if identity is None or not valid_identity_value(note_principal) or note_principal not in identity.values():
            return None
        principal, attributes = note_principal, identity
    else:
        principal = decode_field(user)
        if principal is None:
            return None
        attributes = {}
    base = parse_fields([principal, source, method, raw_host, port])
    if base is None:
        return None
    return ACLRequest(base.principal, base.source_ip, base.method, base.host, base.port,
                      scheme=scheme_value, path=path_value if scope == "request" else None, attributes=attributes)


class AclHandler:
    """Policy decisions. With ``approvals`` (decision scope "api") allows are reused per the
    scope the backend returned; otherwise Squid's own decision cache applies."""

    def __init__(self, backend, backend_name: str, audit: AuditLog, concurrency: PrincipalConcurrency,
                 rate: TokenBucketLimiter | None, *, layout: str = "basic", identity_mode: str = "auth",
                 scope: str = "request", budget_seconds: float = 15.0,
                 approvals: ApprovalCache | None = None) -> None:
        self.backend = backend
        self.backend_name = backend_name
        self.audit = audit
        self.concurrency = concurrency
        self.rate = rate
        self.layout = layout
        self.identity_mode = identity_mode
        self.scope = scope
        self.budget_seconds = budget_seconds
        self.approvals = approvals

    # -- backend call ---------------------------------------------------------------

    def _ask(self, request: ACLRequest, deadline: float) -> Decision:
        started = time.monotonic()
        if self.rate is not None and not self.rate.allow(request.principal):
            decision = Decision.deny(RATE_LIMITED)
        else:
            # Bursts from one principal wait for a slot (up to the decision budget) instead of
            # being denied; other principals keep their own slots.
            with self.concurrency.slot(request.principal, timeout=max(deadline - time.monotonic(), 0)) as acquired:
                decision = (decide(request, self.backend, deadline=deadline) if acquired
                            else Decision.deny(BACKEND_SATURATED))
        METRICS.observe("egress_policy_decision_seconds", time.monotonic() - started, {"backend": self.backend_name})
        # One ID ties this decision to the access log (annotation) and the policy API (requestId).
        decision_id = decision.decision_id or uuid.uuid4().hex
        return Decision(decision.allowed, decision.reason, {**decision.annotations, DECISION_NOTE: decision_id},
                        decision.scope, decision.scope_methods, decision.scope_any_method, decision.scope_ttl,
                        decision_id)

    def _remember(self, request: ACLRequest, decision: Decision) -> str | None:
        """Store an allow in the approval cache; returns the stored scope prefix (for the audit log)."""
        if self.approvals is None:
            return None
        if not decision.allowed:
            self.approvals.forget(request)
            return None
        if request.method == "CONNECT" or decision.scope == "/":
            prefix = "/"
        elif decision.scope is not None:
            prefix = parse_scope(decision.scope, request) or _strip_query(request.path)
        else:
            prefix = _strip_query(request.path)  # no scope: the request URL (and what is beneath it)
        if prefix is None:
            return None
        if decision.scope_any_method:
            methods = None
        elif decision.scope_methods and request.method in decision.scope_methods:
            methods = decision.scope_methods
        else:
            methods = frozenset({request.method})
        ttl = decision.scope_ttl if decision.scope_ttl is not None else self.approvals.max_ttl
        self.approvals.store(request, prefix, methods, ttl, dict(decision.annotations))
        return prefix

    def _refresh(self, request: ACLRequest) -> None:
        try:
            decision = self._ask(request, time.monotonic() + self.budget_seconds)
            if decision.allowed or decision.reason not in RETRYABLE_REASONS:  # keep the approval on transient errors
                self._remember(request, decision)
            self._audit(request, decision, 0.0, refresh=True)
        finally:
            self.approvals.end_refresh(request)  # type: ignore[union-attr]

    def _decide_with_approvals(self, request: ACLRequest, deadline: float) -> tuple[Decision, bool, str | None]:
        assert self.approvals is not None
        if request.path is not None and ambiguous_path(request.path):
            return Decision.deny("ambiguous_path"), False, None
        approval, needs_refresh = self.approvals.lookup(request)
        if approval is None:
            leader, event = self.approvals.begin(request)
            if not leader:
                # Another request of this principal to this origin is asking right now: reuse its answer
                # if it covers us (a burst at the start of a run costs one policy call).
                event.wait(max(deadline - time.monotonic(), 0))
                approval, needs_refresh = self.approvals.lookup(request)
        if approval is not None:
            if needs_refresh and self.approvals.start_refresh(request):
                threading.Thread(target=self._refresh, args=(request,), daemon=True).start()
            return Decision(True, "approved_cached", dict(approval.annotations)), True, approval.prefix
        try:
            decision = self._ask(request, deadline)
            return decision, False, self._remember(request, decision)
        finally:
            self.approvals.end(request)

    # -- entry point ---------------------------------------------------------------

    def _audit(self, request: ACLRequest | None, decision: Decision, started: float, *, refresh: bool = False,
               scope: str | None = None) -> None:
        self.audit.emit(
            "decision",
            mode="acl",
            principal=request.principal if request else None,
            src=request.source_ip if request else None,
            method=request.method if request else None,
            host=request.host if request else None,
            port=request.port if request else None,
            scheme=request.effective_scheme if request else None,
            path=_strip_query(request.path) if request else None,
            identity=dict(request.attributes) if request and request.attributes else None,
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
            decision_id=decision.decision_id,
            scope=scope,
            refresh=refresh or None,
            backend=self.backend_name,
            latency_ms=round((time.monotonic() - started) * 1000, 1) if started else None,
        )

    def __call__(self, fields: list[str]) -> str:
        started = time.monotonic()
        deadline = started + self.budget_seconds
        if self.layout == "v2":
            request = parse_v2_fields(fields, self.identity_mode, self.scope)
        else:
            if len(fields) == 6 and fields[-1] == "-":
                fields = fields[:-1]
            request = parse_fields(fields)
        cached, scope = False, None
        if request is None:
            decision = Decision.deny(INVALID_REQUEST)
        elif self.approvals is not None:
            decision, cached, scope = self._decide_with_approvals(request, deadline)
        else:
            decision = self._ask(request, deadline)
        if decision.decision_id is None and DECISION_NOTE not in decision.annotations:
            decision_id = uuid.uuid4().hex  # every answer is correlatable, including local refusals
            decision = Decision(decision.allowed, decision.reason, {**decision.annotations, DECISION_NOTE: decision_id},
                                decision_id=decision_id)
        METRICS.inc("egress_decisions_total", {"decision": "allow" if decision.allowed else "deny",
                                               "reason": reason_label(decision.reason),
                                               "source": "approval" if cached else "backend"})
        if not cached:  # cache hits are counted, not logged one by one
            self._audit(request, decision, started, scope=scope)
        return _format("OK" if decision.allowed else "ERR", decision)


# ---------------------------------------------------------------------------
# Per-request local checks (never cached)
# ---------------------------------------------------------------------------


class RequestHandler:
    """Checks that must run on every request even when the policy decision is cached."""

    def __init__(self, audit: AuditLog, *, credentials: CredentialInjector | None = None,
                 revocations: RevocationList | None = None, xaction_field: bool = False) -> None:
        self.xaction_field = xaction_field  # first field is Squid's %master_xaction (log correlation)
        self.audit = audit
        self.credentials = credentials
        self.revocations = revocations

    def check(self, fields: list[str]) -> tuple[Decision, dict, str | None]:
        if len(fields) == 9 and fields[-1] == "-":
            fields = fields[:-1]
        if len(fields) != 8:
            return Decision.deny(INVALID_REQUEST), {}, None
        user, method, scheme, raw_host, port, path, note_principal, note_identity = fields
        identity = decode_identity(note_identity)
        principal = note_principal if identity and valid_identity_value(note_principal) else decode_field(user)
        host_value = decode_field(raw_host)
        host = normalize_host(host_value) if host_value else None
        if principal is None or host is None or not port.isdigit():
            return Decision.deny(INVALID_REQUEST), {}, None
        context = {"principal": principal, "method": method, "host": host, "port": int(port)}
        if self.revocations is not None:
            revoked = self.revocations.revoked(principal, identity)
            if revoked is None:
                return Decision.deny("helper_misconfigured"), context, None
            if revoked:
                return Decision.deny("revoked"), context, None
        if self.credentials is not None:
            if method == "CONNECT":
                request = ACLRequest(principal, "0.0.0.0", "CONNECT", host, int(port))
            elif scheme in ("http", "https") and _REQUEST_PATH.fullmatch(path):
                request = ACLRequest(principal, "0.0.0.0", method, host, int(port), scheme=scheme, path=path)
            else:
                return Decision.deny(INVALID_REQUEST), context, None
            deny_reason, notes, rule = self.credentials.apply(request)
            if deny_reason is not None:
                return Decision.deny(deny_reason), context, rule
            if notes:
                return Decision(True, "credential_injected", notes), context, rule
        return Decision.allow("request_ok"), context, None

    def __call__(self, fields: list[str]) -> str:
        xaction = (fields.pop(0) if fields else "-") if self.xaction_field else None
        decision, context, rule = self.check(fields)
        METRICS.inc("egress_request_checks_total", {"decision": "allow" if decision.allowed else "deny",
                                                    "reason": decision.reason})
        if rule is not None and decision.allowed:
            METRICS.inc("egress_credential_injections_total", {"rule": rule})
        if not decision.allowed or rule is not None:  # routine passes are not logged twice
            self.audit.emit("request_check", decision="allow" if decision.allowed else "deny", xaction=xaction,
                            reason=decision.reason, credential=rule, **context)  # rule id only, never the secret
        return _format("OK" if decision.allowed else "ERR", decision)


# ---------------------------------------------------------------------------
# TLS SNI check
# ---------------------------------------------------------------------------


class SniHandler:
    """OK only when the TLS SNI names the host the CONNECT was authorized for."""

    def __init__(self, audit: AuditLog, *, xaction_field: bool = False) -> None:
        self.xaction_field = xaction_field
        self.audit = audit

    def check(self, fields: list[str]) -> tuple[Decision, dict]:
        if len(fields) == 6 and fields[-1] == "-":
            fields = fields[:-1]
        if len(fields) != 5:
            return Decision.deny(INVALID_REQUEST), {}
        principal, source_ip, raw_host, raw_port, raw_sni = fields
        principal, source_ip, host_value, port = (decode_field(principal), decode_field(source_ip),
                                                  decode_field(raw_host), decode_field(raw_port))
        if principal is None or not valid_principal(principal) or source_ip is None or host_value is None or port is None:
            return Decision.deny(INVALID_REQUEST), {}
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            return Decision.deny(INVALID_REQUEST), {}
        host = normalize_host(host_value)
        context = {"principal": principal, "src": source_ip, "host": host, "port": port}
        if host is None:
            return Decision.deny(INVALID_REQUEST), context
        if raw_sni == "-":
            context["sni"] = None
            if is_ip_literal(host):
                return Decision.allow("sni_absent_ip_literal"), context
            return Decision.deny("sni_missing"), context
        sni_value = decode_field(raw_sni)
        sni = normalize_host(sni_value) if sni_value is not None else None
        context["sni"] = sni if sni is not None else "(invalid)"
        if sni is None or is_ip_literal(sni):
            return Decision.deny("sni_invalid"), context
        if sni != host:
            return Decision.deny("sni_mismatch"), context
        return Decision.allow("sni_match"), context

    def __call__(self, fields: list[str]) -> str:
        xaction = (fields.pop(0) if fields else "-") if self.xaction_field else None
        decision, context = self.check(fields)
        METRICS.inc("egress_tls_checks_total", {"decision": "allow" if decision.allowed else "deny",
                                                "reason": decision.reason})
        self.audit.emit("tls_check", mode="sni", decision="allow" if decision.allowed else "deny", xaction=xaction,
                        reason=decision.reason, **context)
        return _format("OK" if decision.allowed else "ERR", decision)


# ---------------------------------------------------------------------------
# Signed identity headers
# ---------------------------------------------------------------------------


def connect_tag(identity: dict[str, str], host: str, port: int | str) -> str:
    return "/".join([CONNECT_TAG_PREFIX, encode_identity(identity), host, str(port)])


class SignedHandler:
    """Verifies signed identity headers against the request's actual destination."""

    def __init__(self, keys: KeyRing, audit: AuditLog, profile: SigningProfile = SigningProfile(), *,
                 max_skew: int = 30, nonces: RedisNonceStore | None = None, xaction_field: bool = False) -> None:
        self.xaction_field = xaction_field
        self.keys = keys
        self.audit = audit
        self.profile = profile
        self.max_skew = max_skew
        self.nonces = nonces

    @property
    def field_count(self) -> int:
        return 5 + len(self.profile.all_headers) + 1

    def _recheck(self, raw_host: str, port: str, tag: str) -> tuple[str, dict, dict | None]:
        """Squid's internal re-check of a peeked CONNECT tunnel (no client headers).

        Accepted only if this client connection carries the tag that our own verification of
        a signed CONNECT set, for exactly this host and port.
        """
        parts = tag.split("/") if tag not in ("", "-") else []
        host_value = decode_field(raw_host)
        host = normalize_host(host_value) if host_value else None
        if len(parts) != 4 or parts[0] != CONNECT_TAG_PREFIX or host is None:
            return "connect_recheck_denied", {}, None
        identity = decode_identity(parts[1])
        if identity is None or set(identity) != set(self.profile.attributes):
            return "connect_recheck_denied", {}, None
        context = {"method": "CONNECT", "host": host, "port": port}
        if parts[2] != host or parts[3] != port:
            return "connect_recheck_denied", context, None
        return "connect_recheck", context, identity

    def check(self, fields: list[str]) -> tuple[str, dict, dict | None]:
        if len(fields) == self.field_count + 1 and fields[-1] == "-":
            fields = fields[:-1]
        if len(fields) != self.field_count:
            return "invalid_request", {}, None
        method, scheme, raw_host, port, path = fields[:5]
        if method == "CONNECT" and scheme == "authority_form":
            return self._recheck(raw_host, port, fields[-1])
        headers = dict(zip(self.profile.all_headers, fields[5:-1]))
        host = decode_field(raw_host)
        if host is None:
            return "invalid_destination", {}, None
        context: dict = {}
        try:
            destination = Destination.build(method, scheme, host, port, path)
            context = {"method": destination.method, "host": destination.host, "port": destination.port,
                       "path": _strip_query(destination.path) or None}
            verified = verify_request(headers, destination, self.keys, self.profile, max_skew_seconds=self.max_skew)
        except SignatureError as error:
            return error.reason, context, None
        if self.nonces is not None:
            try:
                scope = encode_identity(verified.identity)
                if not self.nonces.claim(scope, verified.nonce, (2 * self.max_skew + 5) * 1000):
                    return "nonce_replayed", context, None
            except NonceStoreError:
                return "nonce_store_error", context, None
        return "signature_valid", context, dict(verified.identity)

    def __call__(self, fields: list[str]) -> str:
        xaction = (fields.pop(0) if fields else "-") if self.xaction_field else None
        reason, context, identity = self.check(fields)
        ok = identity is not None
        METRICS.inc("egress_signatures_total", {"decision": "allow" if ok else "deny", "reason": reason})
        self.audit.emit("signature", decision="allow" if ok else "deny", reason=reason, xaction=xaction,
                        principal=identity[self.profile.principal] if ok else None, **context)
        if not ok:
            return _deny_line(reason)
        principal = identity[self.profile.principal]
        answer = (f"OK user={principal} {NOTE_PRINCIPAL}={principal} {NOTE_IDENTITY}={encode_identity(identity)} "
                  f"log={reason}")
        if reason == "signature_valid" and context.get("method") == "CONNECT":
            answer += " clt_conn_tag=" + connect_tag(identity, context["host"], context["port"])
        return answer


# ---------------------------------------------------------------------------
# Line protocol
# ---------------------------------------------------------------------------


def serve(handler: Callable[[list[str]], str], *, concurrent_mode: bool, workers: int,
          stdin=None, stdout=None, audit: AuditLog | None = None) -> int:
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout
    write_lock = threading.Lock()

    def respond(channel: str | None, text: str) -> None:
        line = f"{channel} {text}\n" if channel is not None else f"{text}\n"
        with write_lock:
            stdout.write(line)
            stdout.flush()

    def handle(channel: str | None, fields: list[str]) -> None:
        try:
            text = handler(fields)
        except Exception as error:  # never exit on a bad line; BH = helper failure, never an allow
            if audit is not None:
                audit.emit("helper_error", error=type(error).__name__)
            text = "BH log=helper_error"
        respond(channel, text)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers) if concurrent_mode else None
    try:
        for raw in stdin:
            channel = None
            try:
                if len(raw) > MAX_LINE_BYTES:
                    raise ValueError("line too long")
                line = raw.decode("ascii").rstrip("\r\n")
                fields = line.split(" ")
                if concurrent_mode:
                    channel = fields.pop(0)
                    if not channel.isdigit() or not channel.isascii():
                        raise ValueError("bad channel id")
            except (UnicodeDecodeError, ValueError, IndexError):
                if concurrent_mode:
                    guess = raw.split(b" ", 1)[0]
                    channel = guess.decode("ascii", "replace") if guess.isdigit() else None
                    if channel is None:
                        continue  # cannot address a reply; Squid never sends such lines
                respond(channel, "BH log=invalid_line")
                continue
            if executor is not None:
                executor.submit(handle, channel, fields)
            else:
                handle(channel, fields)
    finally:
        if executor is not None:
            executor.shutdown(wait=True)
    return 0


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def check_policy_main(argv: list[str]) -> int:
    """``clearideas-egress-acl check-policy FILE``: validate a policy file before deployment."""
    if len(argv) != 1:
        print("usage: clearideas-egress-acl check-policy POLICY.json", file=sys.stderr)
        return 2
    try:
        policy = load_file_policy(argv[0])
    except (OSError, PolicyError) as error:
        print(f"policy invalid: {error}", file=sys.stderr)
        return 1
    origins = sum(len(rule.origins) for rule in policy.principals.values())
    print(f"policy ok: {len(policy.principals)} principals, {origins} origins")
    return 0


def _nonce_store() -> RedisNonceStore | None:
    redis_url = os.environ.get("EGRESS_NONCE_REDIS_URL")
    if not redis_url:
        return None
    password = _env_secret("EGRESS_NONCE_REDIS_PASSWORD")
    if password:
        parsed = urllib.parse.urlsplit(redis_url)
        user = urllib.parse.quote(parsed.username or "", safe="")
        netloc = f"{user}:{urllib.parse.quote(password, safe='')}@{parsed.hostname}:{parsed.port or 6379}"
        redis_url = urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    return RedisNonceStore(redis_url, timeout_seconds=_env_float("EGRESS_NONCE_REDIS_TIMEOUT", 0.25),
                           ca_file=os.environ.get("EGRESS_NONCE_REDIS_CA_FILE") or None)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["check-policy"]:
        return check_policy_main(argv[1:])
    parser = argparse.ArgumentParser(prog="clearideas-egress-acl")
    parser.add_argument("--mode", choices=["acl", "sni", "signed", "request"], default="acl")
    parser.add_argument("--scope", choices=["origin", "request", "api"], default="request",
                        help="acl v2: what a decision covers (api: the backend returns a URL scope)")
    parser.add_argument("--fields", choices=["basic", "v2"], default="basic",
                        help="acl mode field layout (v2 adds scheme, path and verified identity)")
    parser.add_argument("--identity", choices=["auth", "signed"], default="auth",
                        help="acl v2: principal from proxy authentication or from verified signed headers")
    parser.add_argument("--xaction", action="store_true",
                        help="sni/signed/request modes: the first field is Squid's %%master_xaction")
    parser.add_argument("--concurrent", action="store_true",
                        help="Squid external_acl_type uses concurrency=N (channel IDs)")
    parser.add_argument("--workers", type=int, default=0,
                        help="worker threads in --concurrent mode (match Squid's concurrency=N)")
    args = parser.parse_args(argv)
    audit = AuditLog.from_setting(os.environ.get("EGRESS_AUDIT_LOG"))
    METRICS.set("egress_helper_misconfigured", 0, {"mode": args.mode})
    try:
        if args.mode == "sni":
            handler: Callable[[list[str]], str] = SniHandler(audit, xaction_field=args.xaction)
            workers = 4
        elif args.mode == "request":
            credentials_file = os.environ.get("EGRESS_CREDENTIALS_FILE")
            revoked_file = os.environ.get("EGRESS_REVOKED_FILE")
            revocations = None
            if revoked_file:
                revocations = RevocationList(revoked_file, on_error=lambda message: audit.emit(
                    "config_error", file="revocations", error=message))
                if not revocations.loaded:
                    print(f"egress ACL: cannot load {revoked_file}; denying all requests", file=sys.stderr)
            handler = RequestHandler(audit, revocations=revocations, xaction_field=args.xaction,
                                     credentials=CredentialInjector.from_file(credentials_file) if credentials_file else None)
            workers = 16
        elif args.mode == "signed":
            keys_dir = os.environ.get("EGRESS_SIGNING_KEYS_DIR")
            if not keys_dir:
                raise ValueError("EGRESS_SIGNING_KEYS_DIR is required for signed-header authentication")
            keys = KeyRing(keys_dir, require_keys=False)
            if not len(keys):
                print(f"egress ACL: no valid <kid>.key files in {keys_dir}; refusing all signatures", file=sys.stderr)
            handler = SignedHandler(keys, audit, SigningProfile.from_env(),
                                    max_skew=_env_int("EGRESS_SIGNATURE_MAX_SKEW", 30), nonces=_nonce_store(),
                                    xaction_field=args.xaction)
            workers = 16
        else:
            backend, name = build_backend()
            max_in_flight = _env_int("EGRESS_POLICY_MAX_IN_FLIGHT", 64)
            per_principal = _env_int("EGRESS_PRINCIPAL_MAX_IN_FLIGHT", max(1, max_in_flight // 2))
            handler = AclHandler(backend, name, audit, PrincipalConcurrency(per_principal),
                                 TokenBucketLimiter.parse(os.environ.get("EGRESS_RATE_LIMIT")),
                                 layout=args.fields, identity_mode=args.identity,
                                 scope="request" if args.scope == "api" else args.scope,
                                 budget_seconds=_env_float("EGRESS_POLICY_TIMEOUT", 15.0),
                                 approvals=ApprovalCache(max_ttl=_env_float("EGRESS_DECISION_TTL", 300.0),
                                                         grace_percent=_env_int("EGRESS_DECISION_GRACE", 10))
                                 if args.scope == "api" else None)
            workers = max_in_flight + 8
    except (OSError, ValueError) as error:
        # Do not exit: Squid aborts entirely when helpers keep failing to start, which would turn
        # a bad policy edit or a missing key into an outage for every tenant. Deny everything
        # instead and say why. (clearideas-egress-render validates all of this before Squid starts.)
        print(f"egress ACL startup failed: {error}; denying all requests", file=sys.stderr)
        reason = "helper_misconfigured"

        METRICS.set("egress_helper_misconfigured", 1, {"mode": args.mode})

        def handler(fields: list[str], _reason=reason) -> str:
            audit.emit("helper_error", error=_reason)
            METRICS.inc("egress_decisions_total", {"decision": "deny", "reason": _reason, "source": "helper"})
            return _deny_line(_reason)

        workers = 4
    collectors = []
    if isinstance(handler, AclHandler):
        collectors.append(_acl_collector(handler))
    start_from_env(args.mode, collectors)
    return serve(handler, concurrent_mode=args.concurrent, workers=args.workers or workers, audit=audit)


def _acl_collector(handler: "AclHandler"):
    def collect(registry) -> None:
        backend = handler.backend
        for attribute, name in (("attempts_total", "egress_policy_api_attempts_total"),
                                ("retries_total", "egress_policy_api_retries_total")):
            if hasattr(backend, attribute):
                with registry._lock:
                    registry.counters[(name, ())] = float(getattr(backend, attribute))
        if handler.approvals is not None:
            with registry._lock:
                registry.counters[("egress_approval_cache_hits_total", ())] = float(handler.approvals.hits)
                registry.counters[("egress_approval_cache_misses_total", ())] = float(handler.approvals.misses)
            registry.set("egress_approval_cache_keys", len(handler.approvals._entries))
    return collect


if __name__ == "__main__":
    raise SystemExit(main())
