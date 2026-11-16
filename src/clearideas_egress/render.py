"""Render the Squid configuration from validated ``EGRESS_*`` settings.

``clearideas-egress-render`` is run by the container entrypoint (and by the E2E
harness) before Squid starts. It writes ``squid.conf``, the destination deny list
and, when TLS enforcement is on, a throwaway certificate for the ``ssl-bump`` port,
into ``EGRESS_RUN_DIR`` (default ``/run/egress``).

Every value that reaches ``squid.conf`` is validated against a strict pattern, so
settings cannot inject Squid directives (e.g. through embedded newlines).
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from string import Template
from typing import Mapping

from .auth import KeyRing
from . import errorpages
from .credentials import ANNOTATION_RULE, ANNOTATION_SECRET, CredentialRule, load_rules
from .policy import PolicyError, load_file_policy
from .signing import SigningProfile

_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/+-]*$")
_SAFE_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$")
_SIZE = re.compile(r"^\s*([0-9]{1,12})\s*(B|KB|MB|GB)?\s*$", re.IGNORECASE)
_SQUID_LOG = re.compile(r"^(?:stdio:/[A-Za-z0-9._/+-]*|none)$")

NCSA_CANDIDATES = ("/usr/lib/squid/basic_ncsa_auth", "/usr/lib64/squid/basic_ncsa_auth",
                   "/usr/libexec/squid/basic_ncsa_auth")
CERTGEN_CANDIDATES = ("/usr/lib/squid/security_file_certgen", "/usr/lib64/squid/security_file_certgen",
                      "/usr/libexec/squid/security_file_certgen")


class SettingsError(ValueError):
    pass


def _path(value: str, name: str) -> str:
    if not _SAFE_PATH.fullmatch(value) or "/../" in f"{value}/":
        raise SettingsError(f"{name} must be an absolute path using [A-Za-z0-9._/+-] only")
    return value


def _int(env: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    if not re.fullmatch(r"[0-9]{1,9}", raw):
        raise SettingsError(f"{name} must be an integer")
    value = int(raw)
    if not low <= value <= high:
        raise SettingsError(f"{name} must be between {low} and {high}")
    return value


def _size(env: Mapping[str, str], name: str, default: str) -> str:
    raw = env.get(name, "").strip() or default
    match = _SIZE.fullmatch(raw)
    if not match:
        raise SettingsError(f"{name} must look like '25 MB'")
    unit = (match.group(2) or "B").upper()
    return f"{int(match.group(1))} {'bytes' if unit == 'B' else unit}"


def _cidrs(raw: str, name: str) -> list[str]:
    items = [item for item in re.split(r"[\s,]+", raw.strip()) if item]
    try:
        return [str(ipaddress.ip_network(item, strict=False)) for item in items]
    except ValueError as error:
        raise SettingsError(f"{name}: {error}") from error


def _ips(raw: str, name: str) -> list[str]:
    items = [item for item in re.split(r"[\s,]+", raw.strip()) if item]
    try:
        return [str(ipaddress.ip_address(item)) for item in items]
    except ValueError as error:
        raise SettingsError(f"{name}: {error}") from error


def _instance(env: Mapping[str, str]) -> str:
    value = env.get("EGRESS_INSTANCE_ID")
    if value is None:
        from .audit import instance_id
        return instance_id()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value):
        raise SettingsError("EGRESS_INSTANCE_ID must match [A-Za-z0-9._-]{1,64}")
    return value


# Read-only cache-manager actions served on the loopback admin port (for the monitor).
ADMIN_ACTIONS = ("info", "counters", "5min", "utilization", "external_acl", "basicauthenticator")


@dataclass
class Settings:
    run_dir: str
    mode: str
    port: int
    visible_hostname: str
    auth_mode: str
    htpasswd_file: str | None
    auth_keys_dir: str | None
    signing_keys_dir: str | None
    signing_profile: SigningProfile
    upstream_ca_file: str | None
    credentials_file: str | None
    revoked_file: str | None
    decision_scope: str
    credentials_ttl: int
    tls_enforcement: str
    tls_port_cert: str | None
    tls_port_key: str | None
    error_ca_cert: str | None
    error_ca_key: str | None
    trusted_proxy_cidrs: list[str]
    decision_ttl: int
    decision_negative_ttl: int
    decision_grace: int
    helper_children: int
    helper_concurrency: int
    max_conn_per_client: int
    request_body_max_size: str
    client_lifetime: int
    read_timeout: int
    request_timeout: int
    connect_timeout: int
    extra_deny_cidrs_file: str | None
    dns_nameservers: list[str]
    access_log: str
    cache_log: str
    squid_extra_conf: str | None
    python: str
    drain_seconds: int
    max_filedescriptors: int
    admin_port: int
    instance_id: str
    policy_file: str | None
    policy_url: str | None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env
        run_dir = _path(env.get("EGRESS_RUN_DIR", "/run/egress"), "EGRESS_RUN_DIR")
        mode = env.get("EGRESS_MODE", "connect")
        if mode not in {"connect", "origination", "both"}:
            raise SettingsError("EGRESS_MODE must be 'connect', 'origination' or 'both'")
        auth_mode = env.get("EGRESS_AUTH_MODE", "token")
        if auth_mode not in {"token", "htpasswd", "signed-headers"}:
            raise SettingsError("EGRESS_AUTH_MODE must be 'token', 'htpasswd' or 'signed-headers'")
        signing_keys_dir = env.get("EGRESS_SIGNING_KEYS_DIR") or None
        upstream_ca = env.get("EGRESS_UPSTREAM_CA_FILE") or None
        if upstream_ca:
            _path(upstream_ca, "EGRESS_UPSTREAM_CA_FILE")
        try:
            profile = SigningProfile.from_env(env)
        except ValueError as error:
            raise SettingsError(str(error)) from error
        revoked_file = env.get("EGRESS_REVOKED_FILE") or None
        if revoked_file:
            _path(revoked_file, "EGRESS_REVOKED_FILE")
        scope = env.get("EGRESS_DECISION_SCOPE", "api")
        if scope not in {"api", "origin", "request"}:
            raise SettingsError("EGRESS_DECISION_SCOPE must be 'api', 'origin' or 'request'")
        credentials_file = env.get("EGRESS_CREDENTIALS_FILE") or None
        if credentials_file:
            _path(credentials_file, "EGRESS_CREDENTIALS_FILE")
            if mode == "connect":
                raise SettingsError("EGRESS_CREDENTIALS_FILE requires EGRESS_MODE=origination or both "
                                    "(headers cannot be rewritten inside CONNECT tunnels)")
        htpasswd_file = env.get("EGRESS_HTPASSWD_FILE") or None
        keys_dir = env.get("EGRESS_AUTH_KEYS_DIR") or None
        if auth_mode == "htpasswd":
            if not htpasswd_file:
                raise SettingsError("EGRESS_AUTH_MODE=htpasswd requires EGRESS_HTPASSWD_FILE")
            _path(htpasswd_file, "EGRESS_HTPASSWD_FILE")
        elif auth_mode == "token":
            if not keys_dir:
                raise SettingsError("EGRESS_AUTH_MODE=token requires EGRESS_AUTH_KEYS_DIR")
            _path(keys_dir, "EGRESS_AUTH_KEYS_DIR")
        else:
            if not signing_keys_dir:
                raise SettingsError("EGRESS_AUTH_MODE=signed-headers requires EGRESS_SIGNING_KEYS_DIR")
            _path(signing_keys_dir, "EGRESS_SIGNING_KEYS_DIR")
        tls = env.get("EGRESS_TLS_ENFORCEMENT", "sni")
        if tls not in {"sni", "off"}:
            raise SettingsError("EGRESS_TLS_ENFORCEMENT must be 'sni' or 'off'")
        cert, key = env.get("EGRESS_TLS_PORT_CERT_FILE") or None, env.get("EGRESS_TLS_PORT_KEY_FILE") or None
        if (cert is None) != (key is None):
            raise SettingsError("EGRESS_TLS_PORT_CERT_FILE and EGRESS_TLS_PORT_KEY_FILE go together")
        for value, name in ((cert, "EGRESS_TLS_PORT_CERT_FILE"), (key, "EGRESS_TLS_PORT_KEY_FILE")):
            if value:
                _path(value, name)
        ca_cert, ca_key = env.get("EGRESS_ERROR_CA_CERT_FILE") or None, env.get("EGRESS_ERROR_CA_KEY_FILE") or None
        if (ca_cert is None) != (ca_key is None):
            raise SettingsError("EGRESS_ERROR_CA_CERT_FILE and EGRESS_ERROR_CA_KEY_FILE go together")
        if ca_cert:
            _path(ca_cert, "EGRESS_ERROR_CA_CERT_FILE")
            _path(ca_key, "EGRESS_ERROR_CA_KEY_FILE")
            if cert:
                raise SettingsError("EGRESS_ERROR_CA_* replaces EGRESS_TLS_PORT_*; set only one pair")
            if tls != "sni" or mode == "origination":
                raise SettingsError("EGRESS_ERROR_CA_* only applies to CONNECT with EGRESS_TLS_ENFORCEMENT=sni "
                                    "(EGRESS_MODE=connect or both)")
        hostname = env.get("EGRESS_VISIBLE_HOSTNAME", "egress")
        if not _SAFE_HOSTNAME.fullmatch(hostname):
            raise SettingsError("EGRESS_VISIBLE_HOSTNAME is not a valid hostname")
        extra_deny = env.get("EGRESS_EXTRA_DENY_CIDRS_FILE") or None
        if extra_deny:
            _path(extra_deny, "EGRESS_EXTRA_DENY_CIDRS_FILE")
        extra_conf = env.get("EGRESS_SQUID_EXTRA_CONF") or None
        if extra_conf:
            _path(extra_conf, "EGRESS_SQUID_EXTRA_CONF")
        access_log = env.get("EGRESS_ACCESS_LOG", "stdio:/dev/stdout")
        if not _SQUID_LOG.fullmatch(access_log):
            raise SettingsError("EGRESS_ACCESS_LOG must be 'stdio:/absolute/path' or 'none'")
        cache_log = _path(env.get("EGRESS_CACHE_LOG", "/dev/stderr"), "EGRESS_CACHE_LOG")
        policy_file = env.get("EGRESS_POLICY_FILE") or None
        policy_url = env.get("EGRESS_POLICY_URL") or None
        if bool(policy_file) == bool(policy_url):
            raise SettingsError("set exactly one of EGRESS_POLICY_FILE or EGRESS_POLICY_URL")
        python = env.get("EGRESS_PYTHON", sys.executable)
        _path(python, "EGRESS_PYTHON")
        concurrency = _int(env, "EGRESS_HELPER_CONCURRENCY", 128, 1, 1000)
        decision_ttl = _int(env, "EGRESS_DECISION_TTL", 300, 0, 86400)
        return cls(
            run_dir=run_dir,
            mode=mode,
            signing_keys_dir=signing_keys_dir,
            signing_profile=profile,
            upstream_ca_file=upstream_ca,
            credentials_file=credentials_file,
            revoked_file=revoked_file,
            decision_scope=scope,
            port=_int(env, "EGRESS_LISTEN_PORT", 3128, 1024, 65535),
            visible_hostname=hostname,
            auth_mode=auth_mode,
            htpasswd_file=htpasswd_file,
            auth_keys_dir=keys_dir,
            credentials_ttl=_int(env, "EGRESS_CREDENTIALS_TTL", 60, 1, 3600),
            tls_enforcement=tls,
            tls_port_cert=cert,
            tls_port_key=key,
            error_ca_cert=ca_cert,
            error_ca_key=ca_key,
            trusted_proxy_cidrs=_cidrs(env.get("EGRESS_TRUSTED_PROXY_CIDRS", ""), "EGRESS_TRUSTED_PROXY_CIDRS"),
            decision_ttl=decision_ttl,
            decision_negative_ttl=_int(env, "EGRESS_DECISION_NEGATIVE_TTL", 5, 0, 3600),
            decision_grace=_int(env, "EGRESS_DECISION_GRACE", 10, 0, 99),
            helper_children=_int(env, "EGRESS_HELPER_CHILDREN", 4, 1, 64),
            helper_concurrency=concurrency,
            max_conn_per_client=_int(env, "EGRESS_MAX_CONN_PER_CLIENT", 256, 0, 100000),
            request_body_max_size=_size(env, "EGRESS_REQUEST_BODY_MAX_SIZE", "25 MB"),
            client_lifetime=_int(env, "EGRESS_CLIENT_LIFETIME", 3600, 1, 7 * 86400),
            read_timeout=_int(env, "EGRESS_READ_TIMEOUT", 300, 1, 86400),
            request_timeout=_int(env, "EGRESS_REQUEST_TIMEOUT", 30, 1, 3600),
            connect_timeout=_int(env, "EGRESS_CONNECT_TIMEOUT", 10, 1, 600),
            extra_deny_cidrs_file=extra_deny,
            dns_nameservers=_ips(env.get("EGRESS_DNS_NAMESERVERS", ""), "EGRESS_DNS_NAMESERVERS"),
            access_log=access_log,
            cache_log=cache_log,
            squid_extra_conf=extra_conf,
            python=python,
            drain_seconds=_int(env, "EGRESS_DRAIN_SECONDS", 30, 0, 3600),
            max_filedescriptors=_int(env, "EGRESS_MAX_FILEDESCRIPTORS", 65536, 1024, 1048576),
            admin_port=_int(env, "EGRESS_ADMIN_PORT", 3129, 0, 65535),
            instance_id=_instance(env),
            policy_file=policy_file,
            policy_url=policy_url,
        )


def _find_ncsa() -> str:
    found = shutil.which("basic_ncsa_auth")
    if found:
        return found
    for candidate in NCSA_CANDIDATES:
        if os.access(candidate, os.X_OK):
            return candidate
    raise SettingsError("basic_ncsa_auth not found (required for EGRESS_AUTH_MODE=htpasswd)")


def find_certgen() -> str:
    found = shutil.which("security_file_certgen")
    if found:
        return found
    for candidate in CERTGEN_CANDIDATES:
        if os.access(candidate, os.X_OK):
            return candidate
    raise SettingsError("security_file_certgen not found (required for EGRESS_ERROR_CA_*)")


def _template(name: str) -> str:
    return resources.files("clearideas_egress").joinpath("templates", name).read_text(encoding="utf-8")


def deny_cidrs(settings: Settings) -> str:
    entries = []
    for line in _template("deny-cidrs.conf").splitlines():
        value = line.split("#", 1)[0].strip()
        if value:
            entries.append(str(ipaddress.ip_network(value, strict=True)))
    if settings.extra_deny_cidrs_file:
        text = Path(settings.extra_deny_cidrs_file).read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            value = line.split("#", 1)[0].strip()
            if not value:
                continue
            try:
                entries.append(str(ipaddress.ip_network(value, strict=False)))
            except ValueError as error:
                raise SettingsError(f"EGRESS_EXTRA_DENY_CIDRS_FILE line {number}: {error}") from error
    return "\n".join(entries) + "\n"


def _credential_config(rules: tuple[CredentialRule, ...]) -> str:
    if not rules:
        return ""
    lines = ["# --- credential injection: the proxy supplies provider keys (EGRESS_CREDENTIALS_FILE) ---",
             "# The secret arrives per request as an annotation from the policy helper; it is never in this file."]
    for rule in rules:
        acl = f"egress_cred_{rule.id.replace('-', '_')}"
        lines.append(f"acl {acl} note {ANNOTATION_RULE} {rule.id}")
        for header in (rule.header, *rule.strip_headers):
            lines.append(f"request_header_access {header} deny {acl}")
        lines.append(f'request_header_add {rule.header} "{rule.prefix}%note{{{ANNOTATION_SECRET}}}{rule.suffix}" {acl}')
    return "\n".join(lines) + "\n"


# Squid-generated error types that mark a reply as the proxy's own (407 excluded: that is an
# authentication challenge clients handle themselves).
# (ERR_ACL_TIME_QUOTA_EXCEEDED and ERR_AGENT_* are page names only, not error types.)
_OWN_ERRORS = tuple(name for name in errorpages.SQUID_PAGES
                    if name not in {"ERR_CACHE_ACCESS_DENIED", "ERR_ACL_TIME_QUOTA_EXCEEDED", "ERR_AGENT_CONFIGURE",
                                    "ERR_AGENT_WPAD"})


def _error_reply_marking(bumping: bool, conn_limit: bool) -> list[str]:
    """``X-Egress-Error: <class>`` on every reply the proxy generates itself, never on a destination's.

    A reply is the proxy's own if Squid generated it (squid_error), if it was refused by one of the
    annotated deny rules, or, on an SNI-enforcing port, if it travels inside a bumped tunnel: the proxy
    only ever bumps to deliver an error (allowed tunnels are spliced). The class follows the status;
    the page body carries the precise ``code`` and ``reason``.
    """
    own = ["egress_squid_error", "egress_retry_503", "egress_retry_429", "egress_dest_unresolved"]
    lines = [f"acl egress_squid_error squid_error {' '.join(_OWN_ERRORS)}"]
    if bumping:
        lines.append("acl egress_bumped_reply connections_encrypted")
        own.append("egress_bumped_reply")
    if conn_limit:
        own.append("egress_conn_limited")
    lines += [
        f"acl egress_own_reply any-of {' '.join(own)}",
        "acl egress_status_400 http_status 400",
        "acl egress_status_403 http_status 403",
        "acl egress_status_407 http_status 407",
        "acl egress_status_429 http_status 429",
        "acl egress_status_503 http_status 503",
        "acl egress_status_unreachable http_status 502 504",
        "acl egress_status_classified http_status 400 403 407 429 502 503 504",
        # A destination cannot forge the marker (removal runs before the additions below).
        "reply_header_access X-Egress-Error deny all",
        'reply_header_add X-Egress-Error "invalid_request" egress_own_reply egress_status_400',
        'reply_header_add X-Egress-Error "denied" egress_own_reply egress_status_403',
        'reply_header_add X-Egress-Error "rate_limited" egress_own_reply egress_status_429',
        'reply_header_add X-Egress-Error "unavailable" egress_own_reply egress_status_503',
        'reply_header_add X-Egress-Error "unreachable" egress_own_reply egress_status_unreachable',
        'reply_header_add X-Egress-Error "error" egress_own_reply !egress_status_classified',
    ]
    return lines


def render(settings: Settings, credential_rules: tuple[CredentialRule, ...] | None = None) -> str:
    module = f"{settings.python} -m clearideas_egress"
    acl_helper = f"{module}.cli"
    tls_cert = settings.tls_port_cert or f"{settings.run_dir}/tls-port.pem"
    tls_key = settings.tls_port_key or f"{settings.run_dir}/tls-port.key"

    sni = settings.tls_enforcement == "sni" and settings.mode in ("connect", "both")
    admin_listener = f"\nhttp_port 127.0.0.1:{settings.admin_port} name=admin" if settings.admin_port else ""
    listener = f"http_port {settings.port}"
    if sni and settings.error_ca_cert:
        # Denied CONNECTs are answered inside TLS (Squid's delayed error). With an error CA the sandbox
        # trusts, Squid mints a certificate for the requested host *only to deliver that error*; allowed
        # tunnels are spliced, never decrypted (ssl_bump below has no bump action).
        listener += (f" ssl-bump tls-cert={settings.error_ca_cert} tls-key={settings.error_ca_key}"
                     " generate-host-certificates=on dynamic_cert_mem_cache_size=4MB")
    elif sni:
        listener += f" ssl-bump tls-cert={tls_cert} tls-key={tls_key} generate-host-certificates=off"
    if settings.trusted_proxy_cidrs:
        listener += " require-proxy-header"

    if settings.auth_mode == "token":
        auth = "\n".join([
            f"auth_param basic program {module} auth --concurrent",
            "auth_param basic children 8 startup=2 idle=2 concurrency=32",
            "auth_param basic realm egress",
            f"auth_param basic credentialsttl {settings.credentials_ttl} seconds",
            "auth_param basic casesensitive on",
            'auth_param basic key_extras "%>a"',
            "acl authenticated proxy_auth REQUIRED",
        ])
    elif settings.auth_mode == "signed-headers":
        auth = "# Identity comes from per-request signed identity headers (no proxy authentication)."
    else:
        auth = "\n".join([
            f"auth_param basic program {_find_ncsa()} {settings.htpasswd_file}",
            "auth_param basic children 8 startup=2 idle=2",
            "auth_param basic realm egress",
            f"auth_param basic credentialsttl {settings.credentials_ttl} seconds",
            "auth_param basic casesensitive on",
            "acl authenticated proxy_auth REQUIRED",
        ])

    proxy_protocol = ""
    if settings.trusted_proxy_cidrs:
        proxy_protocol = "\n".join(
            [f"acl trusted_proxies src {cidr}" for cidr in settings.trusted_proxy_cidrs]
            + ["proxy_protocol_access allow trusted_proxies", "proxy_protocol_access deny all"]
        ) + "\n"

    tls = ""
    if sni:
        tls = "\n".join([
            "# --- TLS enforcement (review H-1): peek at the ClientHello, never decrypt -----",
            "acl step1 at_step SslBump1",
            "acl step2 at_step SslBump2",
            "acl tls_optional note egress_tls_ optional",
            "external_acl_type egress_sni ttl=0 negative_ttl=0 children-max=2 children-startup=1 "
            f"concurrency={settings.helper_concurrency} queue-size={settings.helper_concurrency * 4} "
            f"%master_xaction %un %>a %DST %PORT %ssl::>sni {acl_helper} --mode=sni --xaction --concurrent "
            f"--workers {min(settings.helper_concurrency, 16)}",
            "acl sni_ok external egress_sni",
            *([f"sslcrtd_program {find_certgen()} -s {settings.run_dir}/ssl_db -M 4MB",
               "sslcrtd_children 4 startup=1 idle=1"] if settings.error_ca_cert else []),
            "ssl_bump splice step1 tls_optional",
            "ssl_bump peek step1",
            "ssl_bump splice step2 sni_ok",
            "ssl_bump terminate all",
        ]) + "\n"

    helper_opts = (f"children-max={settings.helper_children} children-startup={min(2, settings.helper_children)} "
                   f"concurrency={settings.helper_concurrency} "
                   f"queue-size={settings.helper_children * settings.helper_concurrency * 4}")
    profile = settings.signing_profile
    signed_header_fields = " ".join(f"%>{{{header}}}" for header in profile.all_headers)
    # The policy decision reads identity only from annotations set by the signature check.
    identity_notes = "%note{egress_principal_} %note{egress_identity_}"
    signed = settings.auth_mode == "signed-headers"
    # Decision reuse. "api": the helper keeps approvals scoped by the backend's answer (URL prefix +
    # methods), so Squid must not cache allows itself. "origin": the path is left out of the format
    # (Squid's cache key), so one decision covers a principal's method + origin. "request": exact path.
    path_field = "" if settings.decision_scope == "origin" else "%>rp "
    squid_ttl = 0 if settings.decision_scope == "api" else settings.decision_ttl
    grace = f"grace={settings.decision_grace} " if squid_ttl else ""
    policy_acls = [
        f"external_acl_type egress_policy ttl={squid_ttl} negative_ttl={settings.decision_negative_ttl} "
        f"{grace}{helper_opts} "
        f"%un %>a %>rm %>rs %>rd %>rP {path_field}{identity_notes} "
        f"{acl_helper} --fields=v2 --identity={'signed' if signed else 'auth'} --scope={settings.decision_scope} "
        f"--concurrent --workers {settings.helper_concurrency}",
        "acl policy_allowed external egress_policy",
    ]
    # Checks that must run on every request regardless of the decision cache.
    request_checks = bool(settings.credentials_file or settings.revoked_file)
    if request_checks:
        policy_acls += [
            f"external_acl_type egress_request ttl=0 negative_ttl=0 {helper_opts} "
            f"%master_xaction %un %>rm %>rs %>rd %>rP %>rp {identity_notes} {acl_helper} --mode=request --xaction "
            f"--concurrent --workers {settings.helper_concurrency}",
            "acl request_ok external egress_request",
        ]
    request_ok = " request_ok" if request_checks else ""
    if signed:
        policy_acls += [
            # Never cached: every request carries a fresh timestamp, nonce and signature.
            f"external_acl_type egress_signed ttl=0 negative_ttl=0 {helper_opts} "
            f"%master_xaction %>rm %>rs %>rd %>rP %>rp {signed_header_fields} %note{{clt_conn_tag}} {acl_helper} "
            f"--mode=signed --xaction --concurrent --workers {settings.helper_concurrency}",
            "acl signed_ok external egress_signed",
        ]
    if settings.max_conn_per_client:
        policy_acls.append(f"acl too_many_conns maxconn {settings.max_conn_per_client}")
    if settings.admin_port:
        policy_acls.append("acl admin_port myportname admin")

    # Destination checks run only after authentication and a policy allow (they resolve the name).
    # The annotate_transaction marks record how far they got, for the access log ("destination")
    # and for the reply: "forbidden" (resolves to an internal/special address), "unresolved" (no
    # address), "ok". They always match, so they never change the outcome of the line.
    policy_acls += [
        "acl egress_dest_mark_forbidden annotate_transaction egress_dest_=forbidden",
        "acl egress_dest_mark_unresolved annotate_transaction egress_dest_=unresolved",
        "acl egress_dest_mark_ok annotate_transaction egress_dest_=ok",
        "acl egress_dest_resolved dst all",
        "acl egress_dest_unresolved note egress_dest_ unresolved",
    ]
    destination_checks = ("egress_dest_mark_forbidden !to_localhost !private_dst "
                          "egress_dest_mark_unresolved egress_dest_resolved egress_dest_mark_ok")

    rules = []
    if settings.admin_port:
        # Loopback-only admin port for the monitor's metrics; nothing else is served there.
        rules += ["http_access allow manager admin_port localhost", "http_access deny admin_port"]
    rules.append("http_access deny manager")
    if settings.mode == "origination":
        rules += ["http_access deny CONNECT", "http_access deny !web_proto"]
    elif settings.mode == "both":
        rules += ["http_access deny !CONNECT !web_proto"]
    else:
        rules += ["http_access deny !CONNECT !http_proto"]
    rules += ["http_access deny !Safe_ports", "http_access deny CONNECT !SSL_ports"]
    if settings.max_conn_per_client:
        # The annotation marks the refusal so the reply can be recognized as the proxy's own.
        rules.append("http_access deny too_many_conns egress_mark_conn_limit")
    if signed:
        rules.append(f"http_access allow signed_ok policy_allowed{request_ok} {destination_checks}")
    else:
        rules += ["http_access deny !authenticated",
                  f"http_access allow authenticated policy_allowed{request_ok} {destination_checks}"]
    # An allowed name that does not resolve: a clear 503 (inside TLS for CONNECT) instead of Squid
    # writing a plain-text error into the client's TLS handshake after "200 Connection established".
    rules.append("http_access deny egress_dest_unresolved")
    # Temporary failures (policy API down/slow, saturation, rate limit, nonce store) are marked by the
    # helpers; answer them with 503/429 + Retry-After so clients and SDKs retry instead of failing.
    rules += ["http_access deny egress_retry_503", "http_access deny egress_retry_429", "http_access deny all"]
    policy_acls += [
        "acl egress_retry_503 note egress_retry_ 503",
        "acl egress_retry_429 note egress_retry_ 429",
    ]
    if settings.max_conn_per_client:
        policy_acls += ["acl egress_mark_conn_limit annotate_transaction egress_limit_=conn",
                        "acl egress_conn_limited note egress_limit_ conn"]
    retry_replies = [
        f"deny_info 503:{errorpages.UNRESOLVED} egress_dest_unresolved",
        f"deny_info 503:{errorpages.UNAVAILABLE} egress_retry_503",
        f"deny_info 429:{errorpages.RATE_LIMITED} egress_retry_429",
        'reply_header_add Retry-After "1" egress_retry_503',
        'reply_header_add Retry-After "1" egress_retry_429',
    ]
    if settings.max_conn_per_client:
        retry_replies += [f"deny_info 503:{errorpages.CONNECTION_LIMIT} egress_mark_conn_limit",
                          'reply_header_add Retry-After "1" egress_conn_limited']
    retry_replies += _error_reply_marking(sni, bool(settings.max_conn_per_client))

    upstream_tls = ""
    if settings.mode in ("origination", "both"):
        # HTTP Upgrade is forwarded only where policy marked the origin websocket: true. The token is
        # case-sensitive and real clients send lowercase "websocket" (Squid's own example does not match).
        upstream_tls += ("acl egress_ws note egress_ws_ yes\n"
                         "http_upgrade_request_protocols websocket allow egress_ws\n")
        options = "min-version=1.2"
        if settings.upstream_ca_file:
            options += f" cafile={settings.upstream_ca_file}"
        upstream_tls += ("# --- TLS originated by the proxy: certificates and host names are verified ----\n"
                         f"tls_outgoing_options {options}\n")

    extra = f"include {settings.squid_extra_conf}\n" if settings.squid_extra_conf else ""
    values = {
        "visible_hostname": settings.visible_hostname,
        "listeners": listener + admin_listener,
        "instance_id": settings.instance_id,
        "max_filedescriptors": settings.max_filedescriptors,
        "cachemgr_actions": (f"cachemgr_passwd none {' '.join(ADMIN_ACTIONS)}" if settings.admin_port else ""),
        "run_dir": settings.run_dir,
        "shutdown_lifetime": settings.drain_seconds,
        "access_log": settings.access_log,
        "cache_log": settings.cache_log,
        "dns_nameservers": (f"dns_nameservers {' '.join(settings.dns_nameservers)}\n"
                            if settings.dns_nameservers else ""),
        "request_body_max_size": settings.request_body_max_size,
        "client_lifetime": settings.client_lifetime,
        "read_timeout": settings.read_timeout,
        "request_timeout": settings.request_timeout,
        "connect_timeout": settings.connect_timeout,
        "auth": auth,
        "policy_acls": "\n".join(policy_acls),
        "strip_identity_headers": "\n".join(f"request_header_access {header} deny all"
                                             for header in profile.all_headers),
        "credentials": _credential_config(credential_rules if credential_rules is not None else
                                          (load_rules(settings.credentials_file) if settings.credentials_file else ())),
        "access_rules": "\n".join(rules + retry_replies) + "\n",
        "upstream_tls": upstream_tls,
        "proxy_protocol": proxy_protocol,
        "tls": tls,
        "extra": extra,
    }
    text = Template(_template("squid.conf.template")).substitute(values)
    for line in text.splitlines():
        if any(ord(char) < 32 and char != "\t" for char in line):
            raise SettingsError("rendered configuration contains control characters")
    return text


def _generate_port_certificate(settings: Settings) -> None:
    """Self-signed certificate Squid requires on an ssl-bump port.

    The proxy never bumps allowed traffic. Squid does, however, deliver the error
    for a *denied* CONNECT inside TLS using this certificate (its "delayed error"
    behavior on ssl-bump ports), so clients see a certificate error whose subject
    points at the proxy's access log. No origin is contacted and nothing is
    resolved for a denied tunnel (verified by tests/e2e)."""
    cert, key = Path(settings.run_dir, "tls-port.pem"), Path(settings.run_dir, "tls-port.key")
    if cert.exists() and key.exists():
        return
    openssl = shutil.which("openssl")
    if not openssl:
        raise SettingsError("openssl is required to generate the ssl-bump port certificate "
                            "(or set EGRESS_TLS_PORT_CERT_FILE/EGRESS_TLS_PORT_KEY_FILE)")
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "3650", "-subj", "/O=egress proxy/CN=egress-denied-see-proxy-access-log"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    os.chmod(key, 0o600)


def _openssl(*args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    openssl = shutil.which("openssl")
    if not openssl:
        raise SettingsError("openssl is required to check EGRESS_ERROR_CA_*")
    return subprocess.run([openssl, *args], input=stdin, capture_output=True)


def _prepare_error_ca(settings: Settings) -> None:
    """Check the error CA and initialize Squid's certificate store for it.

    The CA signs certificates only for the proxy's own error replies. Refuse anything that is not a
    CA certificate matching the key, or that has expired, so a misconfiguration fails at startup
    rather than as opaque TLS errors in sandboxes."""
    cert, key = settings.error_ca_cert, settings.error_ca_key
    for path, name in ((cert, "EGRESS_ERROR_CA_CERT_FILE"), (key, "EGRESS_ERROR_CA_KEY_FILE")):
        if not os.access(path, os.R_OK):
            raise SettingsError(f"{name}: {path} is not readable")
    constraints = _openssl("x509", "-in", cert, "-noout", "-ext", "basicConstraints")
    if constraints.returncode != 0 or b"CA:TRUE" not in constraints.stdout:
        raise SettingsError("EGRESS_ERROR_CA_CERT_FILE must be a CA certificate (basicConstraints CA:TRUE)")
    if _openssl("x509", "-in", cert, "-noout", "-checkend", "0").returncode != 0:
        raise SettingsError("EGRESS_ERROR_CA_CERT_FILE has expired")
    cert_pub = _openssl("x509", "-in", cert, "-noout", "-pubkey")
    key_pub = _openssl("pkey", "-in", key, "-pubout")
    if cert_pub.returncode != 0 or key_pub.returncode != 0 or cert_pub.stdout.strip() != key_pub.stdout.strip():
        raise SettingsError("EGRESS_ERROR_CA_KEY_FILE does not match EGRESS_ERROR_CA_CERT_FILE")
    end = _openssl("x509", "-in", cert, "-noout", "-enddate").stdout.decode().strip()
    import calendar
    import json
    import time as _time
    try:
        not_after = calendar.timegm(_time.strptime(end.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z"))
    except (IndexError, ValueError):
        not_after = 0
    (Path(settings.run_dir) / "error-ca.json").write_text(json.dumps({"not_after": not_after}), encoding="utf-8")
    # Squid's minted-certificate store: created fresh on every start (it only holds error certificates).
    database = Path(settings.run_dir) / "ssl_db"
    if database.exists():
        shutil.rmtree(database)
    subprocess.run([find_certgen(), "-c", "-s", str(database), "-M", "4MB"], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def write_runtime(settings: Settings) -> Path:
    run_dir = Path(settings.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    # Fail before Squid starts, with a clear message. (At runtime the helpers deny instead of
    # exiting, because Squid aborts when helpers keep failing to start.)
    if settings.policy_file:
        load_file_policy(settings.policy_file)
    if settings.revoked_file:
        from .revocation import RevocationError, parse
        try:
            parse(Path(settings.revoked_file).read_text(encoding="utf-8"))
        except (OSError, RevocationError) as error:
            raise SettingsError(f"EGRESS_REVOKED_FILE: {error}") from error
    for directory, name in ((settings.auth_keys_dir if settings.auth_mode == "token" else None, "EGRESS_AUTH_KEYS_DIR"),
                            (settings.signing_keys_dir if settings.auth_mode == "signed-headers" else None,
                             "EGRESS_SIGNING_KEYS_DIR")):
        if directory is not None:
            try:
                KeyRing(directory)
            except (OSError, ValueError) as error:
                raise SettingsError(f"{name}: {error}") from error
    (run_dir / "deny-cidrs.conf").write_text(deny_cidrs(settings), encoding="utf-8")
    (run_dir / "metrics").mkdir(exist_ok=True)
    errorpages.write_pages(run_dir / "errors", settings.instance_id)
    if settings.error_ca_cert:
        _prepare_error_ca(settings)
    elif settings.tls_enforcement == "sni" and not settings.tls_port_cert:
        _generate_port_certificate(settings)
    config = run_dir / "squid.conf"
    config.write_text(render(settings), encoding="utf-8")
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="clearideas-egress-render")
    parser.add_argument("--stdout", action="store_true", help="print squid.conf instead of writing files")
    args = parser.parse_args(argv)
    try:
        settings = Settings.from_env()
        if args.stdout:
            sys.stdout.write(render(settings))
            return 0
        path = write_runtime(settings)
    except (OSError, SettingsError, PolicyError, subprocess.CalledProcessError) as error:
        print(f"egress render failed: {error}", file=sys.stderr)
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
