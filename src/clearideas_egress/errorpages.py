"""Error pages the proxy sends for its own refusals and failures.

Squid's stock pages say "The requested URL could not be retrieved" and name the product. These
replace them (``error_directory``) with short pages that say plainly that the **egress proxy**
answered, why, and what to do, in a form both people and programs (AI agents, SDK error handlers)
can read:

    egress-proxy: request refused by the egress policy

    code: denied
    reason: origin_not_allowed
    destination: -
    url: https://example.org/
    decision_id: 5f0c...
    instance: egress-7c9f-abcde
    time: Sat, 01 Jan 2026 00:00:00 GMT

Every page the proxy generates also carries an ``X-Egress-Error`` header (see render.py).
The ``code`` values are a stable interface (docs/INTEGRATION.md, "Errors from the proxy").
"""

from __future__ import annotations

from pathlib import Path

# Pages the configuration refers to by name (deny_info). Status codes are set there.
UNRESOLVED = "PROXY_UNRESOLVED"        # 503: allowed name did not resolve
UNAVAILABLE = "PROXY_UNAVAILABLE"      # 503: policy service / nonce store temporarily failing
RATE_LIMITED = "PROXY_RATE_LIMITED"    # 429
CONNECTION_LIMIT = "PROXY_CONNECTION_LIMIT"  # 503: per-client connection cap

_DENIED = ("denied", "request refused by the egress policy",
           "This sandbox is not permitted to reach this destination, or the destination resolves to an "
           "internal address. Retrying will not help. If the destination is needed, ask the operator to "
           "allow it and quote the decision_id.")
_UNREACHABLE = ("unreachable", "the destination could not be reached",
                "The request was allowed, but the proxy could not complete the connection to the "
                "destination. It may be down or slow. Retry later.")
_INVALID = ("invalid_request", "the request is malformed or not supported",
            "The proxy accepts CONNECT to port 443 and HTTP requests to ports 80 and 443 with a valid "
            "absolute URL. Fix the request; retrying it unchanged will not help.")
_ERROR = ("error", "the proxy could not complete this request", "Retry later; if it persists, contact the operator.")

PAGES: dict[str, tuple[str, str, str]] = {
    "ERR_ACCESS_DENIED": _DENIED,
    "ERR_FORWARDING_DENIED": _DENIED,
    "ERR_CACHE_MGR_ACCESS_DENIED": _DENIED,
    "ERR_NO_RELAY": _DENIED,
    "ERR_FTP_DISABLED": _DENIED,
    "ERR_CACHE_ACCESS_DENIED": ("auth_required", "proxy authentication required",
                                "Send valid proxy credentials for this sandbox. Tokens expire and are bound "
                                "to the sandbox's address; obtain a fresh one."),
    UNRESOLVED: ("unresolved", "the destination host name could not be resolved",
                 "The request was allowed, but the proxy could not resolve the host name. Check the name. "
                 "If it is correct, the proxy's DNS is failing: retry later or contact the operator."),
    UNAVAILABLE: ("unavailable", "the egress decision could not be made right now",
                  "The proxy could not reach its policy service in time. This is temporary: retry after the "
                  "Retry-After delay."),
    RATE_LIMITED: ("rate_limited", "too many requests",
                   "Slow down and retry after the Retry-After delay."),
    CONNECTION_LIMIT: ("connection_limit", "too many concurrent connections from this client",
                       "Close idle connections or reuse them, then retry."),
    "ERR_SHUTTING_DOWN": ("unavailable", "this proxy instance is shutting down", "Retry; another instance will answer."),
    "ERR_DNS_FAIL": ("unresolved", "the destination host name could not be resolved",
                     "The proxy could not resolve the host name. Check the name, or retry later."),
    "ERR_CONNECT_FAIL": _UNREACHABLE,
    "ERR_SECURE_CONNECT_FAIL": ("unreachable", "TLS to the destination failed",
                                "The proxy could not establish a verified TLS connection to the destination "
                                "(certificate or protocol error). Retrying will not help unless the "
                                "destination changes."),
    "ERR_READ_TIMEOUT": _UNREACHABLE,
    "ERR_READ_ERROR": _UNREACHABLE,
    "ERR_WRITE_ERROR": _UNREACHABLE,
    "ERR_GATEWAY_FAILURE": _UNREACHABLE,
    "ERR_CANNOT_FORWARD": _UNREACHABLE,
    "ERR_SOCKET_FAILURE": _UNREACHABLE,
    "ERR_ZERO_SIZE_OBJECT": _UNREACHABLE,
    "ERR_INVALID_RESP": _UNREACHABLE,
    "ERR_LIFETIME_EXP": ("timeout", "the connection exceeded its maximum lifetime", "Retry with a new connection."),
    "ERR_INVALID_REQ": _INVALID,
    "ERR_INVALID_URL": _INVALID,
    "ERR_UNSUP_REQ": _INVALID,
    "ERR_UNSUP_HTTPVERSION": _INVALID,
    "ERR_PROTOCOL_UNKNOWN": _INVALID,
    "ERR_CONFLICT_HOST": _INVALID,
    "ERR_TOO_BIG": ("too_large", "the request or response is too large",
                    "The proxy limits request body size. Send less data per request."),
}

# Every page Squid 6 may load from error_directory; those without an entry above get the generic page.
SQUID_PAGES = (
    "ERR_ACCESS_DENIED", "ERR_ACL_TIME_QUOTA_EXCEEDED", "ERR_AGENT_CONFIGURE", "ERR_AGENT_WPAD",
    "ERR_CACHE_ACCESS_DENIED", "ERR_CACHE_MGR_ACCESS_DENIED", "ERR_CANNOT_FORWARD", "ERR_CONFLICT_HOST",
    "ERR_CONNECT_FAIL", "ERR_DIR_LISTING", "ERR_DNS_FAIL", "ERR_ESI", "ERR_FORWARDING_DENIED",
    "ERR_FTP_DISABLED", "ERR_FTP_FAILURE", "ERR_FTP_FORBIDDEN", "ERR_FTP_NOT_FOUND", "ERR_FTP_PUT_CREATED",
    "ERR_FTP_PUT_ERROR", "ERR_FTP_PUT_MODIFIED", "ERR_FTP_UNAVAILABLE", "ERR_GATEWAY_FAILURE",
    "ERR_ICAP_FAILURE", "ERR_INVALID_REQ", "ERR_INVALID_RESP", "ERR_INVALID_URL", "ERR_LIFETIME_EXP",
    "ERR_NO_RELAY", "ERR_ONLY_IF_CACHED_MISS", "ERR_PRECONDITION_FAILED", "ERR_PROTOCOL_UNKNOWN",
    "ERR_READ_ERROR", "ERR_READ_TIMEOUT", "ERR_SECURE_CONNECT_FAIL", "ERR_SHUTTING_DOWN", "ERR_SOCKET_FAILURE",
    "ERR_TOO_BIG", "ERR_UNSUP_HTTPVERSION", "ERR_UNSUP_REQ", "ERR_URN_RESOLVE", "ERR_WRITE_ERROR",
    "ERR_ZERO_SIZE_OBJECT",
)

# Squid substitutes %-codes (%u: URL, %T: time, %E: system error) and @Squid{...} logformat codes.
# %u is HTML-escaped by Squid; the logformat values are reason codes, annotations and IDs that the
# helpers restrict to [A-Za-z0-9._:-].
_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>egress-proxy: {summary}</title></head>
<body><pre>
egress-proxy: {summary}

code: {code}
reason: @Squid{{%ea}}
destination: @Squid{{%{{egress_dest_}}note}}
url: %u
decision_id: @Squid{{%{{egress_decision_}}note}}
instance: {instance}
time: %T
{detail}
{explanation}
</pre></body></html>
"""

_WITH_DETAIL = {"unreachable", "unresolved"}


def page(name: str, instance: str) -> str:
    code, summary, explanation = PAGES.get(name, _ERROR)
    detail = "detail: %E\n" if code in _WITH_DETAIL and name.startswith("ERR_") else ""
    return _TEMPLATE.format(summary=summary, code=code, instance=instance, detail=detail,
                            explanation=explanation)


def write_pages(directory: Path, instance: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name in (*SQUID_PAGES, UNRESOLVED, UNAVAILABLE, RATE_LIMITED, CONNECTION_LIMIT):
        (directory / name).write_text(page(name, instance), encoding="utf-8")
    # Squid looks for TLS error detail texts here too; its built-in texts are used when it is empty.
    (directory / "error-details.txt").write_text("", encoding="utf-8")
