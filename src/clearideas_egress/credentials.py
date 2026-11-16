"""Optional credential injection: the proxy, not the sandbox, holds provider API keys.

Only possible when the proxy originates TLS (``EGRESS_MODE=origination`` or
``both``), because it must see and rewrite request headers. For each allowed
request whose origin matches a rule, the proxy:

1. removes the header the sandbox sent (typically a placeholder key its SDK
   requires), plus any other headers listed in ``stripHeaders``;
2. adds the header with the real secret, formatted by ``value`` (``"Bearer {secret}"``);
3. refuses the request if it carries a listed query parameter (``rejectQueryParams``),
   so a credential cannot be smuggled in the URL instead (e.g. ``?key=`` on Google APIs);
4. refuses ``CONNECT`` to the origin, because a tunnel cannot be rewritten and would
   bypass injection.

Because the real key replaces whatever the sandbox sends, a compromised sandbox can
neither read the key nor use an allowed API with a key of its own choosing.

The secret travels from this helper to Squid as a request annotation, so it never
appears in squid.conf (which Squid echoes while parsing) or in any log.

Rules file (``EGRESS_CREDENTIALS_FILE``)::

    {"version": 1, "rules": [
      {"id": "anthropic", "origin": "https://api.anthropic.com",
       "header": "x-api-key", "value": "{secret}", "secretFile": "/run/secrets/anthropic",
       "stripHeaders": ["authorization"]},
      {"id": "openai", "origin": "https://api.openai.com",
       "header": "authorization", "value": "Bearer {secret}", "secretFile": "/run/secrets/openai"}
    ]}
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from .policy import ACLRequest, PolicyError, _origin, load_policy_document

_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
# Printable, no quotes/backslashes/percent (it is embedded in a quoted Squid value).
_TEMPLATE_PART = re.compile(r'^[\x20-\x7e]*$')
_FORBIDDEN_TEMPLATE_CHARS = set('"\\%')
# Typical API key alphabets (sk-..., AIza..., base64/base64url). No whitespace or commas.
_SECRET = re.compile(r"^[A-Za-z0-9._~+/=-]{8,4096}$")
_PARAM = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_UNSAFE_HEADERS = {"host", "connection", "content-length", "transfer-encoding", "proxy-authorization",
                   "proxy-connection", "upgrade", "te", "trailer", "keep-alive", "via", "forwarded",
                   "x-forwarded-for", "cookie"}

ANNOTATION_RULE = "egress_cred_"      # Squid requires custom annotations to end with "_"
ANNOTATION_SECRET = "egress_secret_"
CREDENTIAL_REQUIRES_ORIGINATION = "credential_requires_origination"
CREDENTIAL_QUERY_PARAM = "credential_query_param"
CREDENTIAL_UNAVAILABLE = "credential_unavailable"


@dataclass(frozen=True)
class CredentialRule:
    id: str
    origin: tuple[str, str, int]
    header: str
    prefix: str
    suffix: str
    secret_file: str
    strip_headers: tuple[str, ...]
    reject_query_params: tuple[str, ...]


def _parse_rule(entry: object) -> CredentialRule:
    allowed = {"id", "origin", "header", "value", "secretFile", "stripHeaders", "rejectQueryParams"}
    if not isinstance(entry, dict) or set(entry) - allowed:
        raise PolicyError(f"credential rule keys must be among {sorted(allowed)}")
    rule_id = entry.get("id")
    if not isinstance(rule_id, str) or not _ID.fullmatch(rule_id):
        raise PolicyError("credential rule id must match [a-z0-9][a-z0-9_-]{0,31}")
    origin = _origin(entry.get("origin"))
    if origin[0] != "https":
        raise PolicyError(f"credential rule {rule_id}: origin must be https:// (never send keys in clear text)")
    header = entry.get("header")
    if not isinstance(header, str) or not _HEADER.fullmatch(header) or header.lower() in _UNSAFE_HEADERS:
        raise PolicyError(f"credential rule {rule_id}: invalid header name")
    value = entry.get("value", "{secret}")
    if not isinstance(value, str) or value.count("{secret}") != 1:
        raise PolicyError(f"credential rule {rule_id}: value must contain {{secret}} exactly once")
    prefix, _, suffix = value.partition("{secret}")
    for part in (prefix, suffix):
        if not _TEMPLATE_PART.fullmatch(part) or set(part) & _FORBIDDEN_TEMPLATE_CHARS or "{" in part or "}" in part:
            raise PolicyError(f"credential rule {rule_id}: value may not contain quotes, backslashes, % or braces")
    secret_file = entry.get("secretFile")
    if not isinstance(secret_file, str) or not secret_file.startswith("/"):
        raise PolicyError(f"credential rule {rule_id}: secretFile must be an absolute path")
    strip = entry.get("stripHeaders", [])
    if not isinstance(strip, list) or not all(isinstance(h, str) and _HEADER.fullmatch(h) for h in strip):
        raise PolicyError(f"credential rule {rule_id}: stripHeaders must be header names")
    if {h.lower() for h in strip} & (_UNSAFE_HEADERS - {"cookie"}):
        raise PolicyError(f"credential rule {rule_id}: stripHeaders cannot remove protocol headers")
    params = entry.get("rejectQueryParams", [])
    if not isinstance(params, list) or not all(isinstance(p, str) and _PARAM.fullmatch(p) for p in params):
        raise PolicyError(f"credential rule {rule_id}: rejectQueryParams must be parameter names")
    strip_unique = tuple(dict.fromkeys(h.lower() for h in strip if h.lower() != header.lower()))
    return CredentialRule(rule_id, origin, header.lower(), prefix, suffix, secret_file, strip_unique,
                          tuple(p.lower() for p in params))


def load_rules(path: str | Path) -> tuple[CredentialRule, ...]:
    document = load_policy_document(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("version") != 1 or type(document.get("version")) is not int:
        raise PolicyError("credentials file must have version 1")
    if set(document) - {"version", "rules"} or not isinstance(document.get("rules"), list):
        raise PolicyError("credentials file must contain a rules list")
    rules = tuple(_parse_rule(entry) for entry in document["rules"])
    ids = [rule.id for rule in rules]
    origins = [rule.origin for rule in rules]
    if len(set(ids)) != len(ids) or len(set(origins)) != len(origins):
        raise PolicyError("credential rule ids and origins must be unique")
    return rules


class _Secret:
    """A secret file, re-read when it changes (rotation without restart)."""

    def __init__(self, path: str, refresh_seconds: float) -> None:
        self.path = path
        self.refresh_seconds = refresh_seconds
        self._value: str | None = None
        self._stamp: tuple | None = None
        self._checked = 0.0
        self._lock = threading.Lock()

    def get(self) -> str | None:
        now = time.monotonic()
        with self._lock:
            if self._value is None or now - self._checked >= self.refresh_seconds:
                self._checked = now
                try:
                    stat = os.stat(self.path)
                    stamp = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
                    if stamp != self._stamp:
                        value = Path(self.path).read_text(encoding="ascii").strip()
                        self._value = value if _SECRET.fullmatch(value) else None
                        self._stamp = stamp
                except (OSError, UnicodeDecodeError):
                    self._value, self._stamp = None, None  # missing/unreadable: fail closed
            return self._value


class CredentialInjector:
    def __init__(self, rules: tuple[CredentialRule, ...], *, refresh_seconds: float = 2.0) -> None:
        self.rules = {rule.origin: rule for rule in rules}
        self._secrets = {rule.id: _Secret(rule.secret_file, refresh_seconds) for rule in rules}

    @classmethod
    def from_file(cls, path: str | Path) -> "CredentialInjector":
        return cls(load_rules(path))

    def match(self, request: ACLRequest) -> CredentialRule | None:
        return self.rules.get(("https", request.host, request.port))

    def apply(self, request: ACLRequest) -> tuple[str | None, dict[str, str], str | None]:
        """Return (deny_reason, annotations, rule_id) for an already-allowed request."""
        rule = self.match(request)
        if rule is None:
            return None, {}, None
        if request.method == "CONNECT" or request.effective_scheme != "https":
            return CREDENTIAL_REQUIRES_ORIGINATION, {}, rule.id
        if rule.reject_query_params and request.path and "?" in request.path:
            query = request.path.split("?", 1)[1]
            names = {name.lower() for name, _ in urllib.parse.parse_qsl(query, keep_blank_values=True)}
            if names & set(rule.reject_query_params):
                return CREDENTIAL_QUERY_PARAM, {}, rule.id
        secret = self._secrets[rule.id].get()
        if secret is None:
            return CREDENTIAL_UNAVAILABLE, {}, rule.id
        return None, {ANNOTATION_RULE: rule.id, ANNOTATION_SECRET: secret}, rule.id


def describe(rules: tuple[CredentialRule, ...]) -> str:
    """Human-readable summary without secrets (for `check` commands)."""
    return json.dumps([{"id": r.id, "origin": f"https://{r.origin[1]}:{r.origin[2]}", "header": r.header}
                       for r in rules])
