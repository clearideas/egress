"""Generic, fail-closed policy decisions for a Squid egress proxy."""

from .auth import KeyRing, TokenError, mint_token, verify_token
from .http_backend import HTTPPolicy
from .policy import (
    ACLRequest,
    Decision,
    FilePolicy,
    PolicyError,
    authorize,
    compile_file_policy,
    decide,
    load_file_policy,
    normalize_host,
    parse_acl_line,
)

__all__ = [
    "ACLRequest",
    "Decision",
    "FilePolicy",
    "HTTPPolicy",
    "KeyRing",
    "PolicyError",
    "TokenError",
    "authorize",
    "compile_file_policy",
    "decide",
    "load_file_policy",
    "mint_token",
    "normalize_host",
    "parse_acl_line",
    "verify_token",
]
