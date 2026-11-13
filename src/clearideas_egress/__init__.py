"""Generic, fail-closed policy decisions for a Squid egress proxy."""

from .policy import (
    ACLRequest,
    FilePolicy,
    HTTPPolicy,
    PolicyError,
    authorize,
    compile_file_policy,
    load_file_policy,
    normalize_host,
    parse_acl_line,
)

__all__ = [
    "ACLRequest",
    "FilePolicy",
    "HTTPPolicy",
    "PolicyError",
    "authorize",
    "compile_file_policy",
    "load_file_policy",
    "normalize_host",
    "parse_acl_line",
]
