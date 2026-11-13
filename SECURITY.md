# Security

Please report vulnerabilities privately through the GitHub repository's Security Advisory form. Include affected versions, a reproduction, and the expected security boundary. Do not open a public issue for an unpatched vulnerability.

This package evaluates an authenticated proxy principal against an origin policy. It does not inspect HTTPS payloads or prevent clients from bypassing the proxy through other network paths. Operators must secure the client-to-proxy connection and enforce direct-egress restrictions separately.
