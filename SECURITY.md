# Security

## Reporting a vulnerability

Report vulnerabilities privately through the GitHub repository's Security Advisory form. Include affected versions, a reproduction, and the security boundary you expected. Do not open a public issue for an unpatched vulnerability.

## Security model

This proxy is intended as the **last line of defense** for egress from sandboxed, untrusted compute such as AI-model sandboxes. Assume the code inside a sandbox is adversarial and knows how the proxy works. The proxy's guarantees, each covered by the end-to-end suite in `tests/e2e/`:

- Nothing leaves the proxy for a request that is not authenticated to a valid sandbox identity *and* allowed by policy. This includes DNS lookups: unauthorized names are never resolved.
- Allowed names that resolve to internal, link-local, metadata or other special-purpose addresses are refused. This holds for DNS tricks, rebinding, NAT64/6to4/Teredo, IPv4-mapped IPv6 and numeric encodings too. A network-layer ruleset (`deploy/`) enforces the same independently of Squid.
- `CONNECT` tunnels carry TLS whose SNI names the authorized host, unless policy explicitly allows non-TLS for that destination.
- Sandbox credentials are short-lived, signed, and bound to the sandbox's source address.
- Every failure (bad input, policy or auth errors, timeouts, overload) denies. One tenant cannot exhaust the proxy's decision capacity for the others.
- Tenants cannot observe each other through the proxy: no shared cache, and the cache manager is denied.
- The proxy never decrypts allowed traffic. With the optional error CA (`EGRESS_ERROR_CA_*`), it mints a certificate only to deliver its own refusal inside a refused `CONNECT`, then closes that connection. The CA's private key is a sensitive secret: sandboxes trust this CA. See [docs/OPERATIONS.md](docs/OPERATIONS.md#readable-errors-for-sandboxes).

Limits of the model, detailed in [docs/OPERATIONS.md](docs/OPERATIONS.md#known-limitations):

- HTTPS content is not inspected. An allowed destination can receive anything the sandbox sends.
- Revocation applies to new connections. Active tunnels end only when a side closes them.
- Traffic that bypasses the proxy is out of scope; sandboxes must have no other route out.
