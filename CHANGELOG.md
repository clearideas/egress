# Changelog

## 0.3.0 — signed headers and proxy-originated TLS (2026-11-16)

- `EGRESS_MODE=origination|both`: sandboxes (or an egress helper) send proxied HTTP with absolute `https://` URLs, and the proxy opens TLS to the destination, verifying certificates and host names (TLS ≥ 1.2, optional `EGRESS_UPSTREAM_CA_FILE`). `origination` refuses CONNECT.
- `EGRESS_AUTH_MODE=signed-headers`: per-request identity headers signed with a per-run key derived from master keys (`EGRESS_SIGNING_KEYS_DIR`). The identity attributes and header names are configurable (`EGRESS_SIGNED_IDENTITY`, `EGRESS_SIGNED_PRINCIPAL`, `EGRESS_SIGNED_HEADER_PREFIX`; default `X-Egress-Run-Id`). The signature covers method, scheme, host, port, path and query, identity, timestamp and nonce. Spec and test vectors in docs/INTEGRATION.md.
- Optional credential injection (`EGRESS_CREDENTIALS_FILE`): the proxy replaces the sandbox's (placeholder) API key with the real one per origin, strips alternative credential headers, refuses credential query parameters, and refuses CONNECT to managed origins.
- Optional cluster-wide single-use nonces via Redis (`EGRESS_NONCE_REDIS_URL`, standard-library client, fails closed when configured).
- Identity headers are always stripped before forwarding. The policy decision reads identity only from annotations set by the signature check, never from raw headers.
- Policy API requests carry the real scheme, the path (without query) and, in signed mode, `identity`. File policy `methods` now also apply to `https://` origins (and refuse CONNECT).
- `EGRESS_MAX_CONN_PER_CLIENT=0` disables the per-address limit (tunnel and NAT deployments).
- Access log `principal` uses any authenticated name (token user or signed principal).
- Custom Squid annotations renamed with a trailing `_` (Squid reserves other names and logs their values).
- **Decision caching on by default:** `EGRESS_DECISION_TTL` 300 s (allow), `EGRESS_DECISION_NEGATIVE_TTL` 5 s, `EGRESS_DECISION_GRACE` 10 % background refresh. `EGRESS_DECISION_SCOPE=api` (default): the policy API sees the full URL (without query) and its answer scopes the approval (`scope` URL prefix matched on segment boundaries, `methods`, shorter `ttl`); concurrent misses share one backend call; dot-segment paths are refused. `origin` and `request` remain available. Signatures, authentication, SNI checks, credential injection and the new optional kill switch `EGRESS_REVOKED_FILE` run per request, outside the cache.
- **Operations:** `clearideas-egress-monitor` (`/livez`, `/readyz`, `/metrics`; started by the entrypoint, or as a sidecar); helper metric snapshots aggregated with Squid statistics from a loopback-only admin port; Grafana dashboard, Prometheus alert rules and log queries (`deploy/observability/`); graceful drain (`EGRESS_DRAIN_SECONDS`, `tini -g`); access log gains `decision_id`, `xaction` and `instance`; WebSocket upgrades per origin (`websocket` policy flag or API field); policy file hot reload (last good kept); `EGRESS_MAX_FILEDESCRIPTORS`; load test (`make perf`, docs/PERFORMANCE.md).
- **Readable refusals:** the proxy's own responses now say the egress proxy answered and why: an `X-Egress-Error` header (`denied`, `unavailable`, `rate_limited`, `unreachable`, `invalid_request`, `error`; destinations cannot set it) and a short body with `code`, `reason`, `destination`, `url`, `decision_id`, `instance`. The pages no longer name Squid. New optional **error CA** (`EGRESS_ERROR_CA_CERT_FILE`/`EGRESS_ERROR_CA_KEY_FILE`): sandboxes that trust it see a refused HTTPS request as a normal `403` with that body instead of a certificate error. The CA is used only to deliver refusals; allowed tunnels are never decrypted (tested), and startup checks the CA. New metric `egress_error_ca_not_after_timestamp_seconds` and alert `EgressErrorCAExpiringSoon`. Sandbox trust-store requirements are in docs/INTEGRATION.md; `compose.error-ca.yaml` demonstrates the setup locally.
- **Clearer failures for allowed destinations:** an allowed name that does not resolve is now refused by the destination check with a `503`, delivered like every other `CONNECT` denial (the proxy's `egress-denied-see-proxy-access-log` certificate). Previously Squid wrote a plain-text error into the client's TLS handshake, which clients reported as `wrong version number` / `SEC_E_INVALID_TOKEN`. The access log gains `destination` (`ok`, `forbidden`, `unresolved`, `-`). README quick-start troubleshooting and `.gitattributes` (LF for scripts) added.
- **Testing:** `make test` runs everything in one command. It sets up the environment as needed and fails instead of silently skipping: unit tests, the E2E suite in a bubblewrap sandbox or, when that can't run here, inside a container built from the production image (Alpine Squid, installed package, real entrypoint; `make docker-e2e`), and a black-box image smoke test on a private Docker network (`make docker-smoke`). CI runs the E2E suite in the image too.
- Image `USER` is numeric (`31:31`, the Alpine `squid` user) so Kubernetes can enforce `runAsNonRoot` without `runAsUser`. Previously the example Deployment failed with "image has non-numeric user".
- Burst handling: policy-API retries (`EGRESS_POLICY_RETRIES`, default 3; backoff with jitter; `Retry-After`; same `requestId`), overall budget `EGRESS_POLICY_TIMEOUT` now 15 s with slow answers waited for (optional `EGRESS_POLICY_ATTEMPT_TIMEOUT`), and bursts queue for capacity instead of being denied. Temporary failures return `503` (or `429`) with `Retry-After` instead of `403`, so clients retry. Defaults: `EGRESS_MAX_CONN_PER_CLIENT` 256, `EGRESS_HELPER_CONCURRENCY` 128.

## 0.2.0 — security hardening for sandbox egress

Security fixes (from an internal review; every item has end-to-end tests against Squid 6.14):

- **DNS exfiltration:** unauthenticated and unauthorized requests no longer trigger DNS lookups. Destination checks now run only after authentication and a policy allow.
- **Cache manager:** denied to all clients. Previously any tenant allowed a plain-HTTP origin could read other tenants' usernames, addresses and destinations.
- **Availability:** the helper supports Squid concurrency, keeps policy-API connections alive, enforces a hard deadline (DNS included), fails fast when saturated, and caps in-flight decisions per principal, so one sandbox can no longer deny service to others. Decision caching is configurable (`EGRESS_DECISION_TTL`, `EGRESS_DECISION_NEGATIVE_TTL`, `EGRESS_DECISION_GRACE`).
- **TLS enforcement:** `CONNECT` tunnels must carry TLS with an SNI matching the authorized host (the ClientHello is peeked at, never decrypted). Per-origin `allowNonTls` opt-out.
- **Identity:** signed, short-lived, source-bound sandbox tokens (`EGRESS_AUTH_MODE=token`, default) and PROXY protocol support for load balancers. Usernames are case-sensitive; credential cache TTL is 60 s.
- **Destinations:** added NAT64, 6to4, Teredo, IPv6 multicast and unspecified, `192.0.0.0/24`, benchmarking and documentation ranges, and Azure `168.63.129.16`; operator-extensible deny list; nftables and Kubernetes NetworkPolicy backstops.
- **Parsing:** numeric host forms (`0x7f000001`, `127.1`, …) are rejected; Squid's URL quoting is decoded exactly once (fixes IPv6-literal destinations); the helper never exits on a bad line; policy files reject duplicate keys and non-ASCII hosts.
- **Policy API client:** ignores `HTTP(S)_PROXY` environment variables; supports a CA file and mTLS; sends `requestId` and rejects mismatched echoes.
- **Hardening:** no Squid version or product disclosure, strict header parsing, non-HTTP URL schemes refused, request body limit, per-client connection limit, timeouts for idle tunnels and missing ClientHellos.
- **Container:** runs non-root on a read-only root filesystem; secrets are moved from environment variables into files before Squid starts; the entrypoint refuses root.
- **Logging:** JSON access log on stdout and a JSON audit log of every decision with reason codes; secrets are never logged.

Breaking changes:

- Default authentication is `token`. The single-user `EGRESS_PROXY_USER`/`EGRESS_PROXY_PASSWORD` is replaced by `EGRESS_DEMO_USER`/`EGRESS_DEMO_PASSWORD`, or by `EGRESS_AUTH_MODE=htpasswd` with a mounted file.
- SNI enforcement is on by default. Clients without SNI, ECH, and non-TLS protocols over `CONNECT` are terminated unless the origin has `allowNonTls`. A denied `CONNECT` returns 200 and then fails TLS (see docs/OPERATIONS.md).
- `ftp://`, `whois://` and `GET https://…` requests through the proxy are refused.
- Policy hosts must be ASCII (A-labels). Duplicate JSON keys are errors.
- The policy API request now includes `version`, `requestId` and `scheme`.
- The Squid template moved into the package and is rendered by `clearideas-egress-render`.

## 0.1.0 — Python source release

- Added a standard-library Python package and Squid external ACL command.
- Added exact-origin file policy and HTTPS policy API backends.
- Added a loopback-only Docker Compose example and default-deny Squid template.

The earlier JavaScript npm prototype was published in error and is not part of this Python package.
