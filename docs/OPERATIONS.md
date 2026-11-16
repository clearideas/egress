# Operating the egress proxy

This guide is for platform teams running the proxy as the egress control for sandboxed compute (AI-model sandboxes, code execution, CI runners). It assumes sandboxes are already isolated and that the proxy is their **only** route to the internet.

## Choosing a deployment pattern

How sandbox traffic reaches the proxy decides the mode, the identity scheme, and who sees what.

### Pattern A: egress helper in the sandbox, tunnel to the proxy (proxy originates TLS)

```
sandbox app ─plain HTTP─▶ egress helper ─tunnel─▶ load balancer ─▶ proxy replica ══TLS══▶ api.anthropic.com
             (absolute     (adds signed                             (verifies signature,
              https:// URL) identity headers)                        asks policy API, opens TLS)
```

```sh
EGRESS_MODE=origination            # CONNECT refused; the proxy opens TLS to the destination
EGRESS_AUTH_MODE=signed-headers    # per-request HMAC signatures with a per-run key
EGRESS_SIGNING_KEYS_DIR=/secrets/egress-signing   # master keys (<kid>.key), shared with the control plane
EGRESS_SIGNED_IDENTITY=runId=X-Egress-Run-Id      # identity attributes and their headers (default shown)
EGRESS_MAX_CONN_PER_CLIENT=0       # every sandbox arrives from the tunnel gateway's address
EGRESS_POLICY_URL=https://policy.internal/decide  # must reject finished runs
# optional:
EGRESS_NONCE_REDIS_URL=redis://redis.internal:6379/0   # cluster-wide single-use nonces
EGRESS_CREDENTIALS_FILE=/etc/egress/credentials.json  # proxy-held provider API keys
```

- **Identity.** Behind a tunnel gateway or load balancer, every sandbox shares the gateway's source address, so addresses say nothing about identity. Identity rests on three things: the **per-run key** (derived from a master key; a stolen key only signs as its own run), the **signature over each request including its destination** (method, scheme, host, port, path and query), and the **policy API's check that the run is still active**. See [INTEGRATION.md](INTEGRATION.md#signed-request-headers-v1).
- **Replay.** Signatures expire after `EGRESS_SIGNATURE_MAX_SKEW` (default 30 s) and cannot be moved to another destination. **Redis is optional.** Without it, an *identical* request can be repeated inside the window, and nothing else. With `EGRESS_NONCE_REDIS_URL`, each nonce is accepted once across all replicas; if Redis is then unreachable, signed requests are denied, so run it highly available or don't enable it.
- **What the proxy sees.** Because TLS starts at the proxy, the proxy handles request headers and bodies in the clear, including prompts and any provider API keys the sandbox sends. The proxy never logs headers, bodies or query strings (tested), caches nothing, and strips the signed identity headers before forwarding. Treat proxy hosts as holding the same secrets as the sandboxes, or better, keep the keys only on the proxy with [credential injection](#credential-injection).
- **Upstream TLS.** The proxy verifies destination certificates and host names, with TLS 1.2 as the minimum. `EGRESS_UPSTREAM_CA_FILE` adds a CA bundle (for example a private CA); system trust stays enabled.
- **Controls unique to this pattern:** per-method policy on `https://` origins, the full path available to the policy API, and `EGRESS_REQUEST_BODY_MAX_SIZE` enforced on HTTPS uploads.

### Pattern B: the platform routes all sandbox traffic to the proxy (end-to-end TLS)

Some sandbox providers (e.g. Modal) can force all sandbox egress through a proxy. Standard clients then use `HTTPS_PROXY` and `CONNECT`, and TLS runs end to end between sandbox and destination:

```sh
EGRESS_MODE=connect                # CONNECT + SNI enforcement (default)
EGRESS_AUTH_MODE=token             # per-run token in the proxy URL: http://<run>:<token>@proxy:3128
EGRESS_AUTH_REQUIRE_SOURCE=false   # only if sandboxes have no stable per-sandbox address
```

The proxy sees only the destination host and port, and checks that the TLS SNI matches. It cannot see methods, paths or bodies. No helper is needed inside the sandbox.

### Pattern C: both

`EGRESS_MODE=both` accepts proxied HTTP/HTTPS (originated TLS) and `CONNECT` (with SNI enforcement) on the same port. With `EGRESS_AUTH_MODE=signed-headers`, the egress helper can also sign a `CONNECT` request (path and scheme empty in the canonical string) for protocols that need end-to-end TLS.

## Deployment model

```
sandboxes ──▶ load balancer ──PROXY protocol v2──▶ proxy replicas (N) ──▶ internet
              (TLS termination                      │  │
               optional)                            │  └─▶ policy API (if used)
                                                    └─▶ DNS resolver
```

Checklist for a last-line deployment:

1. **No other way out.** Sandboxes must not have direct internet access or direct DNS. The proxy cannot control traffic that bypasses it.
2. **Per-sandbox identity.** Use `EGRESS_AUTH_MODE=token` (the default). The orchestrator mints a short-lived token for each sandbox, bound to the sandbox's address ([INTEGRATION.md](INTEGRATION.md#issuing-sandbox-tokens)).
3. **Real client addresses.** Put the replicas behind a load balancer that speaks PROXY protocol v2 and set `EGRESS_TRUSTED_PROXY_CIDRS` to the balancer's addresses. Without it, every request appears to come from the balancer, and source binding and per-client limits stop working. With it, connections that don't start with a PROXY header, or come from outside those CIDRs, are rejected.
4. **Encrypt sandbox→proxy traffic** if it crosses an untrusted network. Terminate TLS on the load balancer (for example haproxy `bind … ssl crt …`) and forward with PROXY protocol. Squid's own TLS listener cannot be combined with SNI enforcement (Squid refuses `ssl-bump` on a forward-proxy `https_port`). `tests/e2e/test_h2_identity.py` tests this setup with haproxy.
5. **Network-layer backstop.** Apply `deploy/nftables/egress-proxy.nft` in the proxy's network namespace, or `deploy/kubernetes/networkpolicy.yaml`, so that even a Squid misconfiguration cannot reach metadata services or internal networks. Edit the resolver and control-plane defines first.
6. **Ingress restriction.** Only sandboxes (or the load balancer) should reach port 3128.
7. **Run the container as shipped:** non-root, read-only root filesystem, a tmpfs at `/run/egress`, all capabilities dropped, `no-new-privileges`. The entrypoint refuses to run as root.

## Settings reference

All settings are environment variables read by `clearideas-egress-render` (run by the entrypoint) and by the helpers. Values are validated strictly; an invalid value stops the container with an error instead of being ignored.

### Identity

| Variable | Default | Meaning |
|---|---|---|
| `EGRESS_MODE` | `connect` | `connect` (tunnels + SNI enforcement), `origination` (proxied HTTP/HTTPS, the proxy opens TLS; CONNECT refused), or `both` |
| `EGRESS_AUTH_MODE` | `token` | `token` (per-sandbox token as the proxy password), `htpasswd` (mounted password file), or `signed-headers` (per-request signed identity headers; see INTEGRATION.md) |
| `EGRESS_SIGNING_KEYS_DIR` | required for `signed-headers` | Master keys `<kid>.key` (≥32 random bytes, base64) from which per-run keys are derived; re-read every ~2 s |
| `EGRESS_SIGNED_IDENTITY` | `runId=X-Egress-Run-Id` | Identity attributes and the headers carrying them (see INTEGRATION.md) |
| `EGRESS_SIGNED_PRINCIPAL` | first attribute | Attribute used as the principal |
| `EGRESS_SIGNED_HEADER_PREFIX` | `X-Egress-` | Prefix of the Timestamp/Nonce/Signature headers |
| `EGRESS_SIGNATURE_MAX_SKEW` | `30` | Maximum age (and clock skew) of a signed request, in seconds |
| `EGRESS_NONCE_REDIS_URL` | unset (optional) | `redis://[user@]host:port/db` or `rediss://…`: one-time nonces across all replicas. When set, unreachable Redis ⇒ deny |
| `EGRESS_NONCE_REDIS_PASSWORD_FILE` | unset | Redis password (`EGRESS_NONCE_REDIS_PASSWORD` is also read; prefer the file) |
| `EGRESS_NONCE_REDIS_CA_FILE` | system trust | CA bundle for `rediss://` |
| `EGRESS_NONCE_REDIS_TIMEOUT` | `0.25` | Seconds per Redis operation |
| `EGRESS_AUTH_KEYS_DIR` | required for `token` | Directory of `<kid>.key` files (≥32 random bytes, base64). Re-read every ~2 s: add a file to introduce a key, delete one to revoke every token signed with it |
| `EGRESS_AUTH_REQUIRE_SOURCE` | `true` | Reject tokens without a `src` claim |
| `EGRESS_HTPASSWD_FILE` | required for `htpasswd` | bcrypt htpasswd file; apply changes with `squid -k reconfigure` |
| `EGRESS_CREDENTIALS_TTL` | `60` | Seconds Squid caches a validated credential; bounds how quickly revocation takes effect |
| `EGRESS_DEMO_USER`, `EGRESS_DEMO_PASSWORD` / `EGRESS_DEMO_PASSWORD_FILE` | unset | Single-user demo mode (Compose only) |

### Policy

| Variable | Default | Meaning |
|---|---|---|
| `EGRESS_POLICY_FILE` | | JSON policy file (exactly one of FILE / URL) |
| `EGRESS_POLICY_URL` | | Policy API endpoint (HTTPS, or loopback HTTP for local development) |
| `EGRESS_POLICY_TOKEN_FILE` | | Bearer token for the API (`EGRESS_POLICY_TOKEN` is accepted and moved into a file by the entrypoint) |
| `EGRESS_POLICY_CA_FILE` | system trust | CA bundle for the API |
| `EGRESS_POLICY_CLIENT_CERT_FILE`, `EGRESS_POLICY_CLIENT_KEY_FILE` | | mTLS client certificate for the API |
| `EGRESS_POLICY_TIMEOUT` | `15` | Overall budget per decision in seconds (max 120): waiting for capacity, DNS, connect, TLS, retries and response. Exceeding it denies with `503` |
| `EGRESS_POLICY_RETRIES` | `3` | Retries after connection failures and HTTP 429/500/502/503/504, with exponential backoff and jitter, honoring `Retry-After`, within the budget |
| `EGRESS_POLICY_ATTEMPT_TIMEOUT` | unset | Optional cutoff per attempt. Unset: a slow answer is waited for (within the budget) rather than abandoned and re-sent |
| `EGRESS_POLICY_MAX_IN_FLIGHT` | `64` | Concurrent API calls per helper process; further calls wait for a slot within the budget |
| `EGRESS_PRINCIPAL_MAX_IN_FLIGHT` | max_in_flight/2 | Concurrent API calls one principal may hold per helper process; a principal's burst queues behind its own slots, so it cannot take every slot |
| `EGRESS_RATE_LIMIT` | off | Optional per-principal decision rate, `"<per second>/<burst>"` |
| `EGRESS_POLICY_REQUIRE_REQUEST_ID` | `false` | Require the API to echo `requestId` (will become the default; see INTEGRATION.md) |

### Decision caching and revocation

Permissions for an active sandbox almost never change mid-run, so by default an allow is reused for later requests of the same principal, and the **policy backend decides how far it reaches**: the API answers with a URL prefix (`"scope": "https://api.example.com/v1"` covers everything under `/v1`), optional `methods` and an optional shorter `ttl` (see [INTEGRATION.md](INTEGRATION.md#policy-api-contract-version-2)). File policies are per origin, so a file-policy allow covers the whole origin for its methods.

| Variable | Default | Meaning |
|---|---|---|
| `EGRESS_DECISION_TTL` | `300` | Seconds an **allow** is reused. `0` asks the policy backend on every request |
| `EGRESS_DECISION_NEGATIVE_TTL` | `5` | Seconds a **deny** is reused. This also caches temporary failures (`503`) for that long, so keep it short |
| `EGRESS_DECISION_GRACE` | `10` | When this percentage of the TTL remains, the approval is refreshed in the background, so busy principals do not wait at expiry |
| `EGRESS_DECISION_SCOPE` | `api` | `api`: the backend's answer scopes each approval (URL prefix + methods; an allow without a scope covers the request URL and what is beneath it). `origin`: the path is never sent and one decision covers a principal's method + origin. `request`: one decision per exact path |
| `EGRESS_REVOKED_FILE` | unset | Optional immediate kill switch (see below) |

**Never cached, whatever the TTL:** authentication and signature checks (every request must carry valid credentials; a cached allow never admits an unsigned or forged request), the TLS SNI check, the revocation list, and credential injection (provider keys and `rejectQueryParams` are applied per request, so key rotation takes effect within ~2 s). Proxy-authentication results are cached separately by `EGRESS_CREDENTIALS_TTL` (60 s).

**Revocation paths:**

| To stop… | Use | Takes effect |
|---|---|---|
| a run that finished normally | the policy API denies it | within `EGRESS_DECISION_TTL` + ~1 s |
| a run **right now** (compromise, incident) | add `principal=<p>` or `<attribute>=<value>` (e.g. `runnerAuthId=…`) to `EGRESS_REVOKED_FILE` | ~2 s after the file changes on the replica (ConfigMap/Secret propagation adds to this) |
| everything signed with a master key | delete the `<kid>.key` | ~2 s (signatures are verified per request) |
| all cached decisions on a replica | `squid -k reconfigure` (restarts the helpers, clearing their approvals) | immediately |

How approvals are matched (`api` scope):

- Scopes match on **path-segment boundaries**: `/v1` covers `/v1` and `/v1/…`, never `/v1evil`. The query string is ignored.
- A scope must be on the request's own origin and must cover the request; otherwise only the request URL is approved.
- An approval applies to the request's method unless the answer lists `methods`.
- Paths with dot segments (`/../`, `%2e%2e`) are refused outright (`403 ambiguous_path`). Paths with encoded slashes or backslashes, backslashes, or empty segments are never matched against stored approvals; they always go to the backend.
- When many requests of a principal to one origin miss at once (a burst at the start of a run), the first one asks the backend and the others reuse its answer if it covers them.
- Approvals live in the policy helper processes of each replica: expect up to `EGRESS_HELPER_CHILDREN` backend calls per approval per replica and TTL.

Security-conscious deployments can set `EGRESS_DECISION_TTL` to a few seconds (still enough to absorb bursts) or `0`, or have the policy API return narrow scopes or short `ttl` values.

### Bursts, retries and temporary failures

Agents often send requests in bursts: parallel tool calls, retries, streaming clients opening several connections. The proxy is built so that a burst is **slower, not lost**:

- **Identical decisions are merged.** While one decision for a given input (principal, source, method, URL, identity) is pending, Squid attaches identical concurrent requests to it; 100 parallel calls to the same endpoint cost one policy-API call (tested).
- **Bursts queue instead of failing.** A principal's excess requests wait for one of its slots, and every request waits for a free API connection, up to `EGRESS_POLICY_TIMEOUT` (default 15 s). Other principals keep their own slots, so one sandbox's burst does not starve the rest.
- **Retries.** Connection failures and `429`/`5xx` responses from the policy API are retried (default 3 retries, exponential backoff with jitter, `Retry-After` honored), reusing the same `requestId`. Slow answers are waited for rather than abandoned and re-sent, because re-sending to an overloaded API makes it slower.
- **Temporary failures are retryable for the client.** When a decision cannot be made (API unavailable or too slow, saturation, nonce store down, credential file unreadable), the sandbox gets **`503` with `Retry-After: 1`** (or `429` when `EGRESS_RATE_LIMIT` trips) instead of `403`, so HTTP clients and AI SDKs retry automatically. A policy *denial* is always `403`. The audit log has the exact reason.
- **Decision caching** (`EGRESS_DECISION_TTL`, default 300 s) means a burst from a running sandbox usually needs no policy call at all. `EGRESS_DECISION_NEGATIVE_TTL` also caches temporary failures for its duration (Squid has no per-answer TTL), so keep it to a few seconds; during an API outage this also limits retry storms.
- Capacity per proxy instance: `EGRESS_HELPER_CHILDREN` × `EGRESS_HELPER_CONCURRENCY` decisions in flight (default 512), with Squid queueing up to four times that.

### TLS, network and limits

| Variable | Default | Meaning |
|---|---|---|
| `EGRESS_TLS_ENFORCEMENT` | `sni` | `sni`: SNI must match the authorized host; non-TLS terminated unless `allowNonTls`. `off`: legacy host:port only (allows domain fronting) |
| `EGRESS_TLS_PORT_CERT_FILE`, `EGRESS_TLS_PORT_KEY_FILE` | generated | Certificate Squid requires on its `ssl-bump` port (see *Readable errors for sandboxes* below) |
| `EGRESS_ERROR_CA_CERT_FILE`, `EGRESS_ERROR_CA_KEY_FILE` | unset | **Error CA** (recommended): a dedicated CA that sandboxes trust, so refused HTTPS requests reach them as readable HTTP errors instead of certificate errors. Replaces `EGRESS_TLS_PORT_*`. See *Readable errors for sandboxes* below and the integration requirement in INTEGRATION.md |
| `EGRESS_CREDENTIALS_FILE` | unset (optional) | Credential injection rules (see below); requires `origination` or `both` |
| `EGRESS_UPSTREAM_CA_FILE` | unset | Extra CA bundle for verifying destinations when the proxy originates TLS (`origination`/`both`) |
| `EGRESS_TRUSTED_PROXY_CIDRS` | unset | Load-balancer addresses allowed to send PROXY protocol; enables `require-proxy-header` |
| `EGRESS_EXTRA_DENY_CIDRS_FILE` | unset | Extra destinations to refuse (one CIDR per line): your LB VIPs, the proxy's own public address, internal services on public IP space |
| `EGRESS_DNS_NAMESERVERS` | system | Resolvers for Squid |
| `EGRESS_MAX_CONN_PER_CLIENT` | `256` | Concurrent connections per client address; `0` disables. Over the limit: `503` with `Retry-After`. **Set `0` behind a tunnel gateway or NAT**, where one address carries every sandbox (per-principal caps still apply) |
| `EGRESS_REQUEST_BODY_MAX_SIZE` | `25 MB` | Largest plain-HTTP request body |
| `EGRESS_READ_TIMEOUT` | `300` | Seconds of inactivity after which a connection or tunnel is closed |
| `EGRESS_REQUEST_TIMEOUT` | `30` | Seconds to wait for a request, or for the TLS ClientHello on a new tunnel |
| `EGRESS_CONNECT_TIMEOUT` | `10` | Seconds to connect to a destination |
| `EGRESS_CLIENT_LIFETIME` | `3600` | Maximum lifetime of a client connection in the HTTP phase (does **not** end active tunnels; see below) |
| `EGRESS_HELPER_CHILDREN`, `EGRESS_HELPER_CONCURRENCY` | `4`, `128` | Policy helper processes and concurrent requests per process |
| `EGRESS_LISTEN_PORT` | `3128` | Listening port (≥1024; the container is non-root) |
| `EGRESS_ACCESS_LOG` | `stdio:/dev/stdout` | Squid access log destination |
| `EGRESS_CACHE_LOG` | `/dev/stderr` | Squid diagnostics |
| `EGRESS_AUDIT_LOG` | `stderr` | Helper decision/auth audit log: `stderr`, `off`, or a file path |
| `EGRESS_VISIBLE_HOSTNAME` | `egress` | Name Squid uses for itself |
| `EGRESS_RUN_DIR` | `/run/egress` | Writable runtime directory (generated config, certificates, secrets moved out of the environment); mount a tmpfs here |
| `EGRESS_PYTHON` | interpreter running the renderer | Python used to launch the helpers |
| `EGRESS_ALLOW_ROOT` | `0` | Set to `1` only if you must run as root (not recommended) |
| `EGRESS_DRAIN_SECONDS` | `30` | On SIGTERM, active connections get this long to finish; new ones are refused at once |
| `EGRESS_MAX_FILEDESCRIPTORS` | `65536` | Squid's descriptor limit (capped by the container's `ulimit -n`) |
| `EGRESS_ADMIN_PORT` | `3129` | Loopback-only Squid admin port the monitor reads statistics from; `0` disables it |
| `EGRESS_INSTANCE_ID` | host name | Names this replica in logs and metrics (the pod name in Kubernetes) |
| `EGRESS_MONITOR` | `on` | `off` when the monitor runs as a separate (sidecar) container |
| `EGRESS_MONITOR_ADDRESS`, `EGRESS_MONITOR_PORT` | `0.0.0.0`, `9090` | Where `/livez`, `/readyz` and `/metrics` are served |
| `EGRESS_METRICS_DIR` | `$EGRESS_RUN_DIR/metrics` | Where helper processes publish metric snapshots for the monitor |
| `EGRESS_SQUID_EXTRA_CONF` | unset | File included at the end of squid.conf. It comes after the final `deny all` rules, but it can still change global behavior; review it like code |

## Health, readiness and metrics

`clearideas-egress-monitor` (started by the entrypoint; port 9090) serves:

| Endpoint | Meaning |
|---|---|
| `/livez` | Squid is running and accepting connections. Use as the liveness probe |
| `/readyz` | Live, not draining, and no helper process reports a configuration problem. **Does not depend on the policy API**: an API outage must not mark every replica unready at once (sandboxes get a retryable `503` instead). Use as the readiness probe. The JSON body lists problems |
| `/metrics` | Prometheus metrics (below) |

Restrict port 9090 to the kubelet and Prometheus (NetworkPolicy): it exposes aggregate counters only, but there is no reason for sandboxes to reach it.

**Metrics** are aggregated over all helper processes of the replica (counters of restarted helpers are kept, so totals are monotonic) plus Squid's own statistics, read from a loopback-only admin port that serves a fixed set of read-only actions. There are no per-principal, host or path labels; per-run detail belongs in the logs.

| Metric | Labels | Meaning |
|---|---|---|
| `egress_decisions_total` | `decision`, `reason`, `source` (`backend`/`approval`/`helper`) | Policy decisions |
| `egress_policy_decision_seconds` | `backend` | Histogram of decisions that called the backend |
| `egress_policy_api_attempts_total`, `egress_policy_api_retries_total` | | Policy API calls and retries |
| `egress_approval_cache_hits_total`, `_misses_total`, `egress_approval_cache_keys` | | Approval reuse (`api` scope) |
| `egress_signatures_total`, `egress_tls_checks_total`, `egress_auth_total`, `egress_request_checks_total` | `decision`, `reason` | Per-request checks |
| `egress_credential_injections_total` | `rule` | Provider keys injected |
| `egress_config_reloads_total` | `file`, `result` | Policy file reloads (`error` = rejected edit, last good kept) |
| `egress_helper_misconfigured` | `mode` | 1 while a helper is denying everything because of configuration |
| `egress_squid_up`, `egress_squid_client_requests_total`, `egress_squid_client_bytes_total`, `egress_squid_server_bytes_total`, `egress_squid_file_descriptors`, `egress_squid_clients` | | Squid statistics |
| `egress_helper_pool_requests_total`, `_queue_length`, `_service_seconds`, `_processes` | `helper` | Squid's view of each helper pool |
| `egress_ready`, `egress_draining`, `egress_helper_processes`, `egress_instance_info` | | Monitor state |
| `egress_error_ca_not_after_timestamp_seconds` | | Expiry of the error CA (when `EGRESS_ERROR_CA_*` is set) |

**Dashboards and alerts:** `deploy/observability/` has a Grafana dashboard, Prometheus alert rules (availability: Squid down, replica not ready, misconfigured helpers, policy-backend failures and latency, helper queue backlog, file descriptors, rejected reloads, missing credentials; security: forged/replayed signatures, SNI mismatches, authentication-failure spikes, revoked principals still active, traversal attempts), and log queries for per-request signals such as internal-destination attempts (`log-queries.md`). A unit test checks that every alert and panel only uses metrics the code emits.

## Kubernetes deployment notes

`deploy/kubernetes/deployment.yaml` is a starting point. The parts that matter:

- **Probes:** `livenessProbe: httpGet /livez :9090`, `readinessProbe: httpGet /readyz :9090` (period 5 s).
- **Graceful drain:** on SIGTERM the container (`tini -g`) signals Squid and the monitor. The monitor fails `/readyz` at once; Squid refuses new connections and lets active ones, such as streaming completions and MCP sessions, run for `EGRESS_DRAIN_SECONDS`. Add `preStop: sleep 10` so endpoints are removed before Squid stops accepting, and set `terminationGracePeriodSeconds` ≥ 10 + `EGRESS_DRAIN_SECONDS` + 5. Tested: an in-flight SSE stream completes while new connections are refused.
- **Security context:** non-root, `readOnlyRootFilesystem`, all capabilities dropped, an in-memory `emptyDir` at `/run/egress`.
- Connections stay on the pod they were opened to, so rolling updates drain naturally. Use a PodDisruptionBudget.

## Configuration changes at runtime

| What | How it is picked up |
|---|---|
| Policy file (`EGRESS_POLICY_FILE`) | Re-read within ~2 s of a change. Invalid edits are rejected, the last good policy stays in use, and the rejection is logged and counted. Cached approvals of removed destinations expire within `EGRESS_DECISION_TTL` |
| Revocation list, auth/signing keys, credential secret files | Re-read within ~2 s |
| Credential rules, deny list, most `EGRESS_*` settings | Need a restart (rolling update), because they shape the generated Squid configuration |

## Logging and audit

**Access log** (stdout, one JSON object per request). String values are percent-encoded so every line is valid JSON:

```json
{"ts":"2026-01-01T00:00:00.000Z","client":"10.20.0.7","principal":"sbx-42","method":"CONNECT","url":"pypi.org:443","status":"200","result":"TCP_TUNNEL","hierarchy":"HIER_DIRECT","server":"151.101.0.223","bytes_from_client":"1840","bytes_to_client":"52311","duration_ms":"812","sni":"pypi.org","decision":"sni_match","destination":"ok","decision_id":"5f0c…","xaction":"184","instance":"egress-7c9f-abcde"}
```

**Destination check** (`destination`), run only after authentication and a policy allow: `ok` (resolved to a permitted address), `forbidden` (resolves to an internal or special address; 403), `unresolved` (the proxy could not resolve the name; 503), `-` (not reached, for example denied by policy).

**Correlation:**
- `decision_id` names the policy decision behind the request. It is the policy API's `requestId`, it appears in the audit `decision` record, and requests served by a stored approval carry the ID of the decision that created it.
- `instance` + `xaction` identify one request on one replica. Per-request audit events (`signature`, `tls_check`, `request_check`) carry the same `xaction`.

**Audit log** (helper stderr, JSON lines): `event` is `decision` (policy), `tls_check` (SNI), `auth` (token validation) or `signature` (signed headers). Records carry `principal`, `src`, `host`, `port`, `decision`, a stable `reason` code and `latency_ms`. Passwords and tokens are never logged (tested).

Temporary-failure reasons (`503`/`429` to the client): `backend_error`, `backend_timeout`, `backend_saturated`, `rate_limited`, `nonce_store_error`, `credential_unavailable`, `helper_misconfigured`.

Reason codes: `allowed`, `approved_cached` (allowed by a stored approval; counted, not logged per request), `ambiguous_path`, `unknown_principal`, `source_not_allowed`, `origin_not_allowed`, `method_not_allowed`, `invalid_request`, `backend_denied`, `arbiter:<code>`, `backend_error`, `backend_timeout`, `backend_saturated`, `rate_limited`, `sni_match`, `sni_mismatch`, `sni_missing`, `sni_invalid`, `sni_absent_ip_literal`; auth: `token_valid`, `expired`, `not_yet_valid`, `bad_signature`, `unknown_key`, `subject_mismatch`, `source_not_allowed`, `malformed`; signature: `signature_valid`, `connect_recheck`, `missing_header`, `invalid_identity`, `malformed_header`, `malformed_signature`, `invalid_destination`, `unknown_key`, `stale_timestamp`, `bad_signature`, `nonce_replayed`, `nonce_store_error`, `connect_recheck_denied`.

For a signed-header deployment the access log `principal` is the principal attribute's value, and the audit `decision` record carries the verified `identity`. Decisions with injected credentials carry `credential` (the rule ID, never the key). Credential reasons: `credential_requires_origination`, `credential_query_param`, `credential_unavailable`; per-request checks (`event` = `request_check`): `revoked`, and the credential reasons.

Denied requests are the most important signal: a sandbox repeatedly hitting `origin_not_allowed`, `sni_mismatch` or `source_not_allowed` is probing the boundary.

## Credential injection

With `EGRESS_CREDENTIALS_FILE`, the proxy holds the provider API keys and the sandbox never sees them. This needs `EGRESS_MODE=origination` (or `both`), because the proxy must rewrite request headers. For each **allowed** request to a configured origin, the proxy:

1. removes the credential header the sandbox sent, plus any `stripHeaders`;
2. adds the header with the real key, formatted by `value`;
3. refuses the request if the URL carries a listed `rejectQueryParams` parameter;
4. refuses `CONNECT` to that origin (a tunnel could not be rewritten and would bypass injection).

Because the proxy *replaces* whatever key the sandbox sends, a compromised sandbox can neither read the real key nor point an allowed API at an account of its own choosing.

```json
{"version": 1, "rules": [
  {"id": "anthropic", "origin": "https://api.anthropic.com", "header": "x-api-key",
   "value": "{secret}", "secretFile": "/run/secrets/anthropic", "stripHeaders": ["authorization"]},
  {"id": "openai", "origin": "https://api.openai.com", "header": "authorization",
   "value": "Bearer {secret}", "secretFile": "/run/secrets/openai"},
  {"id": "gemini", "origin": "https://generativelanguage.googleapis.com", "header": "x-goog-api-key",
   "value": "{secret}", "secretFile": "/run/secrets/gemini", "rejectQueryParams": ["key"]}
]}
```

- **Placeholders in the sandbox.** SDKs usually refuse to start without a key, so give the sandbox a dummy value (e.g. `ANTHROPIC_API_KEY=egress-placeholder`). The proxy discards it. Point the SDK at the real API host; with the egress helper or `HTTPS_PROXY` in origination mode, traffic reaches the proxy as usual.
- **Cover every way the API accepts a credential.** Strip alternative headers (`stripHeaders`) and refuse credential query parameters (`rejectQueryParams`). Otherwise a sandbox could send its own credential by another route, for example `?key=` on Google APIs.
- **Secrets** are read from files (mount them from your secret store), re-read within ~2 s of a change, and must match `[A-Za-z0-9._~+/=-]{8,4096}`. A missing or invalid secret denies requests to that origin (`credential_unavailable`). Secrets go from the helper to Squid as a per-request annotation, never into `squid.conf` or any log (tested).
- Injection runs on every request, outside the decision cache, so secret rotation takes effect within ~2 s whatever `EGRESS_DECISION_TTL` is.
- Only `https://` origins can have credentials; the proxy never sends a key in clear text.

## Run lifecycle and revocation

The policy API decides whether a run may still reach anything. **It must deny requests for runs that have finished or been cancelled.** The proxy sends the verified identity with every decision so it can check this. Revocation therefore takes effect:

- within `EGRESS_DECISION_TTL` + ~1 s for new requests (default 300 s; cached decisions are per principal and destination);
- within ~2 s through `EGRESS_REVOKED_FILE` when it cannot wait (see [Decision caching and revocation](#decision-caching-and-revocation));
- for CONNECT tunnels already established: only when the tunnel closes (see below). Pattern A has no long-lived tunnels: every request is checked on its own.

A per-run key is useless outside its run once the policy API treats the run as finished. Rotate master keys (add a new `<kid>.key`, switch the control plane, then delete the old file) to invalidate every run key derived from them.

## Known limitations

### Revocation and tunnel lifetime

Policy and credentials are checked when a connection or tunnel is set up. After that:

- **Idle** tunnels close after `EGRESS_READ_TIMEOUT` (default 5 minutes).
- An **active** `CONNECT` tunnel stays open until the client or server closes it. Squid 6.14 and 7.6 do not end active tunnels at `client_lifetime` (verified: `tests/e2e/test_m5_limits.py`, marked as an expected failure so a Squid change will be noticed).

To bound tunnel lifetime, recycle proxy instances on a schedule (rolling restarts with a drain timeout), or use a front end that enforces a maximum connection duration.

### Readable errors for sandboxes

Every response the proxy generates itself (a refusal, a destination it cannot resolve or reach, a temporary policy-service outage) has:

- an **`X-Egress-Error`** header: `denied` (403), `unavailable` (503), `rate_limited` (429), `unreachable` (502/504), `invalid_request` (400) or `error`. Destinations cannot set this header; the proxy strips it from their responses.
- a short **body** that says the egress proxy answered, with machine-readable lines: `code`, `reason` (the policy reason code, as in the access log `decision`), `destination`, `url`, `decision_id` (joins the access log and the policy API's `requestId`), `instance`, `time`, and what to do next.

The `code` values and their meaning for clients are listed in INTEGRATION.md, "Errors from the proxy".

For plain-HTTP requests (and every request in `origination` mode) that is all there is to it. For **HTTPS through `CONNECT`** with SNI enforcement on, Squid answers `200 Connection established` *before* it checks the TLS ClientHello, and delivers a refusal *inside* TLS ("delayed error"; Squid has no setting to change this). What the sandbox sees then depends on whether it trusts the proxy's **error CA**:

| | Refused HTTPS request looks like | Set up |
|---|---|---|
| **Error CA configured and trusted by the sandbox** (recommended) | An ordinary HTTP response: `403` with `X-Egress-Error: denied` and the body above. curl prints it; SDKs raise their usual HTTP error with the body | `EGRESS_ERROR_CA_CERT_FILE` / `EGRESS_ERROR_CA_KEY_FILE` on every replica; the CA certificate in every sandbox's trust store (INTEGRATION.md) |
| No error CA | A TLS error: untrusted certificate, subject `egress-denied-see-proxy-access-log` (for example curl's `self-signed certificate`). The same body is inside, readable only with certificate checks off (`curl -k`, for diagnosis only) | nothing |

**How the error CA is used.** When Squid must deliver an error inside TLS, it mints a certificate for the requested host name, signed by the error CA, completes the handshake and sends the error page; then it closes the connection. Nothing else is served on that connection (tested with pipelined requests). Allowed tunnels are never decrypted: they are spliced after the SNI check, and the sandbox sees the destination's real certificate (tested). Requests that violate SNI enforcement get no certificate at all; the connection is closed.

Limitation: for an IP-address destination (`https://203.0.113.5/`), Squid names the address in the minted certificate as a DNS name, and clients reject that. Refused IP-address requests therefore still appear as certificate errors. Sandboxes normally use host names, and the refusal itself is unaffected.

**Trust bundles:** sandboxes must trust the error CA **in addition to** the public roots. A trust file that holds only the error CA (for example `--cacert error-ca.pem`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`) makes every allowed HTTPS destination fail to verify. INTEGRATION.md lists the per-runtime settings; `compose.error-ca.yaml` builds `demo-ca/ca-bundle.pem` (roots + CA) for the local demo.

**Security requirements for the error CA:**

- Use a **dedicated CA created for this purpose**. Never use an organization root or any CA that other systems trust. Sandboxes must trust it; nothing else should.
- The private key lets its holder mint certificates that sandboxes trust. Mount it only into the proxy, read-only, from a secret store; restrict who can read that secret. A proxy compromise already exposes sandbox traffic metadata and control over egress; with the key it could also impersonate destinations to sandboxes, so treat the key like the proxy's signing keys.
- Keep it short-lived (for example 90 days) and rotate it: publish the new CA to sandbox images first (trust both), then switch the proxy, then remove the old CA. `egress_error_ca_not_after_timestamp_seconds` and the `EgressErrorCAExpiringSoon` alert track expiry.
- The proxy refuses to start if the certificate is not a CA, has expired, or does not match the key.

Create one, for example:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 90 \
  -subj "/O=Example Corp/CN=Sandbox egress proxy error CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout egress-error-ca.key -out egress-error-ca.pem
```

### Other TLS errors right after `200`

Some failures happen after Squid has committed to splicing the tunnel. Squid can then only close the connection, with or without the error CA:

| Client sees | Access log record (`url` = `host:443`) | Meaning |
|---|---|---|
| Connection closed during the handshake (`unexpected EOF`, handshake failure) | `"decision":"sni_mismatch"` / `sni_missing` | The TLS SNI did not match the authorized host (or was missing) |
| Same | `"status":"503"` with `"server":"<address tried>"` | The proxy could not connect to the destination (refused, unreachable, timed out) |

For refusals, the access log has `"result":"TCP_DENIED"`, the policy reason in `decision`, and, if the policy allowed the request, `destination` (`forbidden` or `unresolved`). For a proxy that can't reach the internet (for example a corporate network that requires its own proxy, or a container without working DNS), see "Quick start troubleshooting" in the README.

### Upload rate

Squid's client-side delay pools did not throttle request bodies in testing, so bandwidth shaping is left to the network layer (Linux `tc`, Kubernetes bandwidth annotations, or cloud controls). The proxy bounds request body size, per-client connections and idle time.

### What SNI enforcement does not cover

SNI enforcement guarantees that the TLS session is *addressed* to the authorized host. It does not prevent an allowed host from relaying data elsewhere, and it terminates Encrypted Client Hello (ECH) connections whose outer SNI differs. Sandboxes should disable ECH.
