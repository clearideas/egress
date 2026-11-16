# Integrating with the egress proxy

Integration points:

1. **Sandbox identity**, one of:
   - [signed request headers](#signed-request-headers-v1): an egress helper in the sandbox signs every request with a per-run key (pattern A in OPERATIONS.md);
   - a [proxy token](#issuing-sandbox-tokens) in the sandbox's proxy URL, for standard clients (pattern B).
2. **The policy API**: decides each request, and must reject finished runs.
3. **Sandbox trust store**: sandboxes that use HTTPS through `CONNECT` should trust the proxy's [error CA](#sandbox-requirement-trust-the-error-ca), so refusals reach them as readable HTTP errors ([errors from the proxy](#errors-from-the-proxy)).

## Issuing sandbox tokens

With `EGRESS_AUTH_MODE=token` (the default), a sandbox authenticates with its **principal** as the proxy username and a **signed token** as the password:

```sh
HTTPS_PROXY=http://sbx-42:<token>@egress.internal:3128
```

Token format (HMAC-SHA256, standard library only):

```
v1.<kid>.<base64url(claims JSON)>.<base64url(HMAC-SHA256(key, "v1.<kid>.<claims>"))>
claims = {"sub": "sbx-42", "src": ["10.20.0.7/32"], "iat": 1767225600, "exp": 1767226500}
```

The proxy accepts a token only if:

- it is signed by a key currently in `EGRESS_AUTH_KEYS_DIR` (`<kid>.key`, ≥32 random bytes, base64);
- `iat` ≤ now ≤ `exp`, with 30 s clock-skew tolerance, and `exp − iat` is at most 24 h;
- `sub` equals the proxy username;
- the connecting address (after PROXY protocol) is inside one of the `src` networks.

Because Squid's credential cache is keyed on the client address too, a token that was just accepted from one address is still refused from another.

**Minting.** In Python:

```python
from clearideas_egress import mint_token
token = mint_token(key_bytes, "2026-01", "sbx-42", ["10.20.0.7/32"], ttl_seconds=900)
```

or from a shell:

```sh
clearideas-egress-token --key-file /secrets/2026-01.key --kid 2026-01 --sub sbx-42 --src 10.20.0.7/32 --ttl 900
```

Guidance for the orchestrator:

- Issue one principal per sandbox (or per tenant), and the narrowest `src` possible, ideally the sandbox's own /32 or /128.
- Keep TTLs short (minutes to an hour) and refresh them. A sandbox that outlives its token loses egress, which is a safe failure mode.
- **Revoking a sandbox:** stop refreshing its token. Takes effect within token expiry + `EGRESS_CREDENTIALS_TTL`.
- **Rotating a key:** add the new `<kid>.key`, start minting with it, and delete the old file after the longest TTL. Deleting a key revokes every token signed with it, within ~2 s + `EGRESS_CREDENTIALS_TTL`.
- The signing key is a secret shared between the orchestrator and the proxies. Distribute it like any other secret (mounted files, never environment variables).

## Signed request headers (v1)

For sandboxes whose traffic an egress helper forwards to the proxy (typically through a tunnel, where every sandbox shares one source address). Run the proxy with `EGRESS_AUTH_MODE=signed-headers`, usually with `EGRESS_MODE=origination`.

### Identity profile

Identity is an ordered set of **attributes**, each carried in its own request header. Configure it to match what your control plane already uses:

| Setting | Default | Meaning |
|---|---|---|
| `EGRESS_SIGNED_IDENTITY` | `runId=X-Egress-Run-Id` | Comma-separated `attribute=Header-Name` pairs (1–8), in canonical order |
| `EGRESS_SIGNED_PRINCIPAL` | first attribute | The attribute used as the principal (logs, per-principal limits, policy `principal`) |
| `EGRESS_SIGNED_HEADER_PREFIX` | `X-Egress-` | Prefix for the `Timestamp`, `Nonce` and `Signature` headers |

Example with a tenant and a run: `EGRESS_SIGNED_IDENTITY=tenantId=X-Egress-Tenant-Id,runId=X-Egress-Run-Id`, `EGRESS_SIGNED_PRINCIPAL=runId`.

Attribute values must match `[A-Za-z0-9._:-]{1,128}`. Attribute names must match `[A-Za-z][A-Za-z0-9]{0,31}`. The egress helper, the control plane and every proxy replica must use the same profile.

### Keys

- The control plane and the proxies share **master keys**: `<kid>.key` files in `EGRESS_SIGNING_KEYS_DIR`, each at least 32 random bytes, base64. Master keys never enter a sandbox.
- For each run the control plane derives a **run key** and gives it to the sandbox, with the `kid`:

  ```
  run_key = HMAC-SHA256(master_key, "egress-run-key/v1" + "\n" + "attr1=value1" + "\n" + "attr2=value2" ...)
  ```

- The proxy re-derives the run key from the identity headers. There is no key-lookup call and no service that hands out secrets. A stolen run key can only sign as its own run, and only while the policy API still treats that run as active.

### Headers on every request

One header per identity attribute, plus:

| Header (default prefix) | Value |
|---|---|
| `X-Egress-Timestamp` | unix seconds |
| `X-Egress-Nonce` | fresh random value per request, `[A-Za-z0-9_-]{16,64}` (use ≥128 bits) |
| `X-Egress-Signature` | `v1.<kid>.<base64url(HMAC-SHA256(run_key, canonical))>`, unpadded |

`canonical` is these lines joined with `\n` (no trailing newline):

```
EGRESS-SIG-V1
<METHOD>          e.g. POST (CONNECT for tunnels)
<scheme>          https | http  ("" for CONNECT)
<host>            lower case, no trailing dot, IDN as A-labels, IPv6 without brackets
<port>            decimal, always explicit (443/80 when the URL has none)
<path>            path and query exactly as in the request line, e.g. /v1/messages?beta=true ("" for CONNECT)
<attr1>=<value1>  one line per identity attribute, in profile order
...
<timestamp>
<nonce>
```

The proxy verifies the signature against the request it actually received, so headers signed for one destination, method or path are rejected anywhere else. It then removes every profile header before forwarding. Requests are rejected (`403`, reason in the audit log) if any header is missing, repeated, or outside its character set; if the timestamp is more than `EGRESS_SIGNATURE_MAX_SKEW` seconds (default 30) from the proxy's clock; if the `kid` is unknown; or if the nonce was already used (only when the optional Redis nonce store is configured).

### Test vectors

Master key `000102…1f` (bytes 0–31), `kid` `m1`; request `POST https://api.anthropic.com/v1/messages?beta=true`; timestamp `1767225600`; nonce `n0nce-0123456789abcdef`. The CONNECT signature is for `CONNECT api.openai.com:443` with the same values.

| Profile | run_key (base64url) | Signature header | CONNECT signature header |
|---|---|---|---|
| default: `runId=run-7f3a` | `VctavRCQzvBuA82WYFCITmZjDIk3NEBhmM_QFHVuil8` | `v1.m1.wGm2lf9OXuKRKHoI4JWDNqlPVbsJNwXNRDp0dLHZUsM` | `v1.m1.1CSd-kY_kUpAVP6i2sUM12LA4ATTzRaNUfwTbdFVoFI` |
| `tenantId=tenant-1`, `runId=run-7f3a` | `OKDytoJZEYeGfQoLrz6RGJsV4Uu6xTVnHIKiGVHW-fs` | `v1.m1.vTX77V54GpPnV6msWMAgkOP_YCV5gXwbaraTUFk71dc` | `v1.m1.vtEk5xOOTojpnyktehU4LteOBdFt-H9swGZjmgd49tk` |

These values can be reproduced with `openssl dgst -sha256 -mac HMAC`; `tests/unit/test_signing.py` checks them. The reference implementation is `clearideas_egress.signing` (`SigningProfile`, `derive_run_key`, `sign_request`, `verify_request`).

### Egress helper requirements

- Send proxied requests in **absolute form with an `https://` URL** (`POST https://api.anthropic.com/v1/messages HTTP/1.1`). The proxy opens TLS to the destination. A plain `http://` URL is forwarded as plain HTTP; the proxy does not upgrade it.
- Sign each request separately, with a new nonce, over the exact request line. Keep the sandbox clock synchronized.
- Never log the run key. Assume code in the sandbox can read it; the design tolerates that because the key only acts as its own run.
- In `EGRESS_MODE=origination` the proxy refuses `CONNECT`. Use `both` if the helper also needs tunnels, and sign the `CONNECT` request itself.

## Sandbox requirement: trust the error CA

Applies to sandboxes that reach HTTPS destinations through `CONNECT` (standard `HTTPS_PROXY` clients, pattern B) when the proxy runs with `EGRESS_ERROR_CA_CERT_FILE`/`EGRESS_ERROR_CA_KEY_FILE` (OPERATIONS.md, "Readable errors for sandboxes"). Sandboxes that only send proxied `https://` URLs to an `origination`-mode proxy (pattern A) get plain HTTP errors already and need nothing.

The proxy refuses a denied HTTPS request *inside* TLS. If the sandbox trusts the error CA, the refusal is an ordinary `403` with an explanation. If it does not, the sandbox sees a certificate error and no explanation. The error CA is used **only** for those refusals. Allowed connections are never decrypted, and the sandbox always sees the destination's real certificate.

**Requirements for the sandbox image or runtime:**

1. Add the error CA certificate (the public `.pem` only, never the key) to the system trust store, **in addition to** the public roots:
   - Debian/Ubuntu/Alpine: copy it to `/usr/local/share/ca-certificates/egress-error-ca.crt` and run `update-ca-certificates`.
   - RHEL/Fedora: copy it to `/etc/pki/ca-trust/source/anchors/` and run `update-ca-trust`.
2. Point runtimes that ship their own root bundle at the system bundle (Debian/Ubuntu/Alpine: `/etc/ssl/certs/ca-certificates.crt`; RHEL: `/etc/pki/tls/certs/ca-bundle.crt`):
   - Python `requests` and `pip` use `certifi`: set `REQUESTS_CA_BUNDLE` and `PIP_CERT`. `httpx` uses `SSL_CERT_FILE`. The standard `ssl` module and `urllib` use the system store.
   - Node.js: `NODE_EXTRA_CA_CERTS=/path/to/egress-error-ca.pem`. This variable adds the CA to Node's bundled roots.
   - Java: import it into the runtime's trust store (`keytool -importcert -cacerts -alias egress-error-ca -file egress-error-ca.pem`).
   - Go, curl, wget, git: the system store (no change on Debian-based images).
   - Rust clients that bundle `webpki-roots`: use the platform verifier or native roots, or add the CA explicitly.
   Never point `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE` at a file that contains **only** the error CA: every allowed HTTPS connection would then fail.
3. During a CA rotation, trust both the old and the new CA.
4. Check it from inside the sandbox:
   ```sh
   curl -sS -x "$HTTPS_PROXY" -D - https://not-allowed.example/ -o /dev/null | grep -i '^x-egress-error'
   # X-Egress-Error: denied
   ```

Trusting the error CA means a holder of its private key can impersonate any destination to the sandbox. Only the proxy holds the key, and the proxy is already the sandbox's trusted path to the internet. Trust this CA in sandboxes, never on developer machines or servers. OPERATIONS.md lists the requirements for creating, storing and rotating the CA.

## Errors from the proxy

Every response the proxy generates itself carries `X-Egress-Error`, which destinations cannot set, and a body like this:

```
egress-proxy: request refused by the egress policy

code: denied
reason: origin_not_allowed
destination: -
url: https://not-allowed.example/
decision_id: 5f0c2a...
instance: egress-7c9f-abcde
time: Sat, 01 Jan 2026 00:00:00 GMT

This sandbox is not permitted to reach this destination, ...
```

The page is `text/html` with the lines inside `<pre>`. Parse `key: value` lines. The header gives the class by HTTP status. The body's `code` is precise:

| `code` | Status | `X-Egress-Error` | Meaning | Client should |
|---|---|---|---|---|
| `denied` | 403 | `denied` | The policy does not allow this request; the port or scheme is not permitted (only `CONNECT` to 443, HTTP to 80/443); or the destination resolves to an internal address (`destination: forbidden`) | Not retry. Report it, quoting `decision_id` |
| `unresolved` | 503 | `unavailable` | Allowed, but the host name does not resolve | Check the name; retry later |
| `unavailable` | 503 | `unavailable` | The policy service could not be reached in time | Retry after `Retry-After` |
| `rate_limited` | 429 | `rate_limited` | Too many requests | Retry after `Retry-After` |
| `connection_limit` | 503 | `unavailable` | Too many concurrent connections from this client address | Reuse or close connections, then retry |
| `unreachable` | 502/503/504 | `unreachable` or `unavailable` | Allowed, but the destination could not be reached (plain HTTP and `origination` mode) | Retry later |
| `invalid_request` | 400 | `invalid_request` | Malformed request line, URL or HTTP version | Fix the request |
| `too_large` | 413 | `error` | Request body over the limit | Send less |
| `auth_required` | 407 | none | Missing, invalid or expired proxy credentials | Get fresh credentials |

`reason` is the policy's reason code (the access log `decision` field; see OPERATIONS.md, "Logging and audit"). A policy API can return its own reason (`arbiter:<code>`). `reason: -` with `decision_id: -` means a fixed rule refused the request before any policy decision, for example a port other than 443. `decision_id` is the policy API's `requestId`. A refused HTTPS request to an IP address (not a host name) still appears as a certificate error; see OPERATIONS.md.

For AI agents: treat `X-Egress-Error: denied` as final. The destination is outside this sandbox's egress policy, and workarounds such as other hosts, IP addresses, or disabling certificate checks will also be refused. Report the `decision_id` to the operator.

## Policy API contract (version 2)

Set `EGRESS_POLICY_URL`. For each decision the proxy sends `POST` with `Authorization: Bearer <EGRESS_POLICY_TOKEN_FILE contents>`:

```json
{"version":2,"requestId":"5f0c…","principal":"sbx-42","sourceIp":"10.20.0.7","method":"CONNECT","scheme":"https","host":"pypi.org","port":443}
```

- `principal` is the authenticated identity from the sandbox's token. Never accept an identity from anywhere else.
- `sourceIp` is the real client address (via PROXY protocol). Check it if sandboxes have known addresses.
- `host` is already normalized: lower-case, a single trailing dot removed, IDN in A-label form, IPv6 without brackets. Numeric forms that resolvers would treat as IPv4 (`0x7f000001`, `127.1`) never reach the API.
- `scheme` is `https` for `CONNECT`, and the real URL scheme for proxied requests (`https` when the proxy originates TLS).
- `url` and `path` (proxied requests, unless `EGRESS_DECISION_SCOPE=origin`): the full request URL and its path, **without** the query string. Query strings are withheld because some APIs carry credentials there (`?key=…`).
- `identity` (signed-header mode only): the verified identity attributes of your profile, e.g. `{"runId": "run-7f3a"}`; `principal` is the principal attribute's value. **Deny requests for runs that are no longer active**: this is how access ends when a run finishes.

Respond with HTTP 200 and:

```json
{"decision":"allow","requestId":"5f0c…","scope":"https://api.example.com/v1","methods":["GET","POST"],"ttl":300}
```

**How far an allow reaches** (`EGRESS_DECISION_SCOPE=api`, the default). The proxy reuses your allow, without asking again, for later requests of the same principal, identity and source address:

| Field | Meaning | Default |
|---|---|---|
| `scope` | URL prefix on the request's origin. `https://api.example.com/v1` approves everything under `/v1`; `https://api.example.com/v1/files/2390423480` approves only that object (and what is beneath it); `https://api.example.com` approves the whole origin | the request URL |
| `methods` | Methods the approval covers; must include the request's method | the request's method |
| `ttl` | Seconds the approval lasts; can only shorten `EGRESS_DECISION_TTL` (default 300); `0` means this answer is not reused | `EGRESS_DECISION_TTL` |

Matching is on path-segment boundaries (`/v1` never covers `/v1evil`), and the query string is ignored. A scope on another origin, or one that does not cover the request, is ignored, and only the request URL is approved. Requests with dot segments are refused before they reach you, and paths with encoded slashes or backslashes are always sent to you rather than matched against earlier approvals. **Answer for the breadth you mean:** if `POST https://api.example.com/v1/files` is fine but `DELETE` is not, return `methods: ["POST"]`; if only one file is approved, return that file's URL.

- **Only** `"decision":"allow"` allows. Any other value, status code, redirect, malformed or oversized (>64 KiB) body, timeout or transport error denies.
- `requestId`: echo the value from the request. A mismatched `requestId` always denies. A *missing* one is accepted for now, but will be required after the deprecation window. Set `EGRESS_POLICY_REQUIRE_REQUEST_ID=true` to require it today.
- `reason` (optional, `[a-z0-9_.-]{1,64}`) on a deny is logged as `arbiter:<reason>`.
- `allowNonTls: true` (optional, `CONNECT` only) lets a non-TLS protocol through the tunnel, for that principal and destination only.
- `websocket: true` (optional, `GET`) allows an HTTP Upgrade to WebSocket (e.g. realtime model APIs) when the proxy originates TLS. Without it the upgrade is stripped. In CONNECT mode WebSockets travel inside the tunnel anyway.
- Your `requestId` is also the **decision ID** in the proxy's access and audit logs (`decision_id`), so one ID joins your logs and the proxy's.

Requirements for the API implementation:

- **Never resolve the `host` you are asked about.** The proxy avoids DNS lookups for unauthorized names so that a sandbox cannot use them to exfiltrate data; an API that resolves names re-opens that channel.
- **Be careful with wildcards over names anyone can register** (`*.github.io`, `*.vercel.app`, `*.ngrok.io`, `*.cloudfront.net`). They let a sandbox choose subdomains, which re-enables DNS exfiltration and leads to attacker-controlled servers.
- **Latency and bursts.** The proxy waits up to `EGRESS_POLICY_TIMEOUT` (default 15 s) per decision, including retries. It keeps connections alive, merges identical concurrent decisions, and caps concurrency per helper, so expect several concurrent persistent connections per proxy replica. Aim for answers in milliseconds: the budget is for bad moments, not normal operation.
- **Retries.** The proxy retries connection failures and `429`/`500`/`502`/`503`/`504` (default 3 retries, backoff with jitter). Return `Retry-After` (seconds) with `429`/`503` to pace it. Every retry of a decision carries the **same `requestId`**, so the API can de-duplicate. Any other status is final and denies.
- **Reuse and revocation.** An approval is reused within its scope until its TTL ends, and refreshed in the background before that (your answer then replaces or, if you now deny, removes it). Revocation through the API therefore takes up to the TTL; use `EGRESS_REVOKED_FILE` for immediate revocation. Denials are reused only for `EGRESS_DECISION_NEGATIVE_TTL` (default 5 s) and only for the exact request.
- An outage denies new decisions (fail closed; sandboxes get `503` and retry). Cached allows keep working until they expire.

Transport security: HTTPS with system trust by default. Use `EGRESS_POLICY_CA_FILE` for a private CA and `EGRESS_POLICY_CLIENT_CERT_FILE`/`…_KEY_FILE` for mTLS. Plain HTTP is accepted only for literal loopback addresses (`127.0.0.1`, `::1`). The client never uses `HTTP(S)_PROXY` environment variables.

## Python library

The package has no runtime dependencies outside the standard library.

```python
from clearideas_egress import ACLRequest, HTTPPolicy, compile_file_policy, decide

policy = compile_file_policy({"version": 2, "principals": {"sbx-42": {"origins": ["https://pypi.org"]}}})
decision = decide(ACLRequest("sbx-42", "10.20.0.7", "CONNECT", "pypi.org", 443), policy)
decision.allowed, decision.reason   # (True, "allowed")
```

A custom backend is any object with `decide(request) -> Decision`, or a callable returning `True` to allow. Exceptions and any other return value deny. To plug a custom backend into Squid, reuse `clearideas_egress.cli.AclHandler` and `serve()`, which implement the Squid helper protocol (including concurrency channel IDs and reason annotations).

If you add caching in front of a backend, key it on the verified principal *and* source address, bound its lifetime, and never cache across principals.
