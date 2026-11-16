# clearideas-egress

An egress-control proxy for **AI-model sandboxes and other untrusted compute**, built on Squid. It is meant to be the *last line of defense*: sandboxes should already be isolated and restricted, and this proxy is the independent layer that decides which destinations on the internet a sandbox may reach, and refuses everything else.

Every request is authenticated to a **sandbox identity**, checked against a **policy** (a local JSON file or your policy service, which can decide per run), and forwarded only if the destination is not an internal address. Denied and failed decisions always fail closed.

Two ways to connect sandboxes (see [docs/OPERATIONS.md](docs/OPERATIONS.md#choosing-a-deployment-pattern)):

- **Egress helper + tunnel:** a helper inside the sandbox forwards plain HTTP with **per-request signed identity headers**, and the proxy opens TLS to the destination itself. This gives per-request, per-path and per-method control.
- **Standard proxy clients:** the sandbox uses `HTTPS_PROXY` with a **short-lived token**. TLS stays end to end, and the proxy checks the destination host and TLS SNI.

> **Scope:** this proxy controls *where* sandboxes can connect. It does not inspect the contents of HTTPS traffic. An allowed destination can receive anything the sandbox sends it. Read [What this protects against](#what-this-protects-against) before relying on it.

## How it works

```
sandbox ──(token)──▶ [load balancer, optional TLS + PROXY protocol] ──▶ Squid ──▶ internet
                                                                         │
                                        authentication ◀── token helper ─┤
                                        policy decision ◀── policy helper ──▶ policy file or policy API
                                        TLS SNI check   ◀── SNI helper ──┘
```

For every request, in this order:

1. **Port and protocol**: only `CONNECT` to port 443 and plain HTTP to ports 80/443; other URL schemes (`ftp://`, …) are refused.
2. **Authentication**: the sandbox presents its principal name and token as proxy credentials. Invalid, expired, or wrong-source tokens get `407`. **No DNS lookup happens before this point**, so unauthenticated or unauthorized sandboxes cannot leak data through the proxy's resolver.
3. **Policy**: the principal, source address, method, host and port go to the policy backend. Only an explicit allow proceeds; errors, timeouts and malformed answers deny.
4. **Destination check**: the allowed name is resolved, and the connection is refused if *any* address it resolves to is private, link-local, cloud metadata, NAT64/6to4/Teredo-embedded, multicast or otherwise special (see `src/clearideas_egress/templates/deny-cidrs.conf`).
5. **TLS check** (for `CONNECT`): the proxy peeks at the TLS ClientHello without decrypting it. The tunnel is spliced only if the SNI names the host that was authorized. Domain fronting, missing SNI and non-TLS protocols are terminated unless the policy marks the destination `allowNonTls`.

Every decision is logged as JSON with a reason code.

## What this protects against

| Threat from a compromised or adversarial sandbox | Control |
|---|---|
| Reaching destinations that are not allowed | Exact-origin policy per sandbox identity; default deny |
| Exfiltrating data through DNS via the proxy's resolver | Names are resolved only after authentication *and* a policy allow |
| Reaching cloud metadata / internal services (directly, via DNS tricks, NAT64, IPv4-embedded IPv6, numeric host encodings, DNS rebinding) | Destination deny list in Squid **plus** a network-layer backstop (`deploy/`) |
| Domain fronting / tunnelling other protocols through an allowed `CONNECT` | SNI must match the authorized host; non-TLS is terminated |
| Using a stolen credential from elsewhere | Tokens are short-lived and bound to the sandbox's source address; signed headers use a per-run key, cover the destination, expire in seconds, and can be single-use cluster-wide (Redis) |
| Starving other tenants or the policy service | Per-principal concurrency caps, fail-fast backend, per-client connection limits, optional decision caching |
| Reading other tenants' activity through the proxy | Cache manager denied; no shared cache |
| Stealing provider API keys, or using an allowed API with an attacker's own key | Optional credential injection: the proxy holds the keys and replaces whatever the sandbox sends (origination mode) |

**What it does not do:**

- **It does not inspect HTTPS content.** If a destination is allowed, the sandbox can send it data: a writable API, a code host, or object storage that accepts any bucket. Allow only destinations you trust to receive anything the sandbox holds, and prefer read-only or tenant-scoped endpoints.
- **Revocation applies to new connections.** Idle tunnels close after `EGRESS_READ_TIMEOUT`. An *active* HTTPS tunnel stays open until one side closes it (verified on Squid 6.14 and 7.6; neither enforces a maximum active tunnel lifetime). See [docs/OPERATIONS.md](docs/OPERATIONS.md#revocation-and-tunnel-lifetime).
- **It cannot stop traffic that bypasses it.** Sandboxes must have no other route out, including direct DNS.
- Upload *rate* shaping belongs at the network layer; the proxy bounds request body size and connection count.

## Quick start (local demo)

```sh
EGRESS_DEMO_PASSWORD='choose-a-local-password' docker compose up --build
curl --proxy http://demo:choose-a-local-password@127.0.0.1:3128 https://example.com/
```

The demo binds only to `127.0.0.1:3128` (proxy) and `127.0.0.1:9090` (`/livez`, `/readyz`, `/metrics`), uses a single password user (demo mode), runs non-root on a read-only filesystem, and allows `demo` to reach `https://example.com` only ([examples/policy.json](examples/policy.json)). Every other destination is refused. Over HTTPS, a refusal appears in curl as an **untrusted certificate error**: the proxy answers with its own error certificate (see troubleshooting below).

To get a readable refusal instead, start the demo with a throwaway **error CA** and trust it in the client. Sandboxes do this in production; see [Readable errors for sandboxes](docs/OPERATIONS.md#readable-errors-for-sandboxes):

```sh
docker compose -f compose.yaml -f compose.error-ca.yaml up --build
# ./demo-ca/ca-bundle.pem is the public roots *plus* the demo CA; use it for every request:
curl --proxy http://demo:choose-a-local-password@127.0.0.1:3128 --cacert demo-ca/ca-bundle.pem -i https://not-allowed.example/
# HTTP/1.1 403 Forbidden
# X-Egress-Error: denied
# ... egress-proxy: request refused by the egress policy / code: denied / reason: origin_not_allowed ...
curl --proxy http://demo:choose-a-local-password@127.0.0.1:3128 --cacert demo-ca/ca-bundle.pem https://example.com/
```

`--cacert` **replaces** the client's trust store, so pass the bundle, not `demo-ca/error-ca.pem` on its own. With the CA alone, allowed destinations fail to verify. Clients with a setting that *adds* CA certificates to their defaults need only `demo-ca/error-ca.pem`. In Postman, that setting is Settings → Certificates → CA certificates.

Clients that show the proxy exchange, such as `curl -v` or the Postman console, first show `200 Connection established` for the tunnel and then the `403` from inside it. That is expected: the `200` only means the proxy accepted the `CONNECT`.

To try other sites, add their origins to `examples/policy.json`. Changes apply within a few seconds, no restart needed:

```json
{"version": 1, "principals": {"demo": ["https://example.com", "https://pypi.org", "https://files.pythonhosted.org"]}}
```

Origins are exact: `https://github.com` does not allow `https://api.github.com` or `https://raw.githubusercontent.com`. Many sites redirect to or load from other hosts, and each needs its own entry. The access log shows every host a client tried. Production deployments use per-sandbox tokens; see [docs/OPERATIONS.md](docs/OPERATIONS.md).

### Quick start troubleshooting

With `https://` URLs the proxy answers `200 Connection established` first and checks the rest afterwards, so most problems show up as a **TLS error in the client, not an HTTP status**. The access log on the container's stdout says what happened:

```sh
docker compose logs egress | grep '"url":"example.com:443"'
```

| Access log record | Cause | Fix |
|---|---|---|
| `"status":"407"` (curl reports `407`) | Wrong user name or password | Use the password you passed in `EGRESS_DEMO_PASSWORD` |
| `"result":"TCP_DENIED"`, `"decision":"origin_not_allowed"` | The policy does not allow this origin. Over HTTPS, curl shows an untrusted-certificate error unless you use the error CA (above) | Add it to `examples/policy.json`. The file is hot-reloaded |
| `"result":"TCP_DENIED"`, `"destination":"unresolved"` | The container cannot resolve the name | See DNS checks below |
| `"status":"503"` with a `"server"` address | The container cannot connect to the destination | The host needs direct internet access on port 443. A corporate network that only allows traffic through its own proxy blocks this |
| `"decision":"sni_mismatch"` or `sni_missing` | The client's TLS SNI is not the host it asked for | Use the real host name in the URL |

DNS and connectivity checks from inside the container:

```sh
docker compose exec egress python3 -c "import socket; print(socket.getaddrinfo('example.com', 443))"
docker compose exec egress cat /etc/resolv.conf
```

If resolution fails inside the container:

1. Check the host: `nslookup example.com`. If the host can't resolve it either, the network only reaches the internet through a corporate proxy. This proxy does not chain to another proxy, so the demo can't reach the internet from that network.
2. Try a specific resolver from a throwaway container: `docker run --rm --dns <resolver-ip> python:3.12-alpine python3 -c "import socket; print(socket.getaddrinfo('example.com', 443))"`. Try your network's DNS servers and a public resolver such as `1.1.1.1`.
3. Give Squid the resolver that works: add `EGRESS_DNS_NAMESERVERS: "<resolver-ip>"` (space- or comma-separated) under `environment:` in `compose.yaml`. To fix it for every container, set `"dns": [...]` in Docker's daemon settings (Docker Desktop: Settings → Docker Engine) instead.

To read the proxy's error message for an HTTPS request, repeat it once with `-k` (`curl -k --proxy ... https://not-allowed.example/`). The certificate is the proxy's own error certificate, and the page explains the refusal. Use `-k` only for this diagnosis.

## Policy file

`EGRESS_POLICY_FILE` points at a JSON document. Each principal lists the exact origins it may reach:

```json
{"version": 2, "principals": {
  "sbx-42": {
    "sources": ["10.20.0.0/24"],
    "origins": [
      "https://pypi.org",
      "https://files.pythonhosted.org",
      {"origin": "http://archive.ubuntu.com", "methods": ["GET", "HEAD"]},
      {"origin": "https://ssh.github.com", "allowNonTls": true}
    ]
  }
}}
```

- Origins are exact `scheme://host[:port]`; there are no wildcards, paths or suffix matches. `https://` means `CONNECT` to that host and port; `http://` means plain HTTP.
- `sources` (optional) restricts the client addresses the principal may use.
- `methods` (optional, `http://` only) restricts plain-HTTP methods, for example read-only mirrors.
- `allowNonTls` (optional, `https://` only) permits a non-TLS protocol through the tunnel, such as SSH on port 443.
- `websocket` (optional) permits HTTP Upgrade to WebSocket when the proxy originates TLS (realtime APIs).
- Hosts must be ASCII: write internationalized names as A-labels (`xn--…`). Duplicate keys, numeric host forms like `0x7f000001`, and conflicting entries are rejected when the file is loaded.
- Version 1 (`{"version":1,"principals":{"name":["https://…"]}}`) is still accepted.

Check a file before deploying it with `clearideas-egress-acl check-policy policy.json`.

## Policy API

Set `EGRESS_POLICY_URL` (HTTPS, bearer token in `EGRESS_POLICY_TOKEN_FILE`) instead of a file, and the proxy asks your service for each decision. The request/response contract, token issuance for sandboxes, and the Python API are in [docs/INTEGRATION.md](docs/INTEGRATION.md).

## Operations at a glance

- `/livez`, `/readyz` and Prometheus `/metrics` on port 9090; Grafana dashboard, alert rules and log queries in `deploy/observability/`.
- Graceful drain on SIGTERM for long-running streams; the policy file is hot-reloaded, keeping the last good version.
- JSON access and audit logs joined by a decision ID (the policy API's `requestId`) and a per-request transaction ID.
- Performance: see [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

## Documentation

- [docs/OPERATIONS.md](docs/OPERATIONS.md): deploying a cluster, settings reference, logging, decision caching, limits, network backstop, known limitations.
- [docs/INTEGRATION.md](docs/INTEGRATION.md): issuing sandbox tokens, the policy API contract, and the Python library.
- [SECURITY.md](SECURITY.md): security model and vulnerability reporting.

## Development and testing

```sh
make test          # everything: unit tests, end-to-end tests, image smoke test
```

`make test` sets up what it needs and picks how to run the end-to-end suite on your machine. If it can't run the suite, it fails and tells you why. It never skips silently.

| Stage | What it runs | Where |
|---|---|---|
| unit | unit tests + compile check | host Python ≥ 3.11, or inside the image if the host has none |
| e2e | real Squid, haproxy, nftables, Redis; fixtures on fake public IPs; no route out | **bwrap**: unprivileged bubblewrap sandbox with a pinned, checksum-verified Ubuntu 24.04 toolchain, downloaded once into `.e2e-cache/` (Linux amd64; no root, no Docker). **docker**: a container built from the production image, so the image's own Squid, Python, installed package and entrypoint are tested (any OS with Docker) |
| smoke | the production image as deployed: read-only root, no capabilities, `no-new-privileges`, on a private Docker network with no route out | Docker (skipped with a note if Docker is not available) |

Tests assert on evidence (DNS queries, origin connections, arbiter requests, access and audit logs), not just status codes.

```sh
make test-docker   # force the Docker runner (E2E in the image + smoke)
make unit          # unit tests only
make e2e           # E2E in the bubblewrap sandbox only
make docker-e2e    # E2E in the image only
make docker-smoke  # image smoke test only
make perf          # load test (docs/PERFORMANCE.md)
make e2e-baseline BASELINE=<old checkout>   # regression tests against another version
```

Settings: `EGRESS_TEST_RUNNER=auto|bwrap|docker|none`, `EGRESS_TEST_SMOKE=auto|1|0`, `EGRESS_IMAGE` (default `clearideas-egress:test`), `EGRESS_DOCKER_VOLUME_OPTS` (for SELinux hosts, `ro,z`). The bubblewrap runner needs unprivileged user namespaces. On Ubuntu 24.04, allow them with `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, or let `make test` fall back to Docker.
