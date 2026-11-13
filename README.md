# @clearideas/egress

A small, generic policy layer for a Squid HTTP(S) forward proxy. It checks the authenticated proxy user and destination host/port against either a local policy file or an HTTP policy service. It has no runtime npm dependencies. This repository contains original MIT-licensed code; Squid remains separately licensed.

This is an early source release. It does not contain Clear Ideas production policies, credentials, infrastructure, or a hosted policy service.

## Local quickstart

Set a local demonstration password and run the included Compose configuration:

```sh
EGRESS_PROXY_PASSWORD='choose-a-local-password' docker compose up --build
curl --proxy http://demo:choose-a-local-password@127.0.0.1:3128 https://example.com/
curl --proxy http://demo:choose-a-local-password@127.0.0.1:3128 https://example.org/
```

The first destination is allowed by [`examples/policy.json`](examples/policy.json); the second is denied. Compose binds only `127.0.0.1:3128`. The container requires `EGRESS_PROXY_PASSWORD` and creates a bcrypt password file at startup. Use a strong unique secret outside this local demonstration.

## File policy

Set `EGRESS_POLICY_FILE` to a JSON file:

```json
{ "version": 1, "principals": { "demo": ["https://example.com", "http://example.net:8080"] } }
```

The key is the Squid-authenticated proxy username. Every entry is an exact HTTP(S) origin; scheme determines the default port. There are no wildcard, path, or URL-query permissions. A missing principal, host, or port is denied. The file is validated and loaded at helper startup; restart the proxy after changes. No decisions are cached.

## HTTP policy

Set `EGRESS_POLICY_URL` instead of `EGRESS_POLICY_FILE`. Remote URLs must use HTTPS and set `EGRESS_POLICY_TOKEN`; loopback HTTP is supported for local development. The helper POSTs JSON for each uncached decision:

```json
{ "principal": "demo", "sourceIp": "192.0.2.10", "method": "CONNECT", "host": "example.com", "port": 443 }
```

It sends `Authorization: Bearer <EGRESS_POLICY_TOKEN>` when configured. Respond with `{"decision":"allow"}` to permit; every other response, HTTP error, timeout, malformed JSON, or transport failure denies. The request timeout is two seconds. Redirects are rejected. Keep the service's policy credentials and access restricted. The API must use `principal` as the authenticated proxy identity; a client cannot set it through a request header.

The npm API exports `parseAclLine`, `normalizeHost`, `compileFilePolicy`, `loadFilePolicy`, `filePolicyBackend`, `httpPolicyBackend`, and `createAuthorizer`. An internal application can import these and supply a private backend. The Squid helper CLI is `clearideas-egress-acl`; Squid sends `%ul %>a %METHOD %DST %PORT` and receives `OK` or `ERR`.

For a private adapter and migration boundary, see [INTEGRATION.md](docs/INTEGRATION.md).

## Security boundary

The supplied Squid template requires Basic proxy authentication, checks safe ports, blocks private/reserved destination addresses, and asks the helper before forwarding. It makes a new policy decision on every request. A permitted HTTPS CONNECT destination is authorized only by host and port; this proxy does not inspect TLS payloads or constrain URL paths. It cannot stop direct outbound connections made outside the proxy.

**Basic proxy credentials must travel over an encrypted client-to-proxy connection.** The included Compose setup is bound to local loopback for testing. For remote clients, provide an authenticated encrypted network or a TLS-protected proxy endpoint, verify certificates, and restrict ingress. Destination HTTPS does not encrypt the outer proxy password. Validate your Squid version, DNS and IPv6 behavior, and network rules before relying on this as an enforcement boundary.

The optional container installs third-party packages; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) before distributing images. For security reports, see [SECURITY.md](SECURITY.md).

## Development

Requires Node 20 or newer. Run `npm run check`, `npm test`, and `npm pack --dry-run`. Pull requests run these checks. A real Squid integration suite and published container release process are future work.
