# clearideas-egress

A small Python policy layer for a Squid HTTP(S) forward proxy. It checks the Squid-authenticated proxy user and requested destination against a local JSON file or an HTTP policy service. The library and CLI use only the Python standard library at runtime.

This is an early source release. It contains no Clear Ideas production policy, credentials, infrastructure, or hosted policy service. It is **not** an npm package. The former JavaScript prototype was removed so a private Python helper can import this library directly.

## Install and run

Requires Python 3.11 or newer. From a checkout:

```sh
python -m pip install .
EGRESS_POLICY_FILE=examples/policy.json clearideas-egress-acl
```

The CLI reads Squid external ACL lines (`%ul %>a %METHOD %DST %PORT`, with Squid's optional trailing `-` placeholder) from standard input and writes one `OK` or `ERR` per line. A malformed line, missing policy, failed API call, or non-allow response denies access.

For a loopback-only local proxy demonstration:

```sh
EGRESS_PROXY_PASSWORD='choose-a-local-password' docker compose up --build
curl --proxy http://demo:choose-a-local-password@127.0.0.1:3128 https://example.com/
```

Compose binds only `127.0.0.1:3128`. It requires a password, creates a bcrypt password file at startup, and uses [`examples/policy.json`](examples/policy.json). The example allows `demo` to CONNECT to `example.com:443` and denies other destinations.

## File policy

Set `EGRESS_POLICY_FILE` to a JSON file:

```json
{"version":1,"principals":{"demo":["https://example.com","http://example.net:8080"]}}
```

Each key is a Squid-authenticated proxy username. Entries are exact HTTP(S) origins. The scheme, normalized host, and port must all match: CONNECT corresponds to HTTPS; other methods correspond to HTTP. There are no wildcards, paths, or query permissions. Unknown users and destinations are denied. The file is validated and loaded at helper startup; restart the helper after changes. Decisions are not cached.

## HTTP policy

Set `EGRESS_POLICY_URL` instead of `EGRESS_POLICY_FILE`. Remote URLs must use HTTPS and set `EGRESS_POLICY_TOKEN`; loopback HTTP is supported for local development. The helper POSTs JSON for every decision:

```json
{"principal":"demo","sourceIp":"192.0.2.10","method":"CONNECT","host":"example.com","port":443}
```

The service must answer HTTP 200 with `{"decision":"allow"}` to permit. Every other response, redirect, timeout, malformed JSON, or transport failure denies. The request timeout is two seconds, and responses over 64 KiB deny. The service must treat `principal` as the username authenticated by Squid; clients cannot supply it through a request header.

The Python API exports `parse_acl_line`, `normalize_host`, `compile_file_policy`, `load_file_policy`, `FilePolicy`, `HTTPPolicy`, and `authorize`. A private Python helper can import these and supply its own policy backend. See [integration guidance](docs/INTEGRATION.md).

## Security boundary

The included Squid template requires Basic proxy authentication, restricts ports, blocks private/reserved destination addresses, and asks the helper before forwarding. It makes a fresh policy decision on every request. An allowed HTTPS CONNECT destination is authorized only by host and port; the proxy does not inspect TLS payloads or constrain URL paths. It cannot prevent direct outbound connections that bypass the proxy.

**Protect Basic proxy credentials in transit.** The included Compose setup is bound to local loopback for testing. For remote clients, provide an authenticated encrypted network or TLS-protected proxy endpoint, verify certificates, and restrict ingress. Destination HTTPS does not encrypt the outer proxy password. Validate your Squid version, DNS and IPv6 behavior, and network rules before relying on this as an enforcement boundary.

The optional container installs separately licensed system packages; see [third-party notices](THIRD_PARTY_NOTICES.md). Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Development

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
python -m compileall -q src
```

CI runs these checks on multiple Python versions. A real Squid integration suite and production deployment verification are future work.
