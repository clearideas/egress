# Using the Python library in a private deployment

The public `clearideas_egress` module handles Squid ACL parsing, exact-origin file policy, HTTP policy calls, and fail-closed authorization. A private Python helper can import these functions and provide a backend that consults its own authorization API. Keep account lookup, request signing, policy management, events, and infrastructure credentials in the private codebase.

The public CLI reads five fields: `%ul %>a %METHOD %DST %PORT`. A private helper that needs additional Squid fields or signed runner headers should keep its own parser or extend this package through a reviewed generic interface. The existing internal Python helper is **not yet importing this package**; migrate it deliberately and run its full tests and Squid integration checks before production use.

Treat the Squid-authenticated `principal` as the caller identity. Never use client-supplied headers as proof of another identity. If a private adapter adds caching, verify the caller before cache lookup, include the verified identity in each key, and bound revocation age. An API outage should not turn a denial into an allow. Keep private destination and safe-port rules in Squid as an independent gate.
