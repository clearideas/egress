# Using the package in a private deployment

The exported npm functions handle Squid ACL parsing, exact destination policy and fail-closed authorization. A private application can import them and provide an organization-specific policy backend. Keep account lookup, request signing, policy management, event storage and infrastructure credentials in that private adapter.

The included `clearideas-egress-acl` command supports only the public file and HTTP backends. To add private behavior, provide another Node CLI that reads the same Squid input format, calls `createAuthorizer(privateBackend)`, and prints one `OK` or `ERR` per input line. Configure `external_acl_type` to execute that CLI. The current Clear Ideas production helper is Python, so adopting this npm package will require replacing or bridging that helper process; Python cannot directly import the Node module.

Treat the Squid-authenticated `principal` as the caller identity. Do not accept a client-supplied header as proof of another identity, and do not reuse a cached policy as proof of authentication. If a private adapter adds caching, verify each caller before cache lookup, scope entries to that verified identity, and bound revocation age. Keep private destination and safe-port rules in Squid as a separate gate.
