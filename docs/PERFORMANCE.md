# Performance

`make perf` runs a load test in the same rootless sandbox as the end-to-end tests. A haproxy instance serves as an in-memory origin for plain HTTP and TLS, and Python worker processes generate the load. Each scenario is measured at concurrency 1 (latency) and 32 (throughput, 16 for TLS), in three interleaved rounds; the table shows medians.

**Run it on hardware like your production nodes before sizing.** The numbers below come from a 4-vCPU shared microVM on which the clients, Squid, its helpers, the origin and the policy stub all compete for the same cores. Single-stream latencies there vary by several milliseconds between identical rounds. Use the numbers to compare configurations, not as capacity figures.

## Reference run (Squid 6.14, 4 shared vCPUs)

| Scenario | Conc. | req/s | p50 ms | p95 ms | p99 ms | Errors |
|---|---:|---:|---:|---:|---:|---:|
| Direct to origin (no proxy) | 1 | 3161 | 0.28 | 0.43 | 1.87 | 0 |
| | 32 | 20839 | 1.25 | 2.95 | 5.28 | 0 |
| Proxy, cached approval, `api` scope (default) | 1 | 201 | 4.36 | 10.22 | 14.70 | 0 |
| | 32 | 3566 | 6.81 | 17.49 | 25.48 | 0 |
| Proxy, cached approval, `origin` scope (Squid cache) | 1 | 861 | 0.77 | 3.71 | 5.79 | 0 |
| | 32 | 4150 | 6.28 | 11.89 | 18.16 | 0 |
| Proxy, policy API called on every request (TTL 0) | 1 | 287 | 2.66 | 6.75 | 13.50 | 0 |
| | 32 | 3211 | 7.92 | 16.38 | 24.69 | 0 |
| Proxy, signed headers verified per request | 1 | 323 | 2.25 | 7.24 | 13.22 | 0 |
| | 32 | 1996 | 12.74 | 26.34 | 36.21 | 0 |
| Proxy, new CONNECT tunnel + TLS handshake per request | 1 | 85 | 9.97 | 23.23 | 29.09 | 0 |
| | 16 | 496 | 29.29 | 46.17 | 54.91 | 0 |
| Direct TLS handshake + request (no proxy) | 1 | 177 | 4.30 | 12.33 | 15.79 | 0 |
| | 16 | 693 | 18.89 | 43.56 | 60.26 | 0 |

## What to take from it

- **No errors under load** in any scenario: bursts are queued, not dropped (see also `tests/e2e/test_bursts.py`).
- **The proxy adds milliseconds.** That is negligible next to model-API latency (hundreds of milliseconds to minutes).
- **`origin` scope is the cheapest path.** Squid answers from its in-process cache with no helper round trip. In the default **`api` scope**, each request makes one round trip to the policy helper; the helper's own work is ~75 µs (measured in-process), and the rest is inter-process communication and scheduling. Choose `origin` for very high request rates when the policy does not need paths; keep `api` when your policy API scopes approvals.
- **Calling the policy API on every request** (`EGRESS_DECISION_TTL=0`) costs the API round trip plus its processing time on every request. The stub here answers in well under a millisecond, and real APIs are slower. This is why caching is on by default.
- **Signed headers** add an HMAC verification (and optionally a Redis round trip) per request.
- **New CONNECT tunnels** cost about one extra TLS-handshake time compared with direct connections (the proxy hop plus the SNI peek). Clients that reuse connections (keep-alive, HTTP/2 inside the tunnel) pay it once per connection.
- Squid is single-threaded per instance. Scale with replicas (and CPU requests of at least one core per replica) rather than larger pods.

## Sizing checklist

- Concurrent connections per replica ≤ `EGRESS_MAX_FILEDESCRIPTORS` / 2 (client plus server side), and the container's `ulimit -n` must allow it.
- Policy-API connections per replica ≤ `EGRESS_HELPER_CHILDREN` × `EGRESS_POLICY_MAX_IN_FLIGHT` (default 4 × 64). Size the API for replicas × that number at worst, and far less with caching.
- Watch `egress_helper_pool_queue_length`, `egress_policy_decision_seconds` and `egress_squid_file_descriptors` (alerts in `deploy/observability/`).
