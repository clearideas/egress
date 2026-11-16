# Log-based detections

Some signals are per request or per principal and belong in logs, not metric labels. Queries are
written for Loki (LogQL). Adapt them for Elasticsearch/OpenSearch. The access log is the JSON on
stdout; the audit log is the JSON on stderr (`event` field).

| Signal | Query |
|---|---|
| Internal/metadata destination attempts (allowed by policy, refused by the destination check) | `{app="egress-proxy"} \| json \| destination="forbidden"` |
| Allowed names the proxy cannot resolve (DNS trouble on the proxy, or a stale policy) | `sum by (instance) (count_over_time({app="egress-proxy"} \| json \| destination="unresolved" [5m]))` |
| Allowed destinations the proxy cannot connect to | `{app="egress-proxy"} \| json \| result="TCP_TUNNEL" and status="503"` |
| Denials per principal (probing) | `sum by (principal) (count_over_time({app="egress-proxy"} \| json \| event="decision" and decision="deny" [15m]))` |
| Top denied destinations | `topk(20, sum by (host) (count_over_time({app="egress-proxy"} \| json \| event="decision" and decision="deny" [1h])))` |
| Everything one decision covered | `{app="egress-proxy"} \| json \| decision_id="<id>"` (access log) and the policy API's log for `requestId=<id>` |
| One request end to end | `{app="egress-proxy"} \| json \| instance="<pod>" and xaction="<n>"` (access log and per-request audit events) |
| Large uploads | `{app="egress-proxy"} \| json \| bytes_from_client > 10000000` |
