"""Load test (make perf): throughput and added latency per scenario, in the E2E sandbox.

The origin is haproxy answering from memory (plain HTTP and TLS), so the proxy is the
component being measured. Clients are Python worker processes. Numbers are relative to
this machine: use them for overhead per request and for comparing configurations.
"""

import base64
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

from tests.e2e.harness import PROXY_IP, REPO, WORK, Arbiter, Proxy, ProxyTestCase

CLIENT = str(Path(__file__).with_name("client.py"))
SECONDS = float(os.environ.get("EGRESS_PERF_SECONDS", "8"))
FAST = "93.184.215.17"
RESULTS: list[dict] = []


def run_load(mode, host, port, url, auth=None, signing=None, processes=4, threads=8):
    procs = [subprocess.Popen([sys.executable, CLIENT, mode, host, str(port), url, str(SECONDS), str(threads),
                               auth or "-", json.dumps(signing) if signing else "-"], stdout=subprocess.PIPE, text=True)
             for _ in range(processes)]
    count = errors = 0
    latencies: list[float] = []
    for proc in procs:
        out, _ = proc.communicate(timeout=SECONDS + 60)
        data = json.loads(out.strip().splitlines()[-1])
        count += data["count"]
        errors += data["errors"]
        latencies += data["latencies_ms"]
    latencies.sort()
    pick = lambda q: latencies[min(len(latencies) - 1, int(q * len(latencies)))] if latencies else float("nan")
    return {"rps": count / SECONDS, "errors": errors, "p50": pick(0.5), "p95": pick(0.95), "p99": pick(0.99),
            "concurrency": processes * threads}


ROUNDS = int(os.environ.get("EGRESS_PERF_ROUNDS", "3"))


def measure(name, mode, host, port, url, auth=None, signing=None, heavy=(4, 8)):
    for processes, threads in ((1, 1), heavy):
        result = run_load(mode, host, port, url, auth, signing, processes, threads)
        result["scenario"] = name
        RESULTS.append(result)


def summary() -> str:
    import statistics
    lines = [f"{'scenario':52} {'conc':>4} {'req/s':>8} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8} errors   (median of rounds)"]
    keys = []
    for r in RESULTS:
        if (r["scenario"], r["concurrency"]) not in keys:
            keys.append((r["scenario"], r["concurrency"]))
    for scenario, concurrency in keys:
        runs = [r for r in RESULTS if r["scenario"] == scenario and r["concurrency"] == concurrency]
        med = lambda k: statistics.median(r[k] for r in runs)
        lines.append(f"{scenario:52} {concurrency:>4} {med('rps'):8.0f} {med('p50'):8.2f} {med('p95'):8.2f} "
                     f"{med('p99'):8.2f} {sum(r['errors'] for r in runs):6}   ({len(runs)} rounds)")
    return "\n".join(lines)


class LoadTests(ProxyTestCase):
    AUTH = base64.b64encode(b"demo:demo-password").decode()
    POLICY = {"version": 1, "principals": {"demo": ["http://fast.example", "https://fast.example"]}}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.fx.dns.set("fast.example", [FAST])
        cert, key = cls.fx.pki.issue("fast.example", ["DNS:fast.example"])
        bundle = WORK / "fast.pem"
        bundle.write_text(Path(cert).read_text() + Path(key).read_text())
        config = WORK / "fast-origin.cfg"
        config.write_text(
            "global\n  maxconn 8000\n  nbthread 2\n"
            "defaults\n  mode http\n  timeout connect 5s\n  timeout client 30s\n  timeout server 30s\n"
            f"frontend plain\n  bind {FAST}:80\n  http-request return status 200 content-type text/plain string ok\n"
            f"frontend tls\n  bind {FAST}:443 ssl crt {bundle}\n"
            "  http-request return status 200 content-type text/plain string ok\n")
        cls.origin = subprocess.Popen(["haproxy", "-db", "-f", str(config)], stdout=subprocess.DEVNULL,
                                      stderr=open(WORK / "fast-origin.log", "wb"))
        time.sleep(0.5)
        if cls.origin.poll() is not None:
            raise RuntimeError("fast origin failed: " + (WORK / "fast-origin.log").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.origin.kill()
        (WORK / "perf-results.json").write_text(json.dumps(RESULTS, indent=2))
        print("\n" + summary())

    def test_scenarios(self):
        """All scenarios, interleaved over several rounds (medians smooth out noisy shared CPUs)."""
        for _ in range(ROUNDS):
            self.direct()
            self.cached_approvals()
            self.cached_origin_scope()
            self.policy_api_every_request()
            self.signed_headers()
            self.connect_tunnels()
            self.direct_tls()
        self.assertEqual(sum(r["errors"] for r in RESULTS), 0)

    def direct(self):
        measure("direct to origin (no proxy)", "direct", FAST, 80, "http://fast.example/perf")

    def cached_approvals(self):
        with Proxy(policy=self.POLICY, env={"EGRESS_MAX_CONN_PER_CLIENT": "0"}) as proxy:
            measure("proxy, cached approval, api scope (default)", "http", PROXY_IP, proxy.port,
                    "http://fast.example/perf", self.AUTH)

    def cached_origin_scope(self):
        with Proxy(policy=self.POLICY, env={"EGRESS_MAX_CONN_PER_CLIENT": "0", "EGRESS_DECISION_SCOPE": "origin"}) as proxy:
            measure("proxy, cached approval, origin scope (Squid cache)", "http", PROXY_IP, proxy.port,
                    "http://fast.example/perf", self.AUTH)

    def policy_api_every_request(self):
        arbiter = Arbiter(port=18900)
        try:
            with Proxy(policy_url=arbiter.url, env={"EGRESS_MAX_CONN_PER_CLIENT": "0", "EGRESS_DECISION_TTL": "0"}) as proxy:
                measure("proxy, policy API call on every request", "http", PROXY_IP, proxy.port,
                        "http://fast.example/perf", self.AUTH)
        finally:
            arbiter.close()

    def signed_headers(self):
        policy = {"version": 1, "principals": {"perf-run": ["http://fast.example"]}}
        proxy = Proxy(policy=policy, auth="signed-headers",
                      env={"EGRESS_MODE": "origination", "EGRESS_MAX_CONN_PER_CLIENT": "0"})
        with proxy:
            measure("proxy, signed headers verified per request", "http", PROXY_IP, proxy.port,
                    "http://fast.example/perf", None,
                    {"src": str(REPO / "src"), "master": base64.b64encode(proxy.signing_key).decode()})

    def connect_tunnels(self):
        with Proxy(policy=self.POLICY, env={"EGRESS_MAX_CONN_PER_CLIENT": "0"}) as proxy:
            measure("proxy, new CONNECT tunnel + TLS per request", "connect", PROXY_IP, proxy.port,
                    "fast.example:443", self.AUTH, {}, heavy=(2, 8))

    def direct_tls(self):
        measure("direct TLS handshake + request (no proxy)", "connect-direct", FAST, 443, "fast.example:443",
                None, {}, heavy=(2, 8))


if __name__ == "__main__":
    unittest.main()
