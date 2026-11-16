"""Health, readiness and Prometheus metrics for one proxy instance (``clearideas-egress-monitor``).

Endpoints (``EGRESS_MONITOR_ADDRESS``:``EGRESS_MONITOR_PORT``, default ``0.0.0.0:9090``):

``/livez``
    200 while Squid runs and accepts connections on its listening port.
``/readyz``
    200 when live, not draining, and no helper process reports a configuration
    problem. **Deliberately independent of the policy API**: an API outage must not
    mark every replica unready at once (sandboxes already get a retryable 503).
``/metrics``
    Prometheus text format: helper counters and histograms (decisions, approvals,
    signatures, TLS checks, auth, credential injections, policy-API attempts and
    retries, config reloads), aggregated over all helper processes including exited
    ones, plus Squid's own counters read from the loopback admin port.

On SIGTERM the monitor reports not-ready at once, so the load balancer stops sending
new connections while Squid drains active ones (``EGRESS_DRAIN_SECONDS``).
"""

from __future__ import annotations

import http.client
import http.server
import json
import os
import re
import signal
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path

from .audit import instance_id
from .metrics import BUCKETS

STALE_SECONDS = 60.0  # a helper snapshot not rewritten for this long belongs to an exited process
SQUID_ACTIONS_TIMEOUT = 2.0


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(labels: dict) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{key}="{_escape(str(value))}"' for key, value in sorted(labels.items())) + "}"


class HelperMetrics:
    """Aggregates helper snapshot files; counters of exited processes are kept (monotonic totals)."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.retired_counters: dict[tuple, float] = {}
        self.retired_histograms: dict[tuple, list] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(entry: dict) -> tuple:
        return entry["name"], tuple(sorted(entry["labels"].items()))

    def collect(self) -> tuple[dict, dict, dict, list[dict]]:
        counters: dict[tuple, float] = {}
        gauges: dict[tuple, float] = {}
        histograms: dict[tuple, list] = {}
        live: list[dict] = []
        now = time.time()
        with self._lock:
            for path in sorted(self.directory.glob("*.json")):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                stale = now - float(data.get("written", 0)) > STALE_SECONDS
                if stale:  # fold the final values of an exited helper into the retired totals
                    for entry in data.get("counters", []):
                        key = self._key(entry)
                        self.retired_counters[key] = self.retired_counters.get(key, 0.0) + entry["value"]
                    for entry in data.get("histograms", []):
                        key = self._key(entry)
                        base = self.retired_histograms.setdefault(key, [0] * len(entry["value"]))
                        self.retired_histograms[key] = [a + b for a, b in zip(base, entry["value"])]
                    try:
                        path.unlink()
                    except OSError:
                        pass
                    continue
                live.append(data)
                for entry in data.get("counters", []):
                    key = self._key(entry)
                    counters[key] = counters.get(key, 0.0) + entry["value"]
                for entry in data.get("gauges", []):
                    key = self._key(entry)
                    if entry["name"] == "egress_helper_misconfigured":
                        gauges[key] = max(gauges.get(key, 0.0), entry["value"])
                    else:
                        gauges[key] = gauges.get(key, 0.0) + entry["value"]
                for entry in data.get("histograms", []):
                    key = self._key(entry)
                    base = histograms.get(key, [0] * len(entry["value"]))
                    histograms[key] = [a + b for a, b in zip(base, entry["value"])]
            for key, value in self.retired_counters.items():
                counters[key] = counters.get(key, 0.0) + value
            for key, value in self.retired_histograms.items():
                base = histograms.get(key, [0] * len(value))
                histograms[key] = [a + b for a, b in zip(base, value)]
        return counters, gauges, histograms, live


class SquidStats:
    """Reads Squid's cache-manager actions from the loopback admin port."""

    COUNTERS = {
        "client_http.requests": ("egress_squid_client_requests_total", {}, 1),
        "client_http.errors": ("egress_squid_client_errors_total", {}, 1),
        "client_http.kbytes_in": ("egress_squid_client_bytes_total", {"direction": "from_client"}, 1024),
        "client_http.kbytes_out": ("egress_squid_client_bytes_total", {"direction": "to_client"}, 1024),
        "server.all.requests": ("egress_squid_server_requests_total", {}, 1),
        "server.all.errors": ("egress_squid_server_errors_total", {}, 1),
        "server.all.kbytes_in": ("egress_squid_server_bytes_total", {"direction": "from_server"}, 1024),
        "server.all.kbytes_out": ("egress_squid_server_bytes_total", {"direction": "to_server"}, 1024),
    }

    def __init__(self, port: int) -> None:
        self.port = port

    def _get(self, action: str) -> str:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=SQUID_ACTIONS_TIMEOUT)
        try:
            connection.request("GET", f"/squid-internal-mgr/{action}",
                               headers={"Host": f"127.0.0.1:{self.port}", "Connection": "close"})
            response = connection.getresponse()
            body = response.read(2_000_000).decode("utf-8", "replace")
            if response.status != 200:
                raise OSError(f"{action}: HTTP {response.status}")
            return body
        finally:
            connection.close()

    def collect(self) -> list[tuple[str, str, dict, float]]:
        """Return (type, name, labels, value) samples; raises OSError if Squid does not answer."""
        samples: list[tuple[str, str, dict, float]] = []
        for line in self._get("counters").splitlines():
            name, _, value = line.partition("=")
            mapping = self.COUNTERS.get(name.strip())
            if mapping and value.strip():
                metric, labels, factor = mapping
                samples.append(("counter", metric, labels, float(value.strip()) * factor))
        info = self._get("info")
        for pattern, metric, labels in (
            (r"Number of file desc currently in use:\s*(\d+)", "egress_squid_file_descriptors", {"state": "used"}),
            (r"Maximum number of file descriptors:\s*(\d+)", "egress_squid_file_descriptors", {"state": "max"}),
            (r"Number of clients accessing cache:\s*(\d+)", "egress_squid_clients", {}),
        ):
            match = re.search(pattern, info)
            if match:
                samples.append(("gauge", metric, labels, float(match.group(1))))
        for action in ("external_acl", "basicauthenticator"):
            try:
                text = self._get(action)
            except OSError:
                continue
            samples.extend(self._helper_pools(text, action))
        return samples

    @staticmethod
    def _helper_pools(text: str, action: str) -> list[tuple[str, str, dict, float]]:
        samples = []
        blocks = re.split(r"\n(?=External ACL Statistics: |[A-Za-z ]*[Aa]uthenticator [Ss]tatistics)", "\n" + text)
        for block in blocks:
            header = re.match(r"\s*External ACL Statistics: (\S+)", block)
            name = header.group(1) if header else ("basic_auth" if action == "basicauthenticator" else None)
            if not name:
                continue
            labels = {"helper": name}
            for pattern, metric, kind, factor in (
                (r"requests sent:\s*(\d+)", "egress_helper_pool_requests_total", "counter", 1),
                (r"queue length:\s*(\d+)", "egress_helper_pool_queue_length", "gauge", 1),
                (r"avg service time:\s*(\d+)\s*msec", "egress_helper_pool_service_seconds", "gauge", 0.001),
                (r"number active:\s*(\d+)", "egress_helper_pool_processes", "gauge", 1),
            ):
                match = re.search(pattern, block)
                if match:
                    samples.append((kind, metric, labels, float(match.group(1)) * factor))
        return samples


class Monitor:
    def __init__(self) -> None:
        run_dir = Path(os.environ.get("EGRESS_RUN_DIR", "/run/egress"))
        self.run_dir = run_dir
        self.pid_file = run_dir / "squid.pid"
        self.listen_port = int(os.environ.get("EGRESS_LISTEN_PORT", "3128"))
        admin = int(os.environ.get("EGRESS_ADMIN_PORT", "3129"))
        self.squid = SquidStats(admin) if admin else None
        metrics_dir = Path(os.environ.get("EGRESS_METRICS_DIR") or run_dir / "metrics")
        self.helpers = HelperMetrics(metrics_dir)
        self.draining = False
        self.started = time.time()

    # -- checks -----------------------------------------------------------------

    def squid_pid(self) -> int | None:
        try:
            pid = int(self.pid_file.read_text().split()[0])
        except (OSError, ValueError, IndexError):
            return None
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return None
        except PermissionError:
            pass  # exists but belongs to someone else: still alive
        return pid

    def accepting(self) -> bool:
        for host in ("127.0.0.1", "::1"):
            try:
                socket.create_connection((host, self.listen_port), timeout=1).close()
                return True
            except OSError:
                continue
        return False

    def liveness(self) -> tuple[bool, list[str]]:
        problems = []
        if self.squid_pid() is None and not self.accepting():
            problems.append("squid_not_running")
        elif not self.accepting():
            problems.append("listener_not_accepting")
        return not problems, problems

    def readiness(self) -> tuple[bool, list[str]]:
        ok, problems = self.liveness()
        if self.draining:
            problems.append("draining")
        _, gauges, _, _ = self.helpers.collect()
        for (name, labels), value in gauges.items():
            if name == "egress_helper_misconfigured" and value:
                problems.append(f"helper_misconfigured:{dict(labels).get('mode', '?')}")
        return not problems, problems

    # -- metrics ------------------------------------------------------------------

    def metrics(self) -> str:
        lines: list[str] = []
        typed: set[str] = set()

        def sample(kind: str, name: str, labels: dict, value: float) -> None:
            if name not in typed:
                lines.append(f"# TYPE {name} {kind}")
                typed.add(name)
            lines.append(f"{name}{_labels(labels)} {value:g}")

        counters, gauges, histograms, live = self.helpers.collect()
        for (name, labels), value in sorted(counters.items()):
            sample("counter", name, dict(labels), value)
        for (name, labels), value in sorted(gauges.items()):
            sample("gauge", name, dict(labels), value)
        for (name, labels), data in sorted(histograms.items()):
            if name not in typed:
                lines.append(f"# TYPE {name} histogram")
                typed.add(name)
            base = dict(labels)
            for bound, count in zip(BUCKETS, data[: len(BUCKETS)]):
                lines.append(f"{name}_bucket{_labels({**base, 'le': f'{bound:g}'})} {count:g}")
            lines.append(f"{name}_bucket{_labels({**base, 'le': '+Inf'})} {data[-1]:g}")
            lines.append(f"{name}_sum{_labels(base)} {data[-2]:g}")
            lines.append(f"{name}_count{_labels(base)} {data[-1]:g}")
        sample("gauge", "egress_helper_processes", {}, float(len(live)))
        if self.squid is not None:
            try:
                for kind, name, labels, value in self.squid.collect():
                    sample(kind, name, labels, value)
                sample("gauge", "egress_squid_up", {}, 1)
            except (OSError, http.client.HTTPException):
                sample("gauge", "egress_squid_up", {}, 0)
        ready, _ = self.readiness()
        sample("gauge", "egress_ready", {}, 1 if ready else 0)
        sample("gauge", "egress_draining", {}, 1 if self.draining else 0)
        sample("gauge", "egress_monitor_start_time_seconds", {}, self.started)
        sample("gauge", "egress_instance_info", {"instance_id": instance_id()}, 1)
        try:  # written by the renderer when EGRESS_ERROR_CA_* is set
            not_after = json.loads((self.run_dir / "error-ca.json").read_text())["not_after"]
            sample("gauge", "egress_error_ca_not_after_timestamp_seconds", {}, float(not_after))
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return "\n".join(lines) + "\n"


def make_handler(monitor: Monitor):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "egress-monitor"
        sys_version = ""

        def _send(self, status: int, body: str, content_type: str) -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/livez":
                ok, problems = monitor.liveness()
                self._send(200 if ok else 503, json.dumps({"live": ok, "problems": problems}), "application/json")
            elif path == "/readyz":
                ok, problems = monitor.readiness()
                self._send(200 if ok else 503, json.dumps({"ready": ok, "problems": problems}), "application/json")
            elif path == "/metrics":
                self._send(200, monitor.metrics(), "text/plain; version=0.0.4; charset=utf-8")
            else:
                self._send(404, json.dumps({"endpoints": ["/livez", "/readyz", "/metrics"]}), "application/json")

        def log_message(self, *args) -> None:
            pass

    return Handler


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main(argv: list[str] | None = None) -> int:
    monitor = Monitor()
    address = os.environ.get("EGRESS_MONITOR_ADDRESS", "0.0.0.0")
    port = int(os.environ.get("EGRESS_MONITOR_PORT", "9090"))
    if ":" in address:
        _Server.address_family = socket.AF_INET6
    server = _Server((address, port), make_handler(monitor))
    drain = float(os.environ.get("EGRESS_DRAIN_SECONDS", "30"))

    def on_term(signum, frame) -> None:
        monitor.draining = True  # readiness fails at once; keep answering probes while Squid drains
        threading.Timer(drain + 5, lambda: os._exit(0)).start()

    signal.signal(signal.SIGTERM, on_term)
    print(f"egress monitor listening on {address}:{port}", file=sys.stderr)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
