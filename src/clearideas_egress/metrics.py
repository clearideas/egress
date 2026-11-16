"""Process-local metrics for the helpers, published as snapshot files for the monitor.

Each helper process counts events in a :class:`Registry` and, when
``EGRESS_METRICS_DIR`` is set, writes a JSON snapshot there every few seconds
(atomically, ``<mode>-<pid>.json``). ``clearideas-egress-monitor`` aggregates the
snapshots of all helper processes (including ones that have exited, so counters stay
monotonic) and serves them in Prometheus format.

Labels are deliberately low-cardinality: no principals, hosts or paths (those
belong in the logs). Free-form reasons from a policy API (``arbiter:<code>``) are
collapsed to ``arbiter``.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

# Latency buckets (seconds) for decision and backend-call histograms.
BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0)


def reason_label(reason: str) -> str:
    return "arbiter" if reason.startswith("arbiter:") else reason


class Registry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counters: dict[tuple, float] = {}
        self.gauges: dict[tuple, float] = {}
        self.histograms: dict[tuple, list] = {}  # key -> [bucket counts..., sum, count]

    @staticmethod
    def _key(name: str, labels: dict | None) -> tuple:
        return (name, tuple(sorted((labels or {}).items())))

    def inc(self, name: str, labels: dict | None = None, value: float = 1.0) -> None:
        key = self._key(name, labels)
        with self._lock:
            self.counters[key] = self.counters.get(key, 0.0) + value

    def set(self, name: str, value: float, labels: dict | None = None) -> None:
        with self._lock:
            self.gauges[self._key(name, labels)] = float(value)

    def observe(self, name: str, seconds: float, labels: dict | None = None) -> None:
        key = self._key(name, labels)
        with self._lock:
            data = self.histograms.setdefault(key, [0] * len(BUCKETS) + [0.0, 0])
            for index, bound in enumerate(BUCKETS):
                if seconds <= bound:
                    data[index] += 1
            data[-2] += seconds
            data[-1] += 1

    def snapshot(self) -> dict:
        def pack(items):
            return [{"name": name, "labels": dict(labels), "value": value} for (name, labels), value in items]

        with self._lock:
            return {
                "counters": pack(self.counters.items()),
                "gauges": pack(self.gauges.items()),
                "histograms": pack((key, list(value)) for key, value in self.histograms.items()),
            }


METRICS = Registry()


class SnapshotWriter:
    """Writes ``METRICS`` snapshots for this process; ``collectors`` refresh gauges first."""

    def __init__(self, directory: str | os.PathLike, mode: str, *, interval: float = 2.0, collectors=()) -> None:
        self.directory = Path(directory)
        self.path = self.directory / f"{mode}-{os.getpid()}.json"
        self.mode = mode
        self.interval = interval
        self.collectors = list(collectors)
        self.started = time.time()

    def write(self) -> None:
        for collect in self.collectors:
            try:
                collect(METRICS)
            except Exception:
                pass
        data = METRICS.snapshot()
        data.update(pid=os.getpid(), mode=self.mode, started=self.started, written=time.time(),
                    buckets=list(BUCKETS))
        tmp = self.path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            pass

    def start(self) -> "SnapshotWriter":
        def loop():
            while True:
                self.write()
                time.sleep(self.interval)

        threading.Thread(target=loop, daemon=True, name="egress-metrics").start()
        return self


def metrics_dir() -> str | None:
    directory = os.environ.get("EGRESS_METRICS_DIR")
    if directory:
        return directory
    run_dir = os.environ.get("EGRESS_RUN_DIR")
    return os.path.join(run_dir, "metrics") if run_dir else None


def start_from_env(mode: str, collectors=()) -> SnapshotWriter | None:
    directory = metrics_dir()
    if not directory or not os.path.isdir(directory):
        return None
    return SnapshotWriter(directory, mode, collectors=collectors).start()
