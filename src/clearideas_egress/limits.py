"""Per-principal fairness controls applied before a policy backend is consulted.

* ``PrincipalConcurrency`` caps how many decisions one principal may have in
  flight at once, so a single sandbox cannot occupy every backend slot and starve
  other tenants (security review H-3).
* ``TokenBucketLimiter`` optionally caps the decision *rate* per principal.

Both are per helper process; Squid may run several helper processes, so the
effective limits are approximate multiples. Squid's per-client ``maxconn`` is the
hard connection limit.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Iterator


class PrincipalConcurrency:
    def __init__(self, limit: int) -> None:
        if limit < 1:
            raise ValueError("per-principal concurrency must be >= 1")
        self.limit = limit
        self._active: dict[str, int] = {}
        self._lock = threading.Lock()
        self._changed = threading.Condition(self._lock)

    @contextmanager
    def slot(self, principal: str, timeout: float = 0.0) -> Iterator[bool]:
        """Acquire one of the principal's slots, waiting up to ``timeout`` seconds.

        Bursts from one principal queue here instead of being denied, while other
        principals keep their own slots (fairness)."""
        deadline = time.monotonic() + max(timeout, 0.0)
        with self._changed:
            while self._active.get(principal, 0) >= self.limit:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._changed.wait(remaining)
            acquired = self._active.get(principal, 0) < self.limit
            if acquired:
                self._active[principal] = self._active.get(principal, 0) + 1
        try:
            yield acquired
        finally:
            if acquired:
                with self._changed:
                    remaining = self._active[principal] - 1
                    if remaining:
                        self._active[principal] = remaining
                    else:
                        del self._active[principal]
                    self._changed.notify_all()


class TokenBucketLimiter:
    MAX_TRACKED = 100_000

    def __init__(self, rate_per_second: float, burst: int) -> None:
        if rate_per_second <= 0 or burst < 1:
            raise ValueError("rate must be > 0 and burst >= 1")
        self.rate = float(rate_per_second)
        self.burst = float(burst)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    @classmethod
    def parse(cls, setting: str | None) -> "TokenBucketLimiter | None":
        """``"<rate>/<burst>"`` (e.g. ``"50/200"``), or empty/``off`` to disable."""
        if not setting or setting == "off":
            return None
        try:
            rate, burst = setting.split("/", 1)
            return cls(float(rate), int(burst))
        except ValueError as error:
            raise ValueError("EGRESS_RATE_LIMIT must look like '<rate>/<burst>', e.g. '50/200'") from error

    def allow(self, principal: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(principal, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            if len(self._buckets) >= self.MAX_TRACKED and principal not in self._buckets:
                self._buckets.clear()  # bounded memory; resets are fail-open only for rate, never for policy
            self._buckets[principal] = (tokens, now)
            return allowed
