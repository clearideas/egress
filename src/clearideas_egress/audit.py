"""Structured (JSON Lines) audit log for policy decisions.

One JSON object per decision, written with a single ``write`` call so lines from
concurrent threads never interleave. Secrets (passwords, tokens) are never passed
to this module.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from typing import IO


_INSTANCE = None


def instance_id() -> str:
    """Identifies this proxy instance in logs and metrics (``EGRESS_INSTANCE_ID``, else the host name)."""
    global _INSTANCE
    if _INSTANCE is None:
        import re
        import socket
        raw = os.environ.get("EGRESS_INSTANCE_ID") or socket.gethostname() or "egress"
        _INSTANCE = re.sub(r"[^A-Za-z0-9._-]", "-", raw)[:64] or "egress"
    return _INSTANCE


class AuditLog:
    def __init__(self, stream: IO[str] | None) -> None:
        self._stream = stream
        self._lock = threading.Lock()

    @classmethod
    def from_setting(cls, setting: str | None) -> "AuditLog":
        """``stderr`` (default; Squid routes helper stderr to cache_log), ``off``, or a file path."""
        if setting in (None, "", "stderr"):
            return cls(sys.stderr)
        if setting == "off":
            return cls(None)
        return cls(open(setting, "a", encoding="utf-8", buffering=1))

    def close(self) -> None:
        """Close a file-backed log (never stderr)."""
        with self._lock:
            stream, self._stream = self._stream, None
        if stream is not None and stream is not sys.stderr:
            try:
                stream.close()
            except OSError:
                pass

    def emit(self, event: str, **fields: object) -> None:
        if self._stream is None:
            return
        now = time.time()
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now * 1000) % 1000:03d}Z",
            "event": event,
            **fields,
        }
        record.setdefault("instance", instance_id())
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True, default=str) + "\n"
        with self._lock:
            try:
                self._stream.write(line)
                self._stream.flush()
            except (OSError, ValueError):
                pass
