"""Optional immediate revocation list (``EGRESS_REVOKED_FILE``).

Policy decisions are cached (``EGRESS_DECISION_TTL``, default 300 s), so revoking a
run through the policy API takes up to that long. This list is the kill switch: it
is checked on **every** request, outside the decision cache, and re-read within ~2 s
of a change.

File format, one entry per line (``#`` comments allowed)::

    principal=sbx-42              # the request's principal
    runnerAuthId=auth-9c1e        # any verified identity attribute (signed-header mode)

An invalid edit or a missing file keeps the last good list (and is logged); to clear
the list, write an empty file.
"""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path
from typing import Mapping

_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,31}$")
_VALUE = re.compile(r"^[A-Za-z0-9._:@-]{1,256}$")


class RevocationError(ValueError):
    pass


def parse(text: str) -> frozenset[tuple[str, str]]:
    entries = set()
    for number, line in enumerate(text.splitlines(), 1):
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        name, sep, value = content.partition("=")
        name, value = name.strip(), value.strip()
        if not sep or not _NAME.fullmatch(name) or not _VALUE.fullmatch(value):
            raise RevocationError(f"line {number}: expected <attribute>=<value> or principal=<value>")
        entries.add((name, value))
    return frozenset(entries)


class RevocationList:
    def __init__(self, path: str | Path, *, refresh_seconds: float = 2.0, on_error=None) -> None:
        self.path = Path(path)
        self.refresh_seconds = refresh_seconds
        self.on_error = on_error
        self._entries: frozenset[tuple[str, str]] | None = None
        self._stamp: tuple | None = None
        self._checked = 0.0
        self._lock = threading.Lock()
        self._reload()

    @property
    def loaded(self) -> bool:
        return self._entries is not None

    def _reload(self) -> None:
        try:
            stat = os.stat(self.path)
            stamp = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
            if stamp == self._stamp:
                return
            entries = parse(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, RevocationError) as error:
            if self.on_error is not None:
                self.on_error(f"{type(error).__name__}: {error}")
            return  # keep the last good list
        self._entries, self._stamp = entries, stamp

    def _current(self) -> frozenset[tuple[str, str]] | None:
        now = time.monotonic()
        with self._lock:
            if now - self._checked >= self.refresh_seconds:
                self._checked = now
                self._reload()
            return self._entries

    def revoked(self, principal: str | None, identity: Mapping[str, str] | None = None) -> bool | None:
        """True/False, or None if no list was ever loaded (caller fails closed)."""
        entries = self._current()
        if entries is None:
            return None
        if principal is not None and ("principal", principal) in entries:
            return True
        return any((name, value) in entries for name, value in (identity or {}).items())
