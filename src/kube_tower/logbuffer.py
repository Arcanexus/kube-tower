"""Keeps the last application log records in memory for the Logs page of the UI.

In the distributed mode every process also ships its lines to Valkey (internal.Reporter), each with the
process (pod) and the roles it came from: the Logs page shows those of every process.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class LogLine:
    seq: int
    time: datetime
    level: str
    logger: str
    thread: str
    message: str
    source: str = ""  # the process (pod) that logged it
    roles: list[str] = field(default_factory=list)  # the roles of that process


class LogBuffer(logging.Handler):
    """A ring buffer of the last `capacity` records; each line gets an increasing sequence number."""

    def __init__(self, capacity: int = 2000, source: str = "", roles: list[str] | None = None):
        super().__init__(level=logging.DEBUG)
        self.lines: deque[LogLine] = deque(maxlen=capacity)
        self.seq = 0
        self.source, self.roles = source, list(roles or [])

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
            if record.exc_info:
                message += "\n" + logging.Formatter().formatException(record.exc_info)
            # Called by Handler.handle() with self.lock held: records come from the web loop and scan threads.
            self.seq += 1
            self.lines.append(
                LogLine(
                    self.seq,
                    datetime.fromtimestamp(record.created),
                    record.levelname,
                    record.name,
                    record.threadName or "",
                    message,
                    self.source,
                    self.roles,
                )
            )
        except Exception:  # noqa: BLE001 - logging must never break the application
            self.handleError(record)

    def since(self, after: int = 0) -> list[LogLine]:
        with self.lock:
            return [line for line in self.lines if line.seq > after]
