"""The processes (pods) of a kube-tower installation and their state, shown on the Administration page.

In the distributed mode every process but the active controller tells every few seconds who it is
and its roles, in a Valkey key that expires (internal.Reporter). The controller reads these keys and
keeps what it read here; a process it has not heard of for LOST seconds is shown as lost, then forgotten.
"""

from __future__ import annotations

import os
import socket
import threading
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta

from kube_tower import __version__
from kube_tower.config import ROLES

LOST = 30  # seconds without news before a process is shown as lost
FORGET = 15 * 60  # seconds without news before it is forgotten (e.g. a pod replaced by a rollout)
STARTED = datetime.now(UTC)  # when this process started


def _now() -> datetime:
    return datetime.now(UTC)


def process_name() -> str:
    """The name of this process: its pod name."""
    return os.environ.get("POD_NAME") or socket.gethostname()


@dataclass
class ProcessInfo:
    name: str
    roles: list[str]
    # active (controller holding the Lease), standby (controller waiting for it), ok, lost
    state: str = "ok"
    version: str = ""
    started_at: datetime | None = None
    seen_at: datetime | None = None
    task: str = ""  # kind of the task it runs
    task_since: datetime | None = None

    @property
    def alive(self) -> bool:
        return self.state != "lost"


@dataclass
class Processes:
    """What the controller knows of the processes, itself included. Updated by the internal API, read by
    the pages and by the state sent to the UI processes (in a thread): guarded by a lock."""

    roles: list[str]
    name: str = field(default_factory=process_name)
    others: dict[str, ProcessInfo] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def seen(self, name: str, roles: list[str], state: str = "ok", version: str = "", started_at: datetime | None = None) -> None:
        with self._lock:
            if state == "stopped":  # e.g. replaced by a rollout: gone, not lost
                self.others.pop(name, None)
                return
            known = self.others.get(name)
            if known is None or known.started_at != started_at:  # new, or restarted: no task anymore
                known = self.others[name] = ProcessInfo(name, roles)
            known.roles, known.state, known.version, known.started_at = roles, state, version, started_at
            known.seen_at = _now()

    def task(self, name: str, kind: str = "") -> None:
        """The process got a task (kind) or sent its result (empty)."""
        if not name:
            return
        with self._lock:
            known = self.others.get(name)
            if known is None:
                known = self.others[name] = ProcessInfo(name, [])
            known.seen_at = _now()
            known.task, known.task_since = kind, (_now() if kind else None)

    def list(self, state: str = "active") -> list[ProcessInfo]:
        """This process first (in `state`), then the others by name; lost ones flagged, old ones forgotten."""
        now = _now()
        with self._lock:
            for name in [n for n, p in self.others.items() if p.seen_at and now - p.seen_at > timedelta(seconds=FORGET)]:
                del self.others[name]
            known = sorted(self.others.values(), key=lambda p: p.name)
        me = ProcessInfo(self.name, self.roles, state, __version__, STARTED, now)
        others = []
        for process in known:
            if process.name == self.name:
                continue
            if process.seen_at and now - process.seen_at > timedelta(seconds=LOST):
                process = replace(process, state="lost")
            others.append(process)
        return [me, *others]


@dataclass
class RoleStatus:
    """How a role runs, over the processes: one tile of the Administration page."""

    role: str
    level: str  # ok, warn (some processes lost), error (no process alive runs it)
    summary: str
    pods: int


def roles_status(processes: list[ProcessInfo]) -> list[RoleStatus]:
    statuses = []
    for role in ROLES:
        pods = [p for p in processes if role in p.roles]
        alive = [p for p in pods if p.alive]
        lost = len(pods) - len(alive)
        if role == "controller":
            active = any(p.state == "active" for p in alive)
            standby = sum(p.state == "standby" for p in alive)
            parts = ["active" if active else "no active controller"]
            if standby:
                parts.append(f"{standby} standby")
            healthy = active
        else:
            parts = [f"{len(alive)} pod{'s' if len(alive) != 1 else ''}" if alive else "no pod"]
            healthy = bool(alive)
        if lost:
            parts.append(f"{lost} lost")
        statuses.append(RoleStatus(role, "error" if not healthy else "warn" if lost else "ok", ", ".join(parts), len(pods)))
    return statuses
