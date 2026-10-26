"""Where the controller keeps the Snapshot (ADR 0002): in memory by default, Redis / Valkey as an option."""

from __future__ import annotations

from typing import Protocol

from kube_tower.models import Snapshot


class SnapshotStore(Protocol):
    def get(self) -> Snapshot: ...
    def set(self, snapshot: Snapshot) -> None: ...


class MemorySnapshotStore:
    """The Snapshot in the memory of this process: rebuilt by a scan after a restart."""

    def __init__(self, snapshot: Snapshot | None = None):
        self._snapshot = snapshot or Snapshot()

    def get(self) -> Snapshot:
        return self._snapshot

    def set(self, snapshot: Snapshot) -> None:
        self._snapshot = snapshot
