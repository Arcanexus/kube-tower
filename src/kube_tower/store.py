"""Where the controller keeps the Snapshot (ADR 0002): in memory by default, Redis / Valkey as an option."""

from __future__ import annotations

import json
import logging
import os
import threading
import zlib
from typing import Any, Protocol

import redis

from kube_tower.config import Settings
from kube_tower.models import Snapshot

log = logging.getLogger(__name__)

RETRY = 10  # seconds before writing the snapshot to Redis again after an error


class SnapshotStore(Protocol):
    def get(self) -> Snapshot: ...
    def set(self, snapshot: Snapshot) -> None: ...
    def changed(self) -> None:
        """The snapshot was changed in place (a rescan, the Trivy phase of a scan)."""

    def load(self) -> None:
        """Read the stored snapshot, when this process becomes the active controller (blocking)."""


class MemorySnapshotStore:
    """The Snapshot in the memory of this process: rebuilt by a scan after a restart."""

    def __init__(self, snapshot: Snapshot | None = None):
        self._snapshot = snapshot or Snapshot()

    def get(self) -> Snapshot:
        return self._snapshot

    def set(self, snapshot: Snapshot) -> None:
        self._snapshot = snapshot

    def changed(self) -> None:
        pass

    def load(self) -> None:
        pass


class RedisSnapshotStore:
    """The Snapshot in memory, also written to Redis / Valkey: read back when the controller starts (or a
    standby takes over, see election.py), never again after: only the active controller writes it.

    The writes run in a thread of their own, the last version only (a scan changes the snapshot often).
    """

    def __init__(self, redis: Any, key: str):
        self.redis, self.key = redis, key
        self._snapshot = Snapshot()
        self._wanted = self._written = 0  # versions of the snapshot asked to be written, and written
        self._cond = threading.Condition()
        threading.Thread(target=self._write_loop, name="redis-store", daemon=True).start()

    def _load(self) -> Snapshot:
        try:
            raw = self.redis.get(self.key)
        except Exception as exc:  # noqa: BLE001 - starts empty, a scan fills it
            log.warning("cannot read the snapshot from Redis (%s): starting with an empty one", exc)
            return Snapshot()
        if raw is None:
            log.info("no snapshot in Redis at %s yet: starting with an empty one", self.key)
            return Snapshot()
        try:
            snapshot = Snapshot.from_dict(json.loads(zlib.decompress(raw)))
        except Exception as exc:  # noqa: BLE001 - e.g. written by another version of kube-tower
            log.warning("cannot decode the snapshot read from Redis at %s (%s): starting with an empty one", self.key, exc)
            return Snapshot()
        log.info(
            "snapshot read from Redis: %d images and %d charts, scanned at %s",
            len(snapshot.images),
            len(snapshot.charts),
            snapshot.finished_at,
        )
        return snapshot

    def load(self) -> None:
        self._snapshot = self._load()

    def get(self) -> Snapshot:
        return self._snapshot

    def set(self, snapshot: Snapshot) -> None:
        self._snapshot = snapshot
        self.changed()

    def changed(self) -> None:
        with self._cond:
            self._wanted += 1
            self._cond.notify_all()

    def flush(self, timeout: float | None = None) -> bool:
        """Wait until the last change is written. Whether it was in time."""
        with self._cond:
            wanted = self._wanted
            return self._cond.wait_for(lambda: self._written >= wanted, timeout)

    def _write_loop(self) -> None:
        while True:
            with self._cond:
                self._cond.wait_for(lambda: self._wanted > self._written)
                version = self._wanted
            try:
                data = zlib.compress(json.dumps(self._snapshot.to_dict()).encode())
                self.redis.set(self.key, data)
            except Exception as exc:  # noqa: BLE001 - written again at the next change, or after RETRY
                log.warning("cannot write the snapshot to Redis (%s): trying again in %ss", exc, RETRY)
                with self._cond:
                    self._cond.wait(RETRY)
                continue
            with self._cond:
                self._written = version
                self._cond.notify_all()


def redis_store(settings: Settings) -> RedisSnapshotStore:
    """The store of settings.redis (redis.url set)."""
    options: dict[str, Any] = {"socket_timeout": 10, "socket_connect_timeout": 10}
    if password := os.environ.get(settings.redis.password_env):
        options["password"] = password  # a password in the URL wins
    return RedisSnapshotStore(redis.Redis.from_url(settings.redis.url, **options), settings.redis.key)
