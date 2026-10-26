import json
import logging
import zlib
from datetime import UTC, datetime, timedelta

import pytest

from kube_tower import store as store_module
from kube_tower.config import Settings
from kube_tower.models import ImageRef, ImageReport, Snapshot, Status, Usage
from kube_tower.scanner import Scanner
from kube_tower.store import MemorySnapshotStore, RedisSnapshotStore, redis_store


class FakeRedis:
    def __init__(self):
        self.data: dict[str, bytes] = {}
        self.fail_reads = self.fail_writes = 0
        self.writes = 0

    def get(self, key):
        if self.fail_reads:
            self.fail_reads -= 1
            raise ConnectionError("connection refused")
        return self.data.get(key)

    def set(self, key, value):
        if self.fail_writes:
            self.fail_writes -= 1
            raise ConnectionError("connection refused")
        self.writes += 1
        self.data[key] = value


def _snapshot(tag="1.25"):
    report = ImageReport(ImageRef("docker.io", "library/nginx", tag), [Usage("c1", "Pod", "default", "web", "nginx")])
    report.status = Status.OUTDATED
    return Snapshot(images=[report], finished_at=datetime.now(UTC))


def _stored(fake, key="kube-tower:snapshot"):
    return Snapshot.from_dict(json.loads(zlib.decompress(fake.data[key])))


def test_memory_store():
    store = MemorySnapshotStore()
    snap = _snapshot()
    store.set(snap)
    store.changed()
    store.load()
    assert store.get() is snap


def test_redis_store_writes_and_reads_back(caplog):
    caplog.set_level(logging.INFO)
    fake = FakeRedis()
    store = RedisSnapshotStore(fake, "kube-tower:snapshot")
    store.load()
    assert store.get().finished_at is None and "no snapshot in Redis" in caplog.text
    store.set(_snapshot())
    assert store.flush(5)
    assert str(_stored(fake).images[0].image) == "docker.io/library/nginx:1.25"
    store.get().images[0].latest_tag = "1.27"  # changed in place, e.g. by a rescan
    store.changed()
    assert store.flush(5)
    assert _stored(fake).images[0].latest_tag == "1.27"

    again = RedisSnapshotStore(fake, "kube-tower:snapshot")  # a standby
    assert again.get().images == []  # read when it becomes the active controller only
    again.load()
    assert again.get().images[0].latest_tag == "1.27"
    assert "snapshot read from Redis: 1 images and 0 charts" in caplog.text


def test_redis_store_keeps_the_last_version_only():
    fake = FakeRedis()
    store = RedisSnapshotStore(fake, "k")
    for tag in ("1", "2", "3", "4"):
        store.set(_snapshot(tag))
    assert store.flush(5)
    assert _stored(fake, "k").images[0].image.tag == "4"
    assert fake.writes <= 4


def test_redis_store_survives_errors(monkeypatch, caplog):
    monkeypatch.setattr(store_module, "RETRY", 0.01)
    fake = FakeRedis()
    fake.fail_reads = 1
    store = RedisSnapshotStore(fake, "k")
    store.load()
    assert store.get().images == [] and "cannot read the snapshot from Redis" in caplog.text
    fake.fail_writes = 2
    store.set(_snapshot())
    assert store.flush(5)
    assert "cannot write the snapshot to Redis" in caplog.text
    assert _stored(fake, "k").images

    fake.data["k"] = b"not a snapshot"
    store = RedisSnapshotStore(fake, "k")
    store.load()
    assert store.get().images == []
    assert "cannot decode the snapshot" in caplog.text


def test_flush_times_out_while_redis_is_down(monkeypatch):
    monkeypatch.setattr(store_module, "RETRY", 0.01)
    fake = FakeRedis()
    fake.fail_writes = 10**9
    store = RedisSnapshotStore(fake, "k")
    store.set(_snapshot())
    assert not store.flush(0.05)


def test_redis_store_from_settings(monkeypatch):
    seen = {}

    def from_url(url, **options):
        seen.update(url=url, **options)
        return FakeRedis()

    monkeypatch.setattr(store_module.redis.Redis, "from_url", staticmethod(from_url))
    settings = Settings()
    settings.redis.url = "redis://valkey:6379/0"
    store = redis_store(settings)
    assert isinstance(store, RedisSnapshotStore) and store.key == "kube-tower:snapshot"
    assert seen["url"] == "redis://valkey:6379/0" and "password" not in seen
    monkeypatch.setenv("KUBE_TOWER_REDIS_PASSWORD", "pw")
    redis_store(settings)
    assert seen["password"] == "pw"


async def test_scanner_waits_for_a_recent_stored_snapshot(monkeypatch):
    settings = Settings()
    settings.refresh_interval = 3600
    snap = _snapshot()
    snap.finished_at = datetime.now(UTC) - timedelta(minutes=10)
    scanner = Scanner(settings, store=MemorySnapshotStore(snap))
    slept = []

    async def sleep(seconds):
        slept.append(seconds)
        raise RuntimeError("stop")

    monkeypatch.setattr("kube_tower.scanner.asyncio.sleep", sleep)
    with pytest.raises(RuntimeError):
        await scanner.run_forever()
    assert 2900 < slept[0] <= 3000  # the scan waits for the rest of the interval

    snap.finished_at = datetime.now(UTC) - timedelta(hours=2)  # too old: scanned at once
    scans = []

    async def scan():
        scans.append(True)

    scanner._safe_scan = scan
    slept.clear()
    with pytest.raises(RuntimeError):
        await scanner.run_forever()
    assert scans and slept == [3600]


def test_changes_in_place_reach_the_store():
    class Recording(MemorySnapshotStore):
        calls = 0

        def changed(self):
            self.calls += 1

    store = Recording()
    scanner = Scanner(Settings(), store=store)
    revision = scanner.revision
    scanner._changed()
    assert store.calls == 1 and scanner.revision == revision + 1


def test_controller_uses_redis_when_configured(monkeypatch):
    from kube_tower.main import create_app

    monkeypatch.setattr(store_module.redis.Redis, "from_url", staticmethod(lambda url, **options: FakeRedis()))
    monkeypatch.setenv("KUBE_TOWER_REDIS_URL", "redis://valkey:6379/0")
    monkeypatch.setenv("KUBE_TOWER_CONFIG", "/nonexistent")
    from kube_tower.config import load_settings

    settings = load_settings()
    assert settings.redis.url == "redis://valkey:6379/0"
    app = create_app(settings, background=False)
    assert isinstance(app.state.scanner.store, RedisSnapshotStore)
