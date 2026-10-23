import asyncio

import pytest

from kube_tower import scanner as scanner_module
from kube_tower.clusters import Cluster
from kube_tower.config import Settings
from kube_tower.models import ChartReport, ClusterStatus, Status, Usage
from kube_tower.scanner import Scanner


class FakeRegistry:
    def discover(self):
        clusters = [Cluster("up", "https://up", "in-cluster", None), Cluster("down", "https://down", "secret", None)]
        return clusters, [
            ClusterStatus("up", "https://up", "in-cluster", True),
            ClusterStatus("down", "https://down", "secret", False),
        ]


@pytest.fixture
def fakes(monkeypatch):
    scanned = []

    def collect(self, cluster):
        scanned.append(cluster.name)
        self.add("nginx:1.25", Usage(cluster.name, "Pod", "default", "web"))
        return ["[up] cannot list StatefulSet: 403 Forbidden"]

    def collect_charts(cluster, settings):
        return [ChartReport(cluster.name, "app", "argocd", "app", "https://charts.example.com", "1.0.0", "helm")], []

    async def check_images(self, reports):
        for r in reports:
            r.status = Status.OUTDATED

    async def check_charts(self, reports):
        for r in reports:
            r.status = Status.UP_TO_DATE

    monkeypatch.setattr(scanner_module.ImageInventory, "collect", collect)
    monkeypatch.setattr(scanner_module, "collect_charts", collect_charts)
    monkeypatch.setattr(scanner_module.ImageChecker, "check_all", check_images)
    monkeypatch.setattr(scanner_module.ChartChecker, "check_all", check_charts)
    return scanned


async def test_scan_only_reachable_clusters(fakes):
    scanner = Scanner(Settings(), FakeRegistry())
    snap = await scanner.scan()
    assert fakes == ["up"]
    assert [str(i.image) for i in snap.images] == ["docker.io/library/nginx:1.25"]
    assert snap.images[0].status == Status.OUTDATED
    assert snap.charts[0].status == Status.UP_TO_DATE
    assert snap.errors == ["[up] cannot list StatefulSet: 403 Forbidden"]
    assert snap.finished_at >= snap.started_at
    assert scanner.snapshot is snap


async def test_trigger_runs_once_at_a_time(fakes):
    scanner = Scanner(Settings(), FakeRegistry())
    assert scanner.trigger() is True
    await asyncio.sleep(0)
    assert scanner.running and scanner.trigger() is False
    await scanner._task
    assert scanner.snapshot.finished_at is not None


async def test_failed_scan_keeps_previous_snapshot():
    class Broken:
        def discover(self):
            raise RuntimeError("boom")

    scanner = Scanner(Settings(), Broken())
    previous = scanner.snapshot
    await scanner._safe_scan()
    assert scanner.snapshot is previous and not scanner.running


async def test_run_forever_loops(monkeypatch, fakes):
    settings = Settings()
    settings.refresh_interval = 0
    scanner = Scanner(settings, FakeRegistry())
    calls = []
    original = scanner._safe_scan

    async def counting():
        calls.append(1)
        await original()
        if len(calls) == 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(scanner, "_safe_scan", counting)
    with pytest.raises(asyncio.CancelledError):
        await scanner.run_forever()
    assert len(calls) == 2
