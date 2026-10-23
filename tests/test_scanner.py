import asyncio
import logging
import threading
import time

import httpx
import pytest

from kube_tower import scanner as scanner_module
from kube_tower.clusters import Cluster
from kube_tower.config import Settings
from kube_tower.models import (
    ChartDependency,
    ChartReport,
    ClusterStatus,
    ImageRef,
    ImageReport,
    Severity,
    Snapshot,
    Status,
    Usage,
    Vulnerability,
    VulnerabilityReport,
)
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
    monkeypatch.setattr(scanner_module, "collect_operator_reports", lambda cluster: ([], []))
    monkeypatch.setattr(scanner_module.ImageChecker, "check_all", check_images)
    monkeypatch.setattr(scanner_module.ChartChecker, "check_all", check_charts)
    monkeypatch.setattr(scanner_module.TrivyScanner, "available", False)
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
    assert scanner.scans_total == {"success": 1, "failure": 0}


async def test_failed_scan_keeps_previous_snapshot():
    class Broken:
        def discover(self):
            raise RuntimeError("boom")

    scanner = Scanner(Settings(), Broken())
    previous = scanner.snapshot
    await scanner._safe_scan()
    assert scanner.snapshot is previous and not scanner.running
    assert scanner.scans_total == {"success": 0, "failure": 1}


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


async def test_scan_does_not_block_the_web_loop(fakes, monkeypatch):
    threads = []

    async def slow_check(self, reports):
        threads.append(threading.current_thread().name)
        time.sleep(0.5)  # CPU bound / blocking work in the scan

    monkeypatch.setattr(scanner_module.ImageChecker, "check_all", slow_check)
    scanner = Scanner(Settings(), FakeRegistry())
    assert scanner.trigger()
    await asyncio.sleep(0.05)
    # The web server's loop keeps serving while the scan blocks its own loop
    start = time.monotonic()
    for _ in range(10):
        await asyncio.sleep(0.01)
    assert time.monotonic() - start < 0.4
    assert scanner.running
    await scanner._task
    assert threads == ["scanner"] and scanner.snapshot.finished_at is not None


async def test_scan_error_is_raised_in_the_web_loop(monkeypatch):
    class Broken:
        def discover(self):
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await Scanner(Settings(), Broken()).scan()


async def test_one_thread_per_cluster(monkeypatch):
    class TwoClusters:
        def discover(self):
            names = ["a", "b"]
            return [Cluster(n, f"https://{n}", "secret", None) for n in names], [
                ClusterStatus(n, f"https://{n}", "secret", True) for n in names
            ]

    threads = []

    def collect(self, cluster):
        threads.append(threading.current_thread().name)
        time.sleep(0.3)
        self.add("nginx:1.25", Usage(cluster.name, "Pod", "default", "web"))
        return [f"[{cluster.name}] error"]

    async def check_all(self, reports):
        pass

    monkeypatch.setattr(scanner_module.ImageInventory, "collect", collect)
    monkeypatch.setattr(scanner_module, "collect_charts", lambda cluster, settings: ([], []))
    monkeypatch.setattr(scanner_module, "collect_operator_reports", lambda cluster: ([], []))
    monkeypatch.setattr(scanner_module.TrivyScanner, "available", False)
    monkeypatch.setattr(scanner_module.ImageChecker, "check_all", check_all)
    monkeypatch.setattr(scanner_module.ChartChecker, "check_all", check_all)

    start = time.monotonic()
    snap = await Scanner(Settings(), TwoClusters()).scan()
    assert time.monotonic() - start < 0.55  # both clusters collected in parallel
    assert sorted(threads) == ["scan-a", "scan-b"]
    assert snap.errors == ["[a] error", "[b] error"]
    assert snap.images[0].clusters == ["a", "b"]


def test_check_errors():
    image = ImageReport(ImageRef("docker.io", "library/nginx", "1.25"), status=Status.ERROR, message="401 Unauthorized")
    ok = ImageReport(ImageRef("docker.io", "library/redis", "7.2"), status=Status.UP_TO_DATE)
    chart = ChartReport("c1", "app", "argocd", "app", "https://charts.example.com", "1.0.0", "helm")
    chart.status, chart.message = Status.ERROR, "404 Not Found"
    parent = ChartReport("c1", "mon", "argocd", "mon", "https://charts.example.com", "1.0.0", "helm", status=Status.UP_TO_DATE)
    nested = ChartDependency("common", "2.0.0", "https://x", status=Status.ERROR, message="404")
    parent.dependencies = [
        ChartDependency("redis", "18.0.0", "https://x", status=Status.ERROR, message="timeout", dependencies=[nested])
    ]
    assert scanner_module.check_errors(Snapshot(images=[image, ok], charts=[chart, parent])) == [
        "image docker.io/library/nginx:1.25: 401 Unauthorized",
        "[c1] chart app of application app: 404 Not Found",
        "[c1] subchart redis 18.0.0 of application mon: timeout",
        "[c1] subchart common 2.0.0 of application mon: 404",
    ]


async def test_scan_logs_each_step(fakes, caplog):
    caplog.set_level(logging.DEBUG, logger="kube_tower")
    await Scanner(Settings(), FakeRegistry()).scan()
    messages = [(r.levelname, r.getMessage()) for r in caplog.records]
    assert ("INFO", "1 cluster(s) to scan: up") in messages
    assert ("INFO", "collection done: 1 distinct image(s), 1 Helm chart(s)") in messages
    assert ("INFO", "registry credentials loaded for: none (anonymous access)") in messages
    assert any(level == "INFO" and m.startswith("scan finished") for level, m in messages)


async def test_http_requests_logged_without_query(caplog):
    caplog.set_level(logging.DEBUG, logger="kube_tower")
    request = httpx.Request("GET", "https://ghcr.io/token?scope=repository:org/app:pull&service=ghcr.io")
    await scanner_module._log_response(httpx.Response(401, request=request))
    assert caplog.records[-1].getMessage() == "GET https://ghcr.io/token -> 401"


async def test_vulnerabilities_from_operator_then_trivy(fakes, monkeypatch):
    operator = VulnerabilityReport("trivy-operator", vulnerabilities=[Vulnerability("CVE-1", Severity.HIGH, "zlib", "1")])

    def collect(self, cluster):
        self.add("nginx:1.25", Usage(cluster.name, "Pod", "default", "web"))
        self.add("redis:7", Usage(cluster.name, "Pod", "default", "cache"))
        self.add("registry.k8s.io/pause:3.9", Usage(cluster.name, "Node", None, "n1"))
        return []

    scanned = []

    async def scan_all(self, reports):
        scanned.extend(str(r.image) for r in reports)
        for r in reports:
            r.vulnerabilities = VulnerabilityReport("trivy")
        return ["trivy: 1 image scan(s) failed"]

    monkeypatch.setattr(scanner_module.ImageInventory, "collect", collect)
    monkeypatch.setattr(
        scanner_module, "collect_operator_reports", lambda c: ([(ImageRef("docker.io", "library/nginx", "1.25"), operator)], [])
    )
    monkeypatch.setattr(scanner_module.TrivyScanner, "available", True)
    monkeypatch.setattr(scanner_module.TrivyScanner, "scan_all", scan_all)
    settings = Settings()
    settings.vulnerabilities.ignore = ["registry.k8s.io/pause*"]
    snap = await Scanner(settings, FakeRegistry()).scan()
    images = {str(r.image): r for r in snap.images}
    assert images["docker.io/library/nginx:1.25"].vulnerabilities is operator
    assert scanned == ["docker.io/library/redis:7"]  # no operator report, not ignored
    assert images["registry.k8s.io/pause:3.9"].vulnerabilities is None
    assert snap.vulnerabilities_finished_at >= snap.finished_at
    assert "trivy: 1 image scan(s) failed" in snap.errors


async def test_vulnerabilities_without_trivy_binary(fakes):
    snap = await Scanner(Settings(), FakeRegistry()).scan()
    assert snap.images[0].vulnerabilities.message == "trivy binary 'trivy' not found (Helm chart: set trivy.enabled=true)"


async def test_vulnerabilities_disabled(fakes):
    settings = Settings()
    settings.vulnerabilities.enabled = False
    snap = await Scanner(settings, FakeRegistry()).scan()
    assert snap.images[0].vulnerabilities is None and snap.vulnerabilities_finished_at is None
