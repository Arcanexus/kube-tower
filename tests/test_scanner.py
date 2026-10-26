import asyncio
import logging
import threading
import time
from datetime import UTC, datetime

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


async def _rescanned(scanner):
    """Wait for the background rescans of the scanner."""
    await asyncio.gather(*scanner._rescans)
    assert not scanner.rescanning


def _snapshot_scanner(settings=None):
    scanner = Scanner(settings or Settings(), FakeRegistry())
    image = ImageReport(
        ImageRef("docker.io", "library/nginx", "1.25"),
        [Usage("up", "Pod", "default", "web")],
        status=Status.ERROR,
        message="timeout",
        latest_tag="1.26",
    )
    chart = ChartReport(
        "up", "app", "argocd", "app", "https://charts.example.com", "1.0.0", "helm", status=Status.ERROR, message="boom"
    )
    scanner.snapshot = Snapshot(images=[image], charts=[chart], errors=["[up] cannot list StatefulSet: 403 Forbidden"])
    scanner.snapshot.errors += scanner_module.check_errors(scanner.snapshot)
    return scanner, image, chart


async def test_rescan_image_version(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="kube_tower")
    threads = []

    async def check(self, report):
        threads.append(threading.current_thread().name)
        assert report.latest_tag is None  # starts from a clean report
        report.status, report.latest_tag = Status.OUTDATED, "1.27"

    monkeypatch.setattr(scanner_module.ImageChecker, "check", check)
    scanner, image, _ = _snapshot_scanner()
    assert scanner.rescan_image(image, vulnerabilities=False) is None
    assert scanner.rescanning == {("image", "docker.io/library/nginx:1.25")}
    assert scanner.rescan_image(image) == "images named docker.io/library/nginx is already being rescanned"
    await _rescanned(scanner)
    assert threads == ["rescan"]
    assert (image.status, image.latest_tag, image.message) == (Status.OUTDATED, "1.27", None)
    assert image.vulnerabilities is None
    # the old check error is gone, the collection errors are kept
    assert scanner.snapshot.errors == ["[up] cannot list StatefulSet: 403 Forbidden", "[up] chart app of application app: boom"]
    assert "rescan of image docker.io/library/nginx:1.25: outdated (latest 1.27)" in caplog.text


async def test_rescan_refused_during_a_scan():
    scanner, image, chart = _snapshot_scanner()
    async with scanner._lock:
        assert scanner.rescan_image(image) == "a scan is running, it checks everything again"
        assert scanner.rescan_chart(chart) == "a scan is running, it checks everything again"
    assert not scanner.rescanning


async def test_rescan_failure_keeps_the_report(monkeypatch, caplog):
    async def check(self, report):
        raise RuntimeError("bug")

    monkeypatch.setattr(scanner_module.ImageChecker, "check", check)
    scanner, image, _ = _snapshot_scanner()
    scanner.rescan_image(image, vulnerabilities=False)
    await _rescanned(scanner)
    assert (image.status, image.latest_tag) == (Status.ERROR, "1.26")
    assert "rescan of images named docker.io/library/nginx failed" in caplog.text


async def test_rescan_chart(monkeypatch):
    async def check(self, report):
        assert report.dependencies == [] and report.latest_version is None
        report.chart = "renamed"  # e.g. git charts get the name of their Chart.yaml
        report.version, report.status, report.latest_version = "1.0.1", Status.OUTDATED, "2.0.0"
        report.dependencies = [ChartDependency("common", "1.0.0", "https://charts.example.com", Status.UP_TO_DATE)]

    monkeypatch.setattr(scanner_module.ChartChecker, "check", check)
    scanner, _, chart = _snapshot_scanner()
    assert scanner.rescan_chart(chart) is None
    assert scanner.rescanning == {("chart", "up", "argocd", "app", "app")}
    await _rescanned(scanner)
    assert (chart.chart, chart.version, chart.status, chart.latest_version, chart.message) == (
        "app",
        "1.0.1",
        Status.OUTDATED,
        "2.0.0",
        None,
    )
    assert [d.name for d in chart.dependencies] == ["common"]
    assert "[up] chart app of application app: boom" not in scanner.snapshot.errors


def test_can_rescan_vulnerabilities():
    settings = Settings()
    scanner, image, _ = _snapshot_scanner(settings)
    assert scanner.can_rescan_vulnerabilities(image)
    settings.vulnerabilities.ignore = ["docker.io/library/nginx*"]
    assert not scanner.can_rescan_vulnerabilities(image)
    assert scanner.rescan_image(image, versions=False).startswith("nothing to rescan")
    settings.vulnerabilities.ignore = []
    settings.vulnerabilities.trivy.enabled = False
    assert not scanner.can_rescan_vulnerabilities(image)
    image.vulnerabilities = VulnerabilityReport("trivy-operator")
    assert scanner.can_rescan_vulnerabilities(image)  # its report is read again from the clusters
    settings.vulnerabilities.enabled = False
    assert not scanner.can_rescan_vulnerabilities(image)


async def test_rescan_vulnerabilities_with_trivy(monkeypatch):
    scans = []

    async def prepare(self):
        return None

    async def scan(self, report):
        scans.append(str(report.image))
        return VulnerabilityReport("trivy", vulnerabilities=[Vulnerability("CVE-1", Severity.HIGH, "zlib", "1")])

    monkeypatch.setattr(scanner_module.TrivyScanner, "available", True)
    monkeypatch.setattr(scanner_module.TrivyScanner, "prepare", prepare)
    monkeypatch.setattr(scanner_module.TrivyScanner, "scan", scan)
    scanner, image, _ = _snapshot_scanner()
    cached = VulnerabilityReport("trivy", datetime.now(UTC))
    scanner.trivy.cache["docker.io/library/nginx:1.25"] = image.vulnerabilities = cached
    scanner.rescan_image(image, versions=False)
    await _rescanned(scanner)
    assert scans == ["docker.io/library/nginx:1.25"]  # the cached result is not reused
    assert image.vulnerabilities.vulnerabilities[0].id == "CVE-1"
    assert scanner.trivy.cache["docker.io/library/nginx:1.25"] is image.vulnerabilities
    assert image.status == Status.ERROR  # version not checked


async def test_rescan_vulnerabilities_errors(monkeypatch):
    scanner, image, _ = _snapshot_scanner()
    monkeypatch.setattr(scanner_module.TrivyScanner, "available", False)
    await scanner._rescan_vulnerabilities([image])
    assert "not found" in image.vulnerabilities.message

    async def prepare(self):
        return "cannot download the Trivy database: 403"

    monkeypatch.setattr(scanner_module.TrivyScanner, "available", True)
    monkeypatch.setattr(scanner_module.TrivyScanner, "prepare", prepare)
    await scanner._rescan_vulnerabilities([image])
    assert image.vulnerabilities.message == "cannot download the Trivy database: 403"
    scanner.settings.vulnerabilities.trivy.enabled = False
    image.vulnerabilities = current = VulnerabilityReport("trivy")
    await scanner._rescan_vulnerabilities([image])
    assert image.vulnerabilities is current


async def test_rescan_vulnerabilities_from_trivy_operator(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="kube_tower")
    newer = VulnerabilityReport(
        "trivy-operator", datetime.now(UTC), vulnerabilities=[Vulnerability("CVE-2", Severity.LOW, "curl", "7")]
    )
    other = VulnerabilityReport("trivy-operator")
    listed = []

    def collect(cluster):
        listed.append(cluster.name)
        reports = [(ImageRef("docker.io", "library/nginx", "1.25"), newer), (ImageRef("docker.io", "library/redis", "7"), other)]
        return reports, ["[up] cannot list VulnerabilityReports: 500 boom"]

    monkeypatch.setattr(scanner_module, "collect_operator_reports", collect)
    scanner, image, _ = _snapshot_scanner()
    scanner._clusters = {"up": Cluster("up", "https://up", "in-cluster", None)}
    image.vulnerabilities = VulnerabilityReport("trivy-operator")
    tag = ImageReport(ImageRef("docker.io", "library/nginx", "1.26"), [Usage("up", "Node", None, "n1")])
    await scanner._rescan_vulnerabilities([image, tag])
    assert listed == ["up"] and "cannot list VulnerabilityReports" in caplog.text  # once for both images
    assert image.vulnerabilities is newer
    assert "not found" in tag.vulnerabilities.message  # no operator report: Trivy (not installed here)
    # report gone from the clusters: scanned with Trivy instead
    monkeypatch.setattr(scanner_module, "collect_operator_reports", lambda cluster: ([], []))
    monkeypatch.setattr(scanner_module.TrivyScanner, "available", False)
    await scanner._rescan_vulnerabilities([image])
    assert image.vulnerabilities.source == "trivy" and "no Trivy Operator report left" in caplog.text


async def test_scan_remembers_the_reachable_clusters(fakes):
    scanner = Scanner(Settings(), FakeRegistry())
    await scanner.scan()
    assert list(scanner._clusters) == ["up"]


async def test_retry_failed(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="kube_tower")
    checked, scanned = [], []

    async def check_images(self, reports):
        for r in reports:
            checked.append(str(r.image))
            assert r.message is None  # starts from clean reports
            r.status, r.latest_tag = Status.OUTDATED, "1.27"

    async def check_charts(self, reports):
        for r in reports:
            checked.append(r.chart)
            r.status, r.latest_version = Status.UP_TO_DATE, "1.0.0"

    async def scan_many(self, reports):
        scanned.extend(str(r.image) for r in reports)
        for r in reports:
            r.vulnerabilities = VulnerabilityReport("trivy", datetime.now(UTC))
        return []

    monkeypatch.setattr(scanner_module.ImageChecker, "check_all", check_images)
    monkeypatch.setattr(scanner_module.ChartChecker, "check_all", check_charts)
    monkeypatch.setattr(scanner_module.TrivyScanner, "available", True)
    monkeypatch.setattr(scanner_module.TrivyScanner, "scan_many", scan_many)
    scanner, image, chart = _snapshot_scanner()
    ok = ImageReport(ImageRef("ghcr.io", "org/app", "1"), status=Status.UP_TO_DATE)
    ok.vulnerabilities = VulnerabilityReport("trivy", message="registry denied")
    scanner.snapshot.images.append(ok)
    images, vulnerabilities, charts = scanner.failed_items()
    assert (images, vulnerabilities, charts) == ([image], [ok], [chart])

    assert scanner.retry_failed() is None
    assert scanner.rescanning == {
        scanner_module.RETRY_KEY,
        ("image", "docker.io/library/nginx:1.25"),
        ("image", "ghcr.io/org/app:1"),
        ("chart", "up", "argocd", "app", "app"),
    }
    assert scanner.retry_failed() == "3 of these items are already being rescanned"
    assert scanner.rescan_image(image).endswith("already being rescanned")
    await _rescanned(scanner)
    assert checked == ["docker.io/library/nginx:1.25", "app"]  # only what failed
    assert scanned == ["ghcr.io/org/app:1"]
    assert (image.status, image.latest_tag, chart.status, chart.message) == (Status.OUTDATED, "1.27", Status.UP_TO_DATE, None)
    assert scanner.failed_items() == ([], [], [])
    assert scanner.snapshot.errors == ["[up] cannot list StatefulSet: 403 Forbidden"]
    assert "retry done: still failing 0 image version check(s), 0 vulnerability scan(s), 0 chart(s)" in caplog.text
    assert scanner.retry_failed() == "nothing failed in the last scan"


async def test_retry_failed_subchart_errors_and_no_trivy(monkeypatch, caplog):
    async def check_all(self, reports):
        return None

    monkeypatch.setattr(scanner_module.ImageChecker, "check_all", check_all)
    monkeypatch.setattr(scanner_module.ChartChecker, "check_all", check_all)
    monkeypatch.setattr(scanner_module.TrivyScanner, "available", False)
    scanner, image, chart = _snapshot_scanner()
    chart.status = Status.UP_TO_DATE
    chart.dependencies = [ChartDependency("common", "1.0.0", "https://x", Status.ERROR, message="404")]
    image.vulnerabilities = VulnerabilityReport("trivy", message="boom")
    assert scanner.failed_items() == ([image], [image], [chart])
    assert scanner.retry_failed() is None
    await _rescanned(scanner)
    assert "vulnerability scans not retried: trivy binary 'trivy' not found" in caplog.text


async def test_exclusive_blocks_scans_and_rescans():
    scanner, image, _ = _snapshot_scanner()
    async with scanner.exclusive("the Trivy database is being updated"):
        assert scanner.locked and not scanner.running  # not shown as a scan
        assert not scanner.trigger()
        assert scanner.rescan_image(image) == "the Trivy database is being updated: try again when it is over"
        assert scanner.retry_failed() == "the Trivy database is being updated: try again when it is over"
    assert scanner.busy is None and not scanner.locked


async def test_version_rescan_covers_every_image_with_the_name(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="kube_tower")
    listed = []

    async def list_tags(self, registry, repository):
        listed.append(repository)
        return ["1.25", "1.26", "1.27"]

    monkeypatch.setattr(scanner_module.OCIClient, "list_tags", list_tags)
    settings = Settings()
    settings.images.fetch_tag_digests = False
    scanner = Scanner(settings, FakeRegistry())
    nginx = [
        ImageReport(ImageRef("docker.io", "library/nginx", "1.25"), [Usage("up", "Pod", "default", "web")]),
        ImageReport(ImageRef("docker.io", "library/nginx", "1.27"), [Usage("up", "Node", None, "n1")]),  # node only
    ]
    redis = ImageReport(ImageRef("docker.io", "library/redis", "7"), status=Status.ERROR, message="timeout")
    scanner.snapshot = Snapshot(images=[*nginx, redis])
    assert scanner.same_name_images(nginx[0]) == nginx
    assert scanner.rescan_image(nginx[0], vulnerabilities=False) is None
    assert scanner.rescanning == {("image", "docker.io/library/nginx:1.25"), ("image", "docker.io/library/nginx:1.27")}
    assert scanner.rescan_image(nginx[1]) == "1 image(s) named docker.io/library/nginx are already being rescanned"
    await _rescanned(scanner)
    assert [(r.status, r.latest_tag) for r in nginx] == [(Status.OUTDATED, "1.27"), (Status.UP_TO_DATE, "1.27")]
    assert listed == ["library/nginx"]  # one tag list for both
    assert (redis.status, redis.message) == (Status.ERROR, "timeout")  # other names untouched
    assert "rescan of docker.io/library/nginx: checking the version of 2 image(s): 1.25, 1.27" in caplog.text


async def test_version_rescan_refused_while_an_image_with_the_name_is_rescanned():
    scanner = Scanner(Settings(), FakeRegistry())
    a = ImageReport(ImageRef("docker.io", "library/nginx", "1.25"))
    b = ImageReport(ImageRef("docker.io", "library/nginx", "1.27"))
    scanner.snapshot = Snapshot(images=[a, b])
    scanner.rescanning.add(("image", "docker.io/library/nginx:1.27"))
    assert (
        scanner.rescan_image(a, vulnerabilities=False) == "1 image(s) named docker.io/library/nginx are already being rescanned"
    )
    # the vulnerability scan alone only concerns this image
    assert scanner.same_name_images(ImageReport(ImageRef("ghcr.io", "o/x", "1"))) == [
        ImageReport(ImageRef("ghcr.io", "o/x", "1"))
    ]


async def test_rescan_finds_the_new_images_with_the_name(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="kube_tower")

    def collect(self, cluster):
        self.add("nginx:1.25", Usage(cluster.name, "Pod", "default", "web"), "sha256:new-pod")
        self.add("nginx:1.28", Usage(cluster.name, "Pod", "default", "canary"))  # deployed since the last scan
        self.add("redis:8", Usage(cluster.name, "Pod", "default", "cache"))  # another name: ignored
        return ["[up] cannot list CronJob: 403 Forbidden"]

    def broken(self, cluster):
        raise RuntimeError("unreachable")

    checked, scanned = [], []

    async def check(self, report):
        checked.append(str(report.image))
        report.status = Status.UP_TO_DATE

    async def scan_many(self, reports):
        scanned.extend(str(r.image) for r in reports)
        for r in reports:
            r.vulnerabilities = VulnerabilityReport("trivy", datetime.now(UTC))
        return []

    monkeypatch.setattr(scanner_module.ImageInventory, "collect", collect)
    monkeypatch.setattr(scanner_module.ImageChecker, "check", check)
    monkeypatch.setattr(scanner_module.TrivyScanner, "available", True)
    monkeypatch.setattr(scanner_module.TrivyScanner, "scan_many", scan_many)
    monkeypatch.setattr(scanner_module, "collect_operator_reports", lambda cluster: ([], []))
    scanner, image, _ = _snapshot_scanner()
    scanner._clusters = {"up": Cluster("up", "https://up", "in-cluster", None)}
    old = ImageReport(ImageRef("docker.io", "library/nginx", "1.20"), [Usage("up", "Node", None, "n1")])
    scanner.snapshot.images.append(old)
    scanner.trivy.cache["docker.io/library/nginx:1.25"] = VulnerabilityReport("trivy", datetime.now(UTC))

    # vulnerabilities only: every tag is scanned, the new one also gets its version checked
    assert scanner.rescan_image(image, versions=False) is None
    await _rescanned(scanner)
    names = [str(r.image) for r in scanner.snapshot.images]
    assert names == ["docker.io/library/nginx:1.20", "docker.io/library/nginx:1.25", "docker.io/library/nginx:1.28"]
    assert checked == ["docker.io/library/nginx:1.28"]
    assert sorted(scanned) == names  # not read from the cache
    assert image.running_digests == {"sha256:new-pod"} and image.usages[0].name == "web"
    assert old.usages == [Usage("up", "Node", None, "n1")]  # not found again: kept until the next full scan
    assert "1 new image(s) found on the clusters: docker.io/library/nginx:1.28" in caplog.text

    # a cluster that fails is logged, the others are still read
    scanner._clusters["down"] = Cluster("down", "https://down", "secret", None)
    monkeypatch.setattr(scanner_module.ImageInventory, "collect", broken)
    checked.clear()
    assert scanner.rescan_image(image, vulnerabilities=False) is None
    await _rescanned(scanner)
    assert sorted(checked) == names
    assert "[down] cannot read the images again: unreachable" in caplog.text


async def test_rescan_without_image_collection(monkeypatch):
    settings = Settings()
    settings.images.enabled = False
    scanner, image, _ = _snapshot_scanner(settings)
    scanner._clusters = {"up": Cluster("up", "https://up", "in-cluster", None)}
    assert await scanner._collect_images_named(scanner.snapshot, image.image.name) == []


async def _until(condition, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        await asyncio.sleep(0.01)


async def test_trivy_phase_has_its_own_lock(fakes, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="kube_tower")
    release = threading.Event()
    scanned: list[Snapshot] = []

    async def scan_vulnerabilities(self, snap):
        scanned.append(snap)
        await asyncio.to_thread(release.wait, 5)

    monkeypatch.setattr(Scanner, "_scan_vulnerabilities", scan_vulnerabilities)
    scanner = Scanner(Settings(), FakeRegistry())
    assert scanner.trigger()
    first = scanner._task
    await _until(lambda: scanned)
    # Trivy phase of the first scan: shown as running, but scans and rescans can start.
    assert scanner.running and scanner.locked and not scanner.checking_versions
    snap1 = scanner.snapshot
    tasks = [first]
    for _ in range(2):  # two more scans: both check their versions, then wait for the Trivy lock
        previous = scanner.snapshot
        assert scanner.trigger()
        tasks.append(scanner._task)
        await _until(lambda previous=previous: scanner.snapshot is not previous and not scanner.checking_versions)
    snap3 = scanner.snapshot
    # An administration action waits for the Trivy phase too.
    entered = []

    async def administration():
        async with scanner.exclusive("the Trivy database is being updated"):
            entered.append(scanner.busy)

    tasks.append(asyncio.create_task(administration()))
    await asyncio.sleep(0.05)
    assert not entered and len(scanned) == 1
    release.set()
    await asyncio.gather(*tasks)
    # The second scan was replaced by the third before its Trivy phase: skipped.
    assert scanned == [snap1, snap3] and entered == ["the Trivy database is being updated"]
    assert "vulnerability scan skipped: a newer scan replaced this one" in caplog.text
    assert scanner.scans_total == {"success": 3, "failure": 0} and not scanner.locked


async def test_activities_list_what_runs(fakes, monkeypatch):
    release = threading.Event()

    async def scan_vulnerabilities(self, snap):
        await asyncio.to_thread(release.wait, 5)

    async def check_all(self, reports):
        await asyncio.to_thread(release.wait, 5)

    async def quick(self, reports):
        return None

    monkeypatch.setattr(Scanner, "_scan_vulnerabilities", scan_vulnerabilities)
    scanner = Scanner(Settings(), FakeRegistry())
    assert scanner.activities() == []
    monkeypatch.setattr(scanner_module.ImageChecker, "check_all", check_all)
    assert scanner.trigger()
    await _until(lambda: scanner.activities())
    [versions] = scanner.activities()
    assert versions.name == "Full scan: clusters and versions" and versions.state == "running" and versions.started_at
    release.set()
    await scanner._task
    release.clear()
    monkeypatch.setattr(scanner_module.ImageChecker, "check_all", quick)
    tasks = []
    for _ in range(2):
        assert scanner.trigger()
        tasks.append(scanner._task)
        await _until(lambda: not scanner.checking_versions and scanner.trivy_started_at)
    await _until(lambda: scanner.trivy_waiting == 1)
    names = [(a.name, a.state) for a in scanner.activities()]
    assert names == [
        ("Full scan: vulnerabilities (Trivy)", "running"),
        ("Full scan: vulnerabilities (Trivy) of 1 newer scan(s)", "waiting"),
    ]
    scanner._rescan_started[("chart", "c")] = ("chart app of application app", datetime.now(UTC))
    assert scanner.activities()[-1].name == "Rescan of chart app of application app"
    release.set()
    await asyncio.gather(*tasks)
    del scanner._rescan_started[("chart", "c")]
    assert scanner.activities() == []


def test_ssl_context_and_ca_bundle(tmp_path, monkeypatch, caplog):
    import certifi

    assert scanner_module.ssl_context("") is True and scanner_module.ca_bundle("") == ""
    ca = tmp_path / "ca.crt"
    ca.write_text(open(certifi.where()).read().split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")
    context = scanner_module.ssl_context(str(ca))
    assert context.cert_store_stats()["x509_ca"] > 1
    monkeypatch.setattr(scanner_module.tempfile, "gettempdir", lambda: str(tmp_path))
    bundle = scanner_module.ca_bundle(str(ca))
    assert open(bundle).read().endswith(ca.read_text())
    assert scanner_module.ca_bundle(str(ca)) == bundle  # unchanged, not written again

    scanner_module.ssl_context(str(tmp_path / "missing.crt"))
    assert scanner_module.ca_bundle(str(tmp_path / "missing.crt")) == ""
    assert "registries.caFile" in caplog.text and "not given to Trivy" in caplog.text


async def test_clients_use_the_registries_settings(monkeypatch):
    settings = Settings()
    settings.registries.insecure = ["registry.local*"]
    settings.registries.docker_config_path = "/none"
    scanner = Scanner(settings, FakeRegistry())
    scanner.pull_secrets = {"harbor.example.com": ("robot", "pw")}
    async with scanner._clients() as (oci, _, credentials):
        assert oci.insecure_http is not None and oci.client_for("registry.local:5000") is oci.insecure_http
        assert await credentials.get("harbor.example.com") == ("robot", "pw")
    assert scanner.trivy.credentials is credentials and scanner.trivy.insecure == ["registry.local*"]
    assert credentials.tokens is scanner.registry_tokens  # cloud tokens are kept between scans
