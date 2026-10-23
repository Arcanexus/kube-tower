"""Runs a full scan (discover clusters, collect, check) and keeps the last result in memory.

kube-tower is stateless: the latest Snapshot only lives in memory and is rebuilt
periodically and at startup. Scans run in a dedicated worker thread with its own event
loop and each cluster is collected in its own thread, so the web server (UI, API,
/healthz) stays responsive while a scan is running.
"""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial

import httpx

from kube_tower.checkers import ChartChecker, ImageChecker
from kube_tower.clusters import Cluster, ClusterRegistry
from kube_tower.collectors.helm import collect_charts
from kube_tower.collectors.images import ImageInventory
from kube_tower.collectors.vulnerabilities import collect_operator_reports, pick_report
from kube_tower.config import Settings
from kube_tower.models import ImageRef, ImageReport, Snapshot, Status, VulnerabilityReport
from kube_tower.registry.auth import resolve_credentials
from kube_tower.registry.helm import HelmClient
from kube_tower.registry.oci import OCIClient
from kube_tower.registry.transport import RetryingClient
from kube_tower.trivy import TrivyScanner

log = logging.getLogger(__name__)


async def run_in_thread[T](name: str, fn: Callable[[], T]) -> T:
    """Run `fn` in a new daemon thread and await its result from the calling event loop.

    Unlike `asyncio.to_thread`, a daemon thread never delays the process shutdown.
    """
    loop = asyncio.get_running_loop()
    future: asyncio.Future[T] = loop.create_future()

    def settle(result: T | None, error: BaseException | None) -> None:
        if future.done():  # cancelled meanwhile (shutdown)
            return
        if error is not None:
            future.set_exception(error)
        else:
            future.set_result(result)

    def work() -> None:
        try:
            result, error = fn(), None
        except BaseException as exc:  # noqa: BLE001 - handed over to the awaiting loop
            result, error = None, exc
        with contextlib.suppress(RuntimeError):  # awaiting loop already closed
            loop.call_soon_threadsafe(settle, result, error)

    threading.Thread(target=work, name=name, daemon=True).start()
    return await future


async def _log_response(response: httpx.Response) -> None:
    """Every registry / Helm repository / git request, at DEBUG level (no headers: they hold credentials)."""
    request = response.request
    log.debug("%s %s -> %s", request.method, request.url.copy_with(query=None), response.status_code)


def check_errors(snap: Snapshot) -> list[str]:
    """Version check failures, listed with the collection errors in the scan errors."""
    errors = [f"image {r.image}: {r.message}" for r in snap.images if r.status == Status.ERROR]
    for c in snap.charts:
        if c.status == Status.ERROR:
            errors.append(f"[{c.cluster}] chart {c.chart} of application {c.application}: {c.message}")
        errors += [
            f"[{c.cluster}] subchart {d.name} {d.version} of application {c.application}: {d.message}"
            for top in c.dependencies
            for _, d in top.walk()
            if d.status == Status.ERROR
        ]
    return errors


class Scanner:
    def __init__(self, settings: Settings, registry: ClusterRegistry | None = None):
        self.settings = settings
        self.registry = registry or ClusterRegistry(settings.clusters)
        self.snapshot = Snapshot()
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None
        self.scans_total = {"success": 0, "failure": 0}  # exported as kube_tower_scans_total
        # Keeps its results between scans; registry credentials are set at each scan.
        self.trivy = TrivyScanner(settings.vulnerabilities.trivy, {})

    @property
    def running(self) -> bool:
        return self._lock.locked()

    async def scan(self) -> Snapshot:
        async with self._lock:
            snap = await run_in_thread("scanner", lambda: asyncio.run(self._scan()))
            # Versions are shown as soon as they are checked, vulnerabilities fill in afterwards.
            self.snapshot = snap
            if self.settings.vulnerabilities.enabled:
                await run_in_thread("trivy", lambda: asyncio.run(self._scan_vulnerabilities(snap)))
            return snap

    async def _scan(self) -> Snapshot:
        """The scan itself, run in the worker thread's event loop."""
        snap = Snapshot(started_at=datetime.now(UTC))
        log.info("scan started")
        clusters, snap.clusters = await asyncio.to_thread(self.registry.discover)
        reachable = {s.name for s in snap.clusters if s.reachable}
        clusters = [c for c in clusters if c.name in reachable]
        log.info("%d cluster(s) to scan: %s", len(clusters), ", ".join(c.name for c in clusters) or "none")

        inventory = ImageInventory(self.settings.images)
        vuln = self.settings.vulnerabilities
        read_operator = self.settings.images.enabled and vuln.enabled and vuln.trivy_operator

        def collect(cluster: Cluster):
            charts, errors, operator_reports = [], [], []
            if self.settings.images.enabled:
                errors += inventory.collect(cluster)
            if self.settings.helm.enabled:
                charts, chart_errors = collect_charts(cluster, self.settings.helm)
                errors += chart_errors
            if read_operator:
                operator_reports, operator_errors = collect_operator_reports(cluster)
                errors += operator_errors
            return charts, errors, operator_reports

        # One thread per cluster: a slow or large cluster does not hold back the others.
        results = await asyncio.gather(*(run_in_thread(f"scan-{c.name}", partial(collect, c)) for c in clusters))
        operator_reports: dict[str, list[VulnerabilityReport]] = {}
        for charts, errors, reports in results:
            snap.charts += charts
            snap.errors += errors
            for key, report in reports:
                operator_reports.setdefault(str(key), []).append(report)
        snap.images = sorted(inventory.reports.values(), key=lambda r: str(r.image))
        log.info("collection done: %d distinct image(s), %d Helm chart(s)", len(snap.images), len(snap.charts))
        attach_operator_reports(snap.images, operator_reports)

        reg = self.settings.registries
        hooks = {"response": [_log_response]}
        async with RetryingClient(
            timeout=reg.timeout, headers={"User-Agent": "kube-tower"}, event_hooks=hooks, retries=reg.retries
        ) as http:
            credentials, _ = resolve_credentials(reg)
            log.info("registry credentials loaded for: %s", ", ".join(sorted(credentials)) or "none (anonymous access)")
            self.trivy.credentials = credentials  # Secrets may have been rotated
            oci = OCIClient(http, credentials, reg.mirrors, self.settings.images.max_tag_pages)
            helm = HelmClient(http, oci, self.settings.git)
            await asyncio.gather(
                ImageChecker(oci, self.settings.images, reg.concurrency).check_all(snap.images),
                ChartChecker(helm, self.settings.helm, reg.concurrency).check_all(snap.charts),
            )
        snap.charts.sort(key=lambda c: (c.cluster, c.application, c.chart))
        snap.errors += check_errors(snap)
        snap.finished_at = datetime.now(UTC)
        log.info(
            "scan finished in %.1fs: %d clusters, %d images, %d charts, %d errors",
            (snap.finished_at - snap.started_at).total_seconds(),
            len(clusters),
            len(snap.images),
            len(snap.charts),
            len(snap.errors),
        )
        return snap

    async def _scan_vulnerabilities(self, snap: Snapshot) -> None:
        """Scan with Trivy the images without a Trivy Operator report, run in a worker thread's event loop."""
        settings = self.settings.vulnerabilities
        todo = [r for r in snap.images if r.vulnerabilities is None and not vulnerabilities_ignored(r.image, settings.ignore)]
        if todo and settings.trivy.enabled:
            if self.trivy.available:
                snap.errors += await self.trivy.scan_all(todo)
            else:
                message = f"trivy binary {settings.trivy.binary!r} not found (Helm chart: set trivy.enabled=true)"
                log.warning("vulnerability scan skipped: %s", message)
                for r in todo:
                    r.vulnerabilities = VulnerabilityReport("trivy", message=message)
        snap.vulnerabilities_finished_at = datetime.now(UTC)
        scanned = sum(1 for r in snap.images if r.vulnerabilities and not r.vulnerabilities.message)
        log.info("vulnerability scan finished: %d/%d images with a report", scanned, len(snap.images))

    def trigger(self) -> bool:
        """Start a scan in the background unless one is already running."""
        if self.running:
            return False
        self._task = asyncio.create_task(self._safe_scan())
        return True

    async def _safe_scan(self) -> None:
        try:
            await self.scan()
            self.scans_total["success"] += 1
        except Exception:  # noqa: BLE001 - keep the previous snapshot and the loop alive
            self.scans_total["failure"] += 1
            log.exception("scan failed")

    async def run_forever(self) -> None:
        while True:
            await self._safe_scan()
            await asyncio.sleep(self.settings.refresh_interval)


def vulnerabilities_ignored(image: ImageRef, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(image.name, p) or fnmatch.fnmatch(str(image), p) for p in patterns)


def attach_operator_reports(images: list[ImageReport], reports: dict[str, list[VulnerabilityReport]]) -> None:
    """Give each image the Trivy Operator report of its reference (all clusters together)."""
    for image in images:
        if candidates := reports.get(str(image.image)):
            image.vulnerabilities = pick_report(candidates, image.running_digests)
