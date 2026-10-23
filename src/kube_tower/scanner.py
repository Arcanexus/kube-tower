"""Runs a full scan (discover clusters, collect, check) and keeps the last result in memory.

kube-tower is stateless: the latest Snapshot only lives in memory and is rebuilt
periodically and at startup. Scans run in a dedicated worker thread with its own event
loop and each cluster is collected in its own thread, so the web server (UI, API,
/healthz) stays responsive while a scan is running.

One image or chart can also be rescanned on its own (from the UI or the API): its report is
checked again in a worker thread and updated in place in the current Snapshot.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import fnmatch
import logging
import threading
from collections.abc import AsyncIterator, Callable, Coroutine
from datetime import UTC, datetime
from functools import partial

import httpx

from kube_tower.checkers import ChartChecker, ImageChecker
from kube_tower.clusters import Cluster, ClusterRegistry
from kube_tower.collectors.helm import collect_charts
from kube_tower.collectors.images import ImageInventory
from kube_tower.collectors.vulnerabilities import collect_operator_reports, pick_report
from kube_tower.config import Settings
from kube_tower.models import ChartReport, ImageRef, ImageReport, Snapshot, Status, VulnerabilityReport
from kube_tower.registry.auth import resolve_credentials
from kube_tower.registry.helm import HelmClient
from kube_tower.registry.oci import OCIClient
from kube_tower.trivy import TrivyScanner, scan_target

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
        # Keys (see image_key / chart_key) of the images and charts being rescanned on their own.
        self.rescanning: set[tuple] = set()
        self._rescans: set[asyncio.Task] = set()  # keeps the background rescans referenced
        self._clusters: dict[str, Cluster] = {}  # reachable clusters of the last scan, by name

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
        self._clusters = {c.name: c for c in clusters}
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

        async with self._clients() as (oci, helm, credentials):
            log.info("registry credentials loaded for: %s", ", ".join(sorted(credentials)) or "none (anonymous access)")
            concurrency = self.settings.registries.concurrency
            await asyncio.gather(
                ImageChecker(oci, self.settings.images, concurrency).check_all(snap.images),
                ChartChecker(helm, self.settings.helm, concurrency).check_all(snap.charts),
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

    @contextlib.asynccontextmanager
    async def _clients(self) -> AsyncIterator[tuple[OCIClient, HelmClient, dict[str, tuple[str, str]]]]:
        """Registry and Helm repository clients, with the registry credentials read again (Secrets may have been rotated)."""
        reg = self.settings.registries
        hooks = {"response": [_log_response]}
        async with httpx.AsyncClient(timeout=reg.timeout, headers={"User-Agent": "kube-tower"}, event_hooks=hooks) as http:
            credentials, _ = resolve_credentials(reg)
            self.trivy.credentials = credentials
            oci = OCIClient(http, credentials, reg.mirrors, self.settings.images.max_tag_pages)
            yield oci, HelmClient(http, oci, self.settings.git), credentials

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

    def can_rescan_vulnerabilities(self, report: ImageReport) -> bool:
        """Whether a vulnerability rescan of the image can give a result (see _rescan_vulnerabilities)."""
        settings = self.settings.vulnerabilities
        if not settings.enabled or vulnerabilities_ignored(report.image, settings.ignore):
            return False
        from_operator = report.vulnerabilities is not None and report.vulnerabilities.source == "trivy-operator"
        return settings.trivy.enabled or (from_operator and settings.trivy_operator)

    def rescan_image(self, report: ImageReport, versions: bool = True, vulnerabilities: bool = True) -> str | None:
        """Check one image again in the background. Returns why it cannot start, None when started."""
        vulnerabilities = vulnerabilities and self.can_rescan_vulnerabilities(report)
        if not versions and not vulnerabilities:
            return "nothing to rescan (vulnerability scans are disabled or ignored for this image)"
        return self._start_rescan(
            image_key(report), f"image {report.image}", partial(self._rescan_image, report, versions, vulnerabilities)
        )

    def rescan_chart(self, report: ChartReport) -> str | None:
        """Check one chart (and its subcharts) again in the background. Returns why it cannot start, None when started."""
        return self._start_rescan(
            chart_key(report), f"chart {report.chart} of application {report.application}", partial(self._rescan_chart, report)
        )

    def _start_rescan(self, key: tuple, name: str, work: Callable[[], Coroutine]) -> str | None:
        if self.running:
            return "a scan is running, it checks everything again"
        if key in self.rescanning:
            return f"{name} is already being rescanned"
        self.rescanning.add(key)
        task = asyncio.create_task(self._safe_rescan(key, name, work))
        self._rescans.add(task)
        task.add_done_callback(self._rescans.discard)
        return None

    async def _safe_rescan(self, key: tuple, name: str, work: Callable[[], Coroutine]) -> None:
        try:
            await run_in_thread("rescan", lambda: asyncio.run(work()))
        except Exception:  # noqa: BLE001 - the report keeps its previous result
            log.exception("rescan of %s failed", name)
        finally:
            self.rescanning.discard(key)

    async def _rescan_image(self, report: ImageReport, versions: bool, vulnerabilities: bool) -> None:
        """Run in a worker thread's event loop. Results are computed apart, then set at once (no half-updated row)."""
        snap = self.snapshot
        before = check_errors(snap)
        if versions:
            log.info("rescan of image %s: checking its version", report.image)
            fresh = dataclasses.replace(
                report, status=Status.UNKNOWN, latest_tag=None, latest_digest=None, tag_digest=None, message=None
            )
            async with self._clients() as (oci, _, _):
                await ImageChecker(oci, self.settings.images, self.settings.registries.concurrency).check(fresh)
            report.status, report.message = fresh.status, fresh.message
            report.latest_tag, report.latest_digest, report.tag_digest = fresh.latest_tag, fresh.latest_digest, fresh.tag_digest
            log.info(
                "rescan of image %s: %s%s",
                report.image,
                report.status.value,
                f" (latest {report.latest_tag})" if report.latest_tag else "",
            )
        if vulnerabilities:
            log.info("rescan of image %s: scanning its vulnerabilities", report.image)
            report.vulnerabilities = await self._rescan_vulnerabilities(report)
            v = report.vulnerabilities
            log.info(
                "rescan of image %s: %s",
                report.image,
                f"vulnerability scan failed: {v.message}"
                if v and v.message
                else f"{len(v.vulnerabilities) if v else 0} vulnerabilities",
            )
        refresh_check_errors(snap, before)

    async def _rescan_vulnerabilities(self, report: ImageReport) -> VulnerabilityReport | None:
        """Images with a Trivy Operator report get it read again from their clusters (the operator scans them).
        The others, and those whose report is gone, are scanned again with Trivy, ignoring the cached result.
        """
        settings = self.settings.vulnerabilities
        current = report.vulnerabilities
        if current and current.source == "trivy-operator" and settings.trivy_operator:
            candidates = []
            for name in report.clusters:
                if cluster := self._clusters.get(name):
                    found, errors = collect_operator_reports(cluster)
                    for error in errors:
                        log.warning(error)
                    candidates += [r for key, r in found if str(key) == str(report.image)]
            if candidates:
                return pick_report(candidates, report.running_digests)
            log.info("no Trivy Operator report left for %s", report.image)
        if not settings.trivy.enabled:
            return current
        if not self.trivy.available:
            return VulnerabilityReport(
                "trivy", message=f"trivy binary {settings.trivy.binary!r} not found (Helm chart: set trivy.enabled=true)"
            )
        self.trivy.credentials, _ = resolve_credentials(self.settings.registries)  # Secrets may have been rotated
        if error := await self.trivy.prepare():
            log.error(error)
            return VulnerabilityReport("trivy", datetime.now(UTC), message=error)
        result = await self.trivy.scan(report)
        self.trivy.cache[scan_target(report)[0]] = result
        return result

    async def _rescan_chart(self, report: ChartReport) -> None:
        """Run in a worker thread's event loop. Results are computed apart, then set at once."""
        snap = self.snapshot
        before = check_errors(snap)
        log.info("[%s] rescan of chart %s of application %s", report.cluster, report.chart, report.application)
        fresh = dataclasses.replace(report, status=Status.UNKNOWN, latest_version=None, message=None, dependencies=[])
        async with self._clients() as (_, helm, _):
            await ChartChecker(helm, self.settings.helm, self.settings.registries.concurrency).check(fresh)
        # `chart` is kept: it identifies the chart in the UI.
        report.version, report.status, report.latest_version = fresh.version, fresh.status, fresh.latest_version
        report.message, report.dependencies = fresh.message, fresh.dependencies
        log.info(
            "[%s] rescan of chart %s of application %s: %s%s",
            report.cluster,
            report.chart,
            report.application,
            report.worst_status.value,
            f" (latest {report.latest_version})" if report.latest_version else "",
        )
        refresh_check_errors(snap, before)

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


def image_key(report: ImageReport) -> tuple:
    return ("image", str(report.image))


def chart_key(report: ChartReport) -> tuple:
    return ("chart", *report.key)


def refresh_check_errors(snap: Snapshot, before: list[str]) -> None:
    """Replace the version check errors listed before a rescan by the current ones."""
    stale = set(before)
    snap.errors = [e for e in snap.errors if e not in stale] + check_errors(snap)


def vulnerabilities_ignored(image: ImageRef, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(image.name, p) or fnmatch.fnmatch(str(image), p) for p in patterns)


def attach_operator_reports(images: list[ImageReport], reports: dict[str, list[VulnerabilityReport]]) -> None:
    """Give each image the Trivy Operator report of its reference (all clusters together)."""
    for image in images:
        if candidates := reports.get(str(image.image)):
            image.vulnerabilities = pick_report(candidates, image.running_digests)
