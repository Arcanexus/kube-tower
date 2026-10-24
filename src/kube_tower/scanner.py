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
from kube_tower.registry.helm import HelmClient, IndexCache
from kube_tower.registry.oci import OCIClient
from kube_tower.registry.transport import RetryingClient
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
        self.helm_indexes = IndexCache()  # index.yaml of the Helm repositories, revalidated at each scan
        # Keys (see image_key / chart_key) of the images and charts being rescanned on their own.
        self.rescanning: set[tuple] = set()
        self._rescans: set[asyncio.Task] = set()  # keeps the background rescans referenced
        self._clusters: dict[str, Cluster] = {}  # reachable clusters of the last scan, by name
        # Set while a maintenance action holds the scan lock (e.g. Trivy database update): why scans must wait.
        self.busy: str | None = None

    @property
    def running(self) -> bool:
        """A scan is running (not a maintenance action holding the scan lock)."""
        return self._lock.locked() and self.busy is None

    @property
    def locked(self) -> bool:
        """A scan or a maintenance action holds the scan lock."""
        return self._lock.locked()

    @contextlib.asynccontextmanager
    async def exclusive(self, reason: str) -> AsyncIterator[None]:
        """Hold the scan lock for a maintenance action: no scan nor rescan starts meanwhile."""
        async with self._lock:
            self.busy = reason
            try:
                yield
            finally:
                self.busy = None

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
        async with RetryingClient(
            timeout=reg.timeout, headers={"User-Agent": "kube-tower"}, event_hooks=hooks, retries=reg.retries
        ) as http:
            credentials, _ = resolve_credentials(reg)
            self.trivy.credentials = credentials
            oci = OCIClient(http, credentials, reg.mirrors, self.settings.images.max_tag_pages)
            yield oci, HelmClient(http, oci, self.settings.git, self.helm_indexes), credentials

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

    def same_name_images(self, report: ImageReport) -> list[ImageReport]:
        """The images of the snapshot with the name (registry/repository) of this one: every tag, used or not."""
        return [r for r in self.snapshot.images if r.image.name == report.image.name] or [report]

    def rescan_image(self, report: ImageReport, versions: bool = True, vulnerabilities: bool = True) -> str | None:
        """Check again, in the background, every image with the name of this one: all its tags, used by
        workloads or only cached on nodes, including the ones that appeared on the clusters since the last
        scan (the clusters are read again first). Returns why it cannot start, None when started.
        """
        vulnerabilities = vulnerabilities and self.can_rescan_vulnerabilities(report)
        if not versions and not vulnerabilities:
            return "nothing to rescan (vulnerability scans are disabled or ignored for this image)"
        others = {image_key(r) for r in self.same_name_images(report)} - {image_key(report)}
        if busy := others & self.rescanning:
            return f"{len(busy)} image(s) named {report.image.name} are already being rescanned"
        error = self._start_rescan(
            image_key(report),
            f"images named {report.image.name}",
            partial(self._rescan_image, report, versions, vulnerabilities, others),
        )
        if error is None:
            self.rescanning |= others  # their detail panels show the rescan
        return error

    def rescan_chart(self, report: ChartReport) -> str | None:
        """Check one chart (and its subcharts) again in the background. Returns why it cannot start, None when started."""
        return self._start_rescan(
            chart_key(report), f"chart {report.chart} of application {report.application}", partial(self._rescan_chart, report)
        )

    def failed_items(self) -> tuple[list[ImageReport], list[ImageReport], list[ChartReport]]:
        """What failed in the current snapshot: image version checks, vulnerability scans, charts (or subcharts)."""
        snap = self.snapshot
        images = [r for r in snap.images if r.status == Status.ERROR]
        vulnerabilities = [
            r for r in snap.images if r.vulnerabilities and r.vulnerabilities.message and self.can_rescan_vulnerabilities(r)
        ]
        charts = [c for c in snap.charts if c.status == Status.ERROR or any(d.status == Status.ERROR for _, d in c.walk())]
        return images, vulnerabilities, charts

    def retry_failed(self) -> str | None:
        """Check again, in the background, everything that failed. Returns why it cannot start, None when started."""
        images, vulnerabilities, charts = self.failed_items()
        if not (images or vulnerabilities or charts):
            return "nothing failed in the last scan"
        keys = {image_key(r) for r in images + vulnerabilities} | {chart_key(c) for c in charts}
        if busy := keys & self.rescanning:
            return f"{len(busy)} of these items are already being rescanned"
        error = self._start_rescan(
            RETRY_KEY, "the failed items", partial(self._retry_failed, images, vulnerabilities, charts, keys)
        )
        if error is None:
            self.rescanning |= keys  # their detail panels show the rescan
        return error

    async def _retry_failed(
        self, images: list[ImageReport], vulnerabilities: list[ImageReport], charts: list[ChartReport], keys: set[tuple]
    ) -> None:
        """Run in a worker thread's event loop, like a scan but only for the failed items."""
        try:
            snap = self.snapshot
            before = check_errors(snap)
            log.info(
                "retrying what failed: %d image version check(s), %d vulnerability scan(s), %d chart(s)",
                len(images),
                len(vulnerabilities),
                len(charts),
            )
            fresh_images = [_fresh_image(r) for r in images]
            fresh_charts = [_fresh_chart(c) for c in charts]
            async with self._clients() as (oci, helm, _):
                concurrency = self.settings.registries.concurrency
                await asyncio.gather(
                    ImageChecker(oci, self.settings.images, concurrency).check_all(fresh_images),
                    ChartChecker(helm, self.settings.helm, concurrency).check_all(fresh_charts),
                )
            for report, fresh in zip(images, fresh_images, strict=True):
                _apply_image(report, fresh)
            for report, fresh in zip(charts, fresh_charts, strict=True):
                _apply_chart(report, fresh)
            if vulnerabilities:
                if self.trivy.available:
                    await self.trivy.scan_many(vulnerabilities)  # failed scans are never cached
                else:
                    log.warning("vulnerability scans not retried: trivy binary %r not found", self.trivy.settings.binary)
            refresh_check_errors(snap, before)
            images_left, vulnerabilities_left, charts_left = self.failed_items()
            log.info(
                "retry done: still failing %d image version check(s), %d vulnerability scan(s), %d chart(s)",
                len(images_left),
                len(vulnerabilities_left),
                len(charts_left),
            )
        finally:
            self.rescanning -= keys

    def _start_rescan(self, key: tuple, name: str, work: Callable[[], Coroutine]) -> str | None:
        if self.running:
            return "a scan is running, it checks everything again"
        if self.busy:
            return f"{self.busy}: try again when it is over"
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

    async def _rescan_image(self, report: ImageReport, versions: bool, vulnerabilities: bool, others: set[tuple]) -> None:
        """Run in a worker thread's event loop. Results are computed apart, then set at once (no half-updated row)."""
        try:
            await self._rescan_image_work(report, versions, vulnerabilities)
        finally:
            self.rescanning -= others

    async def _rescan_image_work(self, report: ImageReport, versions: bool, vulnerabilities: bool) -> None:
        snap = self.snapshot
        before = check_errors(snap)
        name = report.image.name
        new = await self._collect_images_named(snap, name)
        group = [r for r in snap.images if r.image.name == name]
        # Images new to the snapshot were never checked: they get both checks.
        to_check = group if versions else new
        if to_check:
            log.info(
                "rescan of %s: checking the version of %d image(s): %s",
                name,
                len(to_check),
                ", ".join(r.image.tag or r.image.digest or "" for r in to_check),
            )
            fresh = [_fresh_image(r) for r in to_check]
            async with self._clients() as (oci, _, _):
                # One checker: the tag list of the repository is read once for all of them.
                checker = ImageChecker(oci, self.settings.images, self.settings.registries.concurrency)
                await asyncio.gather(*(checker.check(f) for f in fresh))
            for r, f in zip(to_check, fresh, strict=True):
                _apply_image(r, f)
                log.info("rescan of image %s: %s%s", r.image, r.status.value, f" (latest {r.latest_tag})" if r.latest_tag else "")
        to_scan = [r for r in (group if vulnerabilities else new) if self.can_rescan_vulnerabilities(r)]
        if to_scan:
            log.info("rescan of %s: scanning the vulnerabilities of %d image(s)", name, len(to_scan))
            await self._rescan_vulnerabilities(to_scan)
            for r in to_scan:
                v = r.vulnerabilities
                log.info(
                    "rescan of image %s: %s",
                    r.image,
                    f"vulnerability scan failed: {v.message}"
                    if v and v.message
                    else f"{len(v.vulnerabilities) if v else 0} vulnerabilities",
                )
        refresh_check_errors(snap, before)

    async def _collect_images_named(self, snap: Snapshot, name: str) -> list[ImageReport]:
        """Read the images of the clusters again and update those with this name in the snapshot: current
        usages for the known ones, the new ones (e.g. a new tag deployed) added. Returns the new ones.
        Images no longer found stay until the next full scan.
        """
        if not self.settings.images.enabled or not self._clusters:
            return []
        inventory = ImageInventory(self.settings.images)
        clusters = list(self._clusters.values())
        results = await asyncio.gather(
            *(run_in_thread(f"rescan-{c.name}", partial(inventory.collect, c)) for c in clusters), return_exceptions=True
        )
        for cluster, result in zip(clusters, results, strict=True):
            if isinstance(result, BaseException):
                log.warning("[%s] cannot read the images again: %s", cluster.name, result)
        known = {str(r.image): r for r in snap.images if r.image.name == name}
        new = []
        for key, found in inventory.reports.items():
            if found.image.name != name:
                continue
            if current := known.get(key):
                current.usages, current.running_digests = found.usages, found.running_digests
            else:
                new.append(found)
        if new:
            snap.images = sorted([*snap.images, *new], key=lambda r: str(r.image))
            log.info(
                "rescan of %s: %d new image(s) found on the clusters: %s", name, len(new), ", ".join(str(r.image) for r in new)
            )
        return new

    async def _rescan_vulnerabilities(self, reports: list[ImageReport]) -> None:
        """Images with a Trivy Operator report get it read again from their clusters (the operator scans them,
        each cluster is read once). The others, and those whose report is gone, are scanned again with Trivy,
        ignoring the cached results.
        """
        settings = self.settings.vulnerabilities
        todo = reports
        if settings.trivy_operator:
            names = {c for r in reports for c in r.clusters}
            found: dict[str, list[VulnerabilityReport]] = {}
            for cluster in (self._clusters[n] for n in sorted(names) if n in self._clusters):
                cluster_reports, errors = collect_operator_reports(cluster)
                for error in errors:
                    log.warning(error)
                for key, v in cluster_reports:
                    found.setdefault(str(key), []).append(v)
            todo = []
            for r in reports:
                if candidates := found.get(str(r.image)):
                    r.vulnerabilities = pick_report(candidates, r.running_digests)
                else:
                    if r.vulnerabilities and r.vulnerabilities.source == "trivy-operator":
                        log.info("no Trivy Operator report left for %s", r.image)
                    todo.append(r)
        if not todo or not settings.trivy.enabled:
            return
        if not self.trivy.available:
            message = f"trivy binary {settings.trivy.binary!r} not found (Helm chart: set trivy.enabled=true)"
            for r in todo:
                r.vulnerabilities = VulnerabilityReport("trivy", message=message)
            return
        self.trivy.credentials, _ = resolve_credentials(self.settings.registries)  # Secrets may have been rotated
        for r in todo:
            self.trivy.cache.pop(scan_target(r)[0], None)  # scanned again, not read from the cache
        await self.trivy.scan_many(todo)

    async def _rescan_chart(self, report: ChartReport) -> None:
        """Run in a worker thread's event loop. Results are computed apart, then set at once."""
        snap = self.snapshot
        before = check_errors(snap)
        log.info("[%s] rescan of chart %s of application %s", report.cluster, report.chart, report.application)
        fresh = _fresh_chart(report)
        async with self._clients() as (_, helm, _):
            await ChartChecker(helm, self.settings.helm, self.settings.registries.concurrency).check(fresh)
        _apply_chart(report, fresh)
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
        """Start a scan in the background unless one is already running (or a maintenance action holds the lock)."""
        if self.locked:
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


RETRY_KEY = ("retry-failed",)


def _fresh_image(report: ImageReport) -> ImageReport:
    """A copy of the report to check again apart (the current results stay shown meanwhile)."""
    return dataclasses.replace(report, status=Status.UNKNOWN, latest_tag=None, latest_digest=None, tag_digest=None, message=None)


def _apply_image(report: ImageReport, fresh: ImageReport) -> None:
    report.status, report.message = fresh.status, fresh.message
    report.latest_tag, report.latest_digest, report.tag_digest = fresh.latest_tag, fresh.latest_digest, fresh.tag_digest


def _fresh_chart(report: ChartReport) -> ChartReport:
    return dataclasses.replace(report, status=Status.UNKNOWN, latest_version=None, message=None, dependencies=[])


def _apply_chart(report: ChartReport, fresh: ChartReport) -> None:
    # `chart` is kept: it identifies the chart in the UI.
    report.version, report.status, report.latest_version = fresh.version, fresh.status, fresh.latest_version
    report.message, report.dependencies = fresh.message, fresh.dependencies


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
