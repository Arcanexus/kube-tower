"""Runs a full scan (discover clusters, collect, check) and keeps the last result in memory.

kube-tower is stateless: the latest Snapshot only lives in memory and is rebuilt
periodically and at startup. Scans run in a dedicated worker thread with its own event
loop and each cluster is collected in its own thread, so the web server (UI, API,
/healthz) stays responsive while a scan is running.
"""

from __future__ import annotations

import asyncio
import contextlib
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
from kube_tower.config import Settings
from kube_tower.models import ChartReport, Snapshot, Status
from kube_tower.registry.auth import resolve_credentials
from kube_tower.registry.helm import HelmClient
from kube_tower.registry.oci import OCIClient

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


def check_errors(snap: Snapshot) -> list[str]:
    """Version check failures, listed with the collection errors in the scan errors."""
    errors = [f"image {r.image}: {r.message}" for r in snap.images if r.status == Status.ERROR]
    for c in snap.charts:
        if c.status == Status.ERROR:
            errors.append(f"[{c.cluster}] chart {c.chart} of application {c.application}: {c.message}")
        errors += [
            f"[{c.cluster}] subchart {d.name} {d.version} of application {c.application}: {d.message}"
            for d in c.dependencies
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

    @property
    def running(self) -> bool:
        return self._lock.locked()

    async def scan(self) -> Snapshot:
        async with self._lock:
            snap = await run_in_thread("scanner", lambda: asyncio.run(self._scan()))
            self.snapshot = snap
            return snap

    async def _scan(self) -> Snapshot:
        """The scan itself, run in the worker thread's event loop."""
        snap = Snapshot(started_at=datetime.now(UTC))
        log.info("scan started")
        clusters, snap.clusters = await asyncio.to_thread(self.registry.discover)
        reachable = {s.name for s in snap.clusters if s.reachable}
        clusters = [c for c in clusters if c.name in reachable]

        inventory = ImageInventory(self.settings.images)

        def collect(cluster: Cluster) -> tuple[list[ChartReport], list[str]]:
            charts, errors = [], []
            if self.settings.images.enabled:
                errors += inventory.collect(cluster)
            if self.settings.helm.enabled:
                charts, chart_errors = collect_charts(cluster, self.settings.helm)
                errors += chart_errors
            return charts, errors

        # One thread per cluster: a slow or large cluster does not hold back the others.
        results = await asyncio.gather(*(run_in_thread(f"scan-{c.name}", partial(collect, c)) for c in clusters))
        for charts, errors in results:
            snap.charts += charts
            snap.errors += errors
        snap.images = sorted(inventory.reports.values(), key=lambda r: str(r.image))

        reg = self.settings.registries
        async with httpx.AsyncClient(timeout=reg.timeout, headers={"User-Agent": "kube-tower"}) as http:
            credentials, _ = resolve_credentials(reg)
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
