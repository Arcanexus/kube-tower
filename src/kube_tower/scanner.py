"""Runs a full scan (discover clusters, collect, check) and keeps the last result in memory.

kube-tower is stateless: the latest Snapshot only lives in memory and is rebuilt
periodically and at startup. Scans run in a dedicated worker thread with its own event
loop, so the web server (UI, API, /healthz) stays responsive while a scan is running.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
from datetime import UTC, datetime

import httpx

from kube_tower.checkers import ChartChecker, ImageChecker
from kube_tower.clusters import ClusterRegistry
from kube_tower.collectors.helm import collect_charts
from kube_tower.collectors.images import ImageInventory
from kube_tower.config import Settings
from kube_tower.models import Snapshot
from kube_tower.registry.auth import resolve_credentials
from kube_tower.registry.helm import HelmClient
from kube_tower.registry.oci import OCIClient

log = logging.getLogger(__name__)


class Scanner:
    def __init__(self, settings: Settings, registry: ClusterRegistry | None = None):
        self.settings = settings
        self.registry = registry or ClusterRegistry(settings.clusters)
        self.snapshot = Snapshot()
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None

    @property
    def running(self) -> bool:
        return self._lock.locked()

    async def scan(self) -> Snapshot:
        async with self._lock:
            snap = await self._in_worker()
            self.snapshot = snap
            return snap

    async def _in_worker(self) -> Snapshot:
        """Run `_scan` in a daemon thread with its own event loop: a scan never blocks the web
        server's loop, and a scan in progress does not delay the process shutdown."""
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Snapshot] = loop.create_future()

        def settle(result: Snapshot | None, error: BaseException | None) -> None:
            if future.done():  # cancelled meanwhile (shutdown)
                return
            if error is not None:
                future.set_exception(error)
            else:
                future.set_result(result)

        def work() -> None:
            try:
                result, error = asyncio.run(self._scan()), None
            except BaseException as exc:  # noqa: BLE001 - handed over to the web server's loop
                result, error = None, exc
            with contextlib.suppress(RuntimeError):  # web server loop already closed
                loop.call_soon_threadsafe(settle, result, error)

        threading.Thread(target=work, name="scanner", daemon=True).start()
        return await future

    async def _scan(self) -> Snapshot:
        """The scan itself, run in the worker thread's event loop."""
        snap = Snapshot(started_at=datetime.now(UTC))
        log.info("scan started")
        clusters, snap.clusters = await asyncio.to_thread(self.registry.discover)
        reachable = {s.name for s in snap.clusters if s.reachable}
        clusters = [c for c in clusters if c.name in reachable]

        inventory = ImageInventory(self.settings.images)
        for cluster in clusters:
            if self.settings.images.enabled:
                snap.errors += await asyncio.to_thread(inventory.collect, cluster)
            if self.settings.helm.enabled:
                charts, errors = await asyncio.to_thread(collect_charts, cluster, self.settings.helm)
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
        snap.finished_at = datetime.now(UTC)
        log.info(
            "scan finished in %.1fs: %d clusters, %d images, %d charts",
            (snap.finished_at - snap.started_at).total_seconds(),
            len(clusters),
            len(snap.images),
            len(snap.charts),
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
        except Exception:  # noqa: BLE001 - keep the previous snapshot and the loop alive
            log.exception("scan failed")

    async def run_forever(self) -> None:
        while True:
            await self._safe_scan()
            await asyncio.sleep(self.settings.refresh_interval)
