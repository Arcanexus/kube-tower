"""Administration actions of the Administration page: Trivy database, caches, connectivity tests, unused node images.

The rescans (all, failed items, one item) are run by the Scanner; this module holds the
other actions and their last results, in memory like everything else.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx

from kube_tower.errors import explain
from kube_tower.models import Snapshot
from kube_tower.registry.helm import is_oci
from kube_tower.registry.oci import RegistryError
from kube_tower.scanner import Scanner, run_in_thread
from kube_tower.trivy import TrivyStatus

log = logging.getLogger(__name__)


@dataclass
class Check:
    """One connectivity test."""

    kind: str  # cluster | registry | helm-repository | trivy-server
    target: str
    ok: bool
    detail: str = ""
    duration: float = 0.0  # seconds


@dataclass
class ConnectivityReport:
    started_at: datetime
    finished_at: datetime | None = None
    checks: list[Check] = field(default_factory=list)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if not c.ok)


@dataclass
class UnusedImage:
    """An image cached on nodes of a cluster that no workload of this cluster uses."""

    cluster: str
    image: str
    nodes: list[str]


def unused_node_images(snapshot: Snapshot) -> list[UnusedImage]:
    """Images found on nodes only (no Pod, Deployment, CronJob... uses them), by cluster.

    Only images collected by the last scan are known: images ignored by `images.ignore` are not listed.
    """
    unused = []
    for report in snapshot.images:
        for cluster in report.clusters:
            usages = [u for u in report.usages if u.cluster == cluster]
            if all(u.kind == "Node" for u in usages):
                unused.append(UnusedImage(cluster, str(report.image), sorted({u.name for u in usages})))
    return sorted(unused, key=lambda u: (u.cluster, u.image))


class Administration:
    def __init__(self, scanner: Scanner):
        self.scanner = scanner
        self.running: set[str] = set()  # actions in progress: trivy-db, connectivity
        self.trivy_status: TrivyStatus | None = None
        self.trivy_message: str | None = None  # outcome of the last database update
        self.connectivity: ConnectivityReport | None = None
        self._tasks: set[asyncio.Task] = set()

    @property
    def trivy(self):
        return self.scanner.trivy

    def _start(self, action: str, work) -> None:
        self.running.add(action)

        async def run() -> None:
            try:
                await work()
            except Exception:  # noqa: BLE001 - shown on the page as "failed, see the logs"
                log.exception("administration action %s failed", action)
            finally:
                self.running.discard(action)

        task = asyncio.create_task(run())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # Trivy

    async def refresh_trivy_status(self) -> TrivyStatus:
        self.trivy_status = await run_in_thread("trivy-status", lambda: asyncio.run(self.trivy.status()))
        return self.trivy_status

    def update_trivy_db(self) -> str | None:
        """Download the Trivy databases when a newer one is published. Returns why it cannot start, None when started."""
        settings = self.trivy.settings
        if settings.server_url:
            return f"client/server mode: the databases are updated by the Trivy server ({settings.server_url})"
        if not settings.enabled or not self.trivy.available:
            return f"Trivy is disabled or its binary {settings.binary!r} is not found"
        if "trivy-db" in self.running:
            return "the Trivy database is already being updated"
        if self.scanner.locked:
            return "a scan is running: it updates the Trivy database itself"
        if self.scanner.rescanning:
            return "rescans are running: try again when they are over"
        self._start("trivy-db", self._update_trivy_db)
        return None

    async def _update_trivy_db(self) -> None:
        before = self.trivy_status.db.downloaded_at if self.trivy_status and self.trivy_status.db else None
        # Scans use the database too: they wait for the update (and the update for them).
        async with self.scanner.exclusive("the Trivy database is being updated"):
            log.info("updating the Trivy database in %s", self.trivy.settings.cache_dir)
            error = await run_in_thread("trivy-db", lambda: asyncio.run(self.trivy.prepare()))
        status = await self.refresh_trivy_status()
        if error:
            self.trivy_message = error
            log.error(error)
        elif status.db and status.db.downloaded_at and status.db.downloaded_at != before:
            self.trivy_message = "database downloaded"
            log.info("Trivy database updated (built %s)", status.db.updated_at)
        else:
            self.trivy_message = "already up to date: no newer database published yet"
            log.info("Trivy database already up to date")

    def clear_trivy_cache(self) -> int:
        """Forget the Trivy scan results: the next scan scans every image again. Returns how many were forgotten."""
        count = len(self.trivy.cache)
        self.trivy.cache.clear()
        log.info("Trivy results cache cleared (%d image(s)): the next scan scans every image again", count)
        return count

    # Connectivity

    def test_connectivity(self) -> str | None:
        """Test the clusters, registries, Helm repositories and Trivy server in the background."""
        if "connectivity" in self.running:
            return "a connectivity test is already running"
        self.connectivity = ConnectivityReport(datetime.now(UTC))
        report = self.connectivity
        self._start("connectivity", lambda: run_in_thread("connectivity", lambda: asyncio.run(self._test(report))))
        return None

    async def _test(self, report: ConnectivityReport) -> None:
        """Run in a worker thread's event loop."""
        log.info("connectivity test started")
        # The same discovery as a scan: cluster Secrets read again, /version of each cluster.
        _, statuses = await asyncio.to_thread(self.scanner.registry.discover)
        report.checks += [Check("cluster", f"{s.name} ({s.server})", s.reachable, s.version or s.message or "") for s in statuses]

        snap = self.scanner.snapshot
        # A repository per registry, to ask for a pull token (the first one seen in the last scan).
        registries: dict[str, str | None] = {}
        for r in snap.images:
            registries.setdefault(r.image.registry, r.image.repository)
        helm_repositories = set()
        for chart in snap.charts:
            repositories = [chart.repository, *(d.repository for _, d in chart.walk())] if chart.source_type != "git" else []
            for repository in repositories:
                if repository.startswith(("http://", "https://")):
                    helm_repositories.add(repository.rstrip("/"))
                elif repository and is_oci(repository) and "/" in repository.removeprefix("oci://"):
                    registry, _, path = repository.removeprefix("oci://").partition("/")
                    registries.setdefault(registry, path)

        async with self.scanner._clients() as (oci, helm, credentials):
            for registry in credentials:
                registries.setdefault(registry, None)

            async def timed(kind: str, target: str, probe) -> Check:
                start = time.monotonic()
                try:
                    detail = await probe()
                    return Check(kind, target, True, detail, time.monotonic() - start)
                except (RegistryError, httpx.HTTPError) as exc:
                    message = str(exc) if isinstance(exc, RegistryError) else explain(exc)
                    return Check(kind, target, False, message, time.monotonic() - start)

            probes = [timed("registry", r, lambda r=r: oci.ping(r, registries[r])) for r in sorted(registries)]
            probes += [timed("helm-repository", r, lambda r=r: helm.ping(r)) for r in sorted(helm_repositories)]
            if server := self.trivy.settings.server_url:
                probes.append(timed("trivy-server", server, lambda: _ping_trivy_server(oci.http, server)))
            semaphore = asyncio.Semaphore(max(1, self.scanner.settings.registries.concurrency))

            async def limited(probe) -> Check:
                async with semaphore:
                    return await probe

            report.checks += await asyncio.gather(*(limited(p) for p in probes))
        report.finished_at = datetime.now(UTC)
        for check in report.checks:
            if not check.ok:
                log.warning("connectivity test: %s %s failed: %s", check.kind, check.target, check.detail)
        log.info("connectivity test finished: %d/%d OK", len(report.checks) - report.failed, len(report.checks))


async def _ping_trivy_server(http: httpx.AsyncClient, server: str) -> str:
    resp = await http.get(f"{server.rstrip('/')}/healthz")
    if resp.status_code != 200:
        raise RegistryError(f"the Trivy server answered HTTP {resp.status_code} on /healthz")
    return "healthy"
