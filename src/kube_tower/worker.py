"""Runs the tasks of a scan (see tasks.py): what the worker and trivy roles do (ADR 0002).

The Worker keeps what makes the next tasks faster or safer, from one scan to the next: cloud registry
tokens, registries that answered 429, Helm indexes, the Trivy results cache, and whether each registry
accepted the credentials.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import tempfile
import threading
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import certifi
import httpx

from kube_tower.checkers import ChartChecker, ImageChecker
from kube_tower.clusters import Cluster
from kube_tower.collectors.helm import collect_charts
from kube_tower.collectors.images import ImageInventory
from kube_tower.collectors.vulnerabilities import collect_operator_reports
from kube_tower.config import Settings
from kube_tower.models import VulnerabilityReport
from kube_tower.registry.auth import AuthResults, Credentials, TokenCache, resolve_credentials
from kube_tower.registry.helm import HelmClient, IndexCache
from kube_tower.registry.oci import OCIClient
from kube_tower.registry.transport import RateLimits, RetryingClient
from kube_tower.tasks import (
    CheckChartsResult,
    CheckChartsTask,
    CheckImagesResult,
    CheckImagesTask,
    CollectResult,
    CollectTask,
    OperatorReport,
    Result,
    ScanVulnerabilitiesResult,
    ScanVulnerabilitiesTask,
    Task,
)
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


def ssl_context(ca_file: str) -> ssl.SSLContext | bool:
    """The public CAs, plus those of registries.caFile (e.g. an internal Harbor or Artifactory)."""
    if not ca_file:
        return True
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        context.load_verify_locations(cafile=ca_file)
    except (OSError, ssl.SSLError) as exc:
        log.error("registries.caFile %s ignored, it cannot be read as PEM certificates: %s", ca_file, exc)
    return context


def ca_bundle(ca_file: str) -> str:
    """A CA bundle file for Trivy: the public CAs plus registries.caFile ("" without caFile)."""
    if not ca_file:
        return ""
    bundle = Path(tempfile.gettempdir()) / "kube-tower-ca-bundle.pem"
    try:
        content = Path(certifi.where()).read_text() + "\n" + Path(ca_file).read_text()
        if not bundle.is_file() or bundle.read_text() != content:
            bundle.write_text(content)
    except OSError as exc:
        log.error("registries.caFile %s not given to Trivy: %s", ca_file, exc)
        return ""
    return str(bundle)


class Worker:
    def __init__(self, settings: Settings):
        self.settings = settings
        # Keeps its results between scans; registry credentials are set before each use.
        self.trivy = TrivyScanner(settings.vulnerabilities.trivy, {})
        # Short-lived tokens of cloud registries (ECR, Artifact Registry, ACR), kept until shortly before they expire.
        self.registry_tokens = TokenCache()
        # Whether each registry accepted the credentials at the last request that sent them (Settings page).
        self.registry_auth = AuthResults()
        self.rate_limits = RateLimits()  # registries that answered 429, kept between scans
        # Credentials of the image pull secrets read at the last scan (registries.useImagePullSecrets).
        self.pull_secrets: dict[str, tuple[str, str]] = {}
        self.helm_indexes = IndexCache()  # index.yaml of the Helm repositories, revalidated at each scan
        # The clusters tasks may name, by name (the reachable clusters of the last discovery).
        self.clusters: dict[str, Cluster] = {}

    async def execute(self, task: Task) -> Result:
        match task:
            case CollectTask():
                return await self._collect(task)
            case CheckImagesTask():
                return await self._check_images(task)
            case CheckChartsTask():
                return await self._check_charts(task)
            case ScanVulnerabilitiesTask():
                return await self._scan_vulnerabilities(task)
        raise TypeError(f"unknown task {task!r}")

    def credentials(self) -> Credentials:
        """The registry credentials, read again (Secrets may have been rotated), also given to Trivy."""
        reg = self.settings.registries
        credentials, _ = resolve_credentials(reg, self.registry_tokens, self.pull_secrets)
        self.trivy.credentials = credentials
        self.trivy.insecure = reg.insecure
        self.trivy.ca_bundle = ca_bundle(reg.ca_file)
        return credentials

    @contextlib.asynccontextmanager
    async def clients(self) -> AsyncIterator[tuple[OCIClient, HelmClient, Credentials]]:
        """Registry and Helm repository clients, with the registry credentials read again (Secrets may have been rotated)."""
        reg = self.settings.registries
        options = {
            "timeout": reg.timeout,
            "headers": {"User-Agent": "kube-tower"},
            "event_hooks": {"response": [_log_response]},
            "retries": reg.retries,
            "rate_limits": self.rate_limits,
        }
        credentials = self.credentials()
        async with contextlib.AsyncExitStack() as stack:
            http = await stack.enter_async_context(RetryingClient(verify=ssl_context(reg.ca_file), **options))
            # TLS certificates of registries.insecure hosts are not verified.
            insecure = await stack.enter_async_context(RetryingClient(verify=False, **options)) if reg.insecure else None
            oci = OCIClient(
                http, credentials, reg.mirrors, self.settings.images.max_tag_pages, reg.insecure, insecure, self.registry_auth
            )
            yield oci, HelmClient(http, oci, self.settings.git, self.helm_indexes), credentials

    async def _collect(self, task: CollectTask) -> CollectResult:
        if (cluster := self.clusters.get(task.cluster)) is None:
            return CollectResult(errors=[f"[{task.cluster}] unknown cluster: it was not found by the last discovery"])
        settings = self.settings
        vuln = settings.vulnerabilities
        read_operator = settings.images.enabled and vuln.enabled and vuln.trivy_operator

        def collect() -> CollectResult:
            result = CollectResult()
            inventory = ImageInventory(settings.images, settings.registries.use_image_pull_secrets)
            if settings.images.enabled and task.images:
                result.errors += inventory.collect(cluster)
            if settings.helm.enabled and task.charts:
                result.charts, chart_errors = collect_charts(cluster, settings.helm)
                result.errors += chart_errors
            if read_operator and task.operator_reports:
                reports, operator_errors = collect_operator_reports(cluster)
                result.operator_reports = [OperatorReport(str(ref), report) for ref, report in reports]
                result.errors += operator_errors
            result.images = [r for r in inventory.reports.values() if task.image_name in (None, r.image.name)]
            result.pull_secrets = inventory.pull_secrets
            return result

        # Its own thread: a slow or large cluster does not hold back the others.
        return await run_in_thread(f"scan-{cluster.name}", collect)

    async def _check_images(self, task: CheckImagesTask) -> CheckImagesResult:
        async with self.clients() as (oci, _, credentials):
            log.info("registry credentials loaded for: %s", ", ".join(credentials.describe()) or "none (anonymous access)")
            await ImageChecker(oci, self.settings.images, self.settings.registries.concurrency).check_all(task.images)
        return CheckImagesResult(task.images)

    async def _check_charts(self, task: CheckChartsTask) -> CheckChartsResult:
        async with self.clients() as (_, helm, _):
            await ChartChecker(helm, self.settings.helm, self.settings.registries.concurrency).check_all(task.charts)
        return CheckChartsResult(task.charts)

    async def _scan_vulnerabilities(self, task: ScanVulnerabilitiesTask) -> ScanVulnerabilitiesResult:
        """Each image gets its report as soon as it is scanned (the UI shows them as they come)."""
        errors: list[str] = []
        if not self.trivy.available:
            message = f"trivy binary {self.trivy.settings.binary!r} not found (Helm chart: set trivy.enabled=true)"
            log.warning("vulnerability scan skipped: %s", message)
            for r in task.images:
                r.vulnerabilities = VulnerabilityReport("trivy", message=message)
        elif task.images:
            self.credentials()  # Secrets may have been rotated
            if task.fresh:
                for r in task.images:
                    self.trivy.cache.pop(scan_target(r)[0], None)
            errors = await (self.trivy.scan_all if task.full else self.trivy.scan_many)(task.images)
        return ScanVulnerabilitiesResult([r.vulnerabilities for r in task.images], errors)
