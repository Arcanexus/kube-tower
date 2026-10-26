"""What the web layer (UI, JSON API, metrics) needs from the scans: the Backend interface.

The pages and the API only go through a Backend, never through the Scanner or the Administration
directly. A process with the controller role uses the LocalBackend (the Scanner and the Administration
of the process). A `ui` process without the controller uses the RemoteBackend, which asks the
controller over its internal API (ADR 0002): the web layer does not change.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

import httpx

from kube_tower.administration import Administration, ConnectivityReport
from kube_tower.config import Settings, internal_token
from kube_tower.logbuffer import LogBuffer, LogLine
from kube_tower.models import ChartReport, ImageReport, Snapshot, decode, encode
from kube_tower.processes import Processes, ProcessInfo
from kube_tower.registry.auth import AuthResult, CredentialStatus, resolve_credentials
from kube_tower.scanner import Activity, Scanner, can_rescan_vulnerabilities, failed_items, same_name_images
from kube_tower.trivy import TrivyStatus

log = logging.getLogger(__name__)


class Backend(Protocol):
    # The last scan and what runs now
    @property
    def snapshot(self) -> Snapshot: ...
    @property
    def running(self) -> bool: ...  # a scan runs, either phase
    @property
    def checking_versions(self) -> bool: ...  # a scan is in its version phase
    @property
    def locked(self) -> bool: ...  # a scan or an administration action holds the scan locks
    @property
    def busy(self) -> str | None: ...  # why scans wait for an administration action
    @property
    def rescanning(self) -> set[tuple]: ...  # keys of the images and charts being rescanned
    @property
    def scans_total(self) -> dict[str, int]: ...
    def activities(self) -> list[Activity]: ...
    def failed_items(self) -> tuple[list[ImageReport], list[ImageReport], list[ChartReport]]: ...
    def can_rescan_vulnerabilities(self, report: ImageReport) -> bool: ...
    def same_name_images(self, report: ImageReport) -> list[ImageReport]: ...

    # Scans: each returns why it cannot start, None when started (trigger: whether it started)
    async def trigger(self) -> bool: ...
    async def rescan_image(self, report: ImageReport, versions: bool = True, vulnerabilities: bool = True) -> str | None: ...
    async def rescan_chart(self, report: ChartReport) -> str | None: ...
    async def retry_failed(self) -> str | None: ...

    # Registries (Settings page): the credentials in use and whether each registry accepted them
    def registry_credentials(self, settings: Settings) -> tuple[list[CredentialStatus], dict]: ...

    # Trivy and the other administration actions
    @property
    def trivy_available(self) -> bool: ...
    @property
    def trivy_binary(self) -> str: ...
    @property
    def trivy_cached(self) -> int: ...  # images whose Trivy results are cached
    @property
    def trivy_remote(self) -> bool: ...  # Trivy runs in trivy processes apart from the controller
    @property
    def trivy_status(self) -> TrivyStatus | None: ...
    @property
    def trivy_message(self) -> str | None: ...  # outcome of the last database update
    @property
    def connectivity(self) -> ConnectivityReport | None: ...
    @property
    def admin_running(self) -> set[str]: ...  # administration actions in progress: trivy-db, connectivity
    async def refresh_trivy_status(self) -> TrivyStatus: ...
    async def update_trivy_db(self) -> str | None: ...
    async def clear_trivy_cache(self) -> int: ...  # -1: the trivy processes forget theirs at their next task
    async def test_connectivity(self) -> str | None: ...

    # The last log lines of the process with the controller (Logs page), after this sequence number
    async def log_lines(self, after: int = 0) -> list[LogLine]: ...

    def processes(self) -> list[ProcessInfo]: ...  # the processes (pods) of the installation and their state


class LocalBackend:
    """Every role in this process: the Scanner and the Administration of the process, as before."""

    def __init__(
        self,
        scanner: Scanner,
        administration: Administration,
        log_buffer: LogBuffer | None = None,
        processes: Processes | None = None,
        state: Callable[[], str] = lambda: "active",
    ):
        self.scanner = scanner
        self.administration = administration
        self.log_buffer = log_buffer or LogBuffer()
        # The other processes, as they report to this controller; `state` is the one of this process.
        self.process_registry = processes or Processes(scanner.settings.roles)
        self.process_state = state

    def processes(self) -> list[ProcessInfo]:
        return self.process_registry.list(self.process_state())

    async def log_lines(self, after: int = 0) -> list[LogLine]:
        return self.log_buffer.since(after)

    @property
    def snapshot(self) -> Snapshot:
        return self.scanner.snapshot

    @property
    def running(self) -> bool:
        return self.scanner.running

    @property
    def checking_versions(self) -> bool:
        return self.scanner.checking_versions

    @property
    def locked(self) -> bool:
        return self.scanner.locked

    @property
    def busy(self) -> str | None:
        return self.scanner.busy

    @property
    def rescanning(self) -> set[tuple]:
        return self.scanner.rescanning

    @property
    def scans_total(self) -> dict[str, int]:
        return self.scanner.scans_total

    def activities(self) -> list[Activity]:
        return self.scanner.activities()

    def failed_items(self) -> tuple[list[ImageReport], list[ImageReport], list[ChartReport]]:
        return self.scanner.failed_items()

    def can_rescan_vulnerabilities(self, report: ImageReport) -> bool:
        return self.scanner.can_rescan_vulnerabilities(report)

    def same_name_images(self, report: ImageReport) -> list[ImageReport]:
        return self.scanner.same_name_images(report)

    async def trigger(self) -> bool:
        return self.scanner.trigger()

    async def rescan_image(self, report: ImageReport, versions: bool = True, vulnerabilities: bool = True) -> str | None:
        return self.scanner.rescan_image(report, versions, vulnerabilities)

    async def rescan_chart(self, report: ChartReport) -> str | None:
        return self.scanner.rescan_chart(report)

    async def retry_failed(self) -> str | None:
        return self.scanner.retry_failed()

    def registry_credentials(self, settings: Settings) -> tuple[list[CredentialStatus], dict]:
        _, credentials = resolve_credentials(settings.registries, pull_secrets=self.scanner.pull_secrets)
        return credentials, {c.registry: self.scanner.registry_auth.get(c.registry) for c in credentials}

    @property
    def trivy_available(self) -> bool:
        return self.administration.trivy_available

    @property
    def trivy_binary(self) -> str:
        return self.scanner.trivy.settings.binary

    @property
    def trivy_cached(self) -> int:
        return self.administration.trivy_cached

    @property
    def trivy_remote(self) -> bool:
        return self.administration.trivy_remote

    @property
    def trivy_status(self) -> TrivyStatus | None:
        return self.administration.trivy_status

    @property
    def trivy_message(self) -> str | None:
        return self.administration.trivy_message

    @property
    def connectivity(self) -> ConnectivityReport | None:
        return self.administration.connectivity

    @property
    def admin_running(self) -> set[str]:
        return self.administration.running

    async def refresh_trivy_status(self) -> TrivyStatus:
        return await self.administration.refresh_trivy_status()

    async def update_trivy_db(self) -> str | None:
        return self.administration.update_trivy_db()

    async def clear_trivy_cache(self) -> int:
        return self.administration.clear_trivy_cache()

    async def test_connectivity(self) -> str | None:
        return self.administration.test_connectivity()

    def state(self, revision: int | None = None) -> BackendState:
        """What a RemoteBackend shows, with the snapshot unless the UI has this revision and nothing runs
        (results are set in the snapshot while scans and rescans run)."""
        scanner = self.scanner
        credentials, auth = self.registry_credentials(scanner.settings)
        activities = self.activities()
        return BackendState(
            revision=scanner.revision,
            running=self.running,
            checking_versions=self.checking_versions,
            locked=self.locked,
            busy=self.busy,
            rescanning=[list(key) for key in self.rescanning],
            scans_total=dict(self.scans_total),
            activities=activities,
            credentials=credentials,
            registry_auth=auth,
            trivy_available=self.trivy_available,
            trivy_binary=self.trivy_binary,
            trivy_cached=self.trivy_cached,
            trivy_remote=self.trivy_remote,
            trivy_status=self.trivy_status,
            trivy_message=self.trivy_message,
            connectivity=self.connectivity,
            admin_running=sorted(self.admin_running),
            processes=self.processes(),
            snapshot=self.snapshot if revision != scanner.revision or activities else None,
        )

    async def action(self, name: str, params: dict[str, Any]) -> Any:
        """The actions of the RemoteBackend, run here: their JSON-ready result."""
        if name == "rescan-image":
            if (report := self.snapshot.image(params["ref"])) is None:
                return f"image {params['ref']!r} not found in the last scan"
            return await self.rescan_image(report, params.get("versions", True), params.get("vulnerabilities", True))
        if name == "rescan-chart":
            key = (params["cluster"], params["namespace"], params["application"], params["chart"])
            if (chart := self.snapshot.chart(*key)) is None:
                return f"chart {key[3]!r} of application {key[1]}/{key[2]} in cluster {key[0]!r} not found in the last scan"
            return await self.rescan_chart(chart)
        if name == "trivy-status":
            return encode(await self.refresh_trivy_status())
        actions = {
            "trigger": self.trigger,
            "retry-failed": self.retry_failed,
            "trivy-db": self.update_trivy_db,
            "trivy-cache": self.clear_trivy_cache,
            "connectivity": self.test_connectivity,
        }
        if name not in actions:
            raise ValueError(f"unknown action {name!r}")
        return await actions[name]()


@dataclass
class BackendState:
    """The state of the controller that the pages show, sent to the UI processes as JSON."""

    revision: int = -1
    running: bool = False
    checking_versions: bool = False
    locked: bool = False
    busy: str | None = None
    rescanning: list[list[str]] = field(default_factory=list)
    scans_total: dict[str, int] = field(default_factory=lambda: {"success": 0, "failure": 0})
    activities: list[Activity] = field(default_factory=list)
    credentials: list[CredentialStatus] = field(default_factory=list)
    registry_auth: dict[str, AuthResult | None] = field(default_factory=dict)
    trivy_available: bool = False
    trivy_binary: str = ""
    trivy_cached: int = 0
    trivy_remote: bool = False
    trivy_status: TrivyStatus | None = None
    trivy_message: str | None = None
    connectivity: ConnectivityReport | None = None
    admin_running: list[str] = field(default_factory=list)
    processes: list[ProcessInfo] = field(default_factory=list)
    snapshot: Snapshot | None = None


POLL = 2.0  # seconds between two reads of the controller state by a UI process
UNREACHABLE = "the controller cannot be reached: {}"


class RemoteBackend:
    """A `ui` process without the controller: the state of the controller, read again every POLL seconds,
    and the actions sent to it, over its internal API.
    """

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.http = httpx.AsyncClient(
            base_url=settings.internal.controller_url.rstrip("/"),
            headers={"Authorization": f"Bearer {internal_token(settings)}", "User-Agent": "kube-tower"},
            timeout=30,
            transport=transport,
        )
        self.state = BackendState()
        self._snapshot = Snapshot()
        self._unreachable = False

    async def run_forever(self) -> None:
        while True:
            await self.refresh()
            await asyncio.sleep(POLL)

    async def refresh(self) -> None:
        try:
            answer = await self.http.post("/internal/v1/state", json={"revision": self.state.revision})
            answer.raise_for_status()
        except httpx.HTTPError as exc:
            if not self._unreachable:
                log.warning("%s (the pages show its last known state)", UNREACHABLE.format(exc))
            self._unreachable = True
            return
        if self._unreachable:
            log.info("the controller answers again")
        self._unreachable = False
        self.state = decode(BackendState, answer.json())
        if self.state.snapshot is not None:
            self._snapshot, self.state.snapshot = self.state.snapshot, None

    async def _action(self, name: str, unreachable: Any = None, **params: Any) -> Any:
        try:
            answer = await self.http.post(f"/internal/v1/actions/{name}", json=params)
            answer.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("action %s not sent: %s", name, UNREACHABLE.format(exc))
            return UNREACHABLE.format(exc) if unreachable is None else unreachable
        await self.refresh()  # the page shows what the action started
        return answer.json()["result"]

    @property
    def snapshot(self) -> Snapshot:
        return self._snapshot

    @property
    def running(self) -> bool:
        return self.state.running

    @property
    def checking_versions(self) -> bool:
        return self.state.checking_versions

    @property
    def locked(self) -> bool:
        return self.state.locked

    @property
    def busy(self) -> str | None:
        return self.state.busy

    @property
    def rescanning(self) -> set[tuple]:
        return {tuple(key) for key in self.state.rescanning}

    @property
    def scans_total(self) -> dict[str, int]:
        return self.state.scans_total

    def activities(self) -> list[Activity]:
        return self.state.activities

    def failed_items(self) -> tuple[list[ImageReport], list[ImageReport], list[ChartReport]]:
        return failed_items(self.settings, self.snapshot)

    def can_rescan_vulnerabilities(self, report: ImageReport) -> bool:
        return can_rescan_vulnerabilities(self.settings, report)

    def same_name_images(self, report: ImageReport) -> list[ImageReport]:
        return same_name_images(self.snapshot, report)

    async def trigger(self) -> bool:
        return await self._action("trigger", unreachable=False)

    async def rescan_image(self, report: ImageReport, versions: bool = True, vulnerabilities: bool = True) -> str | None:
        return await self._action("rescan-image", ref=str(report.image), versions=versions, vulnerabilities=vulnerabilities)

    async def rescan_chart(self, report: ChartReport) -> str | None:
        return await self._action(
            "rescan-chart",
            cluster=report.cluster,
            namespace=report.app_namespace,
            application=report.application,
            chart=report.chart,
        )

    async def retry_failed(self) -> str | None:
        return await self._action("retry-failed")

    def registry_credentials(self, settings: Settings) -> tuple[list[CredentialStatus], dict]:
        return self.state.credentials, self.state.registry_auth

    @property
    def trivy_available(self) -> bool:
        return self.state.trivy_available

    @property
    def trivy_binary(self) -> str:
        return self.state.trivy_binary

    @property
    def trivy_cached(self) -> int:
        return self.state.trivy_cached

    @property
    def trivy_remote(self) -> bool:
        return self.state.trivy_remote

    @property
    def trivy_status(self) -> TrivyStatus | None:
        return self.state.trivy_status

    @property
    def trivy_message(self) -> str | None:
        return self.state.trivy_message

    @property
    def connectivity(self) -> ConnectivityReport | None:
        return self.state.connectivity

    @property
    def admin_running(self) -> set[str]:
        return set(self.state.admin_running)

    async def refresh_trivy_status(self) -> TrivyStatus:
        status = await self._action("trivy-status", unreachable={})
        if status:
            self.state.trivy_status = decode(TrivyStatus, status)
        return self.state.trivy_status or TrivyStatus(datetime.now(UTC), message="the controller cannot be reached")

    async def update_trivy_db(self) -> str | None:
        return await self._action("trivy-db")

    async def clear_trivy_cache(self) -> int:
        return await self._action("trivy-cache", unreachable=0)

    async def test_connectivity(self) -> str | None:
        return await self._action("connectivity")

    def processes(self) -> list[ProcessInfo]:
        return self.state.processes

    async def log_lines(self, after: int = 0) -> list[LogLine]:
        try:
            answer = await self.http.post("/internal/v1/logs", json={"after": after})
            answer.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("log lines not read: %s", UNREACHABLE.format(exc))
            return []
        return decode(list[LogLine], answer.json())
