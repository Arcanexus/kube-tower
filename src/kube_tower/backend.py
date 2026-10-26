"""What the web layer (UI, JSON API, metrics) needs from the scans: the Backend interface.

The pages and the API only go through a Backend, never through the Scanner or the Administration
directly. Today one implementation runs everything in the process (LocalBackend, every role together).
The distributed mode of ADR 0002 adds a backend for `ui` pods that asks the controller over its
internal API: the web layer will not change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from kube_tower.registry.auth import resolve_credentials

if TYPE_CHECKING:
    from kube_tower.administration import Administration, ConnectivityReport
    from kube_tower.config import Settings
    from kube_tower.models import ChartReport, ImageReport, Snapshot
    from kube_tower.registry.auth import CredentialStatus
    from kube_tower.scanner import Activity, Scanner
    from kube_tower.trivy import TrivyStatus


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
    def trigger(self) -> bool: ...
    def rescan_image(self, report: ImageReport, versions: bool = True, vulnerabilities: bool = True) -> str | None: ...
    def rescan_chart(self, report: ChartReport) -> str | None: ...
    def retry_failed(self) -> str | None: ...

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
    def trivy_status(self) -> TrivyStatus | None: ...
    @property
    def trivy_message(self) -> str | None: ...  # outcome of the last database update
    @property
    def connectivity(self) -> ConnectivityReport | None: ...
    @property
    def admin_running(self) -> set[str]: ...  # administration actions in progress: trivy-db, connectivity
    async def refresh_trivy_status(self) -> TrivyStatus: ...
    def update_trivy_db(self) -> str | None: ...
    def clear_trivy_cache(self) -> int: ...
    def test_connectivity(self) -> str | None: ...


class LocalBackend:
    """Every role in this process: the Scanner and the Administration of the process, as before."""

    def __init__(self, scanner: Scanner, administration: Administration):
        self.scanner = scanner
        self.administration = administration

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

    def trigger(self) -> bool:
        return self.scanner.trigger()

    def rescan_image(self, report: ImageReport, versions: bool = True, vulnerabilities: bool = True) -> str | None:
        return self.scanner.rescan_image(report, versions, vulnerabilities)

    def rescan_chart(self, report: ChartReport) -> str | None:
        return self.scanner.rescan_chart(report)

    def retry_failed(self) -> str | None:
        return self.scanner.retry_failed()

    def registry_credentials(self, settings: Settings) -> tuple[list[CredentialStatus], dict]:
        _, credentials = resolve_credentials(settings.registries, pull_secrets=self.scanner.pull_secrets)
        return credentials, {c.registry: self.scanner.registry_auth.get(c.registry) for c in credentials}

    @property
    def trivy_available(self) -> bool:
        return self.scanner.trivy.available

    @property
    def trivy_binary(self) -> str:
        return self.scanner.trivy.settings.binary

    @property
    def trivy_cached(self) -> int:
        return len(self.scanner.trivy.cache)

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

    def update_trivy_db(self) -> str | None:
        return self.administration.update_trivy_db()

    def clear_trivy_cache(self) -> int:
        return self.administration.clear_trivy_cache()

    def test_connectivity(self) -> str | None:
        return self.administration.test_connectivity()
