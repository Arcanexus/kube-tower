"""Compare inventoried images and charts with what their registries publish."""

from __future__ import annotations

import asyncio
import logging

from kube_tower.config import HelmSettings, ImagesSettings
from kube_tower.models import ChartDependency, ChartReport, ImageReport, Status
from kube_tower.registry.helm import HelmClient, normalize_dependency_repository
from kube_tower.registry.oci import OCIClient
from kube_tower.versions import is_newer, latest_matching, latest_semver, parse

log = logging.getLogger(__name__)

# Subcharts of subcharts are read down to this depth (direct subcharts are depth 1).
MAX_DEPENDENCY_DEPTH = 3


def _short(exc: Exception) -> str:
    return (str(exc) or exc.__class__.__name__).splitlines()[0][:300]


def _dependencies(metadata: dict) -> list[ChartDependency]:
    return [
        ChartDependency(name=d.get("name", ""), version=str(d.get("version", "")), repository=d.get("repository", ""))
        for d in metadata.get("dependencies") or []
    ]


class _Memo:
    """Share in-flight lookups so each repository is queried once per refresh."""

    def __init__(self):
        self._tasks: dict[tuple, asyncio.Task] = {}

    def get(self, key: tuple, factory):
        if key not in self._tasks:
            self._tasks[key] = asyncio.ensure_future(factory())
        return self._tasks[key]


class ImageChecker:
    def __init__(self, oci: OCIClient, settings: ImagesSettings, concurrency: int = 8):
        self.oci = oci
        self.settings = settings
        self.sem = asyncio.Semaphore(concurrency)
        self.memo = _Memo()

    async def _tags(self, registry: str, repository: str) -> list[str]:
        async def fetch():
            async with self.sem:
                return await self.oci.list_tags(registry, repository)

        return await self.memo.get(("tags", registry, repository), fetch)

    async def _digest(self, registry: str, repository: str, tag: str) -> str | None:
        async def fetch():
            async with self.sem:
                return await self.oci.get_digest(registry, repository, tag)

        return await self.memo.get(("digest", registry, repository, tag), fetch)

    async def check(self, report: ImageReport) -> None:
        ref = report.image
        try:
            if not ref.tag:
                report.status, report.message = Status.UNKNOWN, "pinned by digest only"
                return
            if parse(ref.tag) is not None:
                tags = await self._tags(ref.registry, ref.repository)
                report.latest_tag = latest_matching(ref.tag, tags, self.settings.include_prerelease)
                report.status = Status.OUTDATED if is_newer(report.latest_tag, ref.tag) else Status.UP_TO_DATE
                await self._fetch_digests(report)
                return
            # Floating tag (latest, stable, ...): compare digests like watchtower does.
            if not self.settings.check_floating_digests or not report.running_digests:
                report.status, report.message = Status.UNKNOWN, f"floating tag '{ref.tag}'"
                return
            report.latest_digest = await self._digest(ref.registry, ref.repository, ref.tag)
            if report.latest_digest in report.running_digests:
                report.status = Status.UP_TO_DATE
            else:
                report.status, report.message = Status.OUTDATED, f"a newer image is published under '{ref.tag}'"
        except Exception as exc:  # noqa: BLE001 - one registry failure must not stop the others
            report.status, report.message = Status.ERROR, _short(exc)
            log.warning("cannot check image %s: %s", ref, report.message)

    async def _fetch_digests(self, report: ImageReport) -> None:
        """Best effort: published digests of the current and latest tags, shown in the image details."""
        if not self.settings.fetch_tag_digests:
            return
        ref = report.image
        try:
            if report.running_digests:
                report.tag_digest = await self._digest(ref.registry, ref.repository, ref.tag)
            if report.status == Status.OUTDATED and report.latest_tag:
                report.latest_digest = await self._digest(ref.registry, ref.repository, report.latest_tag)
        except Exception as exc:  # noqa: BLE001 - informative only, the status is already known
            log.debug("cannot read digests of %s: %s", ref, _short(exc))

    async def check_all(self, reports: list[ImageReport]) -> None:
        await asyncio.gather(*(self.check(r) for r in reports))


class ChartChecker:
    def __init__(self, helm: HelmClient, settings: HelmSettings, concurrency: int = 8):
        self.helm = helm
        self.settings = settings
        self.sem = asyncio.Semaphore(concurrency)
        self.memo = _Memo()

    async def _versions(self, repository: str, chart: str) -> list[str]:
        async def fetch():
            async with self.sem:
                return await self.helm.list_versions(repository, chart)

        return await self.memo.get(("versions", repository, chart), fetch)

    async def _metadata(self, repository: str, chart: str, version: str) -> dict:
        async def fetch():
            async with self.sem:
                return await self.helm.chart_metadata(repository, chart, version)

        return await self.memo.get(("meta", repository, chart, version), fetch)

    async def _git_metadata(self, repository: str, ref: str, path: str) -> dict:
        async def fetch():
            async with self.sem:
                return await self.helm.git_chart_metadata(repository, ref, path)

        return await self.memo.get(("git", repository, ref, path), fetch)

    async def _latest(self, repository: str, chart: str) -> str | None:
        return latest_semver(await self._versions(repository, chart), self.settings.include_prerelease)

    async def check_dependency(self, dep: ChartDependency, depth: int = 1) -> None:
        repository = normalize_dependency_repository(dep.repository)
        if repository is None:
            dep.status, dep.message = Status.UNKNOWN, "local or aliased dependency"
            return
        try:
            dep.latest_version = await self._latest(repository, dep.name)
            if parse(dep.version) is None:
                # Version constraint such as "~1.2" or "1.x": just display the latest one.
                dep.status, dep.message = Status.UNKNOWN, "version is a constraint"
                return
            dep.status = Status.OUTDATED if is_newer(dep.latest_version, dep.version) else Status.UP_TO_DATE
        except Exception as exc:  # noqa: BLE001
            dep.status, dep.message = Status.ERROR, _short(exc)
            log.warning("cannot check subchart %s %s (%s): %s", dep.name, dep.version, dep.repository, dep.message)
            return
        if depth >= MAX_DEPENDENCY_DEPTH:
            return
        try:
            metadata = await self._metadata(repository, dep.name, dep.version)
        except Exception as exc:  # noqa: BLE001 - the subchart itself is checked, only its tree is missing
            log.debug("cannot read subcharts of %s %s: %s", dep.name, dep.version, _short(exc))
            return
        dep.dependencies = _dependencies(metadata)
        await asyncio.gather(*(self.check_dependency(d, depth + 1) for d in dep.dependencies))

    async def check(self, report: ChartReport) -> None:
        metadata: dict | None = None
        try:
            if report.source_type == "git":
                metadata = await self._git_metadata(report.repository, report.git_ref or "HEAD", report.chart)
                report.chart = metadata.get("name", report.chart)
                report.version = str(metadata.get("version", ""))
                # Charts deployed from git follow the git revision: only subcharts can be outdated.
                report.status, report.message = Status.UP_TO_DATE, f"deployed from git ({report.git_ref})"
            else:
                report.latest_version = await self._latest(report.repository, report.chart)
                if parse(report.version) is None:
                    report.status, report.message = Status.UNKNOWN, f"targetRevision '{report.version}' is not a fixed version"
                else:
                    report.status = Status.OUTDATED if is_newer(report.latest_version, report.version) else Status.UP_TO_DATE
                    if self.settings.check_dependencies:
                        metadata = await self._metadata(report.repository, report.chart, report.version)
        except Exception as exc:  # noqa: BLE001
            report.status, report.message = Status.ERROR, _short(exc)
            log.warning(
                "[%s] cannot check chart %s of application %s (%s): %s",
                report.cluster,
                report.chart,
                report.application,
                report.repository,
                report.message,
            )
            return
        if metadata and self.settings.check_dependencies:
            report.dependencies = _dependencies(metadata)
            await asyncio.gather(*(self.check_dependency(d) for d in report.dependencies))

    async def check_all(self, reports: list[ChartReport]) -> None:
        await asyncio.gather(*(self.check(r) for r in reports))
