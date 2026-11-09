"""Compare inventoried images and charts with what their registries publish."""

from __future__ import annotations

import asyncio
import fnmatch
import logging
from collections import Counter, OrderedDict
from datetime import datetime

from kube_tower.config import HelmSettings, ImagesSettings
from kube_tower.errors import GIT_CREDENTIALS, explain
from kube_tower.helmvalues import merge, not_deployed, parse_values, subchart_values
from kube_tower.models import ChartDependency, ChartReport, ImageReport, Status
from kube_tower.registry.helm import ChartFiles, HelmClient, normalize_dependency_repository
from kube_tower.registry.oci import OCIClient
from kube_tower.versions import is_newer, latest_matching, latest_semver, parse

log = logging.getLogger(__name__)

# Subcharts of subcharts are read down to this depth (direct subcharts are depth 1).
MAX_DEPENDENCY_DEPTH = 3


def _dependencies(metadata: dict) -> list[ChartDependency]:
    return [
        ChartDependency(
            name=d.get("name", ""),
            version=str(d.get("version", "")),
            repository=d.get("repository", ""),
            alias=d.get("alias") or "",
            condition=str(d.get("condition") or ""),
            tags=[str(t) for t in d.get("tags") or []],
        )
        for d in metadata.get("dependencies") or []
    ]


def _mark_deployed(dependencies: list[ChartDependency], values: dict | None, tags: dict) -> None:
    """Note the subcharts that the `values` of their parent chart leave out (unknown values: all deployed)."""
    if values is None:
        return
    for d in dependencies:
        d.not_deployed = not_deployed(d, values, tags)


def _summary(statuses) -> str:
    counts = Counter(s.value for s in statuses)
    return ", ".join(f"{counts[s.value]} {s.value}" for s in Status if counts[s.value]) or "nothing to check"


class _ReleaseDates:
    """Release dates already read, kept between scans (a published version keeps its date): each one is
    asked once per process. Failed lookups are not kept, the next scan tries again."""

    def __init__(self, size: int = 20000):
        self.size = size
        self._dates: OrderedDict[tuple, datetime | None] = OrderedDict()

    def get(self, key: tuple) -> tuple[bool, datetime | None]:
        if key in self._dates:
            self._dates.move_to_end(key)
            return True, self._dates[key]
        return False, None

    def put(self, key: tuple, value: datetime | None) -> None:
        self._dates[key] = value
        self._dates.move_to_end(key)
        while len(self._dates) > self.size:
            self._dates.popitem(last=False)


RELEASE_DATES = _ReleaseDates()


async def _release_date(memo: _Memo, sem: asyncio.Semaphore, key: tuple, lookup) -> datetime | None:
    """Best effort: the date `lookup` reads, None when it fails (logged at debug level)."""
    known, date = RELEASE_DATES.get(key)
    if known:
        return date

    async def fetch():
        async with sem:
            date = await lookup()
        RELEASE_DATES.put(key, date)
        return date

    try:
        return await memo.get(("released", *key), fetch)
    except Exception as exc:  # noqa: BLE001 - informative only, the status is already known
        log.debug("no release date for %s: %s", " ".join(str(k) for k in key if k), explain(exc))
        return None


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
        await self._check(report)
        if report.status != Status.ERROR:  # errors are logged as warnings
            log.debug(
                "image %s: %s%s%s",
                report.image,
                report.status.value,
                f" (latest {report.latest_tag})" if report.latest_tag else "",
                f", {report.message}" if report.message else "",
            )

    async def _check(self, report: ImageReport) -> None:
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
                await self._fetch_release_date(report)
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
            report.status, report.message = Status.ERROR, explain(exc)
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
            log.debug("cannot read digests of %s: %s", ref, explain(exc))

    async def _fetch_release_date(self, report: ImageReport) -> None:
        """Best effort: when the current and latest tags were built or pushed, shown next to them."""
        if not self.settings.fetch_release_dates or not report.latest_tag:
            return
        ref = report.image

        def released(tag: str):
            key = ("image", ref.registry, ref.repository, tag)
            return _release_date(self.memo, self.sem, key, lambda: self.oci.get_created(ref.registry, ref.repository, tag))

        if ref.tag == report.latest_tag:
            report.latest_released = report.current_released = await released(ref.tag)
        else:
            report.latest_released, report.current_released = await asyncio.gather(released(report.latest_tag), released(ref.tag))

    async def check_all(self, reports: list[ImageReport]) -> None:
        log.info("checking %d image(s) against their registries", len(reports))
        await asyncio.gather(*(self.check(r) for r in reports))
        log.info("images checked: %s", _summary(r.status for r in reports))


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

    async def _files(self, repository: str, chart: str, version: str, extra: tuple[str, ...] = ()) -> ChartFiles:
        async def fetch():
            async with self.sem:
                return await self.helm.chart_files(repository, chart, version, extra)

        return await self.memo.get(("files", repository, chart, version, extra), fetch)

    async def _git_metadata(self, repository: str, ref: str, path: str) -> dict:
        async def fetch():
            async with self.sem:
                return await self.helm.git_chart_metadata(repository, ref, path)

        return await self.memo.get(("git", repository, ref, path), fetch)

    async def _git_values(self, repository: str, ref: str, path: str) -> dict:
        async def fetch():
            async with self.sem:
                return await self.helm.git_chart_values(repository, ref, path)

        return await self.memo.get(("git-values", repository, ref, path), fetch)

    async def _git_file(self, repository: str, ref: str, path: str) -> str | None:
        async def fetch():
            async with self.sem:
                return await self.helm.git_file(repository, ref, path, missing_ok=True)

        return await self.memo.get(("git-file", repository, ref, path), fetch)

    async def _release_values(self, report: ChartReport, defaults: dict, chart_files: dict[str, str]) -> dict | None:
        """The values ArgoCD renders the chart with: its defaults, the value files, then the inline values
        (booleans only, see ChartReport.inline_values). None when a value file cannot be read.
        """
        values = defaults
        try:
            for vf in report.value_files:
                if vf.in_chart:
                    text = chart_files.get(vf.path)
                elif vf.repository:
                    text = await self._git_file(vf.repository, vf.revision, vf.path)
                else:
                    raise ValueError(f"value file {vf.path} cannot be read by kube-tower (URL or unknown $ref)")
                if text is None:
                    if report.ignore_missing_value_files:
                        continue
                    hint = (
                        ""
                        if vf.in_chart
                        else f" in {vf.repository} at {vf.revision} (private repository without {GIT_CREDENTIALS}?)"
                    )
                    raise ValueError(f"value file {vf.path} not found{hint}")
                values = merge(values, parse_values(text))
        except Exception as exc:  # noqa: BLE001 - the versions are still checked, every subchart counts as deployed
            log.warning(
                "[%s] cannot read the Helm values of application %s, every subchart of %s is considered deployed: %s",
                report.cluster,
                report.application,
                report.chart,
                explain(exc),
            )
            return None
        return merge(values, report.inline_values)

    async def _latest(self, repository: str, chart: str) -> str | None:
        return latest_semver(await self._versions(repository, chart), self.settings.include_prerelease)

    async def _released(self, repository: str, chart: str, version: str | None) -> datetime | None:
        """Best effort: when `version` of the chart was published."""
        if not self.settings.fetch_release_dates or not version:
            return None
        key = ("chart", repository, chart, version)
        return await _release_date(self.memo, self.sem, key, lambda: self.helm.release_date(repository, chart, version))

    async def check_dependency(self, dep: ChartDependency, depth: int = 1, parent: dict | None = None, tags=None) -> None:
        """Check a subchart, then its own subcharts. `parent` holds the values of the chart that includes it
        (None when unknown) and `tags` the `tags:` block of the release values.
        """
        repository = normalize_dependency_repository(dep.repository)
        if repository is None:
            dep.status, dep.message = Status.UNKNOWN, "local or aliased dependency"
            log.debug("subchart %s %s: %s (%s)", dep.name, dep.version, dep.message, dep.repository)
            return
        try:
            dep.latest_version = await self._latest(repository, dep.name)
            dep.latest_released = await self._released(repository, dep.name, dep.latest_version)
            if parse(dep.version) is None:
                # Version constraint such as "~1.2" or "1.x": just display the latest one.
                dep.status, dep.message = Status.UNKNOWN, "version is a constraint"
                log.debug("subchart %s %s: version is a constraint (latest %s)", dep.name, dep.version, dep.latest_version)
                return
            dep.status = Status.OUTDATED if is_newer(dep.latest_version, dep.version) else Status.UP_TO_DATE
        except Exception as exc:  # noqa: BLE001
            dep.status, dep.message = Status.ERROR, explain(exc)
            log.warning("cannot check subchart %s %s (%s): %s", dep.name, dep.version, dep.repository, dep.message)
            return
        log.debug("subchart %s %s: %s (latest %s)", dep.name, dep.version, dep.status.value, dep.latest_version)
        if not dep.deployed:
            log.debug("subchart %s %s: not deployed (%s)", dep.name, dep.version, dep.not_deployed)
            return  # nor are its own subcharts
        if depth >= MAX_DEPENDENCY_DEPTH:
            return
        try:
            files = await self._files(repository, dep.name, dep.version)
        except Exception as exc:  # noqa: BLE001 - the subchart itself is checked, only its tree is missing
            log.debug("cannot read subcharts of %s %s: %s", dep.name, dep.version, explain(exc))
            return
        dep.dependencies = _dependencies(files.metadata)
        values = None if parent is None else subchart_values(dep, parent, files.values)
        _mark_deployed(dep.dependencies, values, tags or {})
        await asyncio.gather(*(self.check_dependency(d, depth + 1, values, tags) for d in dep.dependencies))

    async def check(self, report: ChartReport) -> None:
        await self._check(report)
        if report.status != Status.ERROR:  # errors are logged as warnings
            log.debug(
                "[%s] chart %s %s of application %s: %s%s%s",
                report.cluster,
                report.chart,
                report.version,
                report.application,
                report.status.value,
                f" (latest {report.latest_version})" if report.latest_version else "",
                f", {len(report.dependencies)} subchart(s)" if report.dependencies else "",
            )

    async def _repository(self, chart: str) -> str | None:
        """The repository of a chart whose release does not record it: helm.repositories, then Artifact Hub."""
        for pattern, repository in self.settings.repositories.items():
            if fnmatch.fnmatchcase(chart, pattern):
                return repository.rstrip("/")
        if not self.settings.artifact_hub_url:
            return None

        async def fetch():
            async with self.sem:
                return await self.helm.artifact_hub_repository(self.settings.artifact_hub_url, chart)

        return await self.memo.get(("artifact-hub", chart), fetch)

    async def _without_repository(self, report: ChartReport) -> bool:
        """Find the repository of a Helm release; when there is none, check only the subcharts recorded in
        the release (their repositories are in its Chart.yaml) and return False."""
        if report.manager == "helm":
            try:
                report.repository = await self._repository(report.chart) or ""
            except Exception as exc:  # noqa: BLE001 - Artifact Hub unreachable: the subcharts are still checked
                report.message = f"repository unknown, Artifact Hub lookup failed: {explain(exc)}"
            else:
                if report.repository:
                    return True
                report.message = "repository unknown: add the chart to helm.repositories"
        report.status, report.message = Status.UNKNOWN, report.message or "repository unknown"
        if report.dependencies and self.settings.check_dependencies:
            values = report.inline_values
            tags = values.get("tags") if isinstance(values.get("tags"), dict) else {}
            _mark_deployed(report.dependencies, values, tags)
            await asyncio.gather(*(self.check_dependency(d, 1, values, tags) for d in report.dependencies))
        return False

    async def _check(self, report: ChartReport) -> None:
        if not report.repository and not await self._without_repository(report):
            return
        metadata: dict | None = None
        defaults: dict = {}
        chart_files: dict[str, str] = {}
        try:
            if report.source_type == "git":
                # `chart` holds the path until Chart.yaml is read, then the chart name (rescans use `path`).
                path = report.path if report.path is not None else report.chart
                metadata = await self._git_metadata(report.repository, report.git_ref or "HEAD", path)
                if self.settings.check_dependencies and metadata.get("dependencies"):
                    defaults = await self._git_values(report.repository, report.git_ref or "HEAD", path)
                report.chart = metadata.get("name", report.chart)
                report.version = str(metadata.get("version", ""))
                # Charts deployed from git follow the git revision: only subcharts can be outdated.
                report.status, report.message = Status.UP_TO_DATE, f"deployed from git ({report.git_ref})"
            else:
                report.latest_version = await self._latest(report.repository, report.chart)
                report.latest_released = await self._released(report.repository, report.chart, report.latest_version)
                if parse(report.version) is None:
                    what = "targetRevision" if report.manager == "argocd" else "version"
                    report.status, report.message = Status.UNKNOWN, f"{what} '{report.version}' is not a fixed version"
                else:
                    report.status = Status.OUTDATED if is_newer(report.latest_version, report.version) else Status.UP_TO_DATE
                    if self.settings.check_dependencies:
                        extra = tuple(vf.path for vf in report.value_files if vf.in_chart)
                        files = await self._files(report.repository, report.chart, report.version, extra)
                        metadata, defaults, chart_files = files.metadata, files.values, files.files
        except Exception as exc:  # noqa: BLE001
            report.status, report.message = Status.ERROR, explain(exc)
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
            values = await self._release_values(report, defaults, chart_files) if report.dependencies else None
            tags = values.get("tags") if values and isinstance(values.get("tags"), dict) else {}
            _mark_deployed(report.dependencies, values, tags)
            await asyncio.gather(*(self.check_dependency(d, 1, values, tags) for d in report.dependencies))

    async def check_all(self, reports: list[ChartReport]) -> None:
        log.info("checking %d Helm chart(s) against their repositories", len(reports))
        await asyncio.gather(*(self.check(r) for r in reports))
        log.info("Helm charts checked: %s", _summary(r.worst_status for r in reports))
