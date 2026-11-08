"""Helm chart sources: classic HTTP repositories (index.yaml), OCI registries and git."""

from __future__ import annotations

import asyncio
import io
import logging
import os
import re
import tarfile
import threading
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urljoin, urlparse

import httpx
import yaml

from kube_tower.config import GitSettings
from kube_tower.errors import GIT_CREDENTIALS, http_error_message
from kube_tower.helmvalues import parse_values
from kube_tower.registry.auth import normalize_host
from kube_tower.registry.oci import OCIClient, RegistryError, parse_created, require_https

log = logging.getLogger(__name__)

YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

HELM_CHART_LAYER = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
HELM_MANIFEST_ACCEPT = "application/vnd.oci.image.manifest.v1+json"


def is_oci(repository: str) -> bool:
    """ArgoCD stores OCI helm repos without scheme (e.g. `ghcr.io/org/charts`)."""
    return repository.startswith("oci://") or "://" not in repository


def split_oci(repository: str, chart: str) -> tuple[str, str]:
    """`oci://ghcr.io/org/charts` + `mychart` -> (`ghcr.io`, `org/charts/mychart`)."""
    path = repository.removeprefix("oci://").rstrip("/")
    registry, _, prefix = path.partition("/")
    return registry, f"{prefix}/{chart}".lstrip("/")


def split_oci_url(url: str, version: str) -> tuple[str, str, str]:
    """`oci://registry-1.docker.io/bitnamicharts/redis:21.0.0` -> (`registry-1.docker.io`, `bitnamicharts/redis`,
    `21.0.0`). Without a tag, the chart version is the tag (Helm pushes each version under its own tag).
    """
    registry, _, path = url.removeprefix("oci://").partition("/")
    name, _, tag = path.rpartition("/")[2].partition(":")
    return registry, f"{path.rpartition('/')[0]}/{name}".lstrip("/"), tag or version


@dataclass
class ChartFiles:
    """What kube-tower reads in a chart: its Chart.yaml, its default values and the value files asked for."""

    metadata: dict
    values: dict = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)  # path in the chart -> content


def chart_files_from_archive(data: bytes, extra: tuple[str, ...] = ()) -> ChartFiles:
    """Chart.yaml, values.yaml and the `extra` files at the root of the chart (not the subcharts' ones)."""
    wanted = {"Chart.yaml", "values.yaml", *extra}
    found: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            path = member.name.partition("/")[2]
            if member.isfile() and path in wanted:
                found[path] = tar.extractfile(member).read().decode(errors="replace")
    if "Chart.yaml" not in found:
        raise RegistryError("Chart.yaml not found in chart archive")
    return ChartFiles(
        yaml.safe_load(found.pop("Chart.yaml")) or {},
        parse_values(found.pop("values.yaml", None)),
        {path: text for path, text in found.items()},
    )


def chart_yaml_from_archive(data: bytes) -> dict:
    return chart_files_from_archive(data).metadata


def _created(entry: dict) -> dict:
    """{"created": date} of an index entry, as text (yaml parses an unquoted timestamp into a datetime)."""
    value = entry.get("created")
    if isinstance(value, datetime):
        value = value.isoformat()
    return {"created": value} if isinstance(value, str) and value else {}


def _trim_index(index: dict | None) -> dict:
    """Keep only what kube-tower reads from an index.yaml (versions, archive URLs, dates): a parsed index
    kept between scans then takes a fraction of the memory of the full one (descriptions, digests...).
    """
    entries = (index or {}).get("entries") or {}
    return {
        "entries": {
            chart: [
                {"version": e.get("version"), "urls": e.get("urls") or []} | _created(e)
                for e in versions or []
                if isinstance(e, dict)
            ]
            for chart, versions in entries.items()
        }
    }


class IndexCache:
    """The parsed index.yaml of the HTTP Helm repositories with their ETag / Last-Modified, kept between
    scans: the next scans download an index again only when the repository says it changed (HTTP 304).
    Shared by the scans and rescans, which run in different threads.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[dict[str, str], dict]] = {}  # repository -> (validators, index)

    def get(self, repository: str) -> tuple[dict[str, str], dict] | None:
        with self._lock:
            return self._entries.get(repository)

    def put(self, repository: str, response: httpx.Response, index: dict) -> None:
        validators = {}
        if etag := response.headers.get("ETag"):
            validators["If-None-Match"] = etag
        if modified := response.headers.get("Last-Modified"):
            validators["If-Modified-Since"] = modified
        with self._lock:
            if validators:
                self._entries[repository] = (validators, index)
            else:  # cannot be revalidated: downloaded again at each scan
                self._entries.pop(repository, None)


class HelmClient:
    def __init__(self, http: httpx.AsyncClient, oci: OCIClient, git: GitSettings, index_cache: IndexCache | None = None):
        self.http = http
        self.oci = oci
        self.git = git
        self.index_cache = index_cache or IndexCache()
        self._indexes: dict[str, asyncio.Future[dict]] = {}

    async def _auth(self, url: str) -> tuple[str, str] | None:
        """Basic auth for private HTTP Helm repositories, from the per registry credentials (https:// only)."""
        host = normalize_host(url)
        credentials = await self.oci.credentials.get(host)
        if credentials:
            require_https(url, f"the Helm repository of {host}, which has credentials in registries.credentials,")
        return credentials

    async def _index(self, repository: str) -> dict:
        """The index.yaml of a Helm repository, downloaded once per scan whatever the number of charts."""
        repository = repository.rstrip("/")
        if repository not in self._indexes:
            self._indexes[repository] = asyncio.ensure_future(self._fetch_index(repository))
        return await self._indexes[repository]

    async def _fetch_index(self, repository: str) -> dict:
        cached = self.index_cache.get(repository)
        resp = await self.oci.client_for(httpx.URL(repository).host).get(
            f"{repository}/index.yaml",
            auth=await self._auth(repository),
            headers=cached[0] if cached else None,
            follow_redirects=True,
        )
        if resp.status_code == 304 and cached:
            log.debug("index.yaml of %s unchanged since the last scan", repository)
            return cached[1]
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot read the index.yaml of the Helm repository {repository}", resp))
        # Big indexes (tens of MB) take seconds to minutes to parse on small nodes: parse them in a
        # thread, with libyaml when available, so the other requests of the scan keep being served.
        index = _trim_index(await asyncio.to_thread(yaml.load, resp.content, Loader=YAML_LOADER))
        log.debug("index.yaml of %s: %d KB, %d chart(s)", repository, len(resp.content) // 1024, len(index["entries"]))
        self.index_cache.put(repository, resp, index)
        return index

    async def ping(self, repository: str) -> str:
        """Check that an HTTP Helm repository serves its index.yaml (without downloading it).
        Returns what was checked, raises RegistryError when it fails.
        """
        url = f"{repository.rstrip('/')}/index.yaml"
        auth = await self._auth(repository)
        async with self.oci.client_for(httpx.URL(url).host).stream("GET", url, auth=auth, follow_redirects=True) as resp:
            if resp.status_code != 200:
                raise RegistryError(http_error_message(f"cannot read the index.yaml of the Helm repository {repository}", resp))
        return f"index.yaml served {'with credentials' if auth else 'anonymously'}"

    async def artifact_hub_repository(self, base_url: str, chart: str) -> str | None:
        """The repository of a chart according to Artifact Hub: among the Helm packages with this exact name,
        the official one, else one of a verified publisher, else the most starred. None when there is none."""
        url = f"{base_url.rstrip('/')}/api/v1/packages/search"
        resp = await self.oci.client_for(httpx.URL(url).host).get(
            url, params={"ts_query_web": chart, "kind": "0", "limit": "60"}, follow_redirects=True
        )
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot search the chart {chart} on Artifact Hub", resp))
        found = resp.json().get("packages") or []
        packages = [p for p in found if p.get("name") == chart and (p.get("repository") or {}).get("url")]
        if not packages:
            return None

        def rank(p: dict) -> tuple:
            repo = p["repository"]
            return (bool(p.get("official") or repo.get("official")), bool(repo.get("verified_publisher")), p.get("stars") or 0)

        return max(packages, key=rank)["repository"]["url"].rstrip("/")

    async def list_versions(self, repository: str, chart: str) -> list[str]:
        if is_oci(repository):
            registry, path = split_oci(repository, chart)
            return await self.oci.list_tags(registry, path)
        entries = (await self._index(repository)).get("entries", {}).get(chart)
        if entries is None:
            raise RegistryError(f"chart {chart} is not published in the Helm repository {repository}: check the chart name")
        return [e["version"] for e in entries]

    async def release_date(self, repository: str, chart: str, version: str) -> datetime | None:
        """When a chart version was published: `created` in the index.yaml of an HTTP repository, the
        `org.opencontainers.image.created` annotation (set by `helm push` since Helm 3.15) in an OCI one."""
        if is_oci(repository):
            registry, path = split_oci(repository, chart)
            return await self.oci.get_created(registry, path, version)
        entries = (await self._index(repository)).get("entries", {}).get(chart) or []
        return parse_created(next((e.get("created") for e in entries if e.get("version") == version), None))

    async def chart_metadata(self, repository: str, chart: str, version: str) -> dict:
        """Return the Chart.yaml of a published chart version (used to read its dependencies)."""
        return (await self.chart_files(repository, chart, version)).metadata

    async def chart_files(self, repository: str, chart: str, version: str, extra: tuple[str, ...] = ()) -> ChartFiles:
        """Chart.yaml, default values and `extra` files of a published chart version."""
        return chart_files_from_archive(await self._chart_archive(repository, chart, version), extra)

    async def _chart_archive(self, repository: str, chart: str, version: str) -> bytes:
        if is_oci(repository):
            registry, path = split_oci(repository, chart)
            return await self._oci_chart_archive(registry, path, version)
        entries = (await self._index(repository)).get("entries", {}).get(chart, [])
        # ArgoCD accepts a leading "v" (targetRevision: v4.11.0) for a chart published as 4.11.0.
        entry = next((e for e in entries if str(e.get("version", "")).removeprefix("v") == version.removeprefix("v")), None)
        if entry is None:
            raise RegistryError(f"version {version} of chart {chart} is not published in {repository} (removed from the index?)")
        url = urljoin(f"{repository.rstrip('/')}/", entry["urls"][0])
        if url.startswith("oci://"):
            # The index can point to charts pushed to an OCI registry (Bitnami since 2025):
            # httpx cannot download them, the registry API serves them.
            registry, path, tag = split_oci_url(url, version)
            return await self._oci_chart_archive(registry, path, tag)
        resp = await self.oci.client_for(httpx.URL(url).host).get(url, auth=await self._auth(url), follow_redirects=True)
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot download chart {chart} {version}", resp))
        return resp.content

    async def _oci_chart_archive(self, registry: str, path: str, version: str) -> bytes:
        manifest = await self.oci.get_manifest(registry, path, version, HELM_MANIFEST_ACCEPT)
        layer = next((layer for layer in manifest.get("layers", []) if layer.get("mediaType") == HELM_CHART_LAYER), None)
        if layer is None:
            raise RegistryError(f"{registry}/{path}:{version} is an OCI artifact but not a Helm chart")
        return await self.oci.get_blob(registry, path, layer["digest"])

    async def git_chart_metadata(self, repo_url: str, ref: str, path: str) -> dict:
        """Fetch `<path>/Chart.yaml` from a git repository through its raw file URL."""
        return yaml.safe_load(await self.git_file(repo_url, ref, f"{path.strip('/')}/Chart.yaml")) or {}

    async def git_chart_values(self, repo_url: str, ref: str, path: str) -> dict:
        """The default values of a chart in a git repository (`<path>/values.yaml`, empty when it has none)."""
        return parse_values(await self.git_file(repo_url, ref, f"{path.strip('/')}/values.yaml", missing_ok=True))

    async def git_file(self, repo_url: str, ref: str, path: str, missing_ok: bool = False) -> str | None:
        """A file of a git repository, through its raw file URL (None for a missing file with `missing_ok`)."""
        parsed = urlparse(repo_url if "://" in repo_url else f"https://{repo_url.split('@')[-1].replace(':', '/', 1)}")
        template = self.git.raw_url_templates.get(parsed.hostname or "")
        if template is None:
            raise RegistryError(f"no raw URL template for git host {parsed.hostname}: add one in git.rawUrlTemplates")
        owner, _, repo = parsed.path.strip("/").removesuffix(".git").partition("/")
        ref = "HEAD" if ref in ("", "HEAD") else ref
        path = path.strip("/")
        url = template.format(owner=owner, repo=repo, ref=ref, path=path)
        headers = {}
        if token := os.environ.get(self.git.token_env):
            require_https(url, f"the raw URL template of {parsed.hostname} (git.rawUrlTemplates), with a git token,")
            headers["Authorization"] = f"Bearer {token}"
        resp = await self.http.get(url, headers=headers, follow_redirects=True)
        if resp.status_code == 404 and missing_ok:
            return None
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot read {path} at {ref} in {repo_url}", resp, GIT_CREDENTIALS))
        return resp.text


def normalize_dependency_repository(repository: str) -> str | None:
    """Return a usable repository URL, or None for local (`file://`) or alias (`@name`) deps."""
    if not repository or repository.startswith(("file://", "@", "alias:")):
        return None
    return re.sub(r"/+$", "", repository)
