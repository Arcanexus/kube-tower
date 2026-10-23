"""Helm chart sources: classic HTTP repositories (index.yaml), OCI registries and git."""

from __future__ import annotations

import io
import logging
import os
import re
import tarfile
from urllib.parse import urljoin, urlparse

import httpx
import yaml

from kube_tower.config import GitSettings
from kube_tower.registry.auth import normalize_host
from kube_tower.registry.oci import OCIClient, RegistryError

log = logging.getLogger(__name__)

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


def chart_yaml_from_archive(data: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            # <chart>/Chart.yaml at the root of the archive, not the subcharts' ones
            if member.name.count("/") == 1 and member.name.endswith("/Chart.yaml"):
                return yaml.safe_load(tar.extractfile(member).read()) or {}
    raise RegistryError("Chart.yaml not found in chart archive")


class HelmClient:
    def __init__(self, http: httpx.AsyncClient, oci: OCIClient, git: GitSettings):
        self.http = http
        self.oci = oci
        self.git = git
        self._indexes: dict[str, dict] = {}

    def _auth(self, url: str) -> tuple[str, str] | None:
        """Basic auth for private HTTP Helm repositories, from the per registry credentials."""
        return self.oci.credentials.get(normalize_host(url))

    async def _index(self, repository: str) -> dict:
        repository = repository.rstrip("/")
        if repository not in self._indexes:
            resp = await self.http.get(f"{repository}/index.yaml", auth=self._auth(repository), follow_redirects=True)
            if resp.status_code != 200:
                raise RegistryError(f"index.yaml fetch failed ({resp.status_code}) for {repository}")
            self._indexes[repository] = yaml.safe_load(resp.text) or {}
        return self._indexes[repository]

    async def list_versions(self, repository: str, chart: str) -> list[str]:
        if is_oci(repository):
            registry, path = split_oci(repository, chart)
            return await self.oci.list_tags(registry, path)
        entries = (await self._index(repository)).get("entries", {}).get(chart)
        if entries is None:
            raise RegistryError(f"chart {chart} not found in {repository}")
        return [e["version"] for e in entries]

    async def chart_metadata(self, repository: str, chart: str, version: str) -> dict:
        """Return the Chart.yaml of a published chart version (used to read its dependencies)."""
        if is_oci(repository):
            registry, path = split_oci(repository, chart)
            manifest = await self.oci.get_manifest(registry, path, version, HELM_MANIFEST_ACCEPT)
            layer = next((layer for layer in manifest.get("layers", []) if layer.get("mediaType") == HELM_CHART_LAYER), None)
            if layer is None:
                raise RegistryError(f"{repository}/{chart}:{version} is not a helm chart")
            return chart_yaml_from_archive(await self.oci.get_blob(registry, path, layer["digest"]))
        entries = (await self._index(repository)).get("entries", {}).get(chart, [])
        entry = next((e for e in entries if e.get("version") == version), None)
        if entry is None:
            raise RegistryError(f"version {version} of {chart} not found in {repository}")
        url = urljoin(f"{repository.rstrip('/')}/", entry["urls"][0])
        resp = await self.http.get(url, auth=self._auth(url), follow_redirects=True)
        if resp.status_code != 200:
            raise RegistryError(f"chart download failed ({resp.status_code}) for {url}")
        return chart_yaml_from_archive(resp.content)

    async def git_chart_metadata(self, repo_url: str, ref: str, path: str) -> dict:
        """Fetch `<path>/Chart.yaml` from a git repository through its raw file URL."""
        parsed = urlparse(repo_url if "://" in repo_url else f"https://{repo_url.split('@')[-1].replace(':', '/', 1)}")
        template = self.git.raw_url_templates.get(parsed.hostname or "")
        if template is None:
            raise RegistryError(f"no raw URL template configured for git host {parsed.hostname}")
        owner, _, repo = parsed.path.strip("/").removesuffix(".git").partition("/")
        ref = "HEAD" if ref in ("", "HEAD") else ref
        url = template.format(owner=owner, repo=repo, ref=ref, path=f"{path.strip('/')}/Chart.yaml".lstrip("/"))
        headers = {}
        if token := os.environ.get(self.git.token_env):
            headers["Authorization"] = f"Bearer {token}"
        resp = await self.http.get(url, headers=headers, follow_redirects=True)
        if resp.status_code != 200:
            raise RegistryError(f"Chart.yaml fetch failed ({resp.status_code}) for {url}")
        return yaml.safe_load(resp.text) or {}


def normalize_dependency_repository(repository: str) -> str | None:
    """Return a usable repository URL, or None for local (`file://`) or alias (`@name`) deps."""
    if not repository or repository.startswith(("file://", "@", "alias:")):
        return None
    return re.sub(r"/+$", "", repository)
