import asyncio
import io
import tarfile

import httpx
import pytest
import respx
import yaml

from kube_tower.config import GitSettings
from kube_tower.registry.helm import (
    HELM_CHART_LAYER,
    HelmClient,
    chart_yaml_from_archive,
    is_oci,
    normalize_dependency_repository,
)
from kube_tower.registry.oci import OCIClient, RegistryError


def _archive(chart: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in [
            (f"{chart['name']}/Chart.yaml", chart),
            (f"{chart['name']}/charts/sub/Chart.yaml", {"name": "sub"}),
        ]:
            data = yaml.safe_dump(content).encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


INDEX = yaml.safe_dump(
    {
        "entries": {
            "app": [
                {"version": "1.1.0", "urls": ["app-1.1.0.tgz"]},
                {"version": "1.0.0", "urls": ["https://cdn.example.com/app-1.0.0.tgz"]},
            ]
        }
    }
)


def test_helpers():
    assert is_oci("oci://ghcr.io/x") and is_oci("ghcr.io/x") and not is_oci("https://charts.example.com")
    assert normalize_dependency_repository("file://../common") is None
    assert normalize_dependency_repository("@bitnami") is None
    assert normalize_dependency_repository("https://charts.example.com/") == "https://charts.example.com"
    with pytest.raises(RegistryError):
        chart_yaml_from_archive(_empty_archive())


def _empty_archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz"):
        pass
    return buf.getvalue()


@respx.mock
async def test_http_repository_with_basic_auth():
    index = respx.get("https://charts.example.com/index.yaml").respond(200, text=INDEX)
    respx.get("https://charts.example.com/app-1.1.0.tgz").respond(
        200, content=_archive({"name": "app", "version": "1.1.0", "dependencies": [{"name": "redis"}]})
    )
    async with httpx.AsyncClient() as http:
        helm = HelmClient(http, OCIClient(http, {"charts.example.com": ("u", "p")}), GitSettings())
        assert await helm.list_versions("https://charts.example.com", "app") == ["1.1.0", "1.0.0"]
        meta = await helm.chart_metadata("https://charts.example.com", "app", "1.1.0")
        with pytest.raises(RegistryError, match="chart missing is not published"):
            await helm.list_versions("https://charts.example.com", "missing")
        with pytest.raises(RegistryError, match="version 9.9.9"):
            await helm.chart_metadata("https://charts.example.com", "app", "9.9.9")
    assert meta["dependencies"] == [{"name": "redis"}]
    assert index.call_count == 1  # index cached
    assert index.calls[0].request.headers["authorization"].startswith("Basic ")


@respx.mock
async def test_http_repository_errors():
    respx.get("https://down.example.com/index.yaml").respond(500)
    async with httpx.AsyncClient() as http:
        helm = HelmClient(http, OCIClient(http), GitSettings())
        with pytest.raises(RegistryError, match="500"):
            await helm.list_versions("https://down.example.com", "app")


@respx.mock
async def test_oci_chart():
    respx.get("https://ghcr.io/v2/org/charts/app/tags/list?n=1000").respond(200, json={"tags": ["1.0.0", "1.2.0"]})
    respx.get("https://ghcr.io/v2/org/charts/app/manifests/1.2.0").respond(
        200, json={"layers": [{"mediaType": HELM_CHART_LAYER, "digest": "sha256:abc"}]}
    )
    respx.get("https://ghcr.io/v2/org/charts/app/blobs/sha256:abc").respond(
        200, content=_archive({"name": "app", "version": "1.2.0"})
    )
    respx.get("https://ghcr.io/v2/org/charts/notchart/manifests/1.0.0").respond(200, json={"layers": []})
    async with httpx.AsyncClient() as http:
        helm = HelmClient(http, OCIClient(http), GitSettings())
        assert await helm.list_versions("oci://ghcr.io/org/charts", "app") == ["1.0.0", "1.2.0"]
        assert (await helm.chart_metadata("ghcr.io/org/charts", "app", "1.2.0"))["version"] == "1.2.0"
        with pytest.raises(RegistryError, match="not a Helm chart"):
            await helm.chart_metadata("oci://ghcr.io/org/charts", "notchart", "1.0.0")


@respx.mock
async def test_git_sources():
    respx.get("https://gitlab.com/grp/repo/-/raw/v1/charts/app/Chart.yaml").respond(200, text="name: app\nversion: 2.0.0\n")
    respx.get("https://raw.githubusercontent.com/org/repo/HEAD/missing/Chart.yaml").respond(404)
    async with httpx.AsyncClient() as http:
        helm = HelmClient(http, OCIClient(http), GitSettings())
        assert (await helm.git_chart_metadata("git@gitlab.com:grp/repo.git", "v1", "charts/app"))["version"] == "2.0.0"
        with pytest.raises(RegistryError, match=r"HTTP 404 Not Found - not found on raw.githubusercontent.com.*git.token"):
            await helm.git_chart_metadata("https://github.com/org/repo", "", "missing")
        with pytest.raises(RegistryError, match="no raw URL template"):
            await helm.git_chart_metadata("https://git.example.com/org/repo", "HEAD", "x")


@respx.mock
async def test_index_fetched_once_for_concurrent_charts_and_v_prefix():
    index = respx.get("https://charts.example.com/index.yaml").respond(200, text=INDEX)
    respx.get("https://charts.example.com/app-1.1.0.tgz").respond(200, content=_archive({"name": "app", "version": "1.1.0"}))
    async with httpx.AsyncClient() as http:
        helm = HelmClient(http, OCIClient(http), GitSettings())
        results = await asyncio.gather(*(helm.list_versions("https://charts.example.com", "app") for _ in range(5)))
        # ArgoCD targetRevision "v1.1.0" for a chart published as "1.1.0"
        meta = await helm.chart_metadata("https://charts.example.com", "app", "v1.1.0")
    assert results == [["1.1.0", "1.0.0"]] * 5
    assert index.call_count == 1
    assert meta["version"] == "1.1.0"


@respx.mock
async def test_ping_helm_repository():
    index = respx.get("https://charts.example.com/index.yaml").respond(200, text="apiVersion: v1\n")
    respx.get("https://private.example.com/index.yaml").respond(401)
    async with httpx.AsyncClient() as http:
        helm = HelmClient(http, OCIClient(http, {"charts.example.com": ("u", "p")}), GitSettings())
        assert await helm.ping("https://charts.example.com/") == "index.yaml served with credentials"
        assert index.calls[-1].request.headers["authorization"].startswith("Basic ")
        with pytest.raises(RegistryError, match="HTTP 401"):
            await helm.ping("https://private.example.com")
