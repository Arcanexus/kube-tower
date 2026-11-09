"""Helm charts outside ArgoCD: Flux HelmReleases, releases installed with the helm command."""

import base64
import gzip
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from kubernetes import client

from kube_tower.checkers import ChartChecker
from kube_tower.clusters import Cluster
from kube_tower.collectors import flux, releases
from kube_tower.collectors import helm as helm_collector
from kube_tower.config import GitSettings, HelmSettings
from kube_tower.models import ChartReport, Status
from kube_tower.registry.helm import HelmClient
from kube_tower.registry.oci import OCIClient, RegistryError


def _meta(name, namespace="flux-system"):
    return {"name": name, "namespace": namespace}


HELM_REPO = {"metadata": _meta("bitnami"), "spec": {"url": "https://charts.bitnami.com/bitnami"}}
OCI_HELM_REPO = {"metadata": _meta("podinfo"), "spec": {"url": "oci://ghcr.io/stefanprodan/charts", "type": "oci"}}
OCI_REPO = {"metadata": _meta("grafana"), "spec": {"url": "oci://ghcr.io/grafana/helm-charts/grafana/", "ref": {"tag": "8.0.0"}}}
GIT_REPO = {"metadata": _meta("apps"), "spec": {"url": "https://github.com/org/apps", "ref": {"branch": "main"}}}


def _release(name, chart_ref=None, chart=None, version="", status=None, **spec):
    body = {"metadata": _meta(name, "apps"), "spec": spec, "status": status or {}}
    if chart_ref:
        body["spec"]["chartRef"] = chart_ref
    if chart:
        body["spec"]["chart"] = {"spec": {"version": version, **chart}}
    return body


def _sources():
    index = flux._index
    return {
        "HelmRepository": index([HELM_REPO, OCI_HELM_REPO]),
        "OCIRepository": index([OCI_REPO]),
        "GitRepository": index([GIT_REPO]),
    }


def test_helmrelease_sources():
    redis = flux.chart_from_helmrelease(
        "c1",
        _release(
            "redis",
            chart={"chart": "redis", "sourceRef": {"kind": "HelmRepository", "name": "bitnami", "namespace": "flux-system"}},
            version="18.x",
            status={"history": [{"chartName": "redis", "chartVersion": "18.0.1", "name": "redis", "namespace": "apps"}]},
            values={"sentinel": {"enabled": False, "password": "secret"}},
            targetNamespace="cache",
        ),
        _sources(),
    )
    assert (redis.manager, redis.chart, redis.repository, redis.source_type, redis.version) == (
        "flux",
        "redis",
        "https://charts.bitnami.com/bitnami",
        "helm",
        "18.0.1",
    )
    assert redis.destination_namespace == "cache" and redis.inline_values == {"sentinel": {"enabled": False}}
    assert flux.release_name(_release("redis", status={"history": [{"name": "redis", "namespace": "apps"}]})) == ("apps", "redis")
    assert flux.release_name(_release("web", targetNamespace="shop")) == ("shop", "shop-web")
    assert flux.release_name(_release("web", releaseName="www")) == ("apps", "www")

    podinfo = flux.chart_from_helmrelease(
        "c1",
        _release(
            "podinfo",
            chart={"chart": "podinfo", "sourceRef": {"kind": "HelmRepository", "name": "podinfo", "namespace": "flux-system"}},
            version="6.5.0",
        ),
        _sources(),
    )
    assert (podinfo.source_type, podinfo.repository, podinfo.version) == ("oci", "oci://ghcr.io/stefanprodan/charts", "6.5.0")

    grafana = flux.chart_from_helmrelease(
        "c1", _release("grafana", chart_ref={"kind": "OCIRepository", "name": "grafana", "namespace": "flux-system"}), _sources()
    )
    assert (grafana.chart, grafana.repository, grafana.version, grafana.source_type) == (
        "grafana",
        "oci://ghcr.io/grafana/helm-charts",
        "8.0.0",
        "oci",
    )

    app = flux.chart_from_helmrelease(
        "c1",
        _release(
            "app",
            chart={"chart": "./charts/app", "sourceRef": {"kind": "GitRepository", "name": "apps", "namespace": "flux-system"}},
            status={"lastAppliedRevision": "0.3.0"},
        ),
        _sources(),
    )
    assert (app.source_type, app.repository, app.git_ref, app.path, app.version) == (
        "git",
        "https://github.com/org/apps",
        "main",
        "./charts/app",
        "",
    )

    missing = flux.chart_from_helmrelease(
        "c1", _release("x", chart={"chart": "x", "sourceRef": {"kind": "HelmRepository", "name": "nope"}}), _sources()
    )
    assert missing.message == "HelmRepository apps/nope not found" and missing.repository == ""
    bucket = flux.chart_from_helmrelease(
        "c1", _release("y", chart={"chart": "y", "sourceRef": {"kind": "Bucket", "name": "b"}}), _sources()
    )
    assert "Bucket not supported" in bucket.message
    helmchart = flux.chart_from_helmrelease("c1", _release("z", chart_ref={"kind": "HelmChart", "name": "z"}), _sources())
    assert "HelmChart" in helmchart.message


def test_flux_collect_falls_back_on_older_api_versions():
    api = MagicMock()

    def objects(group, version, plural):
        if (group, version, plural) == (flux.HELM_GROUP, "v2beta2", "helmreleases"):
            return {
                "items": [
                    _release(
                        "redis",
                        chart={
                            "chart": "redis",
                            "sourceRef": {"kind": "HelmRepository", "name": "bitnami", "namespace": "flux-system"},
                        },
                        version="18.0.0",
                    )
                ]
            }
        if (group, version, plural) == (flux.SOURCE_GROUP, "v1", "helmrepositories"):
            return {"items": [HELM_REPO]}
        raise client.ApiException(status=404)

    api.list_cluster_custom_object.side_effect = objects
    reports, made = flux.collect("c1", api)
    assert [(r.chart, r.repository, r.version) for r in reports] == [("redis", "https://charts.bitnami.com/bitnami", "18.0.0")]
    assert made == {("apps", "redis")}

    api.list_cluster_custom_object.side_effect = client.ApiException(status=404)
    with pytest.raises(flux.NotInstalled):
        flux.collect("c1", api)


def _secret(name, namespace, revision, release, labels=None):
    data = base64.b64encode(base64.b64encode(gzip.compress(json.dumps(release).encode()))).decode()
    meta = client.V1ObjectMeta(
        name=f"sh.helm.release.v1.{name}.v{revision}",
        namespace=namespace,
        labels={"owner": "helm", "status": "deployed", "name": name, "version": str(revision), **(labels or {})},
    )
    return client.V1Secret(metadata=meta, data={"release": data})


def _helm_release(name, namespace, chart, version, deps=(), values=None, config=None):
    return {
        "name": name,
        "namespace": namespace,
        "chart": {
            "metadata": {"name": chart, "version": version, "dependencies": list(deps)},
            "values": values or {},
            "templates": [{"name": "templates/x.yaml", "data": "eA=="}],
        },
        "config": config or {},
    }


def test_helm_releases():
    nginx = _helm_release(
        "ingress",
        "ingress",
        "ingress-nginx",
        "4.10.0",
        values={"metrics": {"enabled": False}},
        config={"metrics": {"enabled": True}, "controller": {"admissionWebhooks": {"password": "x"}}},
    )
    old = _helm_release("ingress", "ingress", "ingress-nginx", "4.9.0")
    redis = _helm_release(
        "cache",
        "db",
        "redis",
        "18.0.0",
        deps=[{"name": "common", "version": "2.0.0", "repository": "oci://registry-1.docker.io/bitnamicharts", "tags": ["x"]}],
    )
    pages = {
        None: SimpleNamespace(
            items=[_secret("ingress", "ingress", 3, nginx), _secret("ingress", "ingress", 2, old)],
            metadata=SimpleNamespace(_continue="next"),
        ),
        "next": SimpleNamespace(
            items=[
                _secret("cache", "db", 1, redis),
                _secret(
                    "podinfo",
                    "apps",
                    1,
                    _helm_release("podinfo", "apps", "podinfo", "6.0.0"),
                    {"helm.toolkit.fluxcd.io/name": "podinfo"},
                ),
                client.V1Secret(
                    metadata=client.V1ObjectMeta(name="broken", namespace="x", labels={"name": "broken"}), data={"release": "!!"}
                ),
            ],
            metadata=SimpleNamespace(_continue=None),
        ),
    }
    core = MagicMock()
    core.list_secret_for_all_namespaces.side_effect = lambda **kw: pages[kw["_continue"]]
    reports = releases.collect("c1", core)
    assert [(r.app_namespace, r.application, r.chart, r.version, r.manager) for r in reports] == [
        ("db", "cache", "redis", "18.0.0", "helm"),
        ("ingress", "ingress", "ingress-nginx", "4.10.0", "helm"),
    ]
    assert reports[1].inline_values == {"metrics": {"enabled": True}}  # the values at install over the defaults
    assert reports[0].dependencies[0].name == "common" and reports[0].dependencies[0].tags == ["x"]
    kwargs = core.list_secret_for_all_namespaces.call_args.kwargs
    assert kwargs["label_selector"] == "owner=helm,status=deployed" and kwargs["field_selector"] == "type=helm.sh/release.v1"
    assert releases.chart_from_release("c1", {"chart": {"metadata": {}}}) is None


def test_collect_charts_from_every_source(monkeypatch):
    custom, core = MagicMock(), MagicMock()
    custom.list_namespaced_custom_object.return_value = {"items": []}

    def objects(group, version, plural):
        if plural == "helmreleases":
            return {
                "items": [
                    _release(
                        "ingress",
                        chart={"chart": "ingress-nginx", "sourceRef": {"kind": "HelmRepository", "name": "x"}},
                        version="4.10.0",
                        status={"history": [{"name": "ingress", "namespace": "ingress", "chartVersion": "4.10.0"}]},
                    )
                ]
            }
        return {"items": []}

    custom.list_cluster_custom_object.side_effect = objects
    made_by_flux = _secret("ingress", "ingress", 1, _helm_release("ingress", "ingress", "ingress-nginx", "4.10.0"))
    by_helm = _secret("cache", "db", 1, _helm_release("cache", "db", "redis", "18.0.0"))
    core.list_secret_for_all_namespaces.return_value = SimpleNamespace(items=[made_by_flux, by_helm], metadata=None)
    monkeypatch.setattr(helm_collector.client, "CustomObjectsApi", lambda _: custom)
    monkeypatch.setattr(helm_collector.client, "CoreV1Api", lambda _: core)
    cluster = Cluster("c1", "https://x", "secret", None)

    charts, errors = helm_collector.collect_charts(cluster, HelmSettings(releases=True))
    assert [(c.manager, c.application) for c in charts] == [("flux", "ingress"), ("helm", "cache")] and errors == []

    charts, _ = helm_collector.collect_charts(cluster, HelmSettings(flux=False))
    assert charts == []  # releases are off by default

    core.list_secret_for_all_namespaces.side_effect = client.ApiException(status=403, reason="Forbidden")
    custom.list_cluster_custom_object.side_effect = client.ApiException(status=403, reason="Forbidden")
    charts, errors = helm_collector.collect_charts(cluster, HelmSettings(releases=True))
    assert charts == [] and len(errors) == 2
    assert "cannot list Flux HelmReleases: 403" in errors[0] and "cannot list Helm releases (Secrets): 403" in errors[1]


class Helm:
    """Repository of ingress-nginx, Artifact Hub knows redis only."""

    async def list_versions(self, repository, chart):
        return {"ingress-nginx": ["4.10.0", "4.11.0"], "redis": ["18.0.0", "19.0.0"], "common": ["2.0.0", "2.1.0"]}[chart]

    async def release_date(self, repository, chart, version):
        return None

    async def chart_files(self, repository, chart, version, extra=()):
        return SimpleNamespace(metadata={"name": chart, "version": version}, values={}, files={})

    lookups = 0

    async def artifact_hub_repository(self, base_url, chart):
        Helm.lookups += 1
        if chart == "down":
            raise RegistryError("Artifact Hub unreachable")
        return "https://charts.bitnami.com/bitnami" if chart == "redis" else None


def _report(chart, version, **kw):
    return ChartReport("c1", "rel", "ns", chart, "", version, "helm", manager="helm", **kw)


async def test_repository_of_helm_releases():
    from kube_tower.models import ChartDependency

    settings = HelmSettings(repositories={"ingress-*": "https://kubernetes.github.io/ingress-nginx/"})
    checker = ChartChecker(Helm(), settings)
    nginx, redis, redis2 = _report("ingress-nginx", "4.10.0"), _report("redis", "18.0.0"), _report("redis", "19.0.0")
    unknown = _report(
        "mine",
        "1.0.0",
        dependencies=[
            ChartDependency("common", "2.0.0", "https://charts.bitnami.com/bitnami", condition="common.enabled"),
            ChartDependency("redis", "18.0.0", "https://charts.bitnami.com/bitnami"),
        ],
        inline_values={"common": {"enabled": False}},
    )
    down = _report("down", "1.0.0")
    await checker.check_all([nginx, redis, redis2, unknown, down])
    assert (nginx.repository, nginx.status, nginx.latest_version) == (
        "https://kubernetes.github.io/ingress-nginx",
        Status.OUTDATED,
        "4.11.0",
    )
    assert (redis.repository, redis.status, redis2.status) == (
        "https://charts.bitnami.com/bitnami",
        Status.OUTDATED,
        Status.UP_TO_DATE,
    )
    assert Helm.lookups == 3  # redis once, mine and down; ingress-nginx from the settings
    assert unknown.status == Status.UNKNOWN and "helm.repositories" in unknown.message
    common, sub = unknown.dependencies
    assert not common.deployed and sub.status == Status.OUTDATED  # the subcharts recorded in the release
    assert down.status == Status.UNKNOWN and "Artifact Hub lookup failed" in down.message

    off = _report("redis", "18.0.0")
    await ChartChecker(Helm(), HelmSettings(artifact_hub_url="")).check(off)
    assert off.status == Status.UNKNOWN and off.repository == ""

    flux_missing = ChartReport("c1", "x", "ns", "x", "", "1.0.0", "helm", manager="flux", message="HelmRepository ns/x not found")
    await checker.check(flux_missing)
    assert (flux_missing.status, flux_missing.message) == (Status.UNKNOWN, "HelmRepository ns/x not found")

    ranged = ChartReport("c1", "x", "ns", "redis", "https://charts.bitnami.com/bitnami", "18.x", "helm", manager="flux")
    await checker.check(ranged)
    assert ranged.message == "version '18.x' is not a fixed version"


@respx.mock
async def test_artifact_hub_lookup():
    search = respx.get("https://artifacthub.io/api/v1/packages/search").respond(
        200,
        json={
            "packages": [
                {"name": "redis-ha", "repository": {"url": "https://other.example.com"}},
                {"name": "redis", "stars": 900, "repository": {"url": "https://fork.example.com"}},
                {
                    "name": "redis",
                    "stars": 2,
                    "repository": {"url": "https://charts.bitnami.com/bitnami/", "verified_publisher": True},
                },
                {"name": "redis", "repository": {}},
            ]
        },
    )
    async with httpx.AsyncClient() as http:
        helm = HelmClient(http, OCIClient(http), GitSettings())
        assert await helm.artifact_hub_repository("https://artifacthub.io/", "redis") == "https://charts.bitnami.com/bitnami"
        assert search.calls.last.request.url.params["ts_query_web"] == "redis"
        search.respond(
            200,
            json={
                "packages": [
                    {"name": "redis", "official": True, "repository": {"url": "oci://registry-1.docker.io/bitnamicharts"}},
                    {"name": "redis", "stars": 5, "repository": {"url": "https://x", "verified_publisher": True}},
                ]
            },
        )
        assert await helm.artifact_hub_repository("https://artifacthub.io", "redis") == "oci://registry-1.docker.io/bitnamicharts"
        search.respond(200, json={"packages": []})
        assert await helm.artifact_hub_repository("https://artifacthub.io", "nothing") is None
        search.respond(503)
        with pytest.raises(RegistryError, match="503"):
            await helm.artifact_hub_repository("https://artifacthub.io", "redis")
