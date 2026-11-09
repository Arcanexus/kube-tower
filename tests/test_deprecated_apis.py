from types import SimpleNamespace

import urllib3
from kubernetes import client

from kube_tower.clusterview import cluster_view, deprecated_findings
from kube_tower.collectors.deprecated import _lines, collect_deprecated_apis, parse_metrics
from kube_tower.models import ClusterStatus, DeprecatedApi, Snapshot, decode, encode
from kube_tower.scope import scope_snapshot


def sample(group, version, resource, removed="", subresource="", value=1):
    labels = f'group="{group}",removed_release="{removed}",resource="{resource}",subresource="{subresource}",version="{version}"'
    return f"apiserver_requested_deprecated_apis{{{labels}}} {value}"


METRICS = "\n".join(
    [
        "# HELP apiserver_requested_deprecated_apis [STABLE] Gauge of deprecated APIs that have been requested",
        "# TYPE apiserver_requested_deprecated_apis gauge",
        sample("policy", "v1beta1", "podsecuritypolicies", "1.25"),
        sample("flowcontrol.apiserver.k8s.io", "v1beta3", "flowschemas", "1.32"),
        sample("", "v1", "componentstatuses"),
        sample("apps", "v1beta1", "deployments", "1.16", "scale", 0),
        'apiserver_request_total{code="200",verb="GET"} 12',
        "",
    ]
)


class Response:
    def __init__(self, text, size=50):
        self.data, self.size, self.released = text.encode(), size, False

    def stream(self, size):
        for i in range(0, len(self.data), self.size):
            yield self.data[i : i + self.size]

    def release_conn(self):
        self.released = True


def cluster_with(answer):
    def call_api(path, method, **kwargs):
        assert path == "/metrics" and method == "GET" and kwargs["_preload_content"] is False
        if isinstance(answer, Exception):
            raise answer
        return answer

    return SimpleNamespace(name="prod", api_client=SimpleNamespace(call_api=call_api))


def test_parse_metrics():
    found = parse_metrics(METRICS.splitlines())
    assert [s["resource"] for s in found] == ["podsecuritypolicies", "flowschemas", "componentstatuses"]
    assert found[0] == {
        "group": "policy",
        "removed_release": "1.25",
        "resource": "podsecuritypolicies",
        "subresource": "",
        "version": "v1beta1",
    }
    assert parse_metrics(['apiserver_requested_deprecated_apis{group="a\\"b",version="v1"} 1.0']) == [
        {"group": 'a"b', "version": "v1"}
    ]


def test_lines_across_chunks():
    response = Response("one\ntwo\nthree", size=2)
    assert list(_lines(response, 2)) == ["one", "two", "three"]


def test_collect_deprecated_apis():
    response = Response(METRICS + METRICS)  # the same API twice is listed once
    found, errors = collect_deprecated_apis(cluster_with(response))
    assert errors == [] and response.released
    assert [a.name for a in found] == [
        "v1 componentstatuses",
        "flowcontrol.apiserver.k8s.io/v1beta3 flowschemas",
        "policy/v1beta1 podsecuritypolicies",
    ]
    assert found[2] == DeprecatedApi("prod", "policy", "v1beta1", "podsecuritypolicies", "", "1.25")
    assert DeprecatedApi("c", "apps", "v1beta1", "deployments", "scale").name == "apps/v1beta1 deployments/scale"


def test_collect_deprecated_apis_errors():
    found, errors = collect_deprecated_apis(cluster_with(client.ApiException(status=403, reason="Forbidden")))
    assert found == [] and "403 Forbidden" in errors[0] and "nonResourceURLs" in errors[0]
    _, errors = collect_deprecated_apis(cluster_with(client.ApiException(status=401, reason="Unauthorized")))
    assert "renew its cluster secret" in errors[0]
    _, errors = collect_deprecated_apis(cluster_with(urllib3.exceptions.ProtocolError("connection reset")))
    assert "connection reset" in errors[0]


def test_deprecated_findings():
    apis = [
        DeprecatedApi("prod", "flowcontrol.apiserver.k8s.io", "v1beta3", "flowschemas", removed_release="1.32"),
        DeprecatedApi("prod", "storage.k8s.io", "v1beta1", "csistoragecapacities", removed_release="1.34"),
        DeprecatedApi("prod", "", "v1", "componentstatuses"),
    ]
    found = deprecated_findings(apis, "v1.31.2-eks-1")
    assert [f.level for f in found] == ["error", "warning", "info"]
    assert found[0].text == (
        "Deprecated API still requested: flowcontrol.apiserver.k8s.io/v1beta3 flowschemas, removed in Kubernetes 1.32"
        " (the next upgrade)"
    )
    assert "(a later release)" in found[1].text and "no removal planned" in found[2].text
    assert [f.level for f in deprecated_findings(apis[:1], None)] == ["warning"]  # version of the API server unknown
    view = cluster_view(
        ClusterStatus("prod", "https://k", "secret", True, "v1.31.2"),
        [],
        deprecated_apis=[*apis, DeprecatedApi("lab", "a", "v1", "b")],
    )
    assert view.level == "error" and len([f for f in view.findings if f.kind == "deprecated-api"]) == 3
    assert [f.level for f in view.details] == ["info"]


def test_snapshot_keeps_the_deprecated_apis():
    snapshot = Snapshot(deprecated_apis=[DeprecatedApi("prod", "policy", "v1beta1", "x"), DeprecatedApi("lab", "", "v1", "y")])
    assert decode(Snapshot, encode(snapshot)).deprecated_apis == snapshot.deprecated_apis
    assert [a.cluster for a in scope_snapshot(snapshot, ["prod"]).deprecated_apis] == ["prod"]


async def test_worker_reads_the_deprecated_apis(monkeypatch):
    from kube_tower import worker as worker_module
    from kube_tower.config import Settings
    from kube_tower.tasks import CollectTask

    monkeypatch.setattr(worker_module.ImageInventory, "collect", lambda self, cluster: [])
    monkeypatch.setattr(worker_module, "collect_nodes", lambda cluster, labels: ([], []))
    monkeypatch.setattr(
        worker_module, "collect_deprecated_apis", lambda cluster: ([DeprecatedApi(cluster.name, "", "v1", "x")], ["warn"])
    )
    settings = Settings()
    settings.helm.enabled = settings.security.enabled = settings.images.enabled = False
    w = worker_module.Worker(settings)
    w.clusters = {"prod": SimpleNamespace(name="prod", api_client=None)}
    result = await w.execute(CollectTask("prod"))
    assert [a.resource for a in result.deprecated_apis] == ["x"] and "warn" in result.errors
    assert (await w.execute(CollectTask("prod", deprecated_apis=False))).deprecated_apis == []
    settings.kubernetes_versions.deprecated_apis = False
    assert (await w.execute(CollectTask("prod"))).deprecated_apis == []
