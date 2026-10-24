from types import SimpleNamespace as NS
from unittest.mock import MagicMock

from kubernetes import client

from kube_tower.clusters import Cluster
from kube_tower.collectors import helm as helm_collector
from kube_tower.collectors import images as images_collector
from kube_tower.collectors.helm import charts_from_application
from kube_tower.collectors.images import ImageInventory
from kube_tower.config import HelmSettings, ImagesSettings
from kube_tower.models import Usage


def _meta(name, namespace=None):
    return client.V1ObjectMeta(name=name, namespace=namespace)


def _spec(*images):
    return client.V1PodSpec(containers=[client.V1Container(name=f"c{i}", image=img) for i, img in enumerate(images)])


def test_image_inventory(monkeypatch):
    pod = client.V1Pod(
        metadata=_meta("web-1", "default"),
        spec=_spec("nginx:1.25"),
        status=client.V1PodStatus(
            container_statuses=[
                client.V1ContainerStatus(
                    name="c0", image="nginx:1.25", image_id="docker.io/library/nginx@sha256:aaa", ready=True, restart_count=0
                )
            ]
        ),
    )
    deploy = NS(metadata=_meta("web", "default"), spec=NS(template=NS(spec=_spec("nginx:1.25", "registry.k8s.io/pause:3.9"))))
    cron = NS(metadata=_meta("backup", "ops"), spec=NS(job_template=NS(spec=NS(template=NS(spec=_spec("alpine:3.19"))))))
    node = NS(
        metadata=_meta("node-1"),
        status=NS(images=[NS(names=["docker.io/library/redis@sha256:bbb", "docker.io/library/redis:7.2"])]),
    )

    core, apps, batch = MagicMock(), MagicMock(), MagicMock()
    core.list_pod_for_all_namespaces.return_value.items = [pod]
    core.list_node.return_value.items = [node]
    apps.list_deployment_for_all_namespaces.return_value.items = [deploy]
    apps.list_stateful_set_for_all_namespaces.side_effect = client.ApiException(status=403, reason="Forbidden")
    apps.list_daemon_set_for_all_namespaces.return_value.items = []
    batch.list_cron_job_for_all_namespaces.return_value.items = [cron]
    for api in (core, apps, batch):
        for fn in (
            "list_pod_for_all_namespaces",
            "list_node",
            "list_deployment_for_all_namespaces",
            "list_daemon_set_for_all_namespaces",
            "list_cron_job_for_all_namespaces",
        ):
            getattr(api, fn).return_value.metadata = client.V1ListMeta()
    monkeypatch.setattr(images_collector.client, "CoreV1Api", lambda _: core)
    monkeypatch.setattr(images_collector.client, "AppsV1Api", lambda _: apps)
    monkeypatch.setattr(images_collector.client, "BatchV1Api", lambda _: batch)

    inventory = ImageInventory(ImagesSettings(ignore=["registry.k8s.io/pause*"]))
    errors = inventory.collect(Cluster("c1", "https://x", "in-cluster", None))

    assert errors == [
        "[c1] cannot list StatefulSet: 403 Forbidden - the ServiceAccount used for this cluster is not allowed to list "
        "StatefulSet in all namespaces: apply deploy/remote-cluster-rbac.yaml on remote clusters, keep rbac.create=true "
        "for the local one"
    ]
    assert set(inventory.reports) == {
        "docker.io/library/nginx:1.25",
        "docker.io/library/alpine:3.19",
        "docker.io/library/redis:7.2",
    }
    nginx = inventory.reports["docker.io/library/nginx:1.25"]
    assert {u.kind for u in nginx.usages} == {"Pod", "Deployment"}
    assert nginx.running_digests == {"sha256:aaa"}
    assert inventory.reports["docker.io/library/redis:7.2"].running_digests == {"sha256:bbb"}


def test_charts_from_application_single_and_multi_source():
    helm_app = {
        "metadata": {"name": "redis", "namespace": "argocd"},
        "spec": {
            "destination": {"namespace": "cache"},
            "source": {"repoURL": "https://charts.bitnami.com/bitnami", "chart": "redis", "targetRevision": "18.0.0"},
        },
        "status": {"sourceType": "Helm"},
    }
    multi_app = {
        "metadata": {"name": "mon", "namespace": "argocd"},
        "spec": {
            "sources": [
                {"repoURL": "ghcr.io/org/charts", "chart": "grafana", "targetRevision": "7.0.0"},
                {"repoURL": "https://github.com/Arcanexus/helm-charts.git", "path": "monitoring", "targetRevision": "HEAD"},
                {"repoURL": "https://github.com/Arcanexus/gitops.git", "path": "manifests"},
            ]
        },
        "status": {"sourceTypes": ["Helm", "Helm", "Directory"]},
    }
    [redis] = charts_from_application("c1", helm_app)
    assert (redis.chart, redis.version, redis.source_type, redis.destination_namespace) == ("redis", "18.0.0", "helm", "cache")

    grafana, monitoring = charts_from_application("c1", multi_app)
    assert grafana.source_type == "oci"
    assert (monitoring.source_type, monitoring.chart, monitoring.git_ref, monitoring.path) == (
        "git",
        "monitoring",
        "HEAD",
        "monitoring",
    )


def test_collect_charts_without_argocd(monkeypatch):
    api = MagicMock()
    api.list_namespaced_custom_object.side_effect = client.ApiException(status=404)
    monkeypatch.setattr(helm_collector.client, "CustomObjectsApi", lambda _: api)
    charts, errors = helm_collector.collect_charts(Cluster("c1", "https://x", "secret", None), HelmSettings())
    assert charts == [] and errors == []


def test_image_inventory_paginates(monkeypatch):
    pages = {
        None: client.V1PodList(
            items=[client.V1Pod(metadata=_meta("a", "ns"), spec=_spec("nginx:1.25"), status=client.V1PodStatus())],
            metadata=client.V1ListMeta(_continue="next"),
        ),
        "next": client.V1PodList(
            items=[client.V1Pod(metadata=_meta("b", "ns"), spec=_spec("alpine:3.19"), status=client.V1PodStatus())],
            metadata=client.V1ListMeta(),
        ),
    }
    calls = []

    def list_pods(limit, _continue=None):
        calls.append((limit, _continue))
        return pages[_continue]

    core, other = MagicMock(), MagicMock()
    core.list_pod_for_all_namespaces = list_pods
    core.list_node.return_value = client.V1NodeList(items=[], metadata=client.V1ListMeta())
    other.configure_mock(
        **{
            f"{fn}.return_value": NS(items=[], metadata=None)
            for fn in (
                "list_deployment_for_all_namespaces",
                "list_stateful_set_for_all_namespaces",
                "list_daemon_set_for_all_namespaces",
                "list_cron_job_for_all_namespaces",
            )
        }
    )
    monkeypatch.setattr(images_collector.client, "CoreV1Api", lambda _: core)
    monkeypatch.setattr(images_collector.client, "AppsV1Api", lambda _: other)
    monkeypatch.setattr(images_collector.client, "BatchV1Api", lambda _: other)

    inventory = ImageInventory(ImagesSettings())
    assert inventory.collect(Cluster("c1", "https://x", "in-cluster", None)) == []
    assert calls == [(images_collector.PAGE_SIZE, None), (images_collector.PAGE_SIZE, "next")]
    assert set(inventory.reports) == {"docker.io/library/nginx:1.25", "docker.io/library/alpine:3.19"}


def test_image_inventory_deduplicates_usages():
    inventory = ImageInventory(ImagesSettings())
    for _ in range(2):
        for node in range(500):
            inventory.add("registry.k8s.io/pause:3.9", Usage("c", "Node", None, f"node-{node}"))
    inventory.add("registry.k8s.io/pause:3.9", Usage("c", "Pod", "ns", "p", "c"))
    report = inventory.reports["registry.k8s.io/pause:3.9"]
    assert len(report.usages) == 501
    assert report.usages[0] == Usage("c", "Node", None, "node-0") and report.usages[-1].kind == "Pod"
