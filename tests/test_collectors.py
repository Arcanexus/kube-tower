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

    def list_pods(limit, _continue=None, **_):
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


def test_image_pull_secrets(monkeypatch, caplog):
    import base64
    import json

    def dockerconfig(host, user, password):
        auth = base64.b64encode(f"{user}:{password}".encode()).decode()
        return base64.b64encode(json.dumps({"auths": {host: {"auth": auth}}}).encode()).decode()

    def spec(*secrets):
        s = _spec("harbor.example.com/team/app:1")
        s.image_pull_secrets = [client.V1LocalObjectReference(name=n) for n in secrets]
        return s

    pod = client.V1Pod(metadata=_meta("app-1", "team"), spec=spec("harbor", "missing", "forbidden"), status=client.V1PodStatus())
    deploy = NS(metadata=_meta("app", "team"), spec=NS(template=NS(spec=spec("harbor"))))
    cron = NS(
        metadata=_meta("job", "ops"), spec=NS(job_template=NS(spec=NS(template=NS(spec=spec("legacy", "garbage", "opaque")))))
    )
    secrets = {
        ("team", "harbor"): client.V1Secret(
            type="kubernetes.io/dockerconfigjson",
            data={".dockerconfigjson": dockerconfig("harbor.example.com", "robot$ci", "pw")},
        ),
        ("ops", "legacy"): client.V1Secret(
            type="kubernetes.io/dockercfg",
            data={".dockercfg": base64.b64encode(json.dumps({"quay.io": {"username": "q", "password": "p"}}).encode()).decode()},
        ),
        ("ops", "garbage"): client.V1Secret(type="kubernetes.io/dockerconfigjson", data={".dockerconfigjson": "bm90IGpzb24="}),
        ("ops", "opaque"): client.V1Secret(type="Opaque", data={"token": "eA=="}),
    }

    def read_secret(name, namespace):
        if name == "forbidden":
            raise client.ApiException(status=403, reason="Forbidden")
        if (namespace, name) not in secrets:
            raise client.ApiException(status=404, reason="Not Found")
        return secrets[(namespace, name)]

    core, apps, batch = MagicMock(), MagicMock(), MagicMock()
    core.list_pod_for_all_namespaces.return_value.items = [pod]
    core.read_namespaced_secret.side_effect = read_secret
    apps.list_deployment_for_all_namespaces.return_value.items = [deploy]
    apps.list_stateful_set_for_all_namespaces.return_value.items = []
    apps.list_daemon_set_for_all_namespaces.return_value.items = []
    batch.list_cron_job_for_all_namespaces.return_value.items = [cron]
    for api in (core, apps, batch):
        for fn in (
            "list_pod_for_all_namespaces",
            "list_deployment_for_all_namespaces",
            "list_stateful_set_for_all_namespaces",
            "list_daemon_set_for_all_namespaces",
            "list_cron_job_for_all_namespaces",
        ):
            getattr(api, fn).return_value.metadata = client.V1ListMeta()
    monkeypatch.setattr(images_collector.client, "CoreV1Api", lambda _: core)
    monkeypatch.setattr(images_collector.client, "AppsV1Api", lambda _: apps)
    monkeypatch.setattr(images_collector.client, "BatchV1Api", lambda _: batch)

    # Off by default: no Secret is read
    inventory = ImageInventory(ImagesSettings(include_node_images=False))
    assert inventory.collect(Cluster("c1", "https://x", "in-cluster", None)) == []
    assert not core.read_namespaced_secret.called and inventory.pull_secrets == {}

    inventory = ImageInventory(ImagesSettings(include_node_images=False), pull_secrets=True)
    errors = inventory.collect(Cluster("c1", "https://x", "in-cluster", None))
    assert inventory.pull_secrets == {"harbor.example.com": ("robot$ci", "pw"), "quay.io": ("q", "p")}
    assert core.read_namespaced_secret.call_count == 6  # team/harbor read once for the pod and the Deployment
    assert len(errors) == 1 and "cannot read 1 image pull secret(s) (e.g. team/forbidden): 403" in errors[0]
    assert "ops/garbage ignored" in caplog.text


def test_pod_owner():
    from kube_tower.collectors.images import _pod_owner

    def pod(kind=None, name=None, pod_hash=None, controller=True):
        refs = [client.V1OwnerReference(api_version="v1", kind=kind, name=name, uid="u", controller=controller)] if kind else []
        labels = {"pod-template-hash": pod_hash} if pod_hash else None
        return client.V1Pod(metadata=client.V1ObjectMeta(name="p", owner_references=refs, labels=labels))

    assert _pod_owner(pod("ReplicaSet", "web-7d9f", "7d9f")) == "Deployment/web"
    assert _pod_owner(pod("ReplicaSet", "web-7d9f")) == "ReplicaSet/web-7d9f"  # no hash label: a bare ReplicaSet
    assert _pod_owner(pod("StatefulSet", "db")) == "StatefulSet/db"
    assert _pod_owner(pod("Job", "backup-28839120")) == "Job/backup-28839120"
    assert _pod_owner(pod("ReplicaSet", "web-7d9f", "7d9f", controller=False)) is None
    assert _pod_owner(pod()) is None


def test_image_inventory_reads_raw_json(monkeypatch):
    """The lists are read as plain JSON (no client models): same result as with the models."""
    import json

    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(
            name="web-7d9f-x2k9p",
            namespace="shop",
            labels={"pod-template-hash": "7d9f"},
            owner_references=[
                client.V1OwnerReference(api_version="apps/v1", kind="ReplicaSet", name="web-7d9f", uid="u", controller=True)
            ],
        ),
        spec=client.V1PodSpec(
            node_name="node-1",
            image_pull_secrets=[client.V1LocalObjectReference(name="regcred")],
            init_containers=[client.V1Container(name="init", image="busybox:1.36")],
            containers=[client.V1Container(name="web", image="nginx:1.25")],
        ),
        status=client.V1PodStatus(
            container_statuses=[
                client.V1ContainerStatus(name="web", image="nginx:1.25", image_id="nginx@sha256:aaa", ready=True, restart_count=0)
            ]
        ),
    )
    template = client.V1PodTemplateSpec(spec=client.V1PodSpec(containers=[client.V1Container(name="web", image="nginx:1.25")]))
    deploy = client.V1Deployment(
        metadata=_meta("web", "shop"), spec=client.V1DeploymentSpec(selector=client.V1LabelSelector(), template=template)
    )
    cron = client.V1CronJob(
        metadata=_meta("backup", "ops"),
        spec=client.V1CronJobSpec(
            schedule="@daily", job_template=client.V1JobTemplateSpec(spec=client.V1JobSpec(template=template))
        ),
    )
    node = client.V1Node(
        metadata=_meta("node-1"),
        status=client.V1NodeStatus(images=[client.V1ContainerImage(names=["redis@sha256:bbb", "redis:7.2"])]),
    )
    lists = {
        "list_pod_for_all_namespaces": [pod],
        "list_node": [node],
        "list_deployment_for_all_namespaces": [deploy],
        "list_stateful_set_for_all_namespaces": [],
        "list_daemon_set_for_all_namespaces": [],
        "list_cron_job_for_all_namespaces": [cron],
    }

    def collect(raw):
        apis = MagicMock()
        for fn, items in lists.items():
            if raw:
                body = client.ApiClient().sanitize_for_serialization({"items": items, "metadata": {}})
                getattr(apis, fn).return_value = NS(data=json.dumps(body).encode())
            else:
                getattr(apis, fn).return_value = NS(items=items, metadata=client.V1ListMeta())
        for name in ("CoreV1Api", "AppsV1Api", "BatchV1Api"):
            monkeypatch.setattr(images_collector.client, name, lambda _: apis)
        apis.read_namespaced_secret.side_effect = client.ApiException(status=404)
        inventory = ImageInventory(ImagesSettings(), pull_secrets=True)
        assert inventory.collect(Cluster("c1", "https://x", "in-cluster", None)) == []
        assert apis.read_namespaced_secret.call_args.args == ("regcred", "shop")
        return {ref: (r.usages, r.running_digests) for ref, r in inventory.reports.items()}

    raw = collect(raw=True)
    assert raw == collect(raw=False)
    usages, digests = raw["docker.io/library/nginx:1.25"]
    assert Usage("c1", "Pod", "shop", "web-7d9f-x2k9p", "web", "Deployment/web", "node-1") in usages
    assert digests == {"sha256:aaa"}
    assert set(raw) == {"docker.io/library/nginx:1.25", "docker.io/library/busybox:1.36", "docker.io/library/redis:7.2"}
