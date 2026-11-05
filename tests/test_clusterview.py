from datetime import UTC, datetime
from types import SimpleNamespace

from kubernetes import client

from kube_tower.clusterview import cluster_view, cluster_views, k8s_version, minor, skew_findings, worst
from kube_tower.collectors import nodes as nodes_module
from kube_tower.collectors.nodes import collect_nodes, memory_size, node_info, node_role
from kube_tower.models import ClusterStatus, NodeInfo, Snapshot, decode, encode
from kube_tower.scope import scope_snapshot

POOLS = ["eks.amazonaws.com/nodegroup", "karpenter.sh/nodepool"]


def v1_node(name, labels=None, kubelet="v1.30.4-eks-a737599", ready="True", unschedulable=None, extra=()):
    conditions = [client.V1NodeCondition(type="Ready", status=ready)]
    conditions += [client.V1NodeCondition(type=t, status="True") for t in extra]
    conditions.append(client.V1NodeCondition(type="DiskPressure", status="False"))
    return client.V1Node(
        metadata=client.V1ObjectMeta(name=name, labels=labels or {}, creation_timestamp=datetime(2026, 1, 2, tzinfo=UTC)),
        spec=client.V1NodeSpec(unschedulable=unschedulable),
        status=client.V1NodeStatus(
            conditions=conditions,
            capacity={"cpu": "4", "memory": "16303540Ki", "pods": "110"},
            node_info=client.V1NodeSystemInfo(
                architecture="amd64",
                boot_id="",
                container_runtime_version="containerd://1.7.13",
                kernel_version="6.1.0",
                kube_proxy_version=kubelet,
                kubelet_version=kubelet,
                machine_id="",
                operating_system="linux",
                os_image="Bottlerocket OS 1.20.0",
                system_uuid="",
            ),
        ),
    )


def test_node_role():
    assert node_role({"node-role.kubernetes.io/control-plane": ""}) == "control-plane"
    assert node_role({"node-role.kubernetes.io/master": "", "node-role.kubernetes.io/etcd": ""}) == "control-plane"
    assert node_role({"node-role.kubernetes.io/ingress": ""}) == "ingress"
    assert node_role({"node-role.kubernetes.io/": "", "kubernetes.io/os": "linux"}) == "worker"


def test_memory_size():
    assert memory_size("16303540Ki") == "15.5 GiB"
    assert memory_size("8Gi") == "8.0 GiB"
    assert memory_size("2147483648") == "2.0 GiB"
    assert memory_size("lots") == "lots" and memory_size("") == ""


def test_node_info():
    labels = {
        "karpenter.sh/nodepool": "spot",
        "topology.kubernetes.io/zone": "eu-west-3a",
        "node.kubernetes.io/instance-type": "m6i.xlarge",
    }
    n = node_info("prod", v1_node("ip-10-0-1-2", labels, extra=["MemoryPressure"], unschedulable=True), POOLS)
    assert (n.cluster, n.name, n.role, n.pool, n.zone, n.instance_type) == (
        "prod",
        "ip-10-0-1-2",
        "worker",
        "spot",
        "eu-west-3a",
        "m6i.xlarge",
    )
    assert n.kubelet_version == "v1.30.4-eks-a737599" and n.os_image == "Bottlerocket OS 1.20.0"
    assert (n.runtime_name, n.runtime_version) == ("containerd", "1.7.13")
    assert n.ready and n.unschedulable and n.problems == ["MemoryPressure"]
    assert (n.cpu, n.memory, n.max_pods) == ("4", "15.5 GiB", 110)
    assert n.created_at == datetime(2026, 1, 2, tzinfo=UTC)
    # A node read as raw JSON-like objects, with missing fields
    bare = SimpleNamespace(metadata=SimpleNamespace(name="n1", labels=None), status=None)
    n = node_info("lab", bare, POOLS)
    assert n.name == "n1" and n.role == "worker" and not n.ready and n.kubelet_version == "" and n.max_pods == 0
    raw = SimpleNamespace(
        metadata=SimpleNamespace(name="n2", labels=None, creation_timestamp="2026-01-02T00:00:00+00:00"),
        status=SimpleNamespace(capacity={"pods": "many"}, conditions=[]),
    )
    n = node_info("lab", raw, POOLS)
    assert n.max_pods == 0 and n.created_at == datetime(2026, 1, 2, tzinfo=UTC)
    assert (
        node_info("lab", SimpleNamespace(metadata=SimpleNamespace(name="n3", creation_timestamp="soon")), []).created_at is None
    )
    assert NodeInfo("c", "n", container_runtime="").runtime_name == ""


def test_collect_nodes(monkeypatch):
    class Core:
        def __init__(self, api_client):
            pass

        def list_node(self):
            return SimpleNamespace(items=[v1_node("a"), v1_node("b")])

    cluster = SimpleNamespace(name="lab", api_client=None)
    monkeypatch.setattr(nodes_module.client, "CoreV1Api", Core)
    found, errors = collect_nodes(cluster, POOLS)
    assert [n.name for n in found] == ["a", "b"] and errors == []

    class Forbidden(Core):
        def list_node(self):
            raise client.ApiException(status=403, reason="Forbidden")

    monkeypatch.setattr(nodes_module.client, "CoreV1Api", Forbidden)
    found, errors = collect_nodes(cluster, POOLS)
    assert found == [] and errors[0].startswith("[lab] cannot list nodes: 403 Forbidden")


def test_versions():
    assert k8s_version("v1.30.4-eks-a737599") == (1, 30, 4)
    assert k8s_version("v1.31.2+k3s1") == (1, 31, 2) and k8s_version("1.29") == (1, 29, 0)
    assert k8s_version("") is None and k8s_version(None) is None and k8s_version("latest") is None
    assert minor("v1.29.8-gke.1211000") == "1.29" and minor("?") == ""
    assert worst(["info", "error", "warning"]) == "error" and worst([]) == "ok"


def test_skew():
    assert skew_findings("kubelet", "v1.30.2", "v1.30.4", "n") == []
    assert skew_findings("kubelet", "v1.28.2", "v1.30.4", "n")[0].level == "warning"
    assert "2 minor versions behind" in skew_findings("kubelet", "v1.28.2", "v1.30.4", "n")[0].text
    assert "1 minor version behind" in skew_findings("kubelet", "v1.29.2", "v1.30.4", "n")[0].text
    assert skew_findings("kubelet", "v1.26.0", "v1.30.4", "n")[0].level == "error"
    assert "newer than the API server" in skew_findings("kubelet", "v1.31.0", "v1.30.4", "n")[0].text
    assert skew_findings("kubelet", "", "v1.30.4", "n") == [] and skew_findings("kubelet", "v1.30.0", None, "n") == []


def test_cluster_view():
    status = ClusterStatus("prod", "https://prod", "secret", True, "v1.30.4")
    nodes = [
        NodeInfo("prod", "w-2", pool="spot", kubelet_version="v1.29.1", os_image="Ubuntu 22.04"),
        NodeInfo("prod", "w-1", pool="spot", kubelet_version="v1.30.4", os_image="Ubuntu 24.04"),
        NodeInfo("prod", "cp", role="control-plane", kubelet_version="v1.30.4", os_image="Ubuntu 24.04"),
        NodeInfo("prod", "gpu", role="gpu", kubelet_version="v1.30.4", kube_proxy_version="v1.31.0", ready=False),
        NodeInfo("prod", "w-3", kubelet_version="v1.30.4", unschedulable=True, problems=["DiskPressure"]),
    ]
    view = cluster_view(status, nodes)
    assert [g.label for g in view.groups] == ["Control plane", "gpu", "Workers", "Workers · spot"]
    assert [n.name for n in view.groups[3].nodes] == ["w-1", "w-2"]
    assert view.groups[3].values("kubelet_version") == [("v1.30.4", 1), ("v1.29.1", 1)]
    assert view.versions("kubelet_version")[0] == ("v1.30.4", 4)
    texts = [f.text for f in view.findings]
    assert "2 kubelet versions across the nodes: v1.30.4 (4), v1.29.1 (1)" in texts
    assert "2 OS images across the nodes: Ubuntu 24.04 (2), Ubuntu 22.04 (1)" in texts
    assert view.node_levels == {"cp": "ok", "gpu": "error", "w-3": "warning", "w-1": "ok", "w-2": "warning"}
    assert [f.text for f in view.node_findings("w-3")] == ["cordoned: no new pod is scheduled on it", "DiskPressure"]
    assert any("kube-proxy v1.31.0 newer" in f.text for f in view.node_findings("gpu"))
    assert view.level == "error" and view.not_ready == 1
    assert view.summary() == [
        ("error", "1 node not ready"),
        ("error", "1 node with an unsupported kubelet version"),
        ("warning", "1 node behind the API server"),
        ("warning", "1 node cordoned"),
        ("warning", "1 node under pressure (memory, disk or PIDs)"),
    ]
    segments = view.kubelet_segments()
    assert [(s.version, s.nodes, s.level, s.percent) for s in segments] == [
        ("v1.30.4", 4, "ok", 80.0),
        ("v1.29.1", 1, "warning", 20.0),
    ]
    assert [f.kind for f in view.details] == ["os_image"]
    patch = cluster_view(
        status, [NodeInfo("prod", "a", kubelet_version="v1.30.4"), NodeInfo("prod", "b", kubelet_version="v1.30.2")]
    )
    assert patch.summary() == [("warning", "2 kubelet versions across the nodes")]
    unknown = cluster_view(status, [NodeInfo("prod", "a")])
    assert [(s.version, s.level) for s in unknown.kubelet_segments()] == [("unknown", "info")] and unknown.summary() == []
    same = cluster_view(status, [NodeInfo("prod", "a", kubelet_version="v1.30.4")])
    assert same.level == "ok" and same.findings == []
    down = cluster_views([ClusterStatus("lab", "https://lab", "secret", False, message="timeout"), status], nodes)
    assert down[0].level == "error" and down[0].nodes == [] and len(down[1].nodes) == 5


def test_nodes_in_snapshot():
    snapshot = Snapshot(
        clusters=[ClusterStatus("prod", "", "secret", True), ClusterStatus("lab", "", "secret", True)],
        nodes=[NodeInfo("prod", "a", created_at=datetime(2026, 1, 2, tzinfo=UTC)), NodeInfo("lab", "b")],
    )
    assert decode(Snapshot, encode(snapshot)).nodes == snapshot.nodes
    assert [n.name for n in scope_snapshot(snapshot, ["prod"]).nodes] == ["a"]


async def test_worker_reads_the_nodes(monkeypatch):
    from kube_tower import worker as worker_module
    from kube_tower.config import Settings
    from kube_tower.tasks import CollectTask

    def inventory(self, cluster):
        self.nodes = [NodeInfo(cluster.name, "with-images")]
        return []

    monkeypatch.setattr(worker_module.ImageInventory, "collect", inventory)
    monkeypatch.setattr(worker_module, "collect_nodes", lambda cluster, labels: ([NodeInfo(cluster.name, "alone")], ["e"]))
    monkeypatch.setattr(worker_module, "collect_operator_reports", lambda cluster: ([], []))
    monkeypatch.setattr(worker_module, "collect_security_reports", lambda *args, **kwargs: ([], [], [], False))
    settings = Settings()
    settings.helm.enabled = settings.security.enabled = False
    w = worker_module.Worker(settings)
    w.clusters = {"prod": SimpleNamespace(name="prod", api_client=None)}
    assert [n.name for n in (await w.execute(CollectTask("prod"))).nodes] == ["with-images"]
    settings.images.enabled = False  # the nodes are still read, for the Clusters page
    result = await w.execute(CollectTask("prod"))
    assert [n.name for n in result.nodes] == ["alone"] and "e" in result.errors
