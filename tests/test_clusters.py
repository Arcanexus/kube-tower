import base64
import json

from kubernetes import client

from kube_tower.clusters import ClusterRegistry, cluster_from_secret
from kube_tower.config import ClustersSettings


def _secret(secret_name, **data):
    return client.V1Secret(
        metadata=client.V1ObjectMeta(name=secret_name),
        data={k: base64.b64encode(v.encode()).decode() for k, v in data.items()},
    )


def test_argocd_format_secret():
    cfg = {"bearerToken": "tok", "tlsClientConfig": {"insecure": True}}
    cluster = cluster_from_secret(_secret("s1", name="prod", server="https://prod:6443", config=json.dumps(cfg)), "secret")
    assert cluster.name == "prod" and cluster.server == "https://prod:6443"
    conf = cluster.api_client.configuration
    assert conf.api_key["authorization"] == "Bearer tok" and conf.verify_ssl is False


def test_kubeconfig_secret():
    kubeconfig = """
apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "https://k:6443", insecure-skip-tls-verify: true}}]
users: [{name: u, user: {token: abc}}]
contexts: [{name: ctx, context: {cluster: c, user: u}}]
current-context: ctx
"""
    cluster = cluster_from_secret(_secret("lab", kubeconfig=kubeconfig), "secret")
    assert cluster.name == "lab" and cluster.server == "https://k:6443"


class FakeRegistry(ClusterRegistry):
    def __init__(self, secrets):
        super().__init__(ClustersSettings(in_cluster=False, namespace="kube-tower"))
        self.secrets = secrets

    def _list_secrets(self, namespace, selector):
        return self.secrets

    def probe(self, cluster):
        from kube_tower.models import ClusterStatus

        return ClusterStatus(cluster.name, cluster.server, cluster.source, reachable=True)


def test_discover_skips_bad_secrets_and_duplicates():
    good = _secret("a", name="a", server="https://a", config="{}")
    dup = _secret("b", name="b", server="https://a/", config="{}")
    bad = _secret("c", name="c")
    clusters, statuses = FakeRegistry([good, dup, bad]).discover()
    assert [c.name for c in clusters] == ["a"]
    assert [(s.name, s.reachable) for s in statuses] == [("c", False), ("a", True)]
