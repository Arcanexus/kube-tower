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


def test_argocd_config_tls_and_basic_auth():
    import base64 as b64

    from kube_tower.clusters import api_client_from_argocd_config

    pem = b64.b64encode(b"-----BEGIN CERTIFICATE-----\n").decode()
    api = api_client_from_argocd_config(
        "https://x:6443",
        {
            "username": "u",
            "password": "p",
            "tlsClientConfig": {"caData": pem, "certData": pem, "keyData": pem, "serverName": "x"},
        },
    )
    conf = api.configuration
    assert conf.api_key["authorization"].startswith("Basic ")
    assert conf.verify_ssl and conf.ssl_ca_cert and conf.cert_file and conf.key_file
    assert conf.tls_server_name == "x"


def test_exec_auth_is_rejected():
    import pytest

    from kube_tower.clusters import api_client_from_argocd_config

    with pytest.raises(ValueError, match="not supported"):
        api_client_from_argocd_config("https://x", {"execProviderConfig": {"command": "aws"}})


def test_discover_in_cluster_and_argocd_secrets(monkeypatch):
    from kube_tower import clusters as clusters_module
    from kube_tower.models import ClusterStatus

    calls = []

    class Registry(ClusterRegistry):
        def local_client(self):
            return client.ApiClient(client.Configuration(host="https://local"))

        def _list_secrets(self, namespace, selector):
            calls.append((namespace, selector))
            if "argocd" in selector:
                # ArgoCD's own in-cluster secret must not duplicate the local cluster
                return [_secret("argo-local", name="in", server="https://kubernetes.default.svc", config="{}")]
            raise client.ApiException(status=403, reason="Forbidden")

        def probe(self, cluster):
            return ClusterStatus(cluster.name, cluster.server, cluster.source, reachable=True)

    monkeypatch.setattr(clusters_module, "current_namespace", lambda: "kube-tower")
    clusters, statuses = Registry(ClustersSettings(use_argocd_secrets=True)).discover()
    assert [c.name for c in clusters] == ["in-cluster"]
    assert calls[0][0] == "kube-tower" and calls[1][0] == "argocd"
    assert statuses[0].message == "Forbidden"


def test_discover_named_secrets(monkeypatch):
    from kube_tower.models import ClusterStatus

    named = {
        "prod-creds": _secret("prod-creds", name="prod", server="https://prod", config="{}"),
        "labelled": _secret("labelled", name="a", server="https://a", config="{}"),
    }

    class Registry(ClusterRegistry):
        def local_client(self):
            return client.ApiClient(client.Configuration(host="https://local"))

        def _list_secrets(self, namespace, selector):
            return [named["labelled"]]

        def _read_secret(self, namespace, name):
            assert namespace == "kube-tower"
            if name not in named:
                raise client.ApiException(status=404, reason="Not Found")
            return named[name]

        def probe(self, cluster):
            return ClusterStatus(cluster.name, cluster.server, cluster.source, reachable=True)

    settings = ClustersSettings(in_cluster=False, namespace="kube-tower", secret_names=["prod-creds", "labelled", "missing"])
    clusters, statuses = Registry(settings).discover()
    assert [c.name for c in clusters] == ["a", "prod"]
    assert ("missing", "Not Found") in [(s.name, s.message) for s in statuses]


def test_read_secret_without_local_client():
    class Registry(ClusterRegistry):
        def local_client(self):
            return None

    assert Registry(ClustersSettings()).discover() == ([], [])
    assert Registry(ClustersSettings())._read_secret("ns", "s") is None


def test_probe_reports_errors(monkeypatch):
    cluster = cluster_from_secret(_secret("s", name="p", server="https://127.0.0.1:1", config="{}"), "secret")
    status = ClusterRegistry(ClustersSettings(request_timeout=1)).probe(cluster)
    assert status.reachable is False and status.message


def test_current_namespace(monkeypatch, tmp_path):
    from kube_tower import clusters as clusters_module

    monkeypatch.setattr(clusters_module, "SA_NAMESPACE_FILE", str(tmp_path / "missing"))
    monkeypatch.setenv("POD_NAMESPACE", "tools")
    assert clusters_module.current_namespace() == "tools"
    (tmp_path / "ns").write_text("kube-tower\n")
    monkeypatch.setattr(clusters_module, "SA_NAMESPACE_FILE", str(tmp_path / "ns"))
    assert clusters_module.current_namespace() == "kube-tower"
