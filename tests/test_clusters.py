import base64
import json

import pytest
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


def _kubeconfig(user: dict, cluster: dict | None = None) -> str:
    return json.dumps(
        {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [{"name": "c", "cluster": cluster or {"server": "https://k:6443", "insecure-skip-tls-verify": True}}],
            "users": [{"name": "u", "user": user}],
            "contexts": [{"name": "ctx", "context": {"cluster": "c", "user": "u"}}],
            "current-context": "ctx",
        }
    )


EXEC_USER = {
    "exec": {
        "apiVersion": "client.authentication.k8s.io/v1beta1",
        "command": "/opt/kube-tower/bin/plugin",
        "args": ["get-token"],
    }
}


def test_kubeconfig_exec_refused_by_default(monkeypatch):
    ran = []
    monkeypatch.setattr("kubernetes.config.exec_provider.subprocess.Popen", lambda *a, **k: ran.append(a))
    with pytest.raises(ValueError, match="exec command '/opt/kube-tower/bin/plugin' is not allowed.*clusters.execCommands"):
        cluster_from_secret(_secret("eks", kubeconfig=_kubeconfig(EXEC_USER)), "secret")
    with pytest.raises(ValueError, match="not allowed"):
        cluster_from_secret(_secret("eks", kubeconfig=_kubeconfig(EXEC_USER)), "secret", ["plugin"])  # not the same command
    assert ran == []


def test_kubeconfig_exec_allowed_command(monkeypatch):
    class Process:
        returncode = 0
        stdout = None

        def __init__(self, args, **kwargs):
            self.args = args

        def communicate(self):
            status = {"apiVersion": "client.authentication.k8s.io/v1beta1", "kind": "ExecCredential"}
            return json.dumps({**status, "status": {"token": "from-plugin"}}), ""

        def wait(self):
            return 0

    monkeypatch.setattr("kubernetes.config.exec_provider.subprocess.Popen", Process)
    cluster = cluster_from_secret(_secret("eks", kubeconfig=_kubeconfig(EXEC_USER)), "secret", ["/opt/kube-tower/bin/plugin"])
    assert cluster.api_client.configuration.api_key["BearerToken"] == "Bearer from-plugin"


@pytest.mark.parametrize(
    "user,cluster,message",
    [
        ({"auth-provider": {"name": "gcp", "config": {"cmd-path": "/bin/sh"}}}, None, "auth-provider is not supported"),
        ({"tokenFile": "/var/run/secrets/kubernetes.io/serviceaccount/token"}, None, "tokenFile .* put the content in token"),
        ({"client-certificate": "/etc/x.crt", "client-key": "/etc/x.key"}, None, "client-certificate .* client-certificate-data"),
        ({"token": "t"}, {"server": "https://k:6443", "certificate-authority": "/etc/ca.crt"}, "certificate-authority"),
    ],
)
def test_kubeconfig_local_files_and_auth_providers_refused(user, cluster, message):
    with pytest.raises(ValueError, match=message):
        cluster_from_secret(_secret("lab", kubeconfig=_kubeconfig(user, cluster)), "secret")


def test_kubeconfig_not_a_mapping():
    with pytest.raises(ValueError, match="not a YAML mapping"):
        cluster_from_secret(_secret("lab", kubeconfig="just text"), "secret")


def test_refused_exec_kubeconfig_reported_in_discovery():
    registry = FakeRegistry([_secret("eks", name="eks", kubeconfig=_kubeconfig(EXEC_USER))])
    clusters, statuses = registry.discover()
    assert clusters == []
    assert "clusters.execCommands" in statuses[0].message


class FakeRegistry(ClusterRegistry):
    def __init__(self, secrets):
        super().__init__(ClustersSettings(in_cluster=False, namespace="kube-tower", list_secrets=True))
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
    clusters, statuses = Registry(ClustersSettings(list_secrets=True, use_argocd_secrets=True)).discover()
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

    settings = ClustersSettings(
        in_cluster=False, namespace="kube-tower", secret_names=["prod-creds", "labelled", "missing"], list_secrets=True
    )
    clusters, statuses = Registry(settings).discover()
    assert [c.name for c in clusters] == ["prod", "a"]  # the listed copy of "labelled" is skipped (same server)
    assert ("missing", "Not Found") in [(s.name, s.message) for s in statuses]


class NamedOnlyRegistry(ClusterRegistry):
    """Fails on any list: reading by name must never list Secrets."""

    def __init__(self, settings, secrets):
        super().__init__(settings)
        self.secrets = secrets
        self.reads = []

    def local_client(self):
        return client.ApiClient(client.Configuration(host="https://local"))

    def _list_secrets(self, namespace, selector):
        raise AssertionError(f"secrets listed in {namespace}")

    def _read_secret(self, namespace, name):
        self.reads.append((namespace, name))
        return self.secrets[name]

    def probe(self, cluster):
        from kube_tower.models import ClusterStatus

        return ClusterStatus(cluster.name, cluster.server, cluster.source, reachable=True)


def test_secrets_read_by_name_only_by_default():
    secrets = {"prod": _secret("prod", name="prod", server="https://prod", config="{}")}
    settings = ClustersSettings(in_cluster=False, namespace="kube-tower", secret_names=["prod"])
    clusters, _ = NamedOnlyRegistry(settings, secrets).discover()
    assert [c.name for c in clusters] == ["prod"]


def test_argocd_secrets_read_by_name():
    secrets = {
        "prod": _secret("prod", name="prod", server="https://prod", config="{}"),
        "cluster-argo-1": _secret("cluster-argo-1", name="argo", server="https://argo", config="{}"),
    }
    settings = ClustersSettings(
        in_cluster=False,
        namespace="kube-tower",
        secret_names=["prod"],
        use_argocd_secrets=True,
        argocd_namespace="gitops",
        argocd_secret_names=["cluster-argo-1"],
    )
    registry = NamedOnlyRegistry(settings, secrets)
    clusters, _ = registry.discover()
    assert [(c.name, c.source) for c in clusters] == [("prod", "secret"), ("argo", "argocd-secret")]
    assert registry.reads == [("kube-tower", "prod"), ("gitops", "cluster-argo-1")]


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


def test_clusters_probed_in_parallel():
    import threading

    from kube_tower.models import ClusterStatus

    secrets = {f"c{i}": _secret(f"c{i}", name=f"c{i}", server=f"https://c{i}", config="{}") for i in range(4)}
    barrier = threading.Barrier(4, timeout=5)  # every probe waits for the 3 others: fails if run one by one

    class Registry(NamedOnlyRegistry):
        def probe(self, cluster):
            barrier.wait()
            return ClusterStatus(cluster.name, cluster.server, cluster.source, reachable=cluster.name != "c2")

    settings = ClustersSettings(in_cluster=False, namespace="kube-tower", secret_names=list(secrets))
    clusters, statuses = Registry(settings, secrets).discover()
    assert [c.name for c in clusters] == ["c0", "c1", "c2", "c3"]
    assert [(s.name, s.reachable) for s in statuses] == [("c0", True), ("c1", True), ("c2", False), ("c3", True)]
