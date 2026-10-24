"""Cluster registry: discovers the clusters to scan, ArgoCD style.

Clusters are declared with Secrets labelled `kube-tower.arcanexus.com/secret-type=cluster`
using the same layout as ArgoCD cluster secrets:

    stringData:
      name: prod
      server: https://prod.example.com:6443
      config: |
        {"bearerToken": "...", "tlsClientConfig": {"caData": "<base64 PEM>", "insecure": false}}

A `kubeconfig` key holding a full kubeconfig is also accepted instead of `server`/`config`.
Secrets listed by name in `clusters.secretNames` are used too, whatever their labels.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import tempfile
from dataclasses import dataclass

import yaml
from kubernetes import client, config

from kube_tower.config import ClustersSettings
from kube_tower.errors import cluster_unreachable_message
from kube_tower.models import ClusterStatus

log = logging.getLogger(__name__)

SA_NAMESPACE_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
ARGOCD_SECRET_SELECTOR = "argocd.argoproj.io/secret-type=cluster"
ARGOCD_IN_CLUSTER_SERVER = "https://kubernetes.default.svc"


@dataclass
class Cluster:
    name: str
    server: str
    source: str
    api_client: client.ApiClient


def current_namespace() -> str:
    try:
        with open(SA_NAMESPACE_FILE) as fh:
            return fh.read().strip()
    except OSError:
        return os.environ.get("POD_NAMESPACE", "default")


def _write_temp(data_b64: str, suffix: str) -> str:
    """kubernetes-client expects file paths for certificates."""
    fh = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    fh.write(base64.b64decode(data_b64))
    fh.close()
    return fh.name


def api_client_from_argocd_config(server: str, raw_config: dict) -> client.ApiClient:
    cfg = client.Configuration()
    cfg.host = server
    if token := raw_config.get("bearerToken"):
        cfg.api_key = {"authorization": f"Bearer {token}"}
    elif raw_config.get("username"):
        cfg.username = raw_config["username"]
        cfg.password = raw_config.get("password", "")
        cfg.api_key = {"authorization": cfg.get_basic_auth_token()}
    tls = raw_config.get("tlsClientConfig") or {}
    cfg.verify_ssl = not tls.get("insecure", False)
    if tls.get("caData"):
        cfg.ssl_ca_cert = _write_temp(tls["caData"], ".crt")
    if tls.get("certData") and tls.get("keyData"):
        cfg.cert_file = _write_temp(tls["certData"], ".crt")
        cfg.key_file = _write_temp(tls["keyData"], ".key")
    if tls.get("serverName"):
        cfg.tls_server_name = tls["serverName"]
    if "execProviderConfig" in raw_config or "awsAuthConfig" in raw_config:
        raise ValueError(
            "exec / AWS auth is not supported in the ArgoCD format: use a bearer token, "
            "or a kubeconfig key with an exec plugin allowed in clusters.execCommands"
        )
    return client.ApiClient(cfg)


# kubeconfig keys that read a file of the pod: a cluster Secret must hold the data itself (`*-data`, `token`).
KUBECONFIG_FILE_KEYS = {
    "cluster": ("certificate-authority",),
    "user": ("tokenFile", "client-certificate", "client-key"),
}


def check_kubeconfig(data: dict, exec_commands: list[str]) -> None:
    """Refuse what a kubeconfig could make kube-tower run or read in its pod: exec plugins whose
    command is not in `clusters.execCommands`, auth providers, and paths of local files.
    Anyone who can write a cluster Secret would otherwise run a command with kube-tower's identity.
    """
    for kind, keys in KUBECONFIG_FILE_KEYS.items():
        for entry in data.get(f"{kind}s") or []:
            for key in keys:
                if (entry.get(kind) or {}).get(key):
                    raise ValueError(
                        f"kubeconfig {kind} {entry.get('name')!r}: {key} (a file path) is not supported, "
                        f"put the content in {'token' if key == 'tokenFile' else key + '-data'}"
                    )
    for entry in data.get("users") or []:
        user = entry.get("user") or {}
        if "auth-provider" in user:
            raise ValueError(
                f"kubeconfig user {entry.get('name')!r}: auth-provider is not supported, use a token or an exec plugin"
            )
        if exec_config := user.get("exec"):
            command = exec_config.get("command", "")
            if command not in exec_commands:
                raise ValueError(
                    f"kubeconfig user {entry.get('name')!r}: exec command {command!r} is not allowed, "
                    "add it to clusters.execCommands to run it (or use a ServiceAccount token)"
                )


def api_client_from_kubeconfig(kubeconfig: str, exec_commands: list[str] | None = None) -> tuple[client.ApiClient, str]:
    cfg = client.Configuration()
    data = yaml.safe_load(kubeconfig)
    if not isinstance(data, dict):
        raise ValueError("kubeconfig is not a YAML mapping")
    check_kubeconfig(data, exec_commands or [])
    loader = config.kube_config.KubeConfigLoader(config_dict=data)
    loader.load_and_set(cfg)
    return client.ApiClient(cfg), cfg.host


def _decode(secret: client.V1Secret, key: str) -> str | None:
    value = (secret.data or {}).get(key)
    return base64.b64decode(value).decode() if value else None


def cluster_from_secret(secret: client.V1Secret, source: str, exec_commands: list[str] | None = None) -> Cluster:
    name = _decode(secret, "name") or secret.metadata.name
    if kubeconfig := _decode(secret, "kubeconfig"):
        api, server = api_client_from_kubeconfig(kubeconfig, exec_commands)
        return Cluster(name=name, server=server, source=source, api_client=api)
    server = _decode(secret, "server")
    if not server:
        raise ValueError("secret has neither 'server' nor 'kubeconfig'")
    raw_config = json.loads(_decode(secret, "config") or "{}")
    return Cluster(name=name, server=server, source=source, api_client=api_client_from_argocd_config(server, raw_config))


class ClusterRegistry:
    def __init__(self, settings: ClustersSettings):
        self.settings = settings
        self._local: client.ApiClient | None = None

    def local_client(self) -> client.ApiClient | None:
        """Client for the cluster kube-tower runs in (or the local kubeconfig in dev)."""
        if self._local is None:
            try:
                config.load_incluster_config()
                log.debug("using the in-cluster configuration")
            except config.ConfigException:
                try:
                    config.load_kube_config()
                    log.debug("using the local kubeconfig")
                except (config.ConfigException, FileNotFoundError):
                    log.warning(
                        "no in-cluster configuration nor kubeconfig found: the local cluster is not scanned "
                        "(set clusters.inCluster=false if this is expected)"
                    )
                    return None
            self._local = client.ApiClient()
        return self._local

    def _list_secrets(self, namespace: str, selector: str) -> list[client.V1Secret]:
        local = self.local_client()
        if local is None:
            return []
        return client.CoreV1Api(local).list_namespaced_secret(namespace, label_selector=selector).items

    def _read_secret(self, namespace: str, name: str) -> client.V1Secret | None:
        local = self.local_client()
        if local is None:
            return None
        return client.CoreV1Api(local).read_namespaced_secret(name, namespace)

    def _named_secrets(self, namespace: str, statuses: list[ClusterStatus]) -> list[client.V1Secret]:
        secrets = []
        for name in self.settings.secret_names:
            try:
                if secret := self._read_secret(namespace, name):
                    secrets.append(secret)
            except client.ApiException as exc:
                log.warning(
                    "cannot read cluster secret %s/%s listed in clusters.secretNames: %s %s%s",
                    namespace,
                    name,
                    exc.status,
                    exc.reason,
                    " (does it exist in this namespace?)" if exc.status == 404 else "",
                )
                statuses.append(ClusterStatus(name, "", "secret", message=exc.reason))
        return secrets

    def discover(self) -> tuple[list[Cluster], list[ClusterStatus]]:
        """Return usable clusters and a status line for every declared cluster."""
        clusters: list[Cluster] = []
        statuses: list[ClusterStatus] = []
        seen_servers: set[str] = set()

        if self.settings.in_cluster and (local := self.local_client()):
            clusters.append(Cluster(self.settings.in_cluster_name, local.configuration.host, "in-cluster", local))
            seen_servers.add(ARGOCD_IN_CLUSTER_SERVER)

        namespace = self.settings.namespace or current_namespace()
        sources = [(namespace, self.settings.secret_label_selector, "secret")]
        if self.settings.use_argocd_secrets:
            sources.append((self.settings.argocd_namespace, ARGOCD_SECRET_SELECTOR, "argocd-secret"))

        for namespace, selector, source in sources:
            try:
                secrets = self._list_secrets(namespace, selector)
            except client.ApiException as exc:
                log.warning(
                    "cannot list %s cluster secrets in namespace %s: %s %s%s",
                    source,
                    namespace,
                    exc.status,
                    exc.reason,
                    " (kube-tower needs read access to secrets there)" if exc.status == 403 else "",
                )
                statuses.append(ClusterStatus(f"<{source}s in {namespace}>", "", source, message=exc.reason))
                secrets = []
            log.debug("%d %s cluster secret(s) in namespace %s (selector %s)", len(secrets), source, namespace, selector)
            if source == "secret":
                # A named secret also matched by the label selector is skipped below (same server).
                secrets = secrets + self._named_secrets(namespace, statuses)
            for secret in secrets:
                try:
                    cluster = cluster_from_secret(secret, source, self.settings.exec_commands)
                except Exception as exc:  # noqa: BLE001 - one bad secret must not break discovery
                    log.warning(
                        "invalid cluster secret %s/%s, cluster ignored: %s (expected keys: name, server, config, or kubeconfig)",
                        namespace,
                        secret.metadata.name,
                        exc,
                    )
                    statuses.append(ClusterStatus(secret.metadata.name, "", source, message=str(exc)))
                    continue
                if cluster.server.rstrip("/") in seen_servers:
                    log.debug("cluster secret %s skipped: server %s already registered", secret.metadata.name, cluster.server)
                    continue
                seen_servers.add(cluster.server.rstrip("/"))
                clusters.append(cluster)

        for cluster in clusters:
            status = self.probe(cluster)
            statuses.append(status)
            if status.reachable:
                log.info(
                    "cluster %s (%s, %s): reachable, Kubernetes %s", cluster.name, cluster.source, cluster.server, status.version
                )
            else:
                log.warning("cluster %s (%s) skipped: %s", cluster.name, cluster.source, status.message)
        return clusters, statuses

    def probe(self, cluster: Cluster) -> ClusterStatus:
        status = ClusterStatus(cluster.name, cluster.server, cluster.source)
        try:
            info = client.VersionApi(cluster.api_client).get_code(_request_timeout=self.settings.request_timeout)
            status.reachable = True
            status.version = info.git_version
        except Exception as exc:  # noqa: BLE001
            status.message = cluster_unreachable_message(exc, cluster.server)
        return status
