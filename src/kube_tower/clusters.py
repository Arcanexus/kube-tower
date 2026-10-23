"""Cluster registry: discovers the clusters to scan, ArgoCD style.

Clusters are declared with Secrets labelled `kube-tower.arcanexus.com/secret-type=cluster`
using the same layout as ArgoCD cluster secrets:

    stringData:
      name: prod
      server: https://prod.example.com:6443
      config: |
        {"bearerToken": "...", "tlsClientConfig": {"caData": "<base64 PEM>", "insecure": false}}

A `kubeconfig` key holding a full kubeconfig is also accepted instead of `server`/`config`.
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
        raise ValueError("exec / AWS auth is not supported, use a bearer token")
    return client.ApiClient(cfg)


def api_client_from_kubeconfig(kubeconfig: str) -> tuple[client.ApiClient, str]:
    cfg = client.Configuration()
    loader = config.kube_config.KubeConfigLoader(config_dict=yaml.safe_load(kubeconfig))
    loader.load_and_set(cfg)
    return client.ApiClient(cfg), cfg.host


def _decode(secret: client.V1Secret, key: str) -> str | None:
    value = (secret.data or {}).get(key)
    return base64.b64decode(value).decode() if value else None


def cluster_from_secret(secret: client.V1Secret, source: str) -> Cluster:
    name = _decode(secret, "name") or secret.metadata.name
    if kubeconfig := _decode(secret, "kubeconfig"):
        api, server = api_client_from_kubeconfig(kubeconfig)
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
            except config.ConfigException:
                try:
                    config.load_kube_config()
                except (config.ConfigException, FileNotFoundError):
                    log.warning("no in-cluster config nor kubeconfig found")
                    return None
            self._local = client.ApiClient()
        return self._local

    def _list_secrets(self, namespace: str, selector: str) -> list[client.V1Secret]:
        local = self.local_client()
        if local is None:
            return []
        return client.CoreV1Api(local).list_namespaced_secret(namespace, label_selector=selector).items

    def discover(self) -> tuple[list[Cluster], list[ClusterStatus]]:
        """Return usable clusters and a status line for every declared cluster."""
        clusters: list[Cluster] = []
        statuses: list[ClusterStatus] = []
        seen_servers: set[str] = set()

        if self.settings.in_cluster and (local := self.local_client()):
            clusters.append(Cluster(self.settings.in_cluster_name, local.configuration.host, "in-cluster", local))
            seen_servers.add(ARGOCD_IN_CLUSTER_SERVER)

        sources = [(self.settings.namespace or current_namespace(), self.settings.secret_label_selector, "secret")]
        if self.settings.use_argocd_secrets:
            sources.append((self.settings.argocd_namespace, ARGOCD_SECRET_SELECTOR, "argocd-secret"))

        for namespace, selector, source in sources:
            try:
                secrets = self._list_secrets(namespace, selector)
            except client.ApiException as exc:
                statuses.append(ClusterStatus(f"<{source}s in {namespace}>", "", source, message=exc.reason))
                continue
            for secret in secrets:
                try:
                    cluster = cluster_from_secret(secret, source)
                except Exception as exc:  # noqa: BLE001 - one bad secret must not break discovery
                    statuses.append(ClusterStatus(secret.metadata.name, "", source, message=str(exc)))
                    continue
                if cluster.server.rstrip("/") in seen_servers:
                    continue
                seen_servers.add(cluster.server.rstrip("/"))
                clusters.append(cluster)

        for cluster in clusters:
            statuses.append(self.probe(cluster))
        return clusters, statuses

    def probe(self, cluster: Cluster) -> ClusterStatus:
        status = ClusterStatus(cluster.name, cluster.server, cluster.source)
        try:
            info = client.VersionApi(cluster.api_client).get_code(_request_timeout=self.settings.request_timeout)
            status.reachable = True
            status.version = info.git_version
        except Exception as exc:  # noqa: BLE001
            status.message = str(exc).splitlines()[0][:300]
        return status
