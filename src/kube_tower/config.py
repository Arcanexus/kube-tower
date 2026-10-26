"""Application settings, read from a YAML file (mounted from a ConfigMap) and env vars.

Secrets (registry credentials, git tokens) are never stored in the ConfigMap: they
are mounted from Kubernetes Secrets as files or env vars and referenced here.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, get_args, get_origin, get_type_hints

import yaml

DEFAULT_CONFIG_PATH = "/etc/kube-tower/config.yaml"
_DURATION_RE = re.compile(r"^(\d+)([smhd]?)$")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: str | int) -> int:
    """Convert `30s`, `15m`, `6h`, `1d` or a number of seconds to seconds."""
    if isinstance(value, int):
        return value
    match = _DURATION_RE.match(str(value).strip())
    if not match:
        raise ValueError(f"invalid duration: {value!r}")
    return int(match[1]) * _UNITS[match[2]]


@dataclass
class LogsSettings:
    level: str = "INFO"
    format: str = "json"  # json | logfmt | custom


@dataclass
class ClustersSettings:
    in_cluster: bool = True
    in_cluster_name: str = "in-cluster"
    # Namespace where cluster secrets live; empty means the pod's own namespace.
    namespace: str = ""
    # Cluster secrets of that namespace, read by name whatever their labels (`get` on these Secrets only).
    secret_names: list[str] = field(default_factory=list)
    # Also list the Secrets of that namespace carrying secretLabelSelector. Listing needs `list` on
    # secrets, which reads every Secret of the namespace (RBAC cannot filter on labels): off by default.
    list_secrets: bool = False
    secret_label_selector: str = "kube-tower.arcanexus.com/secret-type=cluster"
    # Also reuse ArgoCD cluster secrets (label argocd.argoproj.io/secret-type=cluster).
    use_argocd_secrets: bool = False
    argocd_namespace: str = "argocd"
    # ArgoCD cluster secrets read by name. Empty: they are listed, which reads every Secret of the
    # ArgoCD namespace (argocd-secret, repository credentials...).
    argocd_secret_names: list[str] = field(default_factory=list)
    request_timeout: int = 30
    # Commands that kubeconfig exec plugins may run (e.g. /opt/kube-tower/bin/kubelogin for AKS), as
    # written in the kubeconfig. Empty: exec plugins are refused (a cluster Secret could run any command).
    exec_commands: list[str] = field(default_factory=list)


@dataclass
class ImagesSettings:
    enabled: bool = True
    include_node_images: bool = True
    include_prerelease: bool = False
    # Check the digest of floating tags (latest, stable...) against the registry.
    check_floating_digests: bool = True
    # Read the published digests of the current and latest tags, shown in the image details.
    fetch_tag_digests: bool = True
    # fnmatch patterns on the image name (registry/repository), e.g. "registry.k8s.io/pause*".
    ignore: list[str] = field(default_factory=list)
    # Pages of 1000 tags read per repository: some have tens of thousands (CI builds), with the releases
    # anywhere in the list (ghcr.io lists them oldest first).
    max_tag_pages: int = 50


@dataclass
class HelmSettings:
    enabled: bool = True
    # Namespaces where ArgoCD Application objects are read; empty list means all namespaces.
    application_namespaces: list[str] = field(default_factory=lambda: ["argocd"])
    include_prerelease: bool = False
    check_dependencies: bool = True


@dataclass
class TrivySettings:
    """Trivy CLI, used for the images without a Trivy Operator report."""

    enabled: bool = True
    binary: str = "trivy"
    # Trivy server URL (client/server mode, e.g. http://kube-tower-trivy:4954): the server holds
    # the vulnerability database. Empty: standalone mode, the database is downloaded in cacheDir.
    server_url: str = ""
    cache_dir: str = "/tmp/trivy"
    timeout: int = 600  # per image
    concurrency: int = 2
    # Images are scanned again after this delay (new CVEs are published every day).
    rescan_interval: int = 24 * 3600
    ignore_unfixed: bool = False
    # Java DB (~1.5 GB) to scan Java archives (jar, war...): when disabled, they are skipped.
    java_db: bool = False
    extra_args: list[str] = field(default_factory=list)


@dataclass
class VulnerabilitiesSettings:
    enabled: bool = True
    # Read the VulnerabilityReports of Trivy Operator from the clusters where it is installed.
    trivy_operator: bool = True
    trivy: TrivySettings = field(default_factory=TrivySettings)
    # fnmatch patterns on the image name (registry/repository) of images never scanned.
    ignore: list[str] = field(default_factory=list)


@dataclass
class RegistryCredential:
    """Credentials for one registry host (container registry or Helm repository).

    Values are read from files (mounted Secrets) or env vars, never written in the ConfigMap.
    A token-only registry (e.g. ghcr.io with a PAT) only needs `passwordFile`/`passwordEnv`.
    `registry` is a host, or an fnmatch pattern of hosts (e.g. `*.dkr.ecr.*.amazonaws.com`).
    """

    registry: str
    # static: the username/password below. aws (Amazon ECR), gcp (Artifact Registry, gcr.io), azure (ACR):
    # short-lived tokens from the cloud identity of the pod (IRSA / EKS Pod Identity, GKE or AKS Workload Identity).
    provider: str = "static"
    username: str = ""
    username_file: str = ""
    username_env: str = ""
    password_file: str = ""
    password_env: str = ""


@dataclass
class RegistriesSettings:
    # Path of a docker config.json (kubernetes.io/dockerconfigjson secret mounted as a file).
    docker_config_path: str = "/etc/kube-tower/dockerconfig/config.json"
    # Per registry credentials; they take precedence over the docker config.json.
    credentials: list[RegistryCredential] = field(default_factory=list)
    # Registry host aliases, e.g. {"docker.io": "registry-1.docker.io"}.
    mirrors: dict[str, str] = field(default_factory=dict)
    # Also use the image pull secrets of the pods and workloads (kubernetes.io/dockerconfigjson Secrets read
    # in their namespace): needs `get` on Secrets in every namespace of the scanned clusters. Off by default.
    use_image_pull_secrets: bool = False
    # CA certificates (PEM file) trusted in addition to the public ones, e.g. for an internal Harbor or Artifactory.
    ca_file: str = ""
    # Hosts (or fnmatch patterns) whose TLS certificate is not verified, reached over plain http:// when
    # they do not answer in https://. Credentials are never sent over plain http://.
    insecure: list[str] = field(default_factory=list)
    concurrency: int = 8
    timeout: int = 20
    # Extra attempts for a request that timed out, failed to connect or got a 502/503/504.
    retries: int = 2


@dataclass
class GitSettings:
    # URL templates to fetch a raw file; {owner}, {repo}, {ref}, {path} are substituted.
    raw_url_templates: dict[str, str] = field(
        default_factory=lambda: {
            "github.com": "https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}",
            "gitlab.com": "https://gitlab.com/{owner}/{repo}/-/raw/{ref}/{path}",
        }
    )
    # Env var holding a token for private repositories (sent as a Bearer token).
    token_env: str = "GIT_TOKEN"


# What one kube-tower process runs: any combination of the roles, `all` meaning every role (UI, API,
# scans, as before). Pods with different roles split the work for horizontal scaling, see
# docs/adr/0002-horizontal-scaling.md.
ROLES = ("ui", "controller", "worker", "trivy")


@dataclass
class InternalSettings:
    """The internal API between the processes of the distributed mode (unused when one process runs every role)."""

    # Port of the controller's internal API, apart from the UI port so that NetworkPolicies can keep it internal.
    port: int = 8081
    # Where worker and trivy processes reach the controller, e.g. http://kube-tower-controller:8081.
    controller_url: str = ""
    # Env var holding the token shared by the processes (sent as a Bearer token).
    token_env: str = "KUBE_TOWER_INTERNAL_TOKEN"
    # A task pulled by a worker and not answered within this time is given to another one (seconds or 10m).
    task_timeout: int = 30 * 60
    # Images (or charts) per version check or Trivy task: a scan is shared by the worker and trivy processes.
    batch_size: int = 50


@dataclass
class Settings:
    roles: list[str] = field(default_factory=lambda: ["all"])
    refresh_interval: int = 6 * 3600
    logs: LogsSettings = field(default_factory=LogsSettings)
    clusters: ClustersSettings = field(default_factory=ClustersSettings)
    images: ImagesSettings = field(default_factory=ImagesSettings)
    helm: HelmSettings = field(default_factory=HelmSettings)
    vulnerabilities: VulnerabilitiesSettings = field(default_factory=VulnerabilitiesSettings)
    registries: RegistriesSettings = field(default_factory=RegistriesSettings)
    git: GitSettings = field(default_factory=GitSettings)
    internal: InternalSettings = field(default_factory=InternalSettings)

    @property
    def distributed(self) -> bool:
        """Some roles run in other processes: the tasks and results go through the internal API."""
        return set(self.roles) != set(ROLES) and "all" not in self.roles


def _camel_to_snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _build(cls: type, data: dict[str, Any]) -> Any:
    hints = get_type_hints(cls)
    known = {f.name for f in fields(cls)}
    kwargs: dict[str, Any] = {}
    for key, value in (data or {}).items():
        attr = _camel_to_snake(key)
        if attr not in known:
            raise ValueError(f"unknown setting {key!r} in section {cls.__name__}")
        hint = hints[attr]
        if is_dataclass(hint):
            kwargs[attr] = _build(hint, value)
        elif get_origin(hint) is list and get_args(hint) and is_dataclass(get_args(hint)[0]):
            kwargs[attr] = [_build(get_args(hint)[0], item) for item in value or []]
        elif hint is int and isinstance(value, str):  # durations: refreshInterval: 6h, timeout: 10m
            kwargs[attr] = parse_duration(value)
        else:
            kwargs[attr] = value
    return cls(**kwargs)


def load_settings(path: str | None = None) -> Settings:
    path = path or os.environ.get("KUBE_TOWER_CONFIG", DEFAULT_CONFIG_PATH)
    data: dict[str, Any] = {}
    if Path(path).is_file():
        data = yaml.safe_load(Path(path).read_text()) or {}
    settings = _build(Settings, data)
    if level := os.environ.get("KUBE_TOWER_LOG_LEVEL"):
        settings.logs.level = level
    if interval := os.environ.get("KUBE_TOWER_REFRESH_INTERVAL"):
        settings.refresh_interval = parse_duration(interval)
    if roles := os.environ.get("KUBE_TOWER_ROLES"):
        settings.roles = [r.strip() for r in roles.split(",") if r.strip()]
    if url := os.environ.get("KUBE_TOWER_CONTROLLER_URL"):
        settings.internal.controller_url = url
    settings.roles = check_roles(settings.roles)
    check_internal(settings)
    return settings


def check_roles(roles: list[str]) -> list[str]:
    """The roles of this process, `all` expanded, in a fixed order."""
    if unknown := [r for r in roles if r != "all" and r not in ROLES]:
        raise ValueError(f"unknown role(s) {', '.join(map(repr, unknown))}: expected all or a list of {', '.join(ROLES)}")
    chosen = set(ROLES) if "all" in roles else set(roles)
    if not chosen:
        raise ValueError(f"no role: expected all or a list of {', '.join(ROLES)}")
    return [r for r in ROLES if r in chosen]


def check_internal(settings: Settings) -> None:
    """The distributed mode needs the shared token, and the controller URL in processes without the controller."""
    if not settings.distributed:
        return
    if not internal_token(settings):
        raise ValueError(f"roles {', '.join(settings.roles)}: set the internal API token in ${settings.internal.token_env}")
    if "controller" not in settings.roles and not settings.internal.controller_url:
        raise ValueError(
            f"roles {', '.join(settings.roles)}: set internal.controllerUrl (or $KUBE_TOWER_CONTROLLER_URL)"
            " to reach the controller"
        )


def internal_token(settings: Settings) -> str:
    return os.environ.get(settings.internal.token_env, "")
