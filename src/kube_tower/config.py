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
    max_tag_pages: int = 10


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
    """

    registry: str
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


@dataclass
class Settings:
    refresh_interval: int = 6 * 3600
    logs: LogsSettings = field(default_factory=LogsSettings)
    clusters: ClustersSettings = field(default_factory=ClustersSettings)
    images: ImagesSettings = field(default_factory=ImagesSettings)
    helm: HelmSettings = field(default_factory=HelmSettings)
    vulnerabilities: VulnerabilitiesSettings = field(default_factory=VulnerabilitiesSettings)
    registries: RegistriesSettings = field(default_factory=RegistriesSettings)
    git: GitSettings = field(default_factory=GitSettings)


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
    return settings
