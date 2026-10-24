"""Helm chart rendering tests: run where helm is installed (the CI helm job), skipped otherwise."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from kube_tower.config import load_settings

HELM = os.environ.get("HELM_BIN") or shutil.which("helm")
CHART = Path(__file__).parent.parent / "charts" / "kube-tower"

pytestmark = pytest.mark.skipif(HELM is None, reason="helm is not installed")


def render(tmp_path, values: dict) -> dict[tuple[str, str], dict]:
    values_file = tmp_path / "values.yaml"
    values_file.write_text(yaml.safe_dump(values))
    out = subprocess.run(
        [HELM, "template", "kt", str(CHART), "-f", str(values_file)], check=True, capture_output=True, text=True
    ).stdout
    return {(d["kind"], d["metadata"]["name"]): d for d in yaml.safe_load_all(out) if d}


def render_error(tmp_path, values: dict) -> str:
    values_file = tmp_path / "values.yaml"
    values_file.write_text(yaml.safe_dump(values))
    result = subprocess.run([HELM, "template", "kt", str(CHART), "-f", str(values_file)], capture_output=True, text=True)
    assert result.returncode != 0
    return result.stderr


def app_settings(tmp_path, docs):
    """The rendered config must be accepted by the application (unknown keys are rejected)."""
    path = tmp_path / "config.yaml"
    path.write_text(docs[("ConfigMap", "kt-kube-tower")]["data"]["config.yaml"])
    return load_settings(str(path))


def container(docs):
    return docs[("Deployment", "kt-kube-tower")]["spec"]["template"]["spec"]["containers"][0]


def volumes(docs):
    return {v["name"]: v for v in docs[("Deployment", "kt-kube-tower")]["spec"]["template"]["spec"]["volumes"]}


def test_defaults_create_no_secret(tmp_path):
    docs = render(tmp_path, {})
    assert not [k for k in docs if k[0] == "Secret"]
    assert app_settings(tmp_path, docs).clusters.secret_names == []
    assert "dockerconfig" not in volumes(docs)


def test_cluster_secrets_created_or_referenced(tmp_path):
    docs = render(
        tmp_path,
        {
            "clusters": [
                {"name": "prod", "server": "https://prod:6443", "config": {"bearerToken": "abc"}},
                {"name": "lab", "kubeconfig": "apiVersion: v1\nkind: Config\n"},
                {"existingSecret": "staging-cluster"},
            ],
            "config": {"clusters": {"secretNames": ["other", "staging-cluster"]}},
        },
    )
    prod = docs[("Secret", "kt-kube-tower-cluster-prod")]
    assert prod["metadata"]["labels"]["kube-tower.arcanexus.com/secret-type"] == "cluster"
    assert prod["stringData"] == {"name": "prod", "server": "https://prod:6443", "config": '{"bearerToken":"abc"}'}
    assert docs[("Secret", "kt-kube-tower-cluster-lab")]["stringData"]["kubeconfig"].startswith("apiVersion: v1")
    assert ("Secret", "kt-kube-tower-cluster-") not in docs
    assert len([k for k in docs if k[0] == "Secret"]) == 2

    assert app_settings(tmp_path, docs).clusters.secret_names == ["other", "staging-cluster"]
    rules = docs[("Role", "kt-kube-tower-cluster-secrets")]["rules"]
    assert {"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["other", "staging-cluster"], "verbs": ["get"]} in rules


def test_cluster_without_server_fails(tmp_path):
    assert "server or kubeconfig is required" in render_error(tmp_path, {"clusters": [{"name": "x"}]})
    assert "clusters[].name is required" in render_error(tmp_path, {"clusters": [{"server": "https://x"}]})


def test_registry_credentials_created_or_referenced(tmp_path):
    docs = render(
        tmp_path,
        {
            "registries": {
                "credentials": [
                    {"registry": "docker.io", "existingSecret": "dockerhub", "usernameKey": "username"},
                    {"registry": "ghcr.io", "existingSecret": "ghcr", "passwordKey": "token", "password": "ignored"},
                    {"registry": "quay.io", "username": "robot", "password": "s3cret", "passwordKey": "ignored"},
                ]
            }
        },
    )
    assert docs[("Secret", "kt-kube-tower-registry-2")]["stringData"] == {"password": "s3cret"}
    assert ("Secret", "kt-kube-tower-registry-1") not in docs
    vols = volumes(docs)
    assert [vols[f"registry-{i}"]["secret"]["secretName"] for i in range(3)] == ["dockerhub", "ghcr", "kt-kube-tower-registry-2"]

    creds = app_settings(tmp_path, docs).registries.credentials
    assert [(c.registry, c.username, c.username_file, c.password_file) for c in creds] == [
        ("docker.io", "", "/etc/kube-tower/registries/0/username", "/etc/kube-tower/registries/0/password"),
        ("ghcr.io", "", "", "/etc/kube-tower/registries/1/token"),
        ("quay.io", "robot", "", "/etc/kube-tower/registries/2/password"),
    ]


def test_registry_without_secret_fails(tmp_path):
    error = render_error(tmp_path, {"registries": {"credentials": [{"registry": "docker.io"}]}})
    assert "set existingSecret or password" in error


@pytest.mark.parametrize("content", [{"auths": {"ghcr.io": {"auth": "eA=="}}}, '{"auths": {"ghcr.io": {"auth": "eA=="}}}'])
def test_docker_config_created(tmp_path, content):
    docs = render(tmp_path, {"registries": {"dockerConfigJson": content}})
    secret = docs[("Secret", "kt-kube-tower-dockerconfig")]
    assert secret["type"] == "kubernetes.io/dockerconfigjson"
    assert yaml.safe_load(secret["stringData"][".dockerconfigjson"]) == {"auths": {"ghcr.io": {"auth": "eA=="}}}
    assert volumes(docs)["dockerconfig"]["secret"]["secretName"] == "kt-kube-tower-dockerconfig"


def test_docker_config_existing_secret_wins(tmp_path):
    docs = render(tmp_path, {"registries": {"existingSecret": "regcreds", "dockerConfigJson": {"auths": {}}}})
    assert ("Secret", "kt-kube-tower-dockerconfig") not in docs
    assert volumes(docs)["dockerconfig"]["secret"]["secretName"] == "regcreds"


@pytest.mark.parametrize(
    ("git", "secret", "key"),
    [
        ({"token": "ghp_x"}, "kt-kube-tower-git", "token"),
        ({"existingSecret": "git", "secretKey": "pat", "token": "x"}, "git", "pat"),
    ],
)
def test_git_token(tmp_path, git, secret, key):
    docs = render(tmp_path, {"git": git})
    assert (("Secret", "kt-kube-tower-git") in docs) == (secret == "kt-kube-tower-git")
    env = {e["name"]: e for e in container(docs)["env"]}
    assert env["GIT_TOKEN"]["valueFrom"]["secretKeyRef"] == {"name": secret, "key": key}


def test_credentials_change_restarts_pod(tmp_path):
    def checksum(token):
        docs = render(tmp_path, {"git": {"token": token}})
        return docs[("Deployment", "kt-kube-tower")]["spec"]["template"]["metadata"]["annotations"]["checksum/credentials"]

    assert checksum("a") != checksum("b")


def test_probes(tmp_path):
    c = container(render(tmp_path, {}))
    for probe in ("startupProbe", "livenessProbe", "readinessProbe"):
        assert c[probe]["httpGet"] == {"path": "/healthz", "port": "http"}
    assert c["startupProbe"]["failureThreshold"] * c["startupProbe"]["periodSeconds"] >= 300

    c = container(render(tmp_path, {"startupProbe": None, "livenessProbe": {"initialDelaySeconds": 30}}))
    assert "startupProbe" not in c
    assert c["livenessProbe"]["initialDelaySeconds"] == 30
    assert c["livenessProbe"]["periodSeconds"] == 20


def test_monitoring(tmp_path):
    assert not [k for k in render(tmp_path, {}) if k[0] == "ServiceMonitor" or k[1].endswith("-dashboard")]
    docs = render(
        tmp_path,
        {
            "serviceMonitor": {"enabled": True, "labels": {"release": "kps"}, "scrapeTimeout": "30s"},
            "grafanaDashboard": {"enabled": True, "namespace": "grafana", "annotations": {"grafana_folder": "Kubernetes"}},
        },
    )
    monitor = docs[("ServiceMonitor", "kt-kube-tower")]
    assert monitor["metadata"]["labels"]["release"] == "kps"
    assert monitor["spec"]["endpoints"][0]["honorLabels"] is True
    assert monitor["spec"]["endpoints"][0]["scrapeTimeout"] == "30s"
    dashboard = docs[("ConfigMap", "kt-kube-tower-dashboard")]
    assert dashboard["metadata"]["namespace"] == "grafana"
    assert dashboard["metadata"]["labels"]["grafana_dashboard"] == "1"
    assert dashboard["metadata"]["annotations"] == {"grafana_folder": "Kubernetes"}
    assert json.loads(dashboard["data"]["kube-tower.json"])["uid"] == "kube-tower"


def test_vulnerabilities_standalone_by_default(tmp_path):
    docs = render(tmp_path, {})
    settings = app_settings(tmp_path, docs).vulnerabilities
    assert settings.enabled and settings.trivy_operator and settings.trivy.server_url == ""
    assert settings.trivy.timeout == 600 and settings.trivy.rescan_interval == 86400
    assert volumes(docs)["trivy-cache"]["emptyDir"]["sizeLimit"] == "3Gi"
    assert {"name": "trivy-cache", "mountPath": settings.trivy.cache_dir} in container(docs)["volumeMounts"]
    assert not [k for k in docs if k[1] == "kt-kube-tower-trivy"]
    # The Trivy CLI is copied from the official image by an init container
    assert settings.trivy.binary == "/opt/trivy/bin/trivy"
    pod = docs[("Deployment", "kt-kube-tower")]["spec"]["template"]["spec"]
    (init,) = pod["initContainers"]
    assert init["image"] == "ghcr.io/aquasecurity/trivy:0.75.0"
    assert init["command"] == ["cp", "/usr/local/bin/trivy", "/opt/trivy/bin/trivy"]
    assert {"name": "trivy-bin", "mountPath": "/opt/trivy/bin", "readOnly": True} in container(docs)["volumeMounts"]
    assert volumes(docs)["trivy-bin"] == {"name": "trivy-bin", "emptyDir": {}}
    rules = docs[("ClusterRole", "kt-kube-tower")]["rules"]
    assert {"apiGroups": ["aquasecurity.github.io"], "resources": ["vulnerabilityreports"], "verbs": ["get", "list"]} in rules


def test_trivy_server(tmp_path):
    docs = render(tmp_path, {"trivy": {"server": {"enabled": True}}})
    assert app_settings(tmp_path, docs).vulnerabilities.trivy.server_url == "http://kt-kube-tower-trivy:4954"
    server = docs[("Deployment", "kt-kube-tower-trivy")]
    service = docs[("Service", "kt-kube-tower-trivy")]
    labels = server["spec"]["template"]["metadata"]["labels"]
    assert server["spec"]["selector"]["matchLabels"] == labels == service["spec"]["selector"]
    # kube-tower's own Service and Deployment must not select the Trivy server pods
    kube_tower_selector = docs[("Service", "kt-kube-tower")]["spec"]["selector"]
    assert not kube_tower_selector.items() <= labels.items()
    assert docs[("Deployment", "kt-kube-tower")]["spec"]["selector"]["matchLabels"] == kube_tower_selector
    trivy = server["spec"]["template"]["spec"]["containers"][0]
    assert trivy["args"] == ["server", "--listen", "0.0.0.0:4954", "--cache-dir", "/cache"]
    assert trivy["image"] == "ghcr.io/aquasecurity/trivy:0.75.0" and trivy["securityContext"]["readOnlyRootFilesystem"]
    assert "imagePullSecrets" not in server["spec"]["template"]["spec"]

    docs = render(
        tmp_path,
        {
            "trivy": {"server": {"enabled": True}},
            "config": {"vulnerabilities": {"trivy": {"serverUrl": "http://other:4954"}}},
            "imagePullSecrets": [{"name": "mirror"}],
        },
    )
    assert app_settings(tmp_path, docs).vulnerabilities.trivy.server_url == "http://other:4954"
    # A private trivy.image is pulled with the same secrets as kube-tower
    assert docs[("Deployment", "kt-kube-tower-trivy")]["spec"]["template"]["spec"]["imagePullSecrets"] == [{"name": "mirror"}]


@pytest.mark.parametrize(
    "values",
    [
        {"trivy": {"enabled": False}},  # e.g. linux/arm/v7 nodes: no official Trivy image
        {"config": {"vulnerabilities": {"enabled": False}}},
        {"config": {"vulnerabilities": {"trivy": {"enabled": False}}}},
    ],
)
def test_no_trivy_init_container(tmp_path, values):
    docs = render(tmp_path, values)
    assert "initContainers" not in docs[("Deployment", "kt-kube-tower")]["spec"]["template"]["spec"]
    assert "trivy-bin" not in volumes(docs)
    assert app_settings(tmp_path, docs).vulnerabilities.trivy.binary == "trivy"


def test_trivy_images_and_custom_binary(tmp_path):
    values = {
        "trivy": {"image": {"tag": "0.76.1"}, "server": {"enabled": True, "image": {"repository": "mirror/trivy"}}},
        "config": {"vulnerabilities": {"trivy": {"binary": "/usr/bin/trivy"}}},
    }
    docs = render(tmp_path, values)
    assert docs[("Deployment", "kt-kube-tower")]["spec"]["template"]["spec"]["initContainers"][0]["image"].endswith(":0.76.1")
    server = docs[("Deployment", "kt-kube-tower-trivy")]["spec"]["template"]["spec"]["containers"][0]
    assert server["image"] == "mirror/trivy:0.76.1"
    assert app_settings(tmp_path, docs).vulnerabilities.trivy.binary == "/usr/bin/trivy"


def test_exec_plugin_from_extra_init_container(tmp_path):
    docs = render(
        tmp_path,
        {
            "trivy": {"enabled": False},
            "config": {"clusters": {"execCommands": ["/opt/kube-tower/bin/kubelogin"]}},
            "extraInitContainers": [
                {"name": "kubelogin", "image": "plugins:1", "command": ["cp", "/kubelogin", "/opt/kube-tower/bin/"]}
            ],
            "extraEnv": [{"name": "AWS_REGION", "value": "eu-west-1"}],
            "extraVolumes": [{"name": "plugins", "emptyDir": {}}],
            "extraVolumeMounts": [{"name": "plugins", "mountPath": "/opt/kube-tower/bin", "readOnly": True}],
        },
    )
    spec = docs[("Deployment", "kt-kube-tower")]["spec"]["template"]["spec"]
    assert [c["name"] for c in spec["initContainers"]] == ["kubelogin"]
    assert {"name": "AWS_REGION", "value": "eu-west-1"} in container(docs)["env"]
    assert "plugins" in volumes(docs)
    assert {"name": "plugins", "mountPath": "/opt/kube-tower/bin", "readOnly": True} in container(docs)["volumeMounts"]
    assert app_settings(tmp_path, docs).clusters.exec_commands == ["/opt/kube-tower/bin/kubelogin"]


def test_extra_init_containers_after_trivy(tmp_path):
    docs = render(tmp_path, {"extraInitContainers": [{"name": "plugin", "image": "plugins:1"}]})
    names = [c["name"] for c in docs[("Deployment", "kt-kube-tower")]["spec"]["template"]["spec"]["initContainers"]]
    assert names == ["trivy", "plugin"]
