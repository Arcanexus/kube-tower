"""Helm chart rendering tests: run where helm is installed (the CI helm job), skipped otherwise."""

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
