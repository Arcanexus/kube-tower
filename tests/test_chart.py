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

    # Every cluster Secret, created by the chart or not, is read by name: no list on secrets
    names = ["other", "staging-cluster", "kt-kube-tower-cluster-prod", "kt-kube-tower-cluster-lab"]
    settings = app_settings(tmp_path, docs)
    assert settings.clusters.secret_names == names and settings.clusters.list_secrets is False
    rules = docs[("Role", "kt-kube-tower-cluster-secrets")]["rules"]
    assert rules == [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": names, "verbs": ["get"]}]


def test_no_secret_access_by_default(tmp_path):
    docs = render(tmp_path, {})
    assert not [k for k in docs if k[0] in ("Role", "RoleBinding")]


def test_list_cluster_secrets(tmp_path):
    docs = render(tmp_path, {"config": {"clusters": {"listSecrets": True}}})
    assert docs[("Role", "kt-kube-tower-cluster-secrets")]["rules"] == [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}
    ]
    assert ("RoleBinding", "kt-kube-tower-cluster-secrets") in docs
    assert app_settings(tmp_path, docs).clusters.list_secrets is True


def test_argocd_secrets_listed_or_read_by_name(tmp_path):
    docs = render(tmp_path, {"config": {"clusters": {"useArgocdSecrets": True}}})
    assert docs[("Role", "kt-kube-tower-argocd-clusters")]["rules"] == [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}
    ]
    names = ["cluster-prod-123", "cluster-lab-456"]
    docs = render(tmp_path, {"config": {"clusters": {"useArgocdSecrets": True, "argocdSecretNames": names}}})
    assert docs[("Role", "kt-kube-tower-argocd-clusters")]["rules"] == [
        {"apiGroups": [""], "resources": ["secrets"], "resourceNames": names, "verbs": ["get"]}
    ]
    assert app_settings(tmp_path, docs).clusters.argocd_secret_names == names


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
    (trivy_rule,) = [r for r in rules if r["apiGroups"] == ["aquasecurity.github.io"]]
    assert trivy_rule["verbs"] == ["get", "list"]
    assert {"vulnerabilityreports", "configauditreports", "exposedsecretreports", "clustercompliancereports"} <= set(
        trivy_rule["resources"]
    )


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
            "podLabels": {"azure.workload.identity/use": "true"},
        },
    )
    spec = docs[("Deployment", "kt-kube-tower")]["spec"]["template"]["spec"]
    assert [c["name"] for c in spec["initContainers"]] == ["kubelogin"]
    assert {"name": "AWS_REGION", "value": "eu-west-1"} in container(docs)["env"]
    assert "plugins" in volumes(docs)
    assert {"name": "plugins", "mountPath": "/opt/kube-tower/bin", "readOnly": True} in container(docs)["volumeMounts"]
    assert app_settings(tmp_path, docs).clusters.exec_commands == ["/opt/kube-tower/bin/kubelogin"]
    labels = docs[("Deployment", "kt-kube-tower")]["spec"]["template"]["metadata"]["labels"]
    assert labels["azure.workload.identity/use"] == "true" and "app.kubernetes.io/name" in labels


def test_extra_init_containers_after_trivy(tmp_path):
    docs = render(tmp_path, {"extraInitContainers": [{"name": "plugin", "image": "plugins:1"}]})
    names = [c["name"] for c in docs[("Deployment", "kt-kube-tower")]["spec"]["template"]["spec"]["initContainers"]]
    assert names == ["trivy", "plugin"]


def test_network_policies(tmp_path):
    assert not any(kind == "NetworkPolicy" for kind, _ in render(tmp_path, {}))  # optional
    docs = render(tmp_path, {"networkPolicy": {"enabled": True}})
    policy = docs[("NetworkPolicy", "kt-kube-tower")]["spec"]
    assert policy["podSelector"]["matchLabels"] == docs[("Service", "kt-kube-tower")]["spec"]["selector"]
    assert policy["ingress"] == [{"ports": [{"port": "http", "protocol": "TCP"}]}]
    dns, egress = policy["egress"]  # no Trivy server rule without the server
    assert {p["port"] for p in dns["ports"]} == {53} and "to" not in dns
    assert [p["port"] for p in egress["ports"]] == [443, 6443] and "to" not in egress
    assert ("NetworkPolicy", "kt-kube-tower-trivy") not in docs

    monitoring = {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "monitoring"}}}
    docs = render(
        tmp_path,
        {
            "trivy": {"server": {"enabled": True}},
            "networkPolicy": {
                "enabled": True,
                "ingress": {"from": [monitoring]},
                "egress": {"to": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "extra": [{"ports": [{"port": 5000}]}]},
            },
        },
    )
    policy = docs[("NetworkPolicy", "kt-kube-tower")]["spec"]
    assert policy["ingress"][0]["from"] == [monitoring]
    _, egress, trivy, extra = policy["egress"]
    assert egress["to"] == [{"ipBlock": {"cidr": "10.0.0.0/8"}}] and extra == {"ports": [{"port": 5000}]}
    server_labels = docs[("Deployment", "kt-kube-tower-trivy")]["spec"]["template"]["metadata"]["labels"]
    assert trivy["to"] == [{"podSelector": {"matchLabels": server_labels}}] and trivy["ports"][0]["port"] == 4954
    server = docs[("NetworkPolicy", "kt-kube-tower-trivy")]["spec"]
    assert server["podSelector"]["matchLabels"] == server_labels
    assert server["ingress"][0]["from"] == [{"podSelector": {"matchLabels": policy["podSelector"]["matchLabels"]}}]
    assert server["egress"][1]["to"] == [{"ipBlock": {"cidr": "10.0.0.0/8"}}]


def test_cloud_registry_providers_need_no_secret(tmp_path):
    docs = render(
        tmp_path,
        {
            "registries": {
                "credentials": [
                    {"registry": "*.dkr.ecr.*.amazonaws.com", "provider": "aws"},
                    {"registry": "quay.io", "password": "s3cret"},
                    {"registry": "myacr.azurecr.io", "provider": "azure"},
                ]
            }
        },
    )
    assert not [k for k in docs if k[0] == "Secret" and k[1] != "kt-kube-tower-registry-1"]
    assert {"registry-1"} == {name for name in volumes(docs) if name.startswith("registry-")}
    creds = app_settings(tmp_path, docs).registries.credentials
    assert [(c.registry, c.provider, c.password_file) for c in creds] == [
        ("*.dkr.ecr.*.amazonaws.com", "aws", ""),
        ("quay.io", "static", "/etc/kube-tower/registries/1/password"),
        ("myacr.azurecr.io", "azure", ""),
    ]


@pytest.mark.parametrize(
    "ca,configmap,key",
    [
        ({"pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}, "kt-kube-tower-ca", "ca.crt"),
        ({"existingConfigMap": "corp-ca", "key": "root.pem"}, "corp-ca", "root.pem"),
    ],
)
def test_registry_ca(tmp_path, ca, configmap, key):
    docs = render(tmp_path, {"registries": {"ca": ca}})
    assert volumes(docs)["registry-ca"]["configMap"] == {"name": configmap, "items": [{"key": key, "path": "ca.crt"}]}
    assert {"name": "registry-ca", "mountPath": "/etc/kube-tower/ca", "readOnly": True} in container(docs)["volumeMounts"]
    assert app_settings(tmp_path, docs).registries.ca_file == "/etc/kube-tower/ca/ca.crt"
    if "pem" in ca:
        assert docs[("ConfigMap", "kt-kube-tower-ca")]["data"]["ca.crt"].startswith("-----BEGIN CERTIFICATE-----")
    else:
        assert ("ConfigMap", "kt-kube-tower-ca") not in docs


def test_image_pull_secrets_rbac(tmp_path):
    secrets_rule = {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}
    assert secrets_rule not in render(tmp_path, {})[("ClusterRole", "kt-kube-tower")]["rules"]
    docs = render(tmp_path, {"config": {"registries": {"useImagePullSecrets": True, "insecure": ["registry.local:5000"]}}})
    assert secrets_rule in docs[("ClusterRole", "kt-kube-tower")]["rules"]
    settings = app_settings(tmp_path, docs).registries
    assert settings.use_image_pull_secrets and settings.insecure == ["registry.local:5000"] and settings.ca_file == ""


DISTRIBUTED = {"mode": "distributed", "redis": {"valkey": {"enabled": True}}}


def with_groups(groups):
    return {
        "mode": "distributed",
        "distributed": {"groups": groups},
        "redis": {"valkey": {"enabled": True}},
    }


def deployment(docs, group):
    return docs[("Deployment", f"kt-kube-tower-{group}")]["spec"]


def env(spec):
    return {e["name"]: e.get("value", e.get("valueFrom")) for e in spec["template"]["spec"]["containers"][0]["env"]}


def test_single_mode_is_one_pod_with_every_role(tmp_path):
    docs = render(tmp_path, {})
    assert [k for k in docs if k[0] == "Deployment"] == [("Deployment", "kt-kube-tower")]
    assert "KUBE_TOWER_ROLES" not in env(docs[("Deployment", "kt-kube-tower")]["spec"])
    assert ("Service", "kt-kube-tower-controller") not in docs
    assert not [k for k in docs if k[0] in ("HorizontalPodAutoscaler", "Role")]
    assert app_settings(tmp_path, docs).internal.leader_election is False


def test_distributed_mode(tmp_path):
    docs = render(tmp_path, DISTRIBUTED | {"serviceMonitor": {"enabled": True}, "registries": {"ca": {"pem": "x"}}})
    assert sorted(k[1] for k in docs if k[0] == "Deployment") == [
        "kt-kube-tower-controller",
        "kt-kube-tower-trivy",
        "kt-kube-tower-ui",
        "kt-kube-tower-valkey",
        "kt-kube-tower-worker",
    ]
    roles = {g: env(deployment(docs, g))["KUBE_TOWER_ROLES"] for g in ("controller", "ui", "worker", "trivy")}
    assert roles == {"controller": "controller", "ui": "ui", "worker": "worker", "trivy": "trivy"}
    assert {g: deployment(docs, g)["replicas"] for g in roles} == {"controller": 2, "ui": 1, "worker": 2, "trivy": 1}
    assert not [k for k in docs if k[0] == "Secret"]  # no token: the pods only know Valkey
    for group in roles:
        spec = deployment(docs, group)
        assert spec["selector"]["matchLabels"]["app.kubernetes.io/component"] == group
        assert spec["template"]["metadata"]["labels"][f"kube-tower.arcanexus.com/{group}"] == "true"
        # every pod talks through Valkey, under the keys of this release, and never calls the controller
        assert "KUBE_TOWER_CONTROLLER_URL" not in env(spec) and "KUBE_TOWER_INTERNAL_TOKEN" not in env(spec)
        assert env(spec)["KUBE_TOWER_REDIS_URL"] == "redis://kt-kube-tower-valkey:6379/0"
        assert env(spec)["KUBE_TOWER_REDIS_KEY_PREFIX"] == "kt-kube-tower"

    assert deployment(docs, "controller")["strategy"]["rollingUpdate"] == {"maxUnavailable": 1, "maxSurge": 0}
    assert "strategy" not in deployment(docs, "ui")
    controller = deployment(docs, "controller")["template"]["spec"]
    assert controller["containers"][0]["readinessProbe"]["httpGet"]["path"] == "/healthz"
    assert {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}} in controller["containers"][0]["env"]
    assert controller["containers"][0]["ports"] == [{"name": "http", "containerPort": 8080}]
    # The ui pods reach no Kubernetes API nor registry: no token, no credentials
    ui = deployment(docs, "ui")["template"]["spec"]
    assert ui["automountServiceAccountToken"] is False
    assert ui["containers"][0]["readinessProbe"]["httpGet"]["path"] == "/healthz"
    assert {m["name"] for m in ui["containers"][0]["volumeMounts"]} == {"config", "tmp"}
    # The Trivy CLI and its cache in the trivy pod only
    trivy = deployment(docs, "trivy")["template"]["spec"]
    assert [c["name"] for c in trivy["initContainers"]] == ["trivy"]
    assert "initContainers" not in deployment(docs, "worker")["template"]["spec"]
    assert "trivy-cache" not in {v["name"] for v in deployment(docs, "worker")["template"]["spec"]["volumes"]}
    assert "registry-ca" in {v["name"] for v in deployment(docs, "worker")["template"]["spec"]["volumes"]}

    # The UI Service reaches the ui pods, the controller one the active controller (its /metrics)
    assert docs[("Service", "kt-kube-tower")]["spec"]["selector"]["kube-tower.arcanexus.com/ui"] == "true"
    active = docs[("Service", "kt-kube-tower-controller")]["spec"]
    assert active["selector"]["kube-tower.arcanexus.com/active-controller"] == "true"
    assert [p["port"] for p in active["ports"]] == [8080]
    monitored = docs[("ServiceMonitor", "kt-kube-tower")]["spec"]["selector"]["matchLabels"]
    assert monitored["app.kubernetes.io/component"] == "controller"
    lease = docs[("Role", "kt-kube-tower-leader-election")]["rules"]
    assert lease[1]["resourceNames"] == ["kt-kube-tower-controller"] and lease[1]["verbs"] == ["get", "update"]
    assert lease[2] == {"apiGroups": [""], "resources": ["pods"], "verbs": ["patch"]}

    settings = app_settings(tmp_path, docs)
    assert settings.internal.leader_election is True and settings.internal.lease_name == "kt-kube-tower-controller"
    assert settings.internal.label_pod is True


def test_distributed_groups(tmp_path):
    autoscaling = {"enabled": True, "maxReplicas": 6}
    docs = render(
        tmp_path,
        DISTRIBUTED
        | {
            "distributed": {
                "groups": {
                    # controller and ui together, trivy with more replicas and autoscaling (ignored)
                    "controller": {"roles": ["controller", "ui"], "replicas": 3},
                    "ui": None,
                    "worker": {"autoscaling": autoscaling},
                    "trivy": {"replicas": 4, "autoscaling": autoscaling},
                },
            }
        },
    )
    groups = ("controller", "trivy", "valkey", "worker")
    assert sorted(k[1] for k in docs if k[0] == "Deployment") == [f"kt-kube-tower-{g}" for g in groups]
    assert not [k for k in docs if k[0] == "Secret"]
    controller = env(deployment(docs, "controller"))
    assert controller["KUBE_TOWER_ROLES"] == "controller,ui"
    # A standby controller with the UI shows no inventory: the UI Service must skip it
    probe = deployment(docs, "controller")["template"]["spec"]["containers"][0]["readinessProbe"]
    assert probe["httpGet"]["path"] == "/leaderz"
    assert deployment(docs, "controller")["replicas"] == 3
    assert deployment(docs, "trivy")["replicas"] == 1
    assert "replicas" not in deployment(docs, "worker")
    hpa = docs[("HorizontalPodAutoscaler", "kt-kube-tower-worker")]["spec"]
    assert hpa["scaleTargetRef"]["name"] == "kt-kube-tower-worker" and hpa["maxReplicas"] == 6 and hpa["minReplicas"] == 1
    # Damped: a page load or a pod start does not add pods, one pod more per minute at most
    assert hpa["behavior"]["scaleUp"] == {
        "stabilizationWindowSeconds": 120,
        "policies": [{"type": "Pods", "value": 1, "periodSeconds": 60}],
    }
    assert hpa["behavior"]["scaleDown"] == {"stabilizationWindowSeconds": 300}
    assert [k for k in docs if k[0] == "HorizontalPodAutoscaler"] == [("HorizontalPodAutoscaler", "kt-kube-tower-worker")]


@pytest.mark.parametrize(
    ("values", "error"),
    [
        ({"mode": "multi"}, 'mode: "multi" is not single or distributed'),
        ({"mode": "distributed"}, "set redis.valkey.enabled=true or redis.url"),
        (with_groups({"trivy": None}), "runs the trivy role"),
        (with_groups({"ui": {"roles": ["ui", "controller"]}}), "the controller role must run in one group"),
        (with_groups({"ui": {"roles": ["web"]}}), 'unknown role "web"'),
        (with_groups({"web": {"replicas": 2}}), "web.roles is required"),
    ],
)
def test_distributed_mode_errors(tmp_path, values, error):
    assert error in render_error(tmp_path, values)


def test_valkey(tmp_path):
    docs = render(tmp_path, {"redis": {"valkey": {"enabled": True}, "password": "pw"}, "networkPolicy": {"enabled": True}})
    pod = env(docs[("Deployment", "kt-kube-tower")]["spec"])
    assert pod["KUBE_TOWER_REDIS_URL"] == "redis://kt-kube-tower-valkey:6379/0"
    assert pod["KUBE_TOWER_REDIS_PASSWORD"] == {"secretKeyRef": {"name": "kt-kube-tower-redis", "key": "password"}}
    valkey = docs[("Deployment", "kt-kube-tower-valkey")]["spec"]["template"]["spec"]
    assert valkey["containers"][0]["args"][-2:] == ["--requirepass", "$(VALKEY_PASSWORD)"]
    assert valkey["automountServiceAccountToken"] is False
    assert docs[("Service", "kt-kube-tower-valkey")]["spec"]["ports"][0]["port"] == 6379
    ingress = docs[("NetworkPolicy", "kt-kube-tower-valkey")]["spec"]["ingress"][0]
    assert ingress["from"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/name"] == "kube-tower"
    egress = docs[("NetworkPolicy", "kt-kube-tower")]["spec"]["egress"]
    assert {"port": 6379, "protocol": "TCP"} in egress[-1]["ports"]


def test_existing_redis_in_distributed_mode(tmp_path):
    docs = render(
        tmp_path,
        DISTRIBUTED
        | {
            "redis": {"url": "rediss://redis.example:6380/1", "existingSecret": "redis", "passwordKey": "pass", "keyPrefix": "kt"}
        },
    )
    assert ("Deployment", "kt-kube-tower-valkey") not in docs
    controller = env(deployment(docs, "controller"))
    assert controller["KUBE_TOWER_REDIS_URL"] == "rediss://redis.example:6380/1"
    assert controller["KUBE_TOWER_REDIS_PASSWORD"] == {"secretKeyRef": {"name": "redis", "key": "pass"}}
    worker = env(deployment(docs, "worker"))  # every pod talks through it
    assert worker["KUBE_TOWER_REDIS_URL"] == "rediss://redis.example:6380/1" and worker["KUBE_TOWER_REDIS_KEY_PREFIX"] == "kt"
    assert worker["KUBE_TOWER_REDIS_PASSWORD"] == {"secretKeyRef": {"name": "redis", "key": "pass"}}
    render(tmp_path, {"redis": {"url": "redis://r:6379/0"}})  # no password


def test_distributed_network_policy(tmp_path):
    docs = render(tmp_path, DISTRIBUTED | {"networkPolicy": {"enabled": True}})
    spec = docs[("NetworkPolicy", "kt-kube-tower")]["spec"]
    assert spec["ingress"] == [{"ports": [{"port": "http", "protocol": "TCP"}]}]  # no internal port anymore
    assert not any({"port": 8081, "protocol": "TCP"} in rule.get("ports", []) for rule in spec["egress"])
    assert {"port": 6379, "protocol": "TCP"} in spec["egress"][-1]["ports"]  # every pod reaches Valkey


def test_the_internal_api_values_of_rc3_are_ignored(tmp_path):
    values = DISTRIBUTED | {"distributed": {"internal": {"existingSecret": "kube-tower-internal"}}}
    docs = render(tmp_path, values)
    assert not [k for k in docs if k[0] == "Secret"] and ("Service", "kt-kube-tower-internal") not in docs


def test_auth_off_by_default(tmp_path):
    docs = render(tmp_path, {})
    assert "auth" not in yaml.safe_load(docs[("ConfigMap", "kt-kube-tower")]["data"]["config.yaml"])
    assert ("Role", "kt-kube-tower-auth") not in docs and "auth" not in volumes(docs)


def test_auth(tmp_path):
    users = [
        {"name": "alice", "existingSecret": "alice-pw"},
        {"name": "ops", "role": "admin", "existingSecret": "ops", "passwordKey": "pw"},
    ]
    docs = render(tmp_path, {"auth": {"enabled": True, "users": users, "anonymousRole": "readonly", "sessionDuration": "8h"}})
    settings = app_settings(tmp_path, docs).auth
    assert settings.enabled and settings.admin and settings.anonymous_role == "readonly" and settings.metrics_public
    assert settings.session_duration == 8 * 3600
    assert (settings.secret_name, settings.secret_dir) == ("kt-kube-tower-auth", "/etc/kube-tower/auth")
    assert [(u.name, u.role, u.password_file) for u in settings.users] == [
        ("alice", "readonly", "/etc/kube-tower/users/0/password"),
        ("ops", "admin", "/etc/kube-tower/users/1/pw"),
    ]
    # The auth Secret is created by kube-tower (kept on upgrades and ArgoCD syncs), mounted once it exists
    assert not [k for k in docs if k[0] == "Secret"]
    assert volumes(docs)["auth"]["secret"] == {"secretName": "kt-kube-tower-auth", "optional": True}
    assert volumes(docs)["user-1"]["secret"] == {"secretName": "ops"}
    mounts = {m["name"]: m["mountPath"] for m in container(docs)["volumeMounts"]}
    assert mounts["auth"] == "/etc/kube-tower/auth" and mounts["user-0"] == "/etc/kube-tower/users/0"
    rules = docs[("Role", "kt-kube-tower-auth")]["rules"]
    assert rules == [
        {"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["kt-kube-tower-auth"], "verbs": ["get"]},
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]},
    ]
    assert docs[("RoleBinding", "kt-kube-tower-auth")]["roleRef"]["name"] == "kt-kube-tower-auth"

    # A Secret of your own (ExternalSecret...): read only, never created
    docs = render(tmp_path, {"auth": {"enabled": True, "existingSecret": "my-auth", "admin": False, "users": users}})
    assert app_settings(tmp_path, docs).auth.secret_name == "my-auth"
    assert docs[("Role", "kt-kube-tower-auth")]["rules"] == [
        {"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["my-auth"], "verbs": ["get"]}
    ]
    assert "auth.users[0].existingSecret is required" in render_error(
        tmp_path, {"auth": {"enabled": True, "users": [{"name": "x"}]}}
    )


def test_auth_in_distributed_mode(tmp_path):
    docs = render(tmp_path, DISTRIBUTED | {"auth": {"enabled": True}})
    # Only the ui pods check the logins; the controller creates the Secret
    for group, mounted in (("ui", True), ("controller", False), ("worker", False), ("trivy", False)):
        spec = deployment(docs, group)["template"]["spec"]
        assert ("auth" in {v["name"] for v in spec["volumes"]}) is mounted, group
    assert ("Role", "kt-kube-tower-auth") in docs


def test_auth_oidc(tmp_path):
    oidc = {
        "name": "Authentik",
        "issuer": "https://auth.example.com/application/o/kube-tower/",
        "clientId": "kube-tower",
        "clientSecret": {"existingSecret": "kt-oidc"},
        "adminGroups": ["ops"],
    }
    docs = render(tmp_path, {"auth": {"enabled": True, "admin": False, "url": "https://kt.example.com/", "oidc": oidc}})
    auth = app_settings(tmp_path, docs).auth
    assert auth.url == "https://kt.example.com/" and not auth.admin
    assert (auth.oidc.name, auth.oidc.issuer, auth.oidc.client_id) == ("Authentik", oidc["issuer"], "kube-tower")
    assert auth.oidc.admin_groups == ["ops"] and auth.oidc.default_role == "readonly" and auth.oidc.groups_claim == "groups"
    assert env(docs[("Deployment", "kt-kube-tower")]["spec"])["KUBE_TOWER_OIDC_CLIENT_SECRET"] == {
        "secretKeyRef": {"name": "kt-oidc", "key": "clientSecret"}
    }
    assert "auth.url is required" in render_error(tmp_path, {"auth": {"enabled": True, "oidc": oidc}})
    # No issuer: no SSO in the config
    docs = render(tmp_path, {"auth": {"enabled": True, "url": "https://kt.example.com/"}})
    assert app_settings(tmp_path, docs).auth.oidc.issuer == ""
