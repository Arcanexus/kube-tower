from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kube_tower.config import Settings
from kube_tower.main import create_app
from kube_tower.models import ChartDependency, ChartReport, ClusterStatus, ImageRef, ImageReport, Snapshot, Status, Usage


class FakeScanner:
    running = False

    def __init__(self):
        now = datetime.now(UTC)
        self.snapshot = Snapshot(
            images=[
                ImageReport(
                    ImageRef("docker.io", "library/nginx", "1.25"),
                    [
                        Usage("c1", "Pod", "default", "web", "nginx"),
                        Usage("c1", "Pod", "default", "web-7d9f-abcde", "nginx"),
                        Usage("c1", "Deployment", "default", "web", "nginx"),
                        Usage("c1", "Pod", "tools", "debug", "nginx"),
                    ],
                    status=Status.OUTDATED,
                    latest_tag="1.27",
                ),
                ImageReport(
                    ImageRef("ghcr.io", "org/app", "2.0"),
                    [Usage("c2", "Node", None, "n1"), Usage("c2", "Node", None, "n2")],
                    status=Status.UP_TO_DATE,
                ),
                ImageReport(
                    ImageRef("docker.io", "library/redis", "latest"),
                    [Usage("c1", "Node", None, "n1")],
                    status=Status.OUTDATED,
                    latest_digest="sha256:new",
                ),
            ],
            charts=[
                ChartReport(
                    "c1",
                    "redis",
                    "argocd",
                    "redis",
                    "https://charts.bitnami.com/bitnami",
                    "18.0.0",
                    "helm",
                    status=Status.UP_TO_DATE,
                    latest_version="18.0.0",
                    dependencies=[
                        ChartDependency("common", "2.0.0", "https://charts.bitnami.com/bitnami", Status.OUTDATED, "2.1.0")
                    ],
                )
            ],
            clusters=[
                ClusterStatus("c1", "https://c1", "in-cluster", True, "v1.30.0"),
                ClusterStatus("c2", "https://c2", "secret", False, message="timeout"),
            ],
            started_at=now,
            finished_at=now,
        )
        self.triggered = 0
        self.scans_total = {"success": 3, "failure": 1}

    def trigger(self):
        self.triggered += 1
        return True

    async def run_forever(self):
        pass


def _client():
    scanner = FakeScanner()
    return TestClient(create_app(Settings(), scanner, background=False)), scanner


def test_pages():
    client, _ = _client()
    for path in ("/", "/images", "/charts", "/clusters", "/settings", "/status"):
        resp = client.get(path)
        assert resp.status_code == 200, path
    assert "library/nginx" in client.get("/images").text
    assert "common" in client.get("/charts").text
    assert "timeout" in client.get("/clusters").text


def test_filters_and_partial():
    client, _ = _client()
    resp = client.get("/images?status=outdated", headers={"HX-Request": "true", "HX-Target": "results"})
    assert "library/nginx" in resp.text and "org/app" not in resp.text
    assert "<html" not in resp.text
    assert "org/app" in client.get("/images?cluster=c2").text
    assert "library/nginx" not in client.get("/images?q=org").text
    assert "redis" in client.get("/charts?status=outdated").text  # worst status includes subcharts


def test_api_and_metrics():
    client, scanner = _client()
    data = client.get("/api/snapshot").json()
    assert data["images"][0]["image"]["ref"] == "docker.io/library/nginx:1.25"
    assert data["images"][0]["status"] == "outdated"
    assert client.post("/api/refresh").json() == {"started": True} and scanner.triggered == 1
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200


def test_metrics():
    client, _ = _client()
    resp = client.get("/metrics")
    assert resp.headers["content-type"].startswith("text/plain")
    lines = set(resp.text.splitlines())
    expected = [
        'kube_tower_image_outdated{image="docker.io/library/nginx",latest="1.27",status="outdated",tag="1.25",'
        'update="minor"} 1.0',
        'kube_tower_image_outdated{image="ghcr.io/org/app",latest="",status="up-to-date",tag="2.0",update=""} 0.0',
        'kube_tower_image_outdated{image="docker.io/library/redis",latest="sha256:new",status="outdated",tag="latest",'
        'update="digest"} 1.0',
        'kube_tower_image_workload_info{cluster="c1",container="nginx",image="docker.io/library/nginx",kind="Deployment",'
        'namespace="default",tag="1.25",workload="web"} 1.0',
        'kube_tower_image_workload_info{cluster="c1",container="nginx",image="docker.io/library/nginx",kind="Pod",'
        'namespace="tools",tag="1.25",workload="debug"} 1.0',
        'kube_tower_image_nodes{cluster="c2",image="ghcr.io/org/app",tag="2.0"} 2.0',
        'kube_tower_chart_outdated{application="redis",chart="redis",cluster="c1",destination_namespace="",latest="18.0.0",source="helm",'
        'status="outdated",update="",version="18.0.0"} 1.0',
        'kube_tower_chart_dependency_outdated{application="redis",chart="redis",cluster="c1",dependency="common",latest="2.1.0",'
        'status="outdated",update="minor",version="2.0.0"} 1.0',
        'kube_tower_cluster_reachable{cluster="c2"} 0.0',
        'kube_tower_cluster_info{cluster="c1",source="in-cluster",version="v1.30.0"} 1.0',
        "kube_tower_last_scan_duration_seconds 0.0",
        "kube_tower_last_scan_errors 0.0",
        "kube_tower_scan_in_progress 0.0",
        'kube_tower_scans_total{result="success"} 3.0',
        'kube_tower_scans_total{result="failure"} 1.0',
        'kube_tower_build_info{version="0.1.0"} 1.0',
    ]
    for line in expected:
        assert line in lines, line
    # pods owned by the Deployment are not exported (pod names churn on every rollout)
    assert "web-7d9f-abcde" not in resp.text
    assert not any(line.startswith("kube_tower_image_workload_info") and 'kind="Node"' in line for line in lines)


def test_settings_page_shows_credentials_without_secrets(monkeypatch):
    from kube_tower.config import RegistryCredential

    monkeypatch.setenv("DOCKERHUB_TOKEN", "super-secret-token")
    settings = Settings()
    settings.registries.credentials = [
        RegistryCredential("docker.io", username="alex", password_env="DOCKERHUB_TOKEN"),
        RegistryCredential("ghcr.io", password_file="/nonexistent"),
    ]
    page = TestClient(create_app(settings, FakeScanner(), background=False)).get("/settings").text
    assert "docker.io" in page and "alex" in page and "loaded" in page and "invalid" in page
    assert "super-secret-token" not in page
    assert "passwordEnv: DOCKERHUB_TOKEN" in page  # camelCase like config.yaml


def test_grafana_dashboard_uses_exported_metrics():
    import json
    import re
    from pathlib import Path

    dashboard = Path(__file__).parents[1] / "charts/kube-tower/dashboards/kube-tower.json"
    text = dashboard.read_text()
    json.loads(text)
    client, _ = _client()
    exported = {line.split("{")[0].split(" ")[0] for line in client.get("/metrics").text.splitlines() if not line.startswith("#")}
    used = set(re.findall(r"kube_tower_[a-z_]+", text))
    assert used and used <= exported, used - exported


def test_status_reloads_page_when_scan_ends():
    client, scanner = _client()
    scanner.running = True
    resp = client.get("/status?polling=1")
    assert "Scan in progress" in resp.text and "HX-Refresh" not in resp.headers
    scanner.running = False
    assert client.get("/status?polling=1").headers["HX-Refresh"] == "true"
    assert "HX-Refresh" not in client.get("/status").headers
