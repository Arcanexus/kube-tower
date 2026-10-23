import re
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from kube_tower import __version__
from kube_tower.config import Settings
from kube_tower.main import create_app
from kube_tower.models import (
    ChartDependency,
    ChartReport,
    ClusterStatus,
    ImageRef,
    ImageReport,
    Severity,
    Snapshot,
    Status,
    Usage,
    Vulnerability,
    VulnerabilityReport,
)


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
                    vulnerabilities=VulnerabilityReport(
                        "trivy-operator",
                        now,
                        "sha256:run",
                        "debian 11",
                        True,
                        [
                            Vulnerability(
                                "CVE-2024-1", Severity.CRITICAL, "zlib1g", "1.2", "1.3", "zlib overflow", "https://avd/cve-1", 9.8
                            ),
                            Vulnerability("CVE-2024-2", Severity.LOW, "curl", "7.0"),
                        ],
                    ),
                ),
                ImageReport(
                    ImageRef("ghcr.io", "org/app", "2.0"),
                    [Usage("c2", "Node", None, "n1"), Usage("c2", "Node", None, "n2")],
                    status=Status.UP_TO_DATE,
                    vulnerabilities=VulnerabilityReport("trivy", now, message="registry denied"),
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
                        ChartDependency("common", "2.0.0", "https://charts.bitnami.com/bitnami", Status.OUTDATED, "2.1.0"),
                        ChartDependency(
                            "metrics",
                            "1.0.0",
                            "https://charts.example.com",
                            Status.UP_TO_DATE,
                            "1.0.0",
                            dependencies=[ChartDependency("helpers", "0.1.0", "file://../helpers")],
                        ),
                    ],
                )
            ],
            clusters=[
                ClusterStatus("c1", "https://c1", "in-cluster", True, "v1.30.0"),
                ClusterStatus("c2", "https://c2", "secret", False, message="timeout"),
            ],
            started_at=now,
            finished_at=now,
            vulnerabilities_finished_at=now,
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
    for path in ("/", "/images", "/charts", "/vulnerabilities", "/clusters", "/logs", "/settings", "/status"):
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
        f'kube_tower_build_info{{version="{__version__}"}} 1.0',
        'kube_tower_image_vulnerabilities{image="docker.io/library/nginx",'
        'severity="critical",source="trivy-operator",tag="1.25"} 1.0',
        'kube_tower_image_vulnerabilities{image="docker.io/library/nginx",'
        'severity="high",source="trivy-operator",tag="1.25"} 0.0',
        'kube_tower_image_vulnerabilities_fixable{image="docker.io/library/nginx",severity="critical",tag="1.25"} 1.0',
        'kube_tower_image_vulnerabilities_fixable{image="docker.io/library/nginx",severity="low",tag="1.25"} 0.0',
        'kube_tower_image_os_eosl{image="docker.io/library/nginx",os="debian 11",tag="1.25"} 1.0',
        'kube_tower_image_vulnerability_scan_failed{image="ghcr.io/org/app",tag="2.0"} 1.0',
        'kube_tower_image_vulnerability_scan_failed{image="docker.io/library/nginx",tag="1.25"} 0.0',
    ]
    for line in expected:
        assert line in lines, line
    assert any(line.startswith("kube_tower_last_vulnerability_scan_timestamp_seconds ") for line in lines)
    assert "library/redis" not in "".join(line for line in lines if "vulnerabilit" in line)  # not scanned
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


def test_links_are_relative():
    # Relative links work however the UI is exposed: http, https behind a TLS ingress
    # (no mixed content), port-forward or a sub-path.
    client, _ = _client()
    for path in (
        "/",
        "/images",
        "/charts",
        "/clusters",
        "/logs",
        "/settings",
        "/status",
        "/logs/tail",
        "/images/detail?ref=docker.io/library/nginx:1.25",
        "/charts/detail?cluster=c1&namespace=argocd&app=redis&chart=redis",
        "/vulnerabilities",
        "/vulnerabilities/detail?ref=docker.io/library/nginx:1.25",
    ):
        page = client.get(path, headers={"X-Forwarded-Proto": "https"}).text
        assert "http://" not in page, path
        assert not re.search(r'(href|src|hx-get|hx-post)="/', page), path
    page = client.get("/").text
    assert 'href="static/pico.min.css"' in page and 'src="static/htmx.min.js"' in page


def test_counters_toggle_the_status_filter():
    client, _ = _client()
    page = client.get("/images?status=outdated").text
    # counters ignore the status filter (they set it) and show which one is active
    assert re.search(r'counter-up-to-date" aria-pressed="false".*?<strong>1</strong>', page, re.S)
    assert re.search(r'counter-outdated" aria-pressed="true".*?<strong>2</strong>', page, re.S)
    assert "ktFilterStatus('error')" in page
    assert "nothing is ever updated automatically" not in page


def test_latest_tag_is_highlighted():
    client, _ = _client()
    page = client.get("/images").text
    assert page.count('class="tag-latest"') == 1  # redis:latest only


def test_image_detail():
    client, _ = _client()
    detail = client.get("/images/detail", params={"ref": "docker.io/library/redis:latest"}).text
    assert "<html" not in detail and 'role="dialog"' in detail
    assert "https://hub.docker.com/_/redis/tags" in detail
    assert "sha256:new" in detail and "Pin a version" in detail
    detail = client.get("/images/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
    assert "docker.io/library/nginx:1.27" in detail and "web-7d9f-abcde" in detail
    assert client.get("/images/detail", params={"ref": "nope"}).status_code == 404


def test_chart_tree_and_detail():
    client, _ = _client()
    page = client.get("/charts").text
    assert "├─ " in page and "└─ " in page and "   └─ " in page  # helpers under metrics, the last subchart
    assert "<details" not in page  # never collapsed
    assert "redis" in client.get("/charts?status=outdated").text
    detail = client.get("/charts/detail?cluster=c1&namespace=argocd&app=redis&chart=redis").text
    assert "helpers" in detail and "file://../helpers" in detail and "artifacthub.io" in detail
    assert client.get("/charts/detail?cluster=c1&namespace=argocd&app=x&chart=redis").status_code == 404


def test_logs_page_tails_the_log_buffer():
    import logging

    client, _ = _client()
    log = logging.getLogger("kube_tower.test")
    log.info("first line")
    log.debug("hidden at INFO level")
    page = client.get("/logs").text
    assert "first line" in page and "hidden at INFO" not in page
    after = int(re.search(r"logs/tail\?after=(\d+)", page)[1])
    assert "first line" not in client.get(f"/logs/tail?after={after}").text
    log.warning("second <line>")
    tail = client.get(f"/logs/tail?after={after}").text
    assert "second &lt;line&gt;" in tail and 'hx-swap-oob="beforeend:#log-lines"' in tail
    assert "second" not in client.get(f"/logs/tail?after={after}&level=ERROR").text
    assert "first line" not in client.get("/logs?q=second").text
    try:
        raise ValueError("boom")
    except ValueError:
        log.exception("scan failed")
    assert "ValueError: boom" in client.get("/logs?level=ERROR").text


def test_ui_helpers():
    from kube_tower.web.ui import registry_links

    assert registry_links(ImageRef("docker.io", "bitnami/redis", "7"))[0][1] == "https://hub.docker.com/r/bitnami/redis"
    assert registry_links(ImageRef("ghcr.io", "arcanexus/kube-tower", "0.1.0")) == [
        ("GitHub Packages", "https://ghcr.io/arcanexus/kube-tower")
    ]
    assert registry_links(ImageRef("quay.io", "prometheus/node-exporter", "1"))[0][0] == "Quay"
    assert registry_links(ImageRef("registry.k8s.io", "pause", "3.9")) == []


def test_synthesis_is_the_home_page():
    client, _ = _client()
    page = client.get("/").text
    assert 'href="synthesis" aria-current="page"' in page
    assert page == client.get("/synthesis").text
    # 3 images: 2 outdated (nginx minor, redis digest), 1 up to date; 1 chart outdated through its subchart
    assert re.search(r"Images</span><strong>3</strong>\s*<small>33% up to date · 2 outdated", page)
    assert 'href="images?status=outdated"' in page and 'href="charts?status=outdated"' in page
    assert re.search(r"<th scope=\"row\">minor</th>.*?<td class=\"bar-value\">1</td>", page, re.S)
    assert re.search(r"<th scope=\"row\">docker.io</th>.*?<td class=\"bar-value\">2</td>", page, re.S)
    assert "Subcharts: 1 outdated out of 3." in page
    assert "1 unreachable" in page


def test_summary_folds_small_registries():
    from kube_tower.web.summary import summarize

    snap = Snapshot(images=[ImageReport(ImageRef(f"r{i}.io", "x", "1")) for i in range(8)])
    registries = summarize(snap, registries=3).registries
    assert registries[-1] == ("other", 6) and len(registries) == 3


def test_version_comes_from_the_image(monkeypatch):
    import importlib

    import kube_tower

    monkeypatch.setenv("KUBE_TOWER_VERSION", "1.2.3")
    assert importlib.reload(kube_tower).__version__ == "1.2.3"
    monkeypatch.delenv("KUBE_TOWER_VERSION")
    assert importlib.reload(kube_tower).__version__ == "dev"


def test_vulnerabilities_page():
    client, _ = _client()
    page = client.get("/vulnerabilities").text
    # most vulnerable first, then failed and not scanned images
    assert page.index("library/nginx") < page.index("org/app") < page.index("library/redis")
    assert "debian 11 is end of life" in page and "registry denied" in page and "not scanned" in page
    assert re.search(r'sev-critical">critical</span><strong>1</strong>', page)
    assert re.search(r'sev-high">high</span><strong>0</strong>', page)
    assert 'href="vulnerabilities" aria-current="page"' in page
    partial = client.get("/vulnerabilities?status=critical", headers={"HX-Request": "true", "HX-Target": "results"}).text
    assert "library/nginx" in partial and "org/app" not in partial and "<html" not in partial
    assert 'aria-pressed="true"' in partial
    assert "library/nginx" not in client.get("/vulnerabilities?status=high").text.split("<tbody>")[1]
    assert "org/app" in client.get("/vulnerabilities?cluster=c2&q=app").text


def test_vulnerability_detail():
    client, _ = _client()
    detail = client.get("/vulnerabilities/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
    assert 'role="dialog"' in detail and "Trivy Operator report" in detail
    assert '<a href="https://avd/cve-1"' in detail and "zlib overflow" in detail and "no fix" in detail
    assert "end of life" in detail and "1 / 2" in detail and "sha256:run" in detail
    assert "registry denied" in client.get("/vulnerabilities/detail", params={"ref": "ghcr.io/org/app:2.0"}).text
    assert "Not scanned yet" in client.get("/vulnerabilities/detail", params={"ref": "docker.io/library/redis:latest"}).text
    assert client.get("/vulnerabilities/detail", params={"ref": "nope"}).status_code == 404
    # the image detail links to its vulnerabilities
    image = client.get("/images/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
    assert 'hx-get="vulnerabilities/detail?ref=docker.io/library/nginx%3A1.25"' in image
