import dataclasses
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
import respx
from fastapi.testclient import TestClient

from kube_tower import __version__
from kube_tower.administration import Check, ConnectivityReport
from kube_tower.config import Settings, TrivySettings
from kube_tower.main import create_app
from kube_tower.models import (
    ChartDependency,
    ChartReport,
    ClusterStatus,
    DeprecatedApi,
    ImageRef,
    ImageReport,
    NodeInfo,
    PlatformVersion,
    Severity,
    Snapshot,
    Status,
    Usage,
    Vulnerability,
    VulnerabilityReport,
)
from kube_tower.scanner import Activity
from kube_tower.trivy import TrivyDatabase, TrivyScanner, TrivyStatus


class FakeScanner:
    running = False
    checking_versions = False
    locked = False
    busy = None
    pull_secrets: dict = {}

    def __init__(self):
        from kube_tower.registry.auth import AuthResults

        self.registry_auth = AuthResults()
        self.running_activities = []
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
        self.rescanning = set()
        self.rescans = []
        self.rescan_error = None
        self.trivy = TrivyScanner(TrivySettings(binary="/nonexistent/trivy"), {})
        self.retried = 0

    def activities(self):
        return self.running_activities

    def failed_items(self):
        failed = [r for r in self.snapshot.images if r.vulnerabilities and r.vulnerabilities.message]
        return [], failed, []

    def retry_failed(self):
        self.retried += 1
        return self.rescan_error

    def can_rescan_vulnerabilities(self, report):
        return report.image.repository != "library/redis"

    def same_name_images(self, report):
        return [r for r in self.snapshot.images if r.image.name == report.image.name]

    def rescan_image(self, report, versions=True, vulnerabilities=True):
        self.rescans.append((str(report.image), versions, vulnerabilities))
        return self.rescan_error

    def rescan_chart(self, report):
        self.rescans.append(report.key)
        return self.rescan_error

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
    for path in ("/", "/images", "/charts", "/vulnerabilities", "/clusters", "/logs", "/administration", "/settings", "/status"):
        resp = client.get(path)
        assert resp.status_code == 200, path
    assert "library/nginx" in client.get("/images").text
    assert "common" in client.get("/charts").text
    assert "timeout" in client.get("/clusters").text


def test_usage_tree():
    from kube_tower.web.ui import usage_tree

    tree = usage_tree(
        [
            Usage("c1", "Pod", "shop", "web-1", "nginx", "Deployment/web", "n1"),
            Usage("c1", "Pod", "shop", "web-1", "sidecar", "Deployment/web", "n1"),
            Usage("c1", "Deployment", "shop", "web", "nginx"),
            Usage("c1", "Deployment", "shop", "admin", "proxy"),
            Usage("c1", "Pod", "ops", "backup-28839120-x", "c", "Job/backup-28839120", "n2"),
            Usage("c1", "CronJob", "ops", "backup", "c"),
            Usage("c1", "Pod", "ops", "migrate-x", "c", "Job/migrate", "n2"),
            Usage("c1", "Pod", "tools", "debug", "c"),
            Usage("c1", "Node", None, "n2"),
            Usage("c1", "Node", None, "n1"),
            Usage("c2", "Node", None, "m1"),
        ]
    )
    assert [c.name for c in tree] == ["c1", "c2"] and tree[0].pods == 4 and tree[1].pods == 0
    namespaces = {n.name: n for n in tree[0].children if n.kind == "Namespace"}
    assert [(c.kind, c.name) for c in namespaces["shop"].children] == [("Deployment", "admin"), ("Deployment", "web")]
    web = namespaces["shop"].children[1]
    assert web.containers == ["nginx"] and len(web.children) == 1
    pod = web.children[0]
    assert (pod.kind, pod.name, pod.node, pod.containers) == ("Pod", "web-1", "n1", ["nginx", "sidecar"])
    assert namespaces["shop"].children[0].pods == 0  # admin: no pod running
    # Jobs of a CronJob hang under it; another Job stays on its own
    assert [(c.kind, c.name, c.pods) for c in namespaces["ops"].children] == [("CronJob", "backup", 1), ("Job", "migrate", 1)]
    assert [(c.kind, c.name) for c in namespaces["tools"].children] == [("Pod", "debug")]  # a bare pod
    nodes = tree[0].children[-1]
    assert nodes.kind == "Nodes" and [n.name for n in nodes.children] == ["n1", "n2"]


def test_images_running_icons():
    client, _ = _client()
    page = client.get("/images?running=0").text
    # nginx is used by pods; ghcr.io/org/app and redis are only cached on nodes
    assert page.count('aria-label="Running"') == 1 and page.count('aria-label="Not running"') == 2
    assert re.search(r'aria-label="Running".*?</span><code class="image-name" title="docker.io/library/nginx">', page)
    assert "#i-running" in page and "#i-not-running" in page


def test_images_running_only_switch():
    client, _ = _client()
    # A filter of the top bar, on by default
    page = client.get("/images").text
    assert 'class="global-filters"' in page and '<input type="checkbox" role="switch" name="running" value="1" checked' in page
    assert "library/nginx" in page and "org/app" not in page and "library/redis" not in page
    assert '<p><small>1 image<span id="list-shown"></span>, most urgent first' in page  # counters and count follow it
    assert page == client.get("/images?running=0&running=1").text
    page = client.get("/images?running=0").text
    assert 'name="running" value="1" >' in page and "org/app" in page and "library/redis" in page
    assert "library/nginx" not in client.get("/images?cluster=c2").text
    assert 'class="global-filters"' in client.get("/charts").text  # common to every page


def test_global_filters_come_from_cookies():
    """The browser keeps the filters of the top bar in cookies (kube-tower.js): every page follows them, a query
    parameter wins, a cluster that is gone is ignored."""
    client, _ = _client()
    rows = lambda page: page.split("<tbody>")[1]  # noqa: E731
    client.cookies.set("kt-running", "0")
    assert "org/app" in rows(client.get("/images").text)
    assert "org/app" not in rows(client.get("/images?running=1").text)
    client.cookies.set("kt-cluster", "c2")
    page = client.get("/images").text
    assert "library/nginx" not in rows(page) and "org/app" in rows(page) and "<option selected>c2</option>" in page
    assert "No chart." in client.get("/charts").text
    assert "library/nginx" in rows(client.get("/images?cluster=").text)
    client.cookies.set("kt-cluster", "gone")
    assert "library/nginx" in rows(client.get("/images").text)


def test_images_registry_and_update_filters():
    """Set by the links of the Synthesis, shown as removable chips that the filter form keeps."""
    client, _ = _client()
    page = client.get("/images?registry=docker.io&running=0").text
    assert "library/nginx" in page and "library/redis" in page and "org/app" not in page
    assert (
        'class="filter-chip">Registry <strong>docker.io</strong><input type="hidden" name="registry" value="docker.io">' in page
    )
    assert 'onclick="ktRemoveFilter(this)"' in page
    page = client.get("/images?update=minor").text
    assert "library/nginx" in page and "library/redis" not in page and "org/app" not in page
    assert 'name="update" value="minor"' in page
    assert "library/nginx" not in client.get("/images?update=minor&registry=ghcr.io").text
    assert "filter-chip" not in client.get("/images").text
    assert "ktRemoveFilter" in client.get("/static/kube-tower.js").text


def test_maintenance_redirects_to_administration():
    client, _ = _client()
    resp = client.get("/maintenance", follow_redirects=False)
    assert resp.status_code == 301 and resp.headers["location"] == "administration"
    assert client.get("/maintenance").url.path == "/administration"


def test_filters_and_partial():
    client, _ = _client()
    resp = client.get("/images?status=outdated", headers={"HX-Request": "true", "HX-Target": "results"})
    assert "library/nginx" in resp.text and "org/app" not in resp.text
    assert "<html" not in resp.text
    assert "org/app" in client.get("/images?cluster=c2&running=0").text
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
        'kube_tower_chart_outdated{application="redis",chart="redis",cluster="c1",destination_namespace="",latest="18.0.0",'
        'manager="argocd",source="helm",status="outdated",update="",version="18.0.0"} 1.0',
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


def test_administration_page_shows_credentials_without_secrets(monkeypatch):
    from kube_tower.config import RegistryCredential

    monkeypatch.setenv("DOCKERHUB_TOKEN", "super-secret-token")
    settings = Settings()
    settings.registries.credentials = [
        RegistryCredential("docker.io", username="alex", password_env="DOCKERHUB_TOKEN"),
        RegistryCredential("ghcr.io", password_file="/nonexistent"),
    ]
    scanner = FakeScanner()
    page = TestClient(create_app(settings, scanner, background=False)).get("/administration?tab=settings").text
    assert '<article id="registries">' in page
    assert "docker.io" in page and "alex" in page and "loaded" in page and "invalid" in page
    assert page.count("not tried yet") == 2
    scanner.registry_auth.record("docker.io", True)
    scanner.registry_auth.record("ghcr.io", False, "ghcr.io refused the credentials: HTTP 403 Forbidden")
    client = TestClient(create_app(settings, scanner, background=False))
    page = client.get("/administration?tab=settings").text
    assert "not tried yet" not in page and "accepted" in page and "refused" in page and "HTTP 403 Forbidden" in page
    # The settings only reference the secrets
    assert "super-secret-token" not in page
    assert "passwordEnv: DOCKERHUB_TOKEN" in page  # camelCase like config.yaml
    # former Settings page
    resp = client.get("/settings", follow_redirects=False)
    assert resp.status_code == 301 and resp.headers["location"] == "administration?tab=settings"


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
    scanner.running = scanner.checking_versions = True
    resp = client.get("/status?polling=1")
    assert "Scan in progress" in resp.text and "HX-Trigger" not in resp.headers
    scanner.running = scanner.checking_versions = False
    assert client.get("/status?polling=1").headers["HX-Trigger"] == "kt-scan-done"  # the page reloads its content
    assert "HX-Trigger" not in client.get("/status").headers


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
    assert 'href="static/kube-tower.css?v=' in page and 'src="static/htmx.min.js?v=' in page


def test_counters_toggle_the_status_filter():
    client, _ = _client()
    page = client.get("/images?status=outdated&running=0").text
    # counters ignore the status filter (they set it) and show which one is active
    assert re.search(
        r"aria-pressed=\"false\"[^>]*onclick=\"ktToggleFilter\('status', 'up-to-date'\)\">.*?<strong>1</strong>", page, re.S
    )
    assert re.search(
        r"aria-pressed=\"true\"[^>]*onclick=\"ktToggleFilter\('status', 'outdated'\)\">.*?<strong>2</strong>", page, re.S
    )
    assert '<input type="hidden" name="status" value="outdated">' in page
    assert "nothing is ever updated automatically" not in page


def test_latest_tag_is_highlighted():
    client, _ = _client()
    page = client.get("/images?running=0").text
    assert page.count('title="Avoid latest or untagged images: pin a version"') == 1  # redis:latest only


def test_image_detail():
    client, _ = _client()
    detail = client.get("/images/detail", params={"ref": "docker.io/library/redis:latest"}).text
    assert "<html" not in detail and 'role="dialog"' in detail
    assert 'class="drawer-resize" role="separator"' in detail and 'onclick="ktToggleFull()"' in detail
    sprite = (Path(__file__).parents[1] / "src/kube_tower/web/static/icons.svg").read_text()
    assert all(f'id="i-{name}"' in sprite for name in re.findall(r"icons\.svg\?v=\w+#i-([\w-]+)", detail))
    assert re.findall(r"icons\.svg\?v=\w+#i-([\w-]+)", detail)
    # a click beside the panel only closes it: caught before htmx (capture phase), the row under it stays closed
    assert '<div class="drawer-backdrop"></div>' in detail
    js = client.get("/static/kube-tower.js").text
    outside = js[js.index("A click beside the open panel") :]
    assert "e.stopPropagation();\n  ktCloseDetail();\n}, true);" in outside
    assert "https://hub.docker.com/_/redis/tags" in detail
    assert "sha256:new" in detail and "Pin a version" in detail and "Versioning" not in detail
    detail = client.get("/images/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
    assert "docker.io/library/nginx:1.27" in detail and "web-7d9f-abcde" in detail
    assert re.search(r"Versioning</th><td>semver ", detail)
    assert 'class="tree-list"' in detail and '<strong><span class="copyable"' in detail and 'data-copy="c1"' in detail
    assert "<code>tools</code>" in detail
    detail = client.get("/images/detail", params={"ref": "ghcr.io/org/app:2.0"}).text
    assert "cached on 2 nodes" in detail and '<code class="usage-node">n2</code>' in detail
    assert client.get("/images/detail", params={"ref": "nope"}).status_code == 404


def test_detail_values_are_copyable():
    # a click on a value of a detail panel copies it (ktCopy): names, versions, digests, namespaces
    client, _ = _client()
    detail = client.get("/images/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
    for value in ("docker.io/library/nginx", "1.25", "1.27", "docker.io/library/nginx:1.25", "c1"):
        assert f'data-copy="{value}"' in detail, value
    assert 'class="copyable" role="button" tabindex="0"' in detail
    detail = client.get("/charts/detail?cluster=c1&namespace=argocd&app=redis&chart=redis").text
    for value in ("redis", "argocd", "c1"):
        assert f'data-copy="{value}"' in detail, value
    js = client.get("/static/kube-tower.js").text
    assert "function ktCopy(el)" in js and "navigator.clipboard" in js and 'execCommand("copy")' in js
    assert ".copyable.copied .copy-done" in client.get("/static/kube-tower.css").text


def test_release_dates_next_to_the_latest_versions():
    from datetime import UTC, datetime, timedelta

    from kube_tower.web.ui import age

    now = datetime(2026, 11, 6, tzinfo=UTC)
    assert [age(now - timedelta(days=d), now) for d in (0, 1, 5, 20, 90, 800)] == [
        "today",
        "1 day ago",
        "5 days ago",
        "2 weeks ago",
        "3 months ago",
        "2 years ago",
    ]
    client, scanner = _client()
    nginx = next(r for r in scanner.snapshot.images if r.latest_tag)
    nginx.latest_released = datetime(2026, 10, 12, 8, tzinfo=UTC)
    chart = scanner.snapshot.charts[0]
    chart.latest_released = datetime(2026, 9, 1, tzinfo=UTC)
    page = client.get("/images").text
    assert '<small class="released" title="Released 2026-10-12 08:00 UTC, ' in page and "2026-10-12</small>" in page
    detail = client.get("/images/detail", params={"ref": str(nginx.image)}).text
    assert detail.count("2026-10-12</small>") == 2  # summary and Latest tag
    assert "2026-09-01</small>" in client.get("/charts").text


def test_image_size():
    from kube_tower.web.ui import image_size

    client, scanner = _client()
    nginx, app = scanner.snapshot.images[0], scanner.snapshot.images[1]
    assert image_size(nginx) is None
    detail = client.get("/images/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
    assert "unknown (no node has pulled it)" in detail
    # The size of the running digest, the other ones (tag pushed again) are left out
    nginx.running_digests = {"sha256:run"}
    nginx.sizes = {"sha256:run": 70_000_000, "sha256:old": 65_000_000}
    assert image_size(nginx) == (70_000_000, 70_000_000)
    detail = client.get("/images/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
    assert re.search(r"Size</th><td>70.0 MB\s*</td>", detail)
    assert '<small class="muted-text">· 70.0 MB</small>' in detail
    # Only cached on nodes, two architectures: a range
    app.sizes = {"sha256:amd64": 30_000_000, "sha256:arm64": 28_000_000}
    assert image_size(app) == (28_000_000, 30_000_000)
    detail = client.get("/images/detail", params={"ref": "ghcr.io/org/app:2.0"}).text
    assert "28.0 MB to 30.0 MB" in detail


def test_chart_tree_and_detail():
    client, _ = _client()
    page = client.get("/charts").text
    # helpers under metrics, the last subchart: drawn with CSS segments
    assert re.search(r'tree-tee" aria-hidden="true"></span><span class="tree-label"><code>common</code>', page)
    assert re.search(r'tree-elbow" aria-hidden="true"></span><span class="tree-label"><code>metrics</code>', page)
    assert re.search(r'tree-blank" aria-hidden="true"></span><span class="tree-seg tree-elbow".*?<code>helpers</code>', page)
    assert "<details" not in page.split('id="results"')[1]  # never collapsed
    assert "redis" in client.get("/charts?status=outdated").text
    detail = client.get("/charts/detail?cluster=c1&namespace=argocd&app=redis&chart=redis").text
    assert "helpers" in detail and "file://../helpers" in detail and "artifacthub.io" in detail
    assert 'class="tree-list" aria-label="Subchart tree"' in detail
    positions = [
        detail.index(f'<strong><span class="copyable" role="button" tabindex="0" data-copy="{name}"')
        for name in ("redis", "metrics", "helpers")
    ]
    assert positions == sorted(positions)
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


def test_overview_is_the_home_page():
    client, _ = _client()
    page = client.get("/?running=0").text
    assert 'href="./" aria-current="page"' in page and '<span class="nav-label">Overview</span>' in page
    resp = client.get("/synthesis", follow_redirects=False)  # former name
    assert resp.status_code == 301 and resp.headers["location"] == "./"
    # 3 images: 2 outdated (nginx minor, redis digest), 1 up to date; 1 chart outdated through its subchart
    assert re.search(r"Images up to date</span><strong>1<small> / 3</small></strong>\s*<small>2 outdated · 0 to check", page)
    assert re.search(
        r"Helm charts up to date</span><strong>0<small> / 1</small></strong>\s*<small>1 outdated, 1 by a subchart", page
    )
    assert re.search(
        r"Clusters reachable</span><strong>1<small> / 2</small></strong>\s*<small><span class=\"danger\">c2: timeout", page
    )
    assert 'href="images?status=outdated"' in page
    assert re.search(
        r"<th scope=\"row\"><a href=\"images\?update=minor\"[^>]*>minor</a></th>.*?<td class=\"bar-value\">1</td>", page, re.S
    )


def test_overview_to_do_list():
    client, _ = _client()
    page = " ".join(client.get("/?running=0").text.split())
    # nginx: 1 critical with a fix (end of life OS)
    assert re.search(r"Critical CVEs with a fix</span><strong class=\"danger\">1</strong>\s*<small>on 1 image", page)
    assert 'href="images?severity=critical&amp;fixable=1"' in page
    # most urgent first: the unreachable cluster, the fixable critical CVEs, then the floating tag and the end of life OS
    items = re.findall(r'class="todo-tag todo-\w+">([^<]+)</span>', page)
    assert items == ["cluster", "1 critical", "latest", "end of life"]
    assert 'href="clusters"' in page and "Unreachable: timeout" in page
    assert 'hx-get="images/detail?ref=docker.io%2Flibrary%2Fnginx%3A1.25" hx-target="#detail"' in page
    assert '1 critical CVE with a fix · 4 workloads in c1</small></span> <small class="todo-hint">→ 1.27' in page
    assert "debian 11 gets no more security fixes" in page
    # the To do list follows the global filters
    page = client.get("/?running=1&cluster=c1").text
    assert re.findall(r'class="todo-tag todo-\w+">([^<]+)</span>', page) == ["1 critical", "end of life"]


def test_to_do_list_shows_a_few_of_each_kind():
    from kube_tower.web.summary import todo

    images = [
        ImageReport(
            ImageRef("docker.io", f"x{i}", "1.0.0"),
            [Usage("c1", "Pod", "ns", f"p{i}")],
            status=Status.ERROR if i % 2 else Status.OUTDATED,
            latest_tag="2.0.0",
            message="HTTP 401",
        )
        for i in range(8)
    ]
    charts = [ChartReport("c1", "app", "argocd", "argo-cd", "https://r", "5.0.0", "helm", latest_version="7.0.0")]
    items, total = todo(Snapshot(images=images, charts=charts), limit=10, per_kind=3)
    assert [t.tag for t in items] == ["error"] * 3 + ["major"] * 3 + ["major"]
    assert total == 9 and items[-1].href == "charts?q=argo-cd" and items[0].detail == "HTTP 401 · 1 workload in c1"


def test_synthesis_without_vulnerabilities():
    from kube_tower.web.summary import summarize

    s = summarize(Snapshot(images=[ImageReport(ImageRef("docker.io", "library/redis", "7"))])).vulnerabilities
    assert s.worst == {"not scanned": 1} and s.scanned == 0 and s.top == [] and not s.images_with["critical"]


def test_summary_folds_small_registries():
    from kube_tower.web.summary import summarize

    snap = Snapshot(images=[ImageReport(ImageRef(f"r{i}.io", "x", "1")) for i in range(8)])
    registries = summarize(snap, registries=3).registries
    assert registries[-1] == ("other", 6) and len(registries) == 3


def test_summary_counts_not_deployed_subcharts():
    from kube_tower.web.summary import summarize

    def chart(name, *dependencies):
        return ChartReport(
            "c1", name, "argocd", name, "https://r", "1.0.0", "helm", status=Status.UP_TO_DATE, dependencies=list(dependencies)
        )

    left_out = ChartDependency("bitwarden-sdk-server", "v0.6.0", "oci://x", status=Status.OUTDATED, not_deployed="off")
    snap = Snapshot(
        charts=[
            chart("eso", left_out, ChartDependency("redis", "19.0.0", "https://x", status=Status.UP_TO_DATE)),
            chart("loki", ChartDependency("minio", "4.0.0", "https://x", status=Status.OUTDATED)),
        ]
    )
    s = summarize(snap)
    assert s.subcharts == {"not-deployed": 1, "up-to-date": 1, "outdated": 1}
    assert s.charts_subchart_outdated == 1  # loki only: the outdated subchart of eso is not deployed


def test_version_comes_from_the_image(monkeypatch):
    import importlib

    import kube_tower

    monkeypatch.setenv("KUBE_TOWER_VERSION", "1.2.3")
    assert importlib.reload(kube_tower).__version__ == "1.2.3"
    monkeypatch.delenv("KUBE_TOWER_VERSION")
    assert importlib.reload(kube_tower).__version__ == "dev"


def test_images_show_their_vulnerabilities():
    client, _ = _client()
    page = client.get("/images?running=0").text
    # most urgent first: fixable critical CVEs, then outdated images, then by vulnerabilities
    assert page.index("library/nginx") < page.index("library/redis") < page.index("org/app")
    assert "debian 11 is end of life" in page and "scan failed" in page and "registry denied" in page
    assert re.search(
        r"onclick=\"ktToggleFilter\('severity', 'critical'\)\">"
        r"<span class=\"sev sev-critical\">critical</span><strong>1</strong>",
        page,
    )
    assert re.search(r"onclick=\"ktToggleFilter\('fixable', '1'\)\">with a fix<strong>1</strong>", page)
    partial = client.get("/images?severity=critical&running=0", headers={"HX-Request": "true", "HX-Target": "results"}).text
    assert "library/nginx" in partial and "org/app" not in partial and "<html" not in partial
    assert "library/nginx" not in client.get("/images?severity=high").text.split("<tbody>")[1]
    assert "library/nginx" in client.get("/images?fixable=1").text.split("<tbody>")[1]
    assert "org/app" in client.get("/images?cluster=c2&q=app&running=0").text
    # former Vulnerabilities page: its filters go to the Images page
    resp = client.get("/vulnerabilities?cve=CVE-2024-1&status=critical&q=nginx&running=0", follow_redirects=False)
    assert resp.status_code == 301 and resp.headers["location"] == "images?q=nginx+CVE-2024-1&severity=critical&running=0"


def test_vulnerability_detail():
    client, _ = _client()
    detail = client.get("/images/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
    assert 'role="dialog"' in detail and "Trivy Operator report" in detail
    assert '<a href="https://avd/cve-1"' in detail and "zlib overflow" in detail and "no fix" in detail
    assert "end of life" in detail and "<strong>1</strong> / 2 with a fix" in detail and "sha256:run" in detail
    assert "registry denied" in client.get("/images/detail", params={"ref": "ghcr.io/org/app:2.0"}).text
    assert "Not scanned." in client.get("/images/detail", params={"ref": "docker.io/library/redis:latest"}).text
    assert client.get("/images/detail", params={"ref": "nope"}).status_code == 404
    # the former URL of the vulnerability panel opens the image panel
    assert client.get("/vulnerabilities/detail", params={"ref": "docker.io/library/nginx:1.25"}).text == detail


def test_rescan_api():
    client, scanner = _client()
    resp = client.post("/api/rescan/image", params={"ref": "docker.io/library/nginx:1.25", "vulnerabilities": "false"})
    assert resp.status_code == 202 and resp.json() == {"started": True}
    assert client.post("/api/rescan/chart?cluster=c1&namespace=argocd&app=redis&chart=redis").status_code == 202
    assert scanner.rescans == [("docker.io/library/nginx:1.25", True, False), ("c1", "argocd", "redis", "redis")]
    scanner.rescan_error = "a scan is running"
    resp = client.post("/api/rescan/image", params={"ref": "docker.io/library/nginx:1.25"})
    assert resp.status_code == 409 and resp.json() == {"started": False, "reason": "a scan is running"}
    assert client.post("/api/rescan/image", params={"ref": "nope"}).status_code == 404
    assert client.post("/api/rescan/chart?cluster=c1&namespace=argocd&app=x&chart=redis").status_code == 404


def test_rescan_buttons_and_polling():
    client, scanner = _client()
    ref = {"ref": "docker.io/library/nginx:1.25"}
    detail = client.get("/images/detail", params=ref).text
    assert 'hx-post="api/rescan/image?ref=docker.io/library/nginx%3A1.25&amp;vulnerabilities=false"' in detail
    assert 'hx-post="api/rescan/image?ref=docker.io/library/nginx%3A1.25&amp;versions=false"' in detail
    assert "images/detail?ref=docker.io/library/nginx%3A1.25&amp;polling=1" in detail and "Rescanning" not in detail
    # no vulnerability rescan when it cannot give a result
    redis = client.get("/images/detail", params={"ref": "docker.io/library/redis:latest"}).text
    assert "Check version" in redis and "Scan vulnerabilities" not in redis
    chart = client.get("/charts/detail?cluster=c1&namespace=argocd&app=redis&chart=redis").text
    assert 'hx-post="api/rescan/chart?cluster=c1&amp;namespace=argocd&amp;app=redis&amp;chart=redis"' in chart
    # the rescan sits in the header, next to the full screen and close buttons; the subcharts come first
    head = chart[chart.index('<div class="drawer-buttons">') : chart.index("drawer-full-toggle")]
    assert "api/rescan/chart?" in head and "Check again" not in chart
    assert chart.index("<h4>Subcharts</h4>") < chart.index("<h4>Chart</h4>") < chart.index("<h4>ArgoCD Application</h4>")
    # buttons are disabled while a full scan checks versions, not during its Trivy phase
    scanner.running = scanner.checking_versions = True
    assert "disabled" in client.get("/charts/detail?cluster=c1&namespace=argocd&app=redis&chart=redis").text
    scanner.checking_versions = False
    assert "disabled" not in client.get("/charts/detail?cluster=c1&namespace=argocd&app=redis&chart=redis").text
    scanner.running = False
    # while rescanned, the panel polls itself; the poll that sees the end reloads the results
    scanner.rescanning = {("image", "docker.io/library/nginx:1.25")}
    resp = client.get("/images/detail", params={**ref, "polling": "1"})
    assert "Rescanning" in resp.text and 'hx-trigger="every 3s [document' in resp.text and "Check version" not in resp.text
    assert "HX-Trigger" not in resp.headers
    scanner.rescanning = set()
    resp = client.get("/images/detail", params={**ref, "polling": "1"})
    assert resp.headers["HX-Trigger"] == "kt-rescanned" and "Rescanning" not in resp.text
    assert "HX-Trigger" not in client.get("/images/detail", params=ref).headers


def test_administration_page():
    client, scanner = _client()
    page = " ".join(client.get("/administration").text.split())
    assert 'aria-current="page"' in page and "Administration" in page
    assert "Failed in the last scan: 0 image version checks, 1 vulnerability scan, 0 charts" in page
    assert "/nonexistent/trivy&#39; not found" in page  # status read at the first visit
    # unused node images are not listed any more (the icon of the Images page tells it), the API still has them
    assert "Unused node images" not in page
    # tabs, Logs last
    assert re.findall(r'<a href="administration\?tab=(\w+)"', page) == ["scans", "clusters", "pods", "settings", "api", "logs"]
    assert '<a href="administration?tab=scans" aria-current="page">' in page
    assert 'hx-get="administration?polling=1"' not in page  # nothing running
    # What runs is listed first, the scan status links to it
    assert page.index('id="scans"') < page.index("<strong>Full scan</strong>")
    assert "Nothing is running. Last scan finished" in page
    assert 'href="administration?tab=scans"' in page
    m = client.app.state.administration
    scanner.running_activities = [
        Activity("Full scan: vulnerabilities (Trivy)", "running", datetime(2026, 10, 24, 10, tzinfo=UTC)),
        Activity("Full scan: vulnerabilities (Trivy) of 1 newer scan(s)", "waiting"),
    ]
    m.running = {"connectivity"}
    page = " ".join(client.get("/administration").text.split())
    assert "Nothing is running" not in page and "Full scan: vulnerabilities (Trivy)</td>" in page
    assert "2026-10-24 10:00 UTC" in page and "waiting for the current Trivy phase" in page
    assert "<td>Connectivity test</td>" in page
    scanner.running_activities, m.running = [], set()
    m.trivy_status = TrivyStatus(
        datetime.now(UTC), "0.75.0", TrivyDatabase(2, datetime(2026, 10, 23, tzinfo=UTC), datetime(2026, 10, 24, tzinfo=UTC))
    )
    m.connectivity = ConnectivityReport(
        datetime.now(UTC), datetime.now(UTC), [Check("registry", "ghcr.io", False, "HTTP 403", 0.5), Check("cluster", "c1", True)]
    )
    fragment = " ".join(client.get("/administration", headers={"HX-Request": "true", "HX-Target": "administration"}).text.split())
    assert "<html" not in fragment and 'id="administration"' in fragment
    assert "v2 · built 2026-10-23 00:00 UTC" in fragment and "after 2026-10-24 00:00 UTC" in fragment
    assert "1/2 OK" in fragment and "HTTP 403" in fragment and "0.50s" in fragment
    # while something runs, the actions poll themselves; the poll that sees the end reloads the page
    scanner.rescanning = {("retry-failed",)}
    assert 'hx-get="administration?polling=1"' in client.get("/administration").text
    scanner.rescanning = set()
    assert client.get("/administration?polling=1").headers["HX-Refresh"] == "true"


def test_administration_actions(monkeypatch):
    client, scanner = _client()
    m = client.app.state.administration
    assert "Full scan started." in client.post("/administration/scan").text and scanner.triggered == 1
    assert "Retry of the failed items started." in client.post("/administration/retry-failed").text and scanner.retried == 1
    scanner.rescan_error = "nothing failed in the last scan"
    assert "nothing failed in the last scan" in client.post("/administration/retry-failed").text
    assert "Trivy is disabled or its binary" in client.post("/administration/trivy-db").text
    assert "Trivy status read again." in client.post("/administration/trivy-status").text
    scanner.trivy.cache = {"a": None}
    resp = client.post("/administration/trivy-cache-scan").text
    assert "Trivy results cache cleared (1 image). Full scan started." in resp and scanner.triggered == 2
    started = []
    monkeypatch.setattr(m, "test_connectivity", lambda: started.append(1))
    assert "Connectivity test started." in client.post("/administration/connectivity").text and started
    assert client.post("/administration/nope").status_code == 404
    monkeypatch.setattr(scanner, "trigger", lambda: False)
    assert "already running" in client.post("/administration/scan").text


def test_administration_api(monkeypatch):
    client, scanner = _client()
    m = client.app.state.administration
    assert client.post("/api/administration/retry-failed").json() == {"started": True}
    resp = client.post("/api/administration/trivy-db")
    assert resp.status_code == 409 and "not found" in resp.json()["reason"]
    scanner.trivy.cache = {"a": None}
    assert client.delete("/api/administration/trivy-cache").json() == {"cleared": 1}
    assert client.get("/api/administration/connectivity").json() == {
        "running": False,
        "startedAt": None,
        "finishedAt": None,
        "checks": [],
    }
    monkeypatch.setattr(m, "test_connectivity", lambda: None)
    assert client.post("/api/administration/connectivity").status_code == 202
    m.connectivity = ConnectivityReport(datetime(2026, 10, 23, tzinfo=UTC), checks=[Check("cluster", "c1", True, "v1.30.0")])
    data = client.get("/api/administration/connectivity").json()
    assert data["startedAt"] == "2026-10-23T00:00:00+00:00" and data["checks"][0]["detail"] == "v1.30.0"
    assert client.get("/api/administration/unused-images").json() == [
        {"cluster": "c1", "image": "docker.io/library/redis:latest", "nodes": ["n1"]},
        {"cluster": "c2", "image": "ghcr.io/org/app:2.0", "nodes": ["n1", "n2"]},
    ]


def test_images_search_by_cve():
    client, _ = _client()
    rows = lambda page: page.split("<tbody>")[1]  # noqa: E731
    page = client.get("/images?q=CVE-2024-1").text
    assert "library/nginx" in rows(page) and "org/app" not in rows(page) and "library/redis" not in rows(page)
    assert 'value="CVE-2024-1"' in page and 'sev-critical" title="zlib overflow">CVE-2024-1</span>' in page
    # all or part of the ID, case insensitive, several IDs separated by spaces or commas, with words of the image
    assert "library/nginx" in rows(client.get("/images?q=2024-2").text)
    assert "library/nginx" in rows(client.get("/images?q=cve-2023-9,cve-2024-2").text)
    assert "library/nginx" in rows(client.get("/images?q=nginx CVE-2024").text)
    assert "library/nginx" not in rows(client.get("/images?q=redis CVE-2024").text)
    assert "library/nginx" not in rows(client.get("/images?q=CVE-2023").text)
    assert re.search(r"sev-critical\">critical</span><strong>0</strong>", client.get("/images?q=CVE-2023").text)
    # the rows open the detail panel with the CVEs searched, listed first
    assert 'hx-get="images/detail?ref=docker.io/library/nginx%3A1.25&cve=2024-2"' in client.get("/images?q=2024-2").text
    detail = client.get("/images/detail", params={"ref": "docker.io/library/nginx:1.25", "cve": "2024-2"}).text
    assert 'class="cve-match"' in detail and detail.index("CVE-2024-2") < detail.index("CVE-2024-1")
    # the list of all vulnerabilities, folded by default, opens on a search
    assert re.search(r'<details class="drawer-section" open>\s*<summary><h4>All vulnerabilities', detail)
    assert "1 matching <code>2024-2</code> (CVE-2024-2)" in detail


def test_list_pages_layout_and_sortable_columns():
    client, _ = _client()
    for path in ("/images", "/charts", "/administration?tab=clusters", "/administration?tab=logs"):
        page = client.get(path).text
        assert 'class="content list-page"' in page, path
    for path in ("/images", "/charts", "/administration?tab=clusters"):
        page = client.get(path).text
        assert 'class="overflow-auto table-wrap"' in page and "<th data-sort" in page, path
    images = client.get("/images").text
    assert re.search(r'<td data-sort="0">\s*<span class="badge badge-outdated badge-minor"', images)  # outdated sorts first
    assert '<th data-sort="desc" data-server-sort="5" class="hide-sm">Used by</th>' in images
    assert 'class="content "' in client.get("/administration?tab=settings").text  # documents scroll as a whole


def test_lists_load_by_pages_and_sort_on_the_server():
    """Infinite scroll: 30 items per page, the last row loads the next page; headers sort on the server."""
    from kube_tower.web import ui

    client, scanner = _client()
    base = scanner.snapshot.images[0]
    pod = [Usage("c1", "Pod", "ns", "p", "c")]  # running
    scanner.snapshot.images = [
        dataclasses.replace(base, image=ImageRef("docker.io", f"org/app{i}", f"1.{i}"), usages=pod) for i in range(65)
    ]
    page = client.get("/images").text
    assert page.count('hx-get="images/detail') == ui.PAGE_SIZE and "65 images" in page
    assert 'hx-get="images?offset=30" hx-trigger="intersect once" hx-swap="outerHTML"' in page
    assert '<span aria-busy="true">Loading…</span>' in page
    # Rows left to load are visible: the count of shown rows and a "more below" hint at the bottom of the list
    assert '65 images<span id="list-shown"> · 30 shown</span>' in page
    assert 'id="more-hint" class="more-hint">' in page and "35 more below" in page
    # The next page: only its rows (and the row loading the one after)
    more = client.get("/images?offset=30").text
    assert "<html" not in more and "<thead" not in more and more.count('hx-get="images/detail') == 30
    assert "offset=60" in more
    # ... and refreshes the count and the hint out of band (in a <template>, as they are not table rows)
    assert '<template><span id="list-shown" hx-swap-oob="true"> · 60 shown</span>' in more and "5 more below" in more
    last = client.get("/images?offset=60").text
    assert last.count('hx-get="images/detail') == 5 and "load-more" not in last
    assert '<span id="list-shown" hx-swap-oob="true"></span>' in last and 'hx-swap-oob="true" hidden>' in last
    assert '<div id="more-hint" class="more-hint" hidden>' in client.get("/images?q=app1").text  # 11 images: all shown
    # Sorted on the server, natural order of versions; the sort is kept by the next pages and the form
    page = client.get("/images?sort=1&dir=descending").text
    assert page.index("org/app64") < page.index("org/app63") < page.index("org/app40") and "org/app9<" not in page
    assert 'data-server-sort="1" aria-sort="descending"' in page
    assert '<input type="hidden" name="sort" value="1"><input type="hidden" name="dir" value="descending">' in page
    assert "sort=1&amp;dir=descending&amp;offset=30" in page
    ascending = client.get("/images?sort=1").text
    assert ascending.index("org/app2<") < ascending.index("org/app10<")
    assert "aria-sort" not in client.get("/images?sort=99&offset=x").text.split("<tbody>")[0].split("<thead>")[1]
    assert (
        "data-serverSort" in client.get("/static/kube-tower.js").text or "serverSort" in client.get("/static/kube-tower.js").text
    )


def test_natural_sort_and_empty_values_last():
    from kube_tower.web.ui import Column, natural

    assert sorted(["1.10", "1.9", "v10", "v2"], key=natural) == ["1.9", "1.10", "v2", "v10"]
    client, _ = _client()
    # charts accept a sort too, the vulnerabilities of the images sort the most vulnerable first
    assert 'aria-sort="ascending"' in client.get("/charts?sort=0").text
    assert 'aria-sort="descending"' in client.get("/images?sort=4").text
    assert Column(len).descending is False


def test_scan_status_top_right():
    client, scanner = _client()
    scanner.trivy.settings.binary = sys.executable  # Trivy found: no problem of kube-tower itself
    page = client.get("/images").text
    assert page.index('class="topbar-title"') < page.index('id="scan-status"')
    assert '<time datetime="' in page and 'class="dot dot-ok"' in page and ">Scan now</button>" in page
    assert "took 0 s" in page
    scanner.snapshot.errors = ["boom"]
    status = client.get("/status").text
    assert 'class="dot dot-warn"' in status and "1 scan error<" in status and "boom" in status
    scanner.running = scanner.checking_versions = True
    status = client.get("/status").text
    assert "disabled" in status and "Scan in progress" in status
    # Trivy phase: shown as running, a new scan can be started
    scanner.checking_versions = False
    status = client.get("/status").text
    assert "disabled" not in status and "Vulnerability scan in progress" in status


def test_github_link_next_to_version():
    client, _ = _client()
    page = client.get("/about").text
    footer = page[page.index('class="version"') :]
    assert footer.index("<small>") < footer.index('href="https://github.com/Arcanexus/kube-tower"')
    assert "icons.svg?v=" in footer and '#i-github"' in footer


def test_check_version_button_counts_the_tags():
    client, scanner = _client()
    scanner.snapshot.images.append(ImageReport(ImageRef("docker.io", "library/nginx", "1.27"), [Usage("c1", "Node", None, "n1")]))
    detail = client.get("/images/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
    assert "Check versions (2 tags)" in detail and "Scan vulnerabilities (2 tags)" in detail
    assert "and the new ones found on the clusters" in detail
    assert ">Check version</button>" in client.get("/images/detail", params={"ref": "ghcr.io/org/app:2.0"}).text.replace("\n", "")


def test_cross_site_requests_refused(caplog):
    client, scanner = _client()
    refused = [
        {"Sec-Fetch-Site": "cross-site"},
        {"Sec-Fetch-Site": "same-site"},  # another subdomain
        {"Origin": "https://evil.example.com"},
        {"Origin": "null"},
        {"Origin": "http://testserver", "X-Forwarded-Host": "kube-tower.example.com"},
    ]
    for headers in refused:
        resp = client.post("/api/refresh", headers=headers)
        assert resp.status_code == 403 and resp.json() == {"detail": "cross-site request refused"}, headers
        assert client.post("/administration/scan", headers=headers).status_code == 403
    assert scanner.triggered == 0 and "cross-site POST /api/refresh refused" in caplog.text
    allowed = [
        {},  # curl, scripts
        {"Sec-Fetch-Site": "same-origin"},  # the UI
        {"Sec-Fetch-Site": "none"},  # typed in the address bar
        {"Origin": "http://testserver"},
        {"Origin": "https://kube-tower.example.com", "X-Forwarded-Host": "kube-tower.example.com, proxy"},
    ]
    for headers in allowed:
        assert client.post("/api/refresh", headers=headers).status_code == 202, headers
    # Reading stays open to other sites' links
    assert client.get("/images", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 200


def test_chart_row_shows_the_worst_status():
    # redis is up to date, its subchart common is outdated: the chips count it as outdated, the tree tells why
    page = _client()[0].get("/charts").text
    row = " ".join(page.split('id="results"')[1].split())
    assert re.search(
        r"onclick=\"ktToggleFilter\('status', 'outdated'\)\">\s*<span class=\"badge badge-outdated\">.*?<strong>1</strong>",
        page,
        re.S,
    )
    assert "1 chart up to date with an outdated subchart" in row
    # one row per chart: the chart at the root of the tree of the Status column, its subcharts below
    assert re.findall(r"<th[^>]*>([^<]+)</th>", page.split("<thead>")[1].split("</thead>")[0]) == [
        "Chart",
        "Current",
        "Latest",
        "Status (chart and subcharts)",
        "Repository",
        "Deployed by",
    ]
    assert row.count('class="clickable"') == 1
    assert (
        '<span class="tree-label"><code>redis</code></span><span class="tree-versions">18.0.0</span> '
        '<span class="badge badge-up-to-date">' in row
    )
    assert '<small class="subchart-hint">1 subchart outdated</small>' in row
    assert re.search(
        r'tree-tee" aria-hidden="true"></span><span class="tree-label"><code>common</code></span>'
        r'<span class="tree-versions">2.0.0 <span class="arrow" aria-hidden="true">→</span> <strong>2.1.0</strong>',
        row,
    )
    assert '<td class="hide-sm"><small><span class="muted-text">ArgoCD Application</span><br>redis · c1</small></td>' in row


def test_trivy_problem_shown_everywhere():
    client, scanner = _client()
    page = client.get("/").text
    assert (
        'class="dot dot-warn"' in page
        and "1 problem of kube-tower" in page
        and "binary &#39;/nonexistent/trivy&#39; not found" in page
    )
    images = client.get("/images").text
    assert 'class="notice notice-warn"' in images and 'href="administration?tab=scans#trivy"' in images
    scanner.trivy.settings.binary = sys.executable
    assert "problem of kube-tower" not in client.get("/").text
    assert "notice-warn" not in client.get("/images").text


def test_trivy_status_error_is_a_problem():
    from kube_tower.trivy import TrivyStatus

    client, scanner = _client()
    scanner.trivy.settings.binary = sys.executable
    client.app.state.administration.trivy_status = TrivyStatus(datetime.now(UTC), message="database is corrupted")
    assert "Trivy: database is corrupted (see Administration)." in client.get("/").text


def test_images_show_current_and_latest_with_digests():
    client, scanner = _client()
    nginx, app, redis = scanner.snapshot.images
    nginx.running_digests = {"sha256:aaaaaaaaaaaa1111"}
    nginx.latest_digest = "sha256:bbbbbbbbbbbb2222"
    app.tag_digest = "sha256:cccccccccccc3333"
    page = client.get("/images?running=0").text
    # current and latest side by side, with the start of their digest; a different digest is highlighted
    assert '<small class="digest-short " title="sha256:aaaaaaaaaaaa1111">sha256:aaaaaaaaaaaa</small>' in page
    assert '<small class="digest-short digest-differs" title="sha256:bbbbbbbbbbbb2222">sha256:bbbbbbbbbbbb</small>' in page
    # up to date: the latest is the current tag, same digest (not highlighted)
    assert page.count('title="sha256:cccccccccccc3333">') == 2 and 'digest-differs" title="sha256:cccc' not in page
    # latest: the same tag pushed again, the new digest
    assert 'title="sha256:new">sha256:new</small>' in page
    # registry dimmed, full name on hover
    assert '<code class="image-name" title="ghcr.io/org/app"><span class="registry">ghcr.io/</span>org/app</code>' in page
    detail = client.get("/images/detail?ref=docker.io/library/nginx:1.25").text
    assert 'class="drawer-summary"' in detail and detail.index("drawer-summary") < detail.index("<h4>Used by</h4>")
    # two summary cards, then foldable sections: Used by, Vulnerabilities open; the rest folded
    assert detail.count('class="detail-card"') == 2
    assert detail.count('class="vuln-tile vuln-tile-') == 4 and "with a fix" in detail  # unknown only when found
    sections = re.findall(r'<details class="drawer-section"( open)?>\s*<summary><h4>([A-Za-z ]+)', detail)
    assert [(name.strip(), bool(opened)) for opened, name in sections] == [
        ("Used by", True),
        ("Versions and digests", False),
        ("Vulnerabilities", True),
        ("All vulnerabilities", False),
    ]
    # the rescans are in the header, next to the full screen and close buttons
    head = detail[detail.index('<div class="drawer-buttons">') : detail.index("drawer-full-toggle")]
    assert "api/rescan/image?ref=" in head and "Check again" not in detail


def test_image_versions():
    from kube_tower.web.ui import image_versions

    unknown = ImageReport(ImageRef("docker.io", "library/x", "1.0"), status=Status.ERROR)
    assert image_versions(unknown) == (("1.0", ""), ("", ""))
    pinned = ImageReport(ImageRef("docker.io", "library/x", None, "sha256:p"), status=Status.UP_TO_DATE)
    assert image_versions(pinned) == (("", "sha256:p"), ("", "sha256:p"))
    page = _client()[0].get("/images").text
    assert "unknown</small>" not in page.split("<tbody>")[1].split("</tbody>")[0].split("org/app")[0]  # nginx has a latest


def test_units_and_plurals():
    from kube_tower.web.ui import duration, plural, short_digest

    assert plural(1, "image") == "1 image" and plural(0, "image") == "0 images" and plural(2, "CVE", "CVEs") == "2 CVEs"
    assert [duration(s) for s in (12.4, 180, 21600, 5400, 86400 * 3)] == ["12 s", "3 min", "6 h", "1.5 h", "3 days"]
    assert short_digest("sha256:0123456789abcdef") == "sha256:0123456789ab" and short_digest(None) == ""
    assert short_digest("abc") == "abc"


def test_settings_sections():
    settings = Settings()
    settings.refresh_interval = 3600
    page = TestClient(create_app(settings, FakeScanner(), background=False)).get("/administration?tab=settings").text
    assert (
        '<tr class="changed"><th scope="row"><code>refreshInterval</code></th><td>1 h (3600 s) <span class="badge badge-changed">'
        in page
    )
    assert "<code>trivy.rescanInterval</code></th><td>1 day" not in page and "24 h (86400 s)" in page
    assert "(1 value changed from the default)" in page and "(0 values changed from the default)" in page
    assert "<summary>Configuration as YAML</summary>" in page and "refreshInterval: 3600" in page


def test_clusters_tab_has_the_figures_of_each_cluster():
    client = _client()[0]
    page = client.get("/administration?tab=clusters&running=0").text
    assert 'href="images?cluster=c1">2</a>' in page
    assert 'href="images?cluster=c1&amp;status=outdated">2 outdated</a>' in page
    assert 'href="charts?cluster=c1&amp;status=outdated">1 outdated</a>' in page
    assert 'href="images?severity=critical&amp;cluster=c1">1 image</a>' in page
    # By default only the images a pod runs: nginx in c1
    assert 'href="images?cluster=c1">1</a>' in client.get("/administration?tab=clusters").text


def test_clusters_page():
    client, scanner = _client()
    scanner.snapshot.nodes = [
        NodeInfo("c1", "cp-1", role="control-plane", kubelet_version="v1.30.0", container_runtime="containerd://1.7.13"),
        NodeInfo("c1", "w-1", pool="general", kubelet_version="v1.30.0", max_pods=110, pods=30, memory="15.5 GiB", cpu="4"),
        NodeInfo("c1", "w-2", pool="general", kubelet_version="v1.27.3", ready=False, unschedulable=True),
    ]
    nginx = scanner.snapshot.images[0]
    nginx.usages.append(Usage("c1", "Pod", "default", "web-x", "nginx", "Deployment/web", "w-1"))
    page = " ".join(client.get("/clusters").text.split())
    assert "not looked up" in page  # no end of life nor vulnerability of Kubernetes yet
    assert 'aria-current="page"' in page and '<span class="cluster-card-name">c1</span>' in page
    assert "Control plane <small" in page and "Workers · general <small" in page
    assert "Kubernetes <strong>v1.30.0</strong>" in page and ">3</text>" in page and "problem" in page
    # the ring of the kubelet versions: 2 nodes on the version of the API server, 1 behind
    assert (
        'class="donut-segment stroke-ok" cx="21" cy="21" r="15.9155" stroke-dasharray="66.7 33.3" stroke-dashoffset="25.0"'
        in page
    )
    assert 'stroke-dasharray="33.3 66.7" stroke-dashoffset="-41.7"' in page
    assert "4 things to check" in page and "kubelet v1.27.3 is 3 minor versions behind the API server v1.30.0" in page
    assert '<code class="version-warning">v1.27.3</code>' in page
    # vulnerabilities of the images run by the pods: nginx on w-1
    assert 'title="1 critical CVEs">1 C</span>' in page and 'href="images?cluster=c1&amp;running=1">1 image</a>' in page
    assert "no pod" in page
    assert "timeout" in page and "unreachable" in page  # c2
    page = client.get("/clusters?cluster=c2").text
    assert 'cluster-card-name">c1' not in page and "unreachable" in page
    scanner.snapshot.platform = [
        PlatformVersion(
            "kubernetes",
            "1.30.0",
            "1.30",
            "2025-06-28",
            "1.30.14",
            "1.34",
            [
                Vulnerability(
                    "CVE-2025-1", Severity.HIGH, "k8s.io/kubernetes", "1.30.0", "1.30.9", "Kubelet flaw", "https://osv.dev/x"
                )
            ],
            latest_released="2025-07-15",
            newest_released="2025-08-27",
        )
    ]
    page = " ".join(client.get("/clusters").text.split())
    assert 'Kubernetes <strong>v1.30.0</strong> <span class="eol-tag level-error"' in page
    assert (
        'end of life since 2025-06-28</span> · latest patch 1.30.14 <small class="released" title="Released 2025-07-15">' in page
    )
    assert "2025-07-15</small> · newest 1.34" in page and "2025-08-27</small>" in page
    assert "Kubernetes 1.30 is end of life since 2025-06-28: no more security fixes" in page
    assert 'title="1 high CVEs">1 H</span>' in page
    detail = " ".join(client.get("/clusters/node?cluster=c1&name=w-1").text.split())
    assert "kubernetes 1.30.0" in detail and "CVE-2025-1" in detail and "1.30.9" in detail
    assert "Images run on this node (1)" in detail and "library/nginx:1.25" in detail
    assert "Node · c1" in detail and "4 CPU · 15.5 GiB" in detail and "30 / 110" in detail and "general" in detail
    assert "not ready" in client.get("/clusters/node?cluster=c1&name=w-2").text
    assert client.get("/clusters/node?cluster=c1&name=nope").status_code == 404
    assert client.get("/clusters/node?cluster=c9&name=w-1").status_code == 404
    metrics = client.get("/metrics").text
    assert 'kube_tower_nodes{cluster="c1",kubelet_version="v1.30.0",pool="general",ready="true",role="worker"} 1.0' in metrics
    assert 'kube_tower_nodes{cluster="c1",kubelet_version="v1.27.3",pool="general",ready="false",role="worker"} 1.0' in metrics
    metrics = client.get("/metrics").text
    assert 'kube_tower_kubernetes_end_of_life_days{cluster="c1",cycle="1.30",version="v1.30.0"}' in metrics
    assert 'kube_tower_platform_vulnerabilities{component="kubernetes",severity="high",version="1.30.0"} 1.0' in metrics
    scanner.snapshot.deprecated_apis = [
        DeprecatedApi("c1", "flowcontrol.apiserver.k8s.io", "v1beta3", "flowschemas", "", "1.32"),
        DeprecatedApi("c1", "", "v1", "componentstatuses"),
    ]
    page = " ".join(client.get("/clusters").text.split())
    assert "flowcontrol.apiserver.k8s.io/v1beta3 flowschemas, removed in Kubernetes 1.32 (a later release)" in page
    assert "v1 componentstatuses (no removal planned)" in page
    assert (
        'kube_tower_deprecated_api_requested{cluster="c1",group="flowcontrol.apiserver.k8s.io",removed_release="1.32",'
        'resource="flowschemas",subresource="",version="v1beta3"} 1.0'
    ) in client.get("/metrics").text
    scanner.snapshot.nodes, scanner.snapshot.platform, scanner.snapshot.deprecated_apis = scanner.snapshot.nodes[:2], [], []
    page = " ".join(client.get("/clusters").text.split())
    assert "healthy" in page and "to check</summary>" not in page


def test_accessibility_helpers():
    page = _client()[0].get("/images").text
    assert '<a class="skip-link" href="#main">' in page and '<main id="main" tabindex="-1">' in page
    assert 'class="help" tabindex="0"' in page and 'class="help-text" role="tooltip"' in page
    assert 'aria-label="Running"' in page


def test_administration_api_links():
    client = _client()[0]
    page = client.get("/administration?tab=api").text
    assert 'href="api/docs"' in page and 'href="api/snapshot"' in page and 'href="metrics"' in page
    assert "<code>GET api/snapshot</code>" in page
    page = client.get("/administration").text
    assert ">Scan now</button>" in page and 'id="trivy"' in page
    assert client.get("/administration?tab=bogus").text == page


async def test_watch_event_loop_warns_when_blocked(monkeypatch, caplog):
    import asyncio
    import time

    from kube_tower import main

    caplog.set_level("INFO", logger="kube_tower.main")
    monkeypatch.setattr(main, "LAG_CHECK", 0.01)
    monkeypatch.setattr(main, "LAG_WARNING", 0.05)
    task = asyncio.create_task(main.watch_event_loop())
    await asyncio.sleep(0)  # the watch starts its first check
    time.sleep(0.1)  # blocks the event loop, as a scan holding the GIL would
    await asyncio.sleep(0.05)
    task.cancel()
    assert "the web server was blocked for 0.1s" in caplog.text
    task = asyncio.create_task(main.watch_event_loop(ui=False))  # a worker: no page waited
    await asyncio.sleep(0)
    time.sleep(0.1)
    await asyncio.sleep(0.05)
    task.cancel()
    assert "the event loop was busy for 0.1s" in caplog.text


def test_web_layer_only_talks_to_the_backend():
    # The distributed mode swaps the backend of `ui` pods for one that asks the controller:
    # pages, API and metrics must not reach the scanner or the administration directly.
    web = Path(__file__).parent.parent / "src" / "kube_tower" / "web"
    for path in [*web.glob("*.py"), *web.glob("templates/*.html")]:
        text = path.read_text()
        assert not re.search(r"state\.(scanner|administration)\b|\bscanner\.", text), path.name
    client, _ = _client()
    assert client.get("/administration").status_code == 200


def test_roles_and_pods_on_the_administration_page(monkeypatch):
    from kube_tower.processes import ProcessInfo, roles_status

    client, _ = _client()
    page = " ".join(client.get("/administration?tab=pods").text.split())
    # one pod runs every role
    assert 'id="processes"' in page and 'id="scans"' not in page
    assert page.count('class="role-tile role-ok"') == 4 and "One pod runs every role" in page
    fragment = client.get("/administration/processes").text
    assert "<html" not in fragment and 'hx-get="administration/processes?polling=1"' in fragment
    # distributed: the controller and the pods that report to it
    registry = client.app.state.backend.process_registry
    registry.roles = ["controller"]
    registry.seen("kube-tower-ui-1", ["ui"], version="1.0.0")
    registry.seen("kube-tower-controller-1", ["controller"], "standby")
    registry.seen("kube-tower-worker-1", ["worker"])
    registry.task("kube-tower-worker-1", "check-images")
    fragment = " ".join(client.get("/administration/processes").text.split())
    assert "One pod runs every role" not in fragment
    assert '<span aria-busy="true">check-images</span>' in fragment and "<small>1.0.0</small>" in fragment
    assert fragment.count("dot dot-standby") == 1
    assert 'class="role-tile role-error"' in fragment and "no pod" in fragment  # no trivy pod

    # the krr pod of the chart, read from its health check
    resources = client.app.state.settings.resources
    resources.enabled, resources.server_url = True, "http://kube-tower-krr:8080"
    with respx.mock:
        route = respx.get("http://kube-tower-krr:8080/healthz")
        route.respond(json={"status": "ok", "pod": "kube-tower-krr-1", "version": "v1.31.3", "running": 0, "concurrency": 2})
        fragment = " ".join(client.get("/administration/processes").text.split())
        assert "<code>kube-tower-krr-1</code>" in fragment and "<small>v1.31.3</small>" in fragment
        assert "<strong>krr</strong><small>1 pod</small>" in fragment
        route.side_effect = httpx.ConnectError("refused")
        fragment = " ".join(client.get("/administration?tab=pods").text.split())
        assert "<strong>krr</strong><small>unreachable</small>" in fragment and "unreachable: ConnectError" in fragment
    resources.enabled = False

    # every pod of the Helm release, from the Kubernetes API: Valkey, Dex, krr (with its runs)...
    from kube_tower.chartpods import ChartPod

    release = [
        ChartPod("kube-tower-worker-1", "worker", True, "ok", 2),
        ChartPod("kube-tower-dex-5d", "dex", True, "ok", 0, "v2.46.1"),
        ChartPod("kube-tower-krr-7b", "krr", True, "ok", 0, "v1.31.3"),
        ChartPod("kube-tower-valkey-0", "valkey", False, "crashloopbackoff", 5, "9.1.3"),
    ]

    async def pods():
        return release

    monkeypatch.setattr("kube_tower.web.ui.chart_pods", pods)
    resources.enabled = True
    with respx.mock:
        respx.get("http://kube-tower-krr:8080/healthz").respond(json={"pod": "kube-tower-krr-7b", "running": 1, "concurrency": 2})
        fragment = " ".join(client.get("/administration/processes").text.split())
    resources.enabled = False
    assert "<code>kube-tower-dex-5d</code>" in fragment and "<small>v2.46.1</small>" in fragment
    assert fragment.count("<code>kube-tower-worker-1</code>") == 1  # a kube-tower pod: its own report
    assert "2 restarts" in fragment and "5 restarts" in fragment
    assert "<strong>dex</strong><small>1 pod</small>" in fragment
    assert "<strong>krr</strong><small>1 pod, 1/2 krr run(s)</small>" in fragment
    assert (
        'class="role-tile role-error"' in fragment
        and "<strong>valkey</strong><small>no pod ready, 1 not ready</small>" in fragment
    )
    assert "crashloopbackoff" in fragment and "1/2 krr run(s)" in fragment

    now = datetime.now(UTC)
    statuses = roles_status(
        [
            ProcessInfo("c0", ["controller"], "lost", seen_at=now),
            ProcessInfo("c1", ["controller"], "standby"),
            ProcessInfo("u0", ["ui"]),
            ProcessInfo("u1", ["ui"], "lost"),
            ProcessInfo("w0", ["worker", "trivy"]),
        ]
    )
    assert [(s.role, s.level, s.summary) for s in statuses] == [
        ("ui", "warn", "1 pod, 1 lost"),
        ("controller", "error", "no active controller, 1 standby, 1 lost"),
        ("worker", "ok", "1 pod"),
        ("trivy", "ok", "1 pod"),
    ]


def test_logs_of_every_pod_filtered_by_role():
    import json

    import fakeredis

    from kube_tower.bus import Bus
    from kube_tower.logbuffer import LogLine
    from kube_tower.models import encode
    from kube_tower.worker import Worker

    settings = Settings(roles=["ui", "controller"])
    settings.redis.url = "redis://kube-tower-valkey:6379/0"
    scanner = FakeScanner()
    scanner.worker = Worker(settings)
    server = fakeredis.FakeServer()
    bus = Bus(fakeredis.FakeAsyncRedis(server=server), "kt")
    valkey = fakeredis.FakeRedis(server=server)  # the other pods ship their lines there

    def ship(source, roles, level, logger, message):
        line = LogLine(0, datetime.now(), level, logger, "", message, source, roles)
        valkey.xadd("kt:logs", {"data": json.dumps(encode(line))})

    client = TestClient(create_app(settings, scanner, background=False, bus=bus))
    assert 'name="role"' in client.get("/logs").text  # distributed mode only
    assert 'name="role"' not in _client()[0].get("/logs").text
    ship("kube-tower-worker-1", ["worker"], "WARNING", "kube_tower.collectors.images", "cannot list CronJob")
    ship("kube-tower-trivy-0", ["trivy"], "INFO", "kube_tower.trivy", "database updated")
    page = client.get("/logs").text
    assert "cannot list CronJob" in page and "database updated" in page
    assert '<span class="log-source" title="Roles: worker">kube-tower-worker-1</span>' in page
    page = client.get("/logs?role=worker&role=bogus").text
    assert "cannot list CronJob" in page and "database updated" not in page
    assert "&amp;role=worker" in page and "bogus" not in page.split('id="log-tail"')[1]
    assert "database updated" in client.get("/logs?q=trivy-0").text  # the text filter also matches the pod
    after = re.search(r"after=(\d+)", client.get("/logs?role=trivy").text).group(1)
    ship("kube-tower-trivy-0", ["trivy"], "INFO", "kube_tower.trivy", "scan done")
    assert "scan done" not in client.get(f"/logs/tail?after={after}&role=ui&role=worker").text
    assert "scan done" in client.get(f"/logs/tail?after={after}&role=trivy").text
    assert "database updated" not in client.get(f"/logs/tail?after={after}&role=trivy").text


def test_overview_counts_the_running_images_by_default():
    """Images only cached on nodes or declared by workloads without pods are left out, unless the switch is off."""
    client, _ = _client()
    page = client.get("/").text
    assert re.search(r"Images up to date</span><strong>0<small> / 1</small></strong>\s*<small>1 outdated", page)
    assert 'name="running" value="1" checked' in page
    page = client.get("/?running=0").text
    assert re.search(r"Images up to date</span><strong>1<small> / 3</small></strong>", page)


def test_static_files_cached_and_compressed():
    client, _ = _client()
    page = client.get("/images", headers={"Accept-Encoding": "gzip"})
    assert page.headers["content-encoding"] == "gzip"
    assert '<body hx-boost="true">' in page.text  # links swap the page body, styles and scripts stay loaded
    css = re.search(r'href="(static/kube-tower\.css\?v=[0-9a-f]{12})"', page.text).group(1)
    assert re.search(r'href="static/icons\.svg\?v=[0-9a-f]{12}#i-images"', page.text)
    resp = client.get("/" + css, headers={"Accept-Encoding": "gzip"})
    assert resp.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert resp.headers["content-encoding"] == "gzip"
    assert client.get("/static/kube-tower.css").headers["cache-control"] == "no-cache"


def test_polling_pauses_in_hidden_tabs():
    client, scanner = _client()
    scanner.running = True
    assert "every 3s [document.visibilityState=='visible']" in client.get("/status").text


def test_about_page():
    client, _ = _client()
    page = client.get("/about").text
    assert 'href="about" aria-current="page"' in page and "<span>About</span>" in page
    assert "One pod running every role" in page and "every 6 h" in page and "/etc/kube-tower/config.yaml" in page
    assert '<th scope="row">htmx</th><td>2.0.4</td>' in page and "Apache-2.0" in page
    # the latest release is asked to GitHub by the browser, never by kube-tower
    assert 'id="latest-release" data-current="dev" data-repo="Arcanexus/kube-tower"' in page
    assert "api.github.com" in client.get("/static/kube-tower.js").text
    # the version of every page links to it
    assert '<a href="about" title="About kube-tower"><small>dev</small></a>' in client.get("/images").text


def test_subchart_not_deployed():
    # common, the outdated subchart of redis, is left out by the Helm values: redis is up to date
    client, scanner = _client()
    scanner.snapshot.charts[0].dependencies[0].not_deployed = "common.enabled is false"
    page = client.get("/charts").text
    row = " ".join(page.split('id="results"')[1].split())
    assert (
        '<span class="badge badge-not-deployed" title="Left out of the release: common.enabled is false (version outdated)">'
        in row
    )
    assert "subchart-hint" not in row and "with an outdated subchart" not in row
    assert "redis" not in client.get("/charts?status=outdated").text.split('id="results"')[1]
    detail = client.get("/charts/detail?cluster=c1&namespace=argocd&app=redis&chart=redis").text
    assert "Not deployed: common.enabled is false" in detail
    assert (
        'kube_tower_chart_dependency_outdated{application="redis",chart="redis",cluster="c1",dependency="common",latest="2.1.0",'
        'status="not-deployed",update="minor",version="2.0.0"} 0.0'
    ) in client.get("/metrics").text


def _with_resources(scanner):
    from kube_tower.models import Fit, ResourceRecommendation, ResourceScan, ResourceValue

    now = datetime.now(UTC)
    mi = 1024**2
    scanner.snapshot.resources = [
        ResourceRecommendation(
            "c1", "shop", "Deployment", "api", "app",
            cpu_request=ResourceValue(1.0, 0.05, True, Fit.CRITICAL),
            cpu_limit=ResourceValue(2.0, None, True, Fit.WARNING),
            memory_request=ResourceValue(512 * mi, 200 * mi, True, Fit.WARNING),
            memory_limit=ResourceValue(None, 200 * mi, True, Fit.CRITICAL),
            fit=Fit.CRITICAL, pods=3,
        ),
        ResourceRecommendation(
            "c1", "shop", "StatefulSet", "db", "db",
            cpu_request=ResourceValue(None, None, False), memory_request=ResourceValue(None, None, False),
            fit=Fit.UNKNOWN, hpa=True, info="Not enough data",
        ),
    ]  # fmt: skip
    scanner.snapshot.resource_scans = [
        ResourceScan("c1", now, strategy="simple", score=42, settings={"history_duration": "336.0"}),
        ResourceScan("c2", now, message="Prometheus not found", strategy="simple"),
    ]


def _resources_client(enabled=True):
    scanner = FakeScanner()
    _with_resources(scanner)
    settings = Settings()
    settings.resources.enabled = enabled
    return TestClient(create_app(settings, scanner, background=False)), scanner


def test_resources_page():
    client, _ = _resources_client()
    page = " ".join(client.get("/resources").text.split())
    assert 'href="resources" aria-current="page"' in page  # in the sidebar once enabled
    assert "score <strong>42</strong>/100" in page and "336 h of history" in page and "Prometheus not found" in page
    # current → recommended, coloured by fit; CPU limit removed
    assert (
        '<span class="resource-value fit-text-critical">1 <span class="arrow" aria-hidden="true">→</span> <strong>50m</strong>'
        in page
    )
    assert '2 <span class="arrow" aria-hidden="true">→</span> <strong>none</strong>' in page
    assert "512Mi" in page and "200Mi" in page and "unset" in page and "Not enough data" in page and "HPA" in page
    assert "1<small> → 50m</small>" in page and "950m less to reserve" in page  # requests with a recommendation
    assert page.index("<strong>api</strong>") < page.index("<strong>db</strong>")  # critical first
    assert "<strong>db</strong>" not in client.get("/resources?fit=critical").text
    assert "<strong>api</strong>" not in client.get("/resources?q=db").text
    assert "No container." in client.get("/resources?cluster=c2").text
    assert client.get("/resources?sort=3&dir=descending").status_code == 200


def test_resources_detail():
    client, _ = _resources_client()
    url = "/resources/detail?cluster=c1&namespace=shop&kind=Deployment&name=api&container=app"
    page = " ".join(client.get(url).text.split())
    assert "api / app" in page and "far from the usage" in page and "-950m" in page and "-312Mi" in page
    assert "requests: cpu: 50m memory: 200Mi limits: memory: 200Mi" in page  # the block to paste
    assert "history_duration 336.0" in page and "found by krr in the cluster" in page and "<td>3</td>" in page
    assert client.get(url.replace("api", "nope")).status_code == 404


def test_resources_page_off_and_empty():
    client, scanner = _resources_client(enabled=False)
    page = client.get("/resources").text
    assert "CPU and memory recommendations are off" in page and 'href="resources"' not in page.split("<main")[0]
    client, scanner = _resources_client()
    scanner.snapshot.resources, scanner.snapshot.resource_scans = [], []
    assert "krr has not answered yet" in client.get("/resources").text


def test_clusters_page_shows_the_resources():
    client, scanner = _resources_client()
    scanner.snapshot.nodes = [NodeInfo("c1", "w-1", kubelet_version="v1.30.0")]
    page = " ".join(client.get("/clusters").text.split())
    assert "CPU and memory" in page and '<span class="badge fit-critical">1 critical</span>' in page
    assert "CPU 1 → 50m, memory 512Mi → 200Mi · score 42/100" in page


def test_resources_metrics_and_api():
    client, _ = _resources_client()
    metrics = client.get("/metrics").text
    assert (
        'kube_tower_resources_current{cluster="c1",container="app",kind="Deployment",namespace="shop",resource="cpu",'
        'type="request",workload="api"} 1.0' in metrics
    )
    assert (
        'kube_tower_resources_recommended{cluster="c1",container="app",kind="Deployment",namespace="shop",resource="cpu",'
        'type="request",workload="api"} 0.05' in metrics
    )
    assert 'resource="cpu",type="limit",workload="api"} 2.0' in metrics
    assert (
        'kube_tower_resources_recommended{cluster="c1",container="app",kind="Deployment",namespace="shop",resource="cpu",type="limit"'
        not in metrics
    )  # noqa: E501
    assert 'kube_tower_resources_containers{cluster="c1",fit="critical"} 1.0' in metrics
    data = client.get("/api/resources?cluster=c1").json()
    assert [s["cluster"] for s in data["scans"]] == ["c1"] and data["recommendations"][0]["cpu_request"]["recommended"] == 0.05


def test_charts_outside_argocd():
    client, scanner = _client()
    scanner.snapshot.charts += [
        ChartReport("c1", "ingress", "ingress", "ingress-nginx", "", "4.10.0", "helm", "ingress", manager="helm"),
        ChartReport(
            "c1", "podinfo", "apps", "podinfo", "oci://ghcr.io/stefanprodan/charts", "6.5.0", "oci", "web", manager="flux"
        ),
    ]
    page = client.get("/charts").text
    assert '<span class="muted-text">Helm release</span><br>ingress · c1' in page
    assert "helm · unknown" in page
    assert client.get("/charts", params={"q": "flux"}).text.count('class="clickable"') == 1
    detail = client.get("/charts/detail?cluster=c1&namespace=ingress&app=ingress&chart=ingress-nginx").text
    assert "<h4>Helm release</h4>" in detail and "Destination namespace" not in detail
    assert '<th scope="row">Repository</th><td>unknown' in detail
    detail = client.get("/charts/detail?cluster=c1&namespace=apps&app=podinfo&chart=podinfo").text
    assert "<h4>Flux HelmRelease</h4>" in detail and "Target namespace" in detail
