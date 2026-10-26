import dataclasses
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from kube_tower import __version__
from kube_tower.administration import Check, ConnectivityReport
from kube_tower.config import Settings, TrivySettings
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
    page = client.get("/images").text
    # nginx is used by pods; ghcr.io/org/app and redis are only cached on nodes
    assert page.count('aria-label="Running"') == 1 and page.count('aria-label="Not running"') == 2
    assert re.search(r'aria-label="Running".*?</span><code class="image-name" title="docker.io/library/nginx">', page)
    assert "#i-running" in page and "#i-not-running" in page


def test_images_running_only_switch():
    client, _ = _client()
    page = client.get("/images").text
    assert 'role="switch" name="running"' in page and "checked" not in page
    page = client.get("/images?running=1").text
    assert 'name="running" value="1" checked' in page
    assert "library/nginx" in page and "org/app" not in page and "library/redis" not in page
    assert "<p><small>1 image</small></p>" in page  # counters and count follow the switch
    assert "library/nginx" not in client.get("/images?running=1&cluster=c2").text
    assert 'name="running"' not in client.get("/charts").text


def test_images_registry_and_update_filters():
    """Set by the links of the Synthesis, shown as removable chips that the filter form keeps."""
    client, _ = _client()
    page = client.get("/images?registry=docker.io").text
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
    scanner = FakeScanner()
    page = TestClient(create_app(settings, scanner, background=False)).get("/settings").text
    assert "docker.io" in page and "alex" in page and "loaded" in page and "invalid" in page
    assert page.count("not tried yet") == 2
    scanner.registry_auth.record("docker.io", True)
    scanner.registry_auth.record("ghcr.io", False, "ghcr.io refused the credentials: HTTP 403 Forbidden")
    page = TestClient(create_app(settings, scanner, background=False)).get("/settings").text
    assert "not tried yet" not in page and "accepted" in page and "refused" in page and "HTTP 403 Forbidden" in page
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
    scanner.running = scanner.checking_versions = True
    resp = client.get("/status?polling=1")
    assert "Scan in progress" in resp.text and "HX-Refresh" not in resp.headers
    scanner.running = scanner.checking_versions = False
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
    assert 'class="drawer-resize" role="separator"' in detail and 'onclick="ktToggleFull()"' in detail
    sprite = (Path(__file__).parents[1] / "src/kube_tower/web/static/icons.svg").read_text()
    assert all(f'id="i-{name}"' in sprite for name in re.findall(r"icons\.svg#i-([\w-]+)", detail))
    # a click on the backdrop (on another row) is passed on, so one click opens that row
    assert 'class="drawer-backdrop" onclick="ktCloseDetail()"' in detail
    assert 'contains("drawer-backdrop")' in client.get("/static/kube-tower.js").text
    assert "https://hub.docker.com/_/redis/tags" in detail
    assert "sha256:new" in detail and "Pin a version" in detail and "Versioning" not in detail
    detail = client.get("/images/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
    assert "docker.io/library/nginx:1.27" in detail and "web-7d9f-abcde" in detail
    assert re.search(r"Versioning</th><td>semver ", detail)
    assert 'class="tree-list"' in detail and "<strong>c1</strong>" in detail and "<code>tools</code>" in detail
    detail = client.get("/images/detail", params={"ref": "ghcr.io/org/app:2.0"}).text
    assert "cached on 2 nodes" in detail and '<code class="usage-node">n2</code>' in detail
    assert client.get("/images/detail", params={"ref": "nope"}).status_code == 404


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
    positions = [detail.index(f"<strong>{name}</strong>") for name in ("redis", "metrics", "helpers")]
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


def test_synthesis_is_the_home_page():
    client, _ = _client()
    page = client.get("/").text
    assert 'href="synthesis" aria-current="page"' in page
    assert page == client.get("/synthesis").text
    # 3 images: 2 outdated (nginx minor, redis digest), 1 up to date; 1 chart outdated through its subchart
    assert re.search(r"Images</span><strong>3</strong>\s*<small>33% up to date · 2 outdated", page)
    assert 'href="images?status=outdated"' in page and 'href="charts?status=outdated"' in page
    assert re.search(
        r"<th scope=\"row\"><a href=\"images\?update=minor\"[^>]*>minor</a></th>.*?<td class=\"bar-value\">1</td>", page, re.S
    )
    assert re.search(
        r"<th scope=\"row\"><a href=\"images\?registry=docker.io\"[^>]*>docker.io</a></th>.*?<td class=\"bar-value\">2</td>",
        page,
        re.S,
    )
    assert "Subcharts: 1 outdated out of 3." in page
    assert "1 unreachable" in page


def test_synthesis_shows_vulnerabilities():
    client, _ = _client()
    page = client.get("/").text
    # nginx: 1 critical with a fix (end of life OS); app: scan failed; redis: not scanned
    assert re.search(
        r"Images with critical CVEs</span><strong class=\"danger\">1</strong>\s*<small>1 critical or high CVE with a fix", page
    )
    assert "(1 of 3 scanned)" in page
    assert 'class="segment segment-sev-critical" style="flex-grow: 1"' in page
    assert 'class="segment segment-sev-failed"' in page and 'class="segment segment-sev-not-scanned"' in page
    assert "1 image on an end of life OS release" in page
    # Most vulnerable images open the vulnerability details
    assert 'hx-get="vulnerabilities/detail?ref=docker.io/library/nginx%3A1.25"' in page
    assert 'href="vulnerabilities?status=critical&amp;cluster=c1">1 image</a>' in page


def test_synthesis_without_vulnerabilities():
    from kube_tower.web.summary import summarize

    s = summarize(Snapshot(images=[ImageReport(ImageRef("docker.io", "library/redis", "7"))])).vulnerabilities
    assert s.worst == {"not scanned": 1} and s.scanned == 0 and s.top == [] and not s.images_with["critical"]


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
    assert re.search(r'sev-critical">critical</span><span class="counter-value"><strong>1</strong><small>image</small>', page)
    assert re.search(r'sev-high">high</span><span class="counter-value"><strong>0</strong><small>images</small>', page)
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
    assert "Scan now" not in client.get("/vulnerabilities/detail", params={"ref": "docker.io/library/redis:latest"}).text
    assert "Scan again" in client.get("/vulnerabilities/detail", params=ref).text
    chart = client.get("/charts/detail?cluster=c1&namespace=argocd&app=redis&chart=redis").text
    assert 'hx-post="api/rescan/chart?cluster=c1&amp;namespace=argocd&amp;app=redis&amp;chart=redis"' in chart
    # buttons are disabled while a full scan checks versions, not during its Trivy phase
    scanner.running = scanner.checking_versions = True
    assert "disabled" in client.get("/charts/detail?cluster=c1&namespace=argocd&app=redis&chart=redis").text
    scanner.checking_versions = False
    assert "disabled" not in client.get("/charts/detail?cluster=c1&namespace=argocd&app=redis&chart=redis").text
    scanner.running = False
    # while rescanned, the panel polls itself; the poll that sees the end reloads the results
    scanner.rescanning = {("image", "docker.io/library/nginx:1.25")}
    resp = client.get("/images/detail", params={**ref, "polling": "1"})
    assert "Rescanning" in resp.text and 'hx-trigger="every 3s"' in resp.text and "Check version" not in resp.text
    assert "HX-Trigger" not in resp.headers
    assert "Rescanning" in client.get("/vulnerabilities/detail", params=ref).text
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
    # unused node images: ghcr.io/org/app in c2, redis in c1
    assert "c1: 1 unused image" in page and "crictl rmi docker.io/library/redis:latest" in page
    assert "c2: 1 unused image" in page
    assert 'hx-get="administration?polling=1"' not in page  # nothing running
    # What runs is listed first, the scan status links to it
    assert page.index('id="scans"') < page.index("<strong>Full scan</strong>")
    assert "Nothing is running. Last scan finished" in page
    assert 'href="administration#scans"' in page
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


def test_vulnerabilities_cve_filter():
    client, _ = _client()
    rows = lambda page: page.split("<tbody>")[1]  # noqa: E731
    page = client.get("/vulnerabilities?cve=CVE-2024-1").text
    assert "library/nginx" in rows(page) and "org/app" not in rows(page) and "library/redis" not in rows(page)
    assert 'value="CVE-2024-1"' in page and 'sev-critical" title="zlib overflow">CVE-2024-1</span>' in page
    # all or part of the ID, case insensitive, several IDs separated by spaces or commas
    assert "library/nginx" in rows(client.get("/vulnerabilities?cve=2024-2").text)
    assert "library/nginx" in rows(client.get("/vulnerabilities?cve=nope,cve-2024-2").text)
    assert "library/nginx" not in rows(client.get("/vulnerabilities?cve=CVE-2023").text)
    assert re.search(
        r'sev-critical">critical</span><span class="counter-value"><strong>0</strong>',
        client.get("/vulnerabilities?cve=CVE-2023").text,
    )
    # the detail panel lists the matching vulnerabilities first
    detail = client.get("/vulnerabilities/detail", params={"ref": "docker.io/library/nginx:1.25", "cve": "2024-2"}).text
    assert 'class="cve-match"' in detail and detail.index("CVE-2024-2") < detail.index("CVE-2024-1")
    assert "1 matching <code>2024-2</code> (CVE-2024-2)" in detail


def test_list_pages_layout_and_sortable_columns():
    client, _ = _client()
    for path in ("/images", "/charts", "/vulnerabilities", "/clusters"):
        page = client.get(path).text
        assert 'class="content list-page"' in page and 'class="overflow-auto table-wrap"' in page, path
        assert "<th data-sort" in page, path
    images = client.get("/images").text
    assert re.search(r'<td data-sort="0">\s*<span class="badge badge-outdated">', images)  # outdated sorts first
    assert '<th data-sort="desc" data-server-sort="4" class="hide-sm">Used by</th>' in images
    assert 'class="content "' in client.get("/settings").text  # documents scroll as a whole


def test_lists_load_by_pages_and_sort_on_the_server():
    """Infinite scroll: 30 items per page, the last row loads the next page; headers sort on the server."""
    from kube_tower.web import ui

    client, scanner = _client()
    base = scanner.snapshot.images[0]
    scanner.snapshot.images = [
        dataclasses.replace(base, image=ImageRef("docker.io", f"org/app{i}", f"1.{i}"), usages=[]) for i in range(65)
    ]
    page = client.get("/images").text
    assert page.count('hx-get="images/detail') == ui.PAGE_SIZE and "65 images" in page
    assert 'hx-get="images?offset=30" hx-trigger="intersect once" hx-swap="outerHTML"' in page
    assert '<span aria-busy="true">Loading…</span>' in page
    # The next page: only its rows (and the row loading the one after)
    more = client.get("/images?offset=30").text
    assert "<html" not in more and "<thead" not in more and more.count('hx-get="images/detail') == 30
    assert "offset=60" in more
    last = client.get("/images?offset=60").text
    assert last.count('hx-get="images/detail') == 5 and "load-more" not in last
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
    # charts and vulnerabilities pages accept a sort too (vulnerabilities: most vulnerable first)
    assert 'aria-sort="ascending"' in client.get("/charts?sort=0").text
    assert 'aria-sort="descending"' in client.get("/vulnerabilities?sort=2").text
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
    page = client.get("/settings").text
    footer = page[page.index('class="version"') :]
    assert footer.index("<small>") < footer.index('href="https://github.com/Arcanexus/kube-tower"')
    assert 'href="static/icons.svg#i-github"' in footer


def test_check_version_button_counts_the_tags():
    client, scanner = _client()
    scanner.snapshot.images.append(ImageReport(ImageRef("docker.io", "library/nginx", "1.27"), [Usage("c1", "Node", None, "n1")]))
    detail = client.get("/images/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
    assert "Check versions (2 tags)" in detail and "Scan vulnerabilities (2 tags)" in detail
    assert "and the new ones found on the clusters" in detail
    assert "Scan again (2 tags)" in client.get("/vulnerabilities/detail", params={"ref": "docker.io/library/nginx:1.25"}).text
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
    # redis is up to date, its subchart common is outdated: the row says outdated, like the counters
    page = _client()[0].get("/charts").text
    row = page.split('id="results"')[1]
    assert 'class="counter counter-outdated" aria-pressed="false"' in page
    assert re.search(
        r'<span class="badge badge-outdated">.*?outdated</span><br><small>chart up-to-date, subchart outdated</small>', row
    )


def test_trivy_problem_shown_everywhere():
    client, scanner = _client()
    page = client.get("/").text
    assert (
        'class="dot dot-warn"' in page
        and "1 problem of kube-tower" in page
        and "binary &#39;/nonexistent/trivy&#39; not found" in page
    )
    vulns = client.get("/vulnerabilities").text
    assert 'class="notice notice-warn"' in vulns and 'href="administration#trivy"' in vulns
    scanner.trivy.settings.binary = sys.executable
    assert "problem of kube-tower" not in client.get("/").text
    assert "notice-warn" not in client.get("/vulnerabilities").text


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
    page = client.get("/images").text
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
    assert 'class="drawer-summary"' in detail and detail.index("drawer-summary") < detail.index("<h4>Versions</h4>")
    assert detail.index("<h4>Digests</h4>") < detail.index("<h4>Check again</h4>") < detail.index("<h4>Used by")


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
    page = TestClient(create_app(settings, FakeScanner(), background=False)).get("/settings").text
    assert (
        '<tr class="changed"><th scope="row"><code>refreshInterval</code></th><td>1 h (3600 s) <span class="badge badge-changed">'
        in page
    )
    assert "<code>trivy.rescanInterval</code></th><td>1 day" not in page and "24 h (86400 s)" in page
    assert "(1 value changed from the default)" in page and "(0 values changed from the default)" in page
    assert "<summary>Configuration as YAML</summary>" in page and "refreshInterval: 3600" in page


def test_clusters_page_has_the_figures_of_the_synthesis():
    page = _client()[0].get("/clusters").text
    assert 'href="images?cluster=c1">2</a>' in page and 'href="images?cluster=c1&amp;status=outdated">2 outdated</a>' in page
    assert 'href="charts?cluster=c1&amp;status=outdated">1 outdated</a>' in page
    assert 'href="vulnerabilities?status=critical&amp;cluster=c1">1 image</a>' in page


def test_accessibility_helpers():
    page = _client()[0].get("/images").text
    assert '<a class="skip-link" href="#main">' in page and '<main id="main" tabindex="-1">' in page
    assert 'class="help" tabindex="0"' in page and 'class="help-text" role="tooltip"' in page
    vulns = _client()[0].get("/vulnerabilities").text
    assert 'aria-label="Running"' in vulns  # same icon as the Images page


def test_administration_api_links():
    page = _client()[0].get("/administration").text
    assert 'href="api/docs"' in page and 'href="api/snapshot"' in page and 'href="metrics"' in page
    assert ">Scan now</button>" in page and 'id="trivy"' in page


async def test_watch_event_loop_warns_when_blocked(monkeypatch, caplog):
    import asyncio
    import time

    from kube_tower import main

    monkeypatch.setattr(main, "LAG_CHECK", 0.01)
    monkeypatch.setattr(main, "LAG_WARNING", 0.05)
    task = asyncio.create_task(main.watch_event_loop())
    await asyncio.sleep(0)  # the watch starts its first check
    time.sleep(0.1)  # blocks the event loop, as a scan holding the GIL would
    await asyncio.sleep(0.05)
    task.cancel()
    assert "the web server was blocked for 0.1s" in caplog.text
