from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from kubernetes import client

from kube_tower.collectors import security
from kube_tower.config import Settings, load_settings
from kube_tower.main import create_app
from kube_tower.models import (
    ComplianceControl,
    ComplianceReport,
    SecurityCheck,
    SecurityKind,
    SecurityReport,
    Severity,
    Snapshot,
)
from kube_tower.web.ui import SecurityBreakdown, security_summary
from test_web import FakeScanner

NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)

CONFIG_AUDIT = {
    "metadata": {
        "name": "replicaset-web-7d9f",
        "namespace": "shop",
        "labels": {
            "trivy-operator.resource.kind": "ReplicaSet",
            "trivy-operator.resource.name": "web-7d9f",
            "trivy-operator.resource.namespace": "shop",
        },
    },
    "report": {
        "updateTimestamp": "2026-10-29T10:00:00Z",
        "checks": [
            {
                "checkID": "KSV014",
                "title": "Root file system is not read-only",
                "severity": "LOW",
                "success": False,
                "description": "An immutable root file system...",
                "messages": ["Container 'web' should set readOnlyRootFilesystem"],
                "remediation": "Set readOnlyRootFilesystem to true",
                "category": "Kubernetes Security Check",
            },
            {"checkID": "KSV017", "title": "Privileged container", "severity": "HIGH", "success": False, "messages": [""]},
            {"checkID": "KSV001", "title": "Can elevate its own privileges", "severity": "MEDIUM", "success": True},
        ],
    },
}
SECRETS = {
    "metadata": {
        "name": "replicaset-web-7d9f-web",
        "namespace": "shop",
        "labels": {
            "trivy-operator.resource.kind": "ReplicaSet",
            "trivy-operator.resource.name": "web-7d9f",
            "trivy-operator.resource.namespace": "shop",
            "trivy-operator.container.name": "web",
        },
    },
    "report": {
        "registry": {"server": "ghcr.io"},
        "artifact": {"repository": "acme/web", "tag": "1.2"},
        "secrets": [
            {
                "ruleID": "aws-access-key-id",
                "title": "AWS Access Key ID",
                "category": "AWS",
                "severity": "CRITICAL",
                "target": "/app/.env",
                "match": "AWS_ACCESS_KEY_ID=********************",
            },
        ],
    },
}
CLUSTER_RBAC = {
    "metadata": {"name": "clusterrole-admin", "ownerReferences": [{"kind": "ClusterRole", "name": "admin"}]},
    "report": {"checks": [{"checkID": "KSV046", "title": "Manage all resources", "severity": "CRITICAL", "success": False}]},
}
COMPLIANCE = {
    "metadata": {"name": "k8s-cis-1.23"},
    "spec": {"compliance": {"id": "k8s-cis-1.23", "title": "CIS Kubernetes Benchmarks v1.23", "description": "CIS"}},
    "status": {
        "updateTimestamp": "2026-10-29T06:00:00Z",
        "summary": {"passCount": 90, "failCount": 10},
        "summaryReport": {
            "controlCheck": [
                {"id": "5.1.3", "name": "Minimize wildcard use in Roles", "severity": "HIGH", "totalFail": 3},
                {"id": "1.1.1", "name": "API server pod spec permissions", "severity": "CRITICAL", "totalFail": 1},
                {"id": "1.1.2", "name": "Passing", "severity": "LOW", "totalFail": 0},
            ]
        },
    },
}


def test_parse_config_audit_report():
    r = security.parse_security_report("prod", SecurityKind.CONFIG_AUDIT, CONFIG_AUDIT)
    assert (r.resource_kind, r.resource_name, r.namespace) == ("ReplicaSet", "web-7d9f", "shop")
    assert [c.id for c in r.checks] == ["KSV017", "KSV014"]  # failed only, most severe first
    assert r.passed == 1 and r.worst == Severity.HIGH
    assert r.checks[0].messages == [] and r.checks[1].remediation.startswith("Set readOnly")
    assert r.checks[1].url == "https://avd.aquasec.com/misconfig/ksv014"
    assert r.scanned_at == datetime(2026, 10, 29, 10, 0, tzinfo=UTC)
    assert r.key == ("prod", "config-audit", "shop", "ReplicaSet", "web-7d9f", "")


def test_parse_exposed_secret_and_cluster_reports():
    s = security.parse_security_report("prod", SecurityKind.EXPOSED_SECRET, SECRETS)
    assert (s.container, s.image) == ("web", "ghcr.io/acme/web:1.2")
    (secret,) = s.checks
    assert (secret.id, secret.target, secret.severity) == ("aws-access-key-id", "/app/.env", Severity.CRITICAL)
    assert secret.url == ""  # secret rules have no page
    rbac = security.parse_security_report("prod", SecurityKind.RBAC, CLUSTER_RBAC)
    assert (rbac.resource_kind, rbac.resource_name, rbac.namespace) == ("ClusterRole", "admin", None)


def test_parse_compliance_report():
    c = security.parse_compliance_report("prod", COMPLIANCE)
    assert (c.id, c.title, c.passed, c.failed, c.score) == ("k8s-cis-1.23", "CIS Kubernetes Benchmarks v1.23", 90, 10, 90)
    assert [x.id for x in c.controls] == ["1.1.1", "5.1.3"]
    # Older operators: the fields in spec; `all` report type: the detail of each control
    old = security.parse_compliance_report(
        "prod",
        {
            "metadata": {"name": "nsa"},
            "spec": {"id": "nsa", "title": "NSA"},
            "status": {
                "detailReport": {
                    "results": [
                        {
                            "id": "1.0",
                            "name": "Non-root",
                            "severity": "MEDIUM",
                            "checks": [{"success": False}, {"success": True}, {}],
                        }
                    ]
                }
            },
        },
    )
    assert (old.id, old.title, old.score) == ("nsa", "NSA", None)
    assert [(x.id, x.failed) for x in old.controls] == [("1.0", 2)]


class FakeCluster:
    name = "prod"
    api_client = None


class FakeCustomObjects:
    items: dict = {}
    errors: dict = {}

    def __init__(self, api_client):
        pass

    def list_cluster_custom_object(self, group, version, plural, **kwargs):
        assert (group, version) == ("aquasecurity.github.io", "v1alpha1")
        if plural in self.errors:
            raise client.ApiException(status=self.errors[plural], reason="Nope")
        if plural not in self.items:
            raise client.ApiException(status=404, reason="Not Found")
        pages = self.items[plural]
        page = int(kwargs.get("_continue") or 0)
        more = {"continue": str(page + 1)} if page + 1 < len(pages) else {}
        return {"items": pages[page], "metadata": more}


@pytest.fixture
def custom_objects(monkeypatch):
    monkeypatch.setattr(security.client, "CustomObjectsApi", FakeCustomObjects)
    FakeCustomObjects.items, FakeCustomObjects.errors = {}, {}
    return FakeCustomObjects


def test_collect_without_trivy_operator(custom_objects):
    found = security.collect_security_reports(FakeCluster())
    assert not found.installed and not found.reports and not found.errors


def test_collect_reads_every_kind_page_by_page(custom_objects):
    custom_objects.items = {
        "configauditreports": [[CONFIG_AUDIT], [CONFIG_AUDIT]],
        "exposedsecretreports": [[SECRETS]],
        "clusterrbacassessmentreports": [[CLUSTER_RBAC]],
        "clustercompliancereports": [[COMPLIANCE]],
    }
    custom_objects.errors = {"infraassessmentreports": 403}
    found = security.collect_security_reports(FakeCluster())
    assert found.installed
    assert [r.kind for r in found.reports] == [SecurityKind.CONFIG_AUDIT] * 2 + [SecurityKind.EXPOSED_SECRET, SecurityKind.RBAC]
    assert [c.id for c in found.compliance] == ["k8s-cis-1.23"]
    (error,) = found.errors
    assert "infraassessmentreports: 403" in error and "RBAC" in error


def test_settings(tmp_path):
    assert Settings().security.enabled and Settings().security.exposed_secrets
    path = tmp_path / "config.yaml"
    path.write_text("security:\n  enabled: false\n  exposedSecrets: false\n")
    settings = load_settings(str(path))
    assert not settings.security.enabled and not settings.security.exposed_secrets


async def test_worker_collects_security_reports(monkeypatch, custom_objects):
    from kube_tower import worker as worker_module
    from kube_tower.tasks import CollectTask

    custom_objects.items = {"configauditreports": [[CONFIG_AUDIT]], "exposedsecretreports": [[SECRETS]]}
    monkeypatch.setattr(worker_module.ImageInventory, "collect", lambda self, cluster: [])
    monkeypatch.setattr(worker_module, "collect_operator_reports", lambda cluster: ([], []))
    monkeypatch.setattr(worker_module, "collect_security_reports", security.collect_security_reports)
    settings = Settings()
    settings.helm.enabled = False
    w = worker_module.Worker(settings)
    w.clusters = {"prod": FakeCluster()}
    result = await w.execute(CollectTask("prod"))
    assert result.trivy_operator and len(result.security) == 2
    settings.security.exposed_secrets = False
    result = await w.execute(CollectTask("prod"))
    assert [r.kind for r in result.security] == [SecurityKind.CONFIG_AUDIT]
    result = await w.execute(CollectTask("prod", security=False))  # rescans
    assert not result.trivy_operator and not result.security


def _reports() -> tuple[list[SecurityReport], list[ComplianceReport]]:
    reports = [
        security.parse_security_report("c1", SecurityKind.CONFIG_AUDIT, CONFIG_AUDIT),
        security.parse_security_report("c1", SecurityKind.EXPOSED_SECRET, SECRETS),
        security.parse_security_report("c1", SecurityKind.RBAC, CLUSTER_RBAC),
        SecurityReport("c2", SecurityKind.INFRA, "Node", "n1", passed=12),
        SecurityReport(
            "c2",
            SecurityKind.CONFIG_AUDIT,
            "Deployment",
            "api",
            "billing",
            checks=[SecurityCheck("KSV020", "Runs with a low user ID", Severity.MEDIUM)],
        ),
    ]
    return reports, [security.parse_compliance_report("c1", COMPLIANCE)]


def _client(with_operator=True):
    scanner = FakeScanner()
    if with_operator:
        scanner.snapshot.security, scanner.snapshot.compliance = _reports()
        scanner.snapshot.trivy_operator = ["c1", "c2"]
    return TestClient(create_app(Settings(), scanner, background=False)), scanner


def test_security_tab_only_with_trivy_operator():
    client, _ = _client(with_operator=False)
    assert 'href="security"' not in client.get("/").text
    page = client.get("/security").text  # still reachable: says why it is empty
    assert "Trivy Operator was not found" in page
    client, _ = _client()
    home = client.get("/").text
    assert 'href="security"' in home
    assert "Security" in home and "shop" in home  # Overview card: most exposed namespaces


def test_security_page_lists_resources_with_findings():
    client, _ = _client()
    page = client.get("/security").text
    assert "4 resources with findings" in page and "1 resource passing every check" in page
    # Most severe first: the exposed secret and the ClusterRole (critical), the ReplicaSet (high), the Deployment
    rows = page.split("<tbody>")[1]
    assert rows.index("kind=exposed-secret") < rows.index("kind=config-audit&namespace=shop") < rows.index("billing")
    assert rows.index("kind=rbac") < rows.index("kind=config-audit&namespace=shop")
    assert "CIS Kubernetes Benchmarks v1.23" in page and "90%" in page  # compliance tile
    # Tiles: config audit 0 of 2 resources passing, infrastructure 1 of 1
    assert "0%<small> passing" in page and "100%<small> passing" in page and "2 of 2 resources with findings" in page
    # Filters: kind, severity, clean resources, search, cluster
    page = client.get("/security?kind=config-audit", headers={"HX-Request": "true", "HX-Target": "results"}).text
    assert "<html" not in page and "web-7d9f" in page and "admin" not in page.split("<tbody>")[1]
    page = client.get("/security?severity=medium").text
    assert "billing" in page and "ClusterRole" not in page.split("<tbody>")[1]
    page = client.get("/security?all=1&kind=infra").text
    assert "n1" in page.split("<tbody>")[1] and "none" in page
    page = client.get("/security?q=KSV046").text
    assert "1 resource with findings" in page
    page = client.get("/security?cluster=c2").text
    assert "billing" in page and "web-7d9f" not in page.split("<tbody>")[1]
    page = client.get("/security?sort=3").text
    assert 'aria-sort="descending"' in page


def test_security_and_compliance_details():
    client, _ = _client()
    page = client.get(
        "/security/detail?cluster=c1&kind=config-audit&namespace=shop&rkind=ReplicaSet&name=web-7d9f&container="
    ).text
    assert "Privileged container" in page and "Set readOnlyRootFilesystem" in page and "2 failed, 1 passed" in page
    assert "https://avd.aquasec.com/misconfig/ksv014" in page
    page = client.get(
        "/security/detail?cluster=c1&kind=exposed-secret&namespace=shop&rkind=ReplicaSet&name=web-7d9f&container=web"
    ).text
    assert "/app/.env" in page and "AWS_ACCESS_KEY_ID=****" in page and "ghcr.io/acme/web:1.2" in page
    assert client.get("/security/detail?cluster=c1&kind=rbac&rkind=ClusterRole&name=admin").status_code == 200
    assert client.get("/security/detail?cluster=c9&kind=rbac").status_code == 404
    page = client.get("/security/compliance?cluster=c1&id=k8s-cis-1.23").text
    assert "Minimize wildcard use in Roles" in page and "90%" in page
    assert client.get("/security/compliance?cluster=c1&id=nope").status_code == 404


def test_security_links_are_relative():
    import re

    client, _ = _client()
    for path in (
        "/security",
        "/security/compliance?cluster=c1&id=k8s-cis-1.23",
        "/security/detail?cluster=c1&kind=rbac&rkind=ClusterRole&name=admin",
    ):
        page = client.get(path).text
        assert not re.search(r'(href|src|hx-get|hx-post)="/', page), path


def test_security_metrics():
    client, _ = _client()
    lines = set(client.get("/metrics").text.splitlines())
    for line in (
        'kube_tower_security_findings{cluster="c1",namespace="shop",severity="critical",type="exposed-secret"} 1.0',
        'kube_tower_security_findings{cluster="c1",namespace="",severity="critical",type="rbac"} 1.0',
        'kube_tower_security_resources{cluster="c2",result="pass",type="infra"} 1.0',
        'kube_tower_compliance_controls{cluster="c1",compliance="k8s-cis-1.23",result="fail",'
        'title="CIS Kubernetes Benchmarks v1.23"} 10.0',
    ):
        assert line in lines, line


def test_snapshot_round_trip_keeps_security_reports():
    reports, compliance = _reports()
    snap = Snapshot(security=reports, compliance=compliance, trivy_operator=["c1"])
    again = Snapshot.from_dict(snap.to_dict())
    assert again.security == reports and again.compliance == compliance and again.trivy_operator == ["c1"]
    assert again.security_report(reports[0].key) is again.security[0]
    assert Snapshot.from_dict({}).security == []  # snapshots of older versions


def test_ui_helpers():
    reports, _ = _reports()
    summary = security_summary(reports)
    assert summary["findings"][Severity.CRITICAL] == 2
    # shop: 1 critical + 1 high + 1 low; cluster-scoped: 1 critical
    assert [k for k, _ in summary["namespaces"]] == [("c1", "shop"), ("c1", ""), ("c2", "billing")]
    assert security_summary(reports, "c2")["namespaces"] == [
        (("c2", "billing"), {**dict.fromkeys(Severity, 0), Severity.MEDIUM: 1})
    ]
    assert SecurityBreakdown(SecurityKind.RBAC, 0, 0).pass_rate is None
    assert SecurityBreakdown(SecurityKind.RBAC, 4, 1).pass_rate == 75
    assert [k.icon for k in SecurityKind] == ["clipboard-check", "key", "users", "cpu"]
    assert ComplianceControl("1", "x", Severity.LOW).failed == 0
