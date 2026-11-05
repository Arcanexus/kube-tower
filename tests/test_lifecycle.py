from datetime import date

import httpx
import respx

from kube_tower.clusterview import cluster_view
from kube_tower.config import KubernetesVersionsSettings
from kube_tower.lifecycle import days_left, end_of_life, lookup, osv_vulnerabilities, plain_version, platform_versions
from kube_tower.models import ClusterStatus, NodeInfo, PlatformVersion, Severity, Vulnerability

CYCLES = [
    {"cycle": "1.31", "eol": "2025-10-28", "latest": "1.31.4"},
    {"cycle": "1.30", "eol": "2025-06-28", "latest": "1.30.8"},
    {"cycle": "1.29", "eol": "2025-02-28", "latest": "1.29.12"},
    {"cycle": "next", "eol": False},
]
GO_ENTRY = {
    "id": "GO-2024-3001",
    "aliases": ["CVE-2024-9042", "GHSA-vv39-3w5q-974q"],
    "summary": "Command injection on Windows nodes",
    "affected": [
        {
            "package": {"name": "k8s.io/kubernetes", "ecosystem": "Go"},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "1.29.13"}, {"introduced": "1.30.0"}, {"fixed": "1.30.9"}],
                }
            ],
        }
    ],
}
GHSA_ENTRY = {
    "id": "GHSA-vv39-3w5q-974q",
    "aliases": ["CVE-2024-9042"],
    "summary": "",
    "database_specific": {"severity": "MODERATE"},
    "affected": [
        {"package": {"name": "k8s.io/kubernetes"}, "ranges": [{"events": [{"introduced": "1.31.0"}, {"fixed": "1.31.5"}]}]}
    ],
}
HIGH = {"id": "GHSA-xxxx", "summary": "A high one", "database_specific": {"severity": "HIGH"}, "affected": []}


def test_versions():
    assert plain_version("v1.30.4-eks-a737599") == "1.30.4" and plain_version("v1.31.2+k3s1") == "1.31.2"
    assert plain_version("1.7.13-1") == "1.7.13" and plain_version("1.30") == "" and plain_version(None) == ""
    clusters = [ClusterStatus("a", "", "secret", True, "v1.30.4"), ClusterStatus("b", "", "secret", False, "v1.20.0")]
    nodes = [
        NodeInfo("a", "n1", kubelet_version="v1.29.8", container_runtime="containerd://1.7.13"),
        NodeInfo("a", "n2", kubelet_version="v1.30.4", container_runtime="cri-o://1.30.0"),
        NodeInfo("a", "n3"),
    ]
    assert platform_versions(clusters, nodes) == {("kubernetes", "1.30.4"), ("kubernetes", "1.29.8"), ("containerd", "1.7.13")}
    assert end_of_life(CYCLES, "1.30.4") == ("1.30", "2025-06-28", "1.30.8", "1.31")
    assert end_of_life(CYCLES, "1.32.0") == ("1.32", "", "", "1.31")
    assert end_of_life([{"cycle": "1.28", "eol": True}], "1.28.1") == ("1.28", "", "", "1.28")
    assert days_left("2025-06-28", date(2025, 6, 18)) == 10 and days_left("", date(2025, 1, 1)) is None


def test_osv_vulnerabilities():
    found = osv_vulnerabilities([GO_ENTRY, GHSA_ENTRY, HIGH], "k8s.io/kubernetes", "1.30.4")
    assert [(v.id, v.severity, v.fixed_version) for v in found] == [
        ("GHSA-xxxx", Severity.HIGH, ""),
        ("CVE-2024-9042", Severity.MEDIUM, "1.30.9"),  # GO and GHSA entries merged, fix of its own cycle
    ]
    assert found[1].title == "Command injection on Windows nodes" and found[1].url == "https://osv.dev/vulnerability/GO-2024-3001"
    assert osv_vulnerabilities([GO_ENTRY], "k8s.io/kubernetes", "1.31.0")[0].severity == Severity.UNKNOWN


@respx.mock
async def test_lookup():
    settings = KubernetesVersionsSettings()
    respx.get(settings.end_of_life_url).respond(200, json=CYCLES)
    osv = respx.post(settings.osv_url)
    osv.side_effect = lambda request: httpx.Response(
        200, json={"vulns": [GO_ENTRY]} if b"k8s.io/kubernetes" in request.content else {}
    )
    found = await lookup(settings, {("kubernetes", "1.30.4"), ("containerd", "1.7.13")})
    by = {p.component: p for p in found}
    assert by["kubernetes"].cycle == "1.30" and by["kubernetes"].end_of_life == "2025-06-28"
    assert [v.id for v in by["kubernetes"].vulnerabilities] == ["CVE-2024-9042"] and by["containerd"].vulnerabilities == []
    assert by["containerd"].cycle == "" and by["kubernetes"].message is None
    # sources out of reach: a message, no failure
    respx.get(settings.end_of_life_url).respond(503)
    osv.side_effect = httpx.ConnectError("refused")
    (found,) = await lookup(settings, {("kubernetes", "1.30.4")})
    assert "cannot read the vulnerabilities of kubernetes 1.30.4" in found.message and found.cycle == ""
    assert await lookup(KubernetesVersionsSettings(enabled=False), {("kubernetes", "1.30.4")}) == []
    assert await lookup(settings, set()) == []


@respx.mock
async def test_lookup_without_end_of_life():
    settings = KubernetesVersionsSettings()
    respx.get(settings.end_of_life_url).respond(200, text="not json")
    respx.post(settings.osv_url).respond(200, json={"vulns": []})
    (found,) = await lookup(settings, {("kubernetes", "1.30.4")})
    assert "cannot read the end of life of Kubernetes" in found.message and found.vulnerabilities == []


def test_end_of_life_in_the_clusters_page():
    cve = Vulnerability("CVE-1", Severity.HIGH, "k8s.io/kubernetes", "1.29.8", "1.29.9")
    platform = [
        PlatformVersion("kubernetes", "1.30.4", "1.30", "2025-06-28", "1.30.8", "1.31"),
        PlatformVersion("kubernetes", "1.28.2", "1.28", "2024-10-28", "1.28.15", "1.31", [cve]),
        PlatformVersion("containerd", "1.7.13", vulnerabilities=[cve, Vulnerability("CVE-2", Severity.CRITICAL, "c", "1")]),
    ]
    status = ClusterStatus("prod", "", "secret", True, "v1.30.4")
    nodes = [
        NodeInfo("prod", "a", kubelet_version="v1.30.4", container_runtime="containerd://1.7.13"),
        NodeInfo("prod", "b", kubelet_version="v1.28.2"),
    ]
    view = cluster_view(status, nodes, [], platform, warn_days=90, today=date(2025, 6, 1))
    texts = {(f.level, f.node, f.text) for f in view.findings}
    assert ("warning", "", "Kubernetes 1.30 reaches its end of life on 2025-06-28") in texts
    assert ("info", "", "Kubernetes 1.30.8 is the latest patch of 1.30") in texts
    assert ("error", "b", "kubelet 1.28 is end of life since 2024-10-28: no more security fixes") in texts
    assert ("error", "1 node with a kubelet at its end of life") in view.summary()
    assert [f.level for f in view.to_check] == sorted((f.level for f in view.to_check), key=["error", "warning"].index)
    assert view.api.cycle == "1.30" and view.eol_days(view.api) == 27 and view.eol_days(None) is None
    assert view.platform_cves.vulnerabilities[Severity.HIGH] == 1 and view.platform_cves.vulnerabilities[Severity.CRITICAL] == 1
    assert view.node_platform(nodes[0]).vulnerabilities[Severity.CRITICAL] == 1
    assert view.node_platform(nodes[1]).images == 1
    late = cluster_view(status, nodes, [], platform, today=date(2025, 7, 1))
    assert any(f.text == "Kubernetes 1.30 is end of life since 2025-06-28: no more security fixes" for f in late.findings)
    unknown = PlatformVersion("kubernetes", "1.30.4", message="offline")
    assert cluster_view(status, nodes[:1], [], [unknown]).platform_cves.unscanned == 1
