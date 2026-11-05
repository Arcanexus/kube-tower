"""What the Clusters page shows of each cluster: its nodes by group, and what differs or is wrong
(version skew between the kubelets and the API server, versions mixed across the nodes, nodes not ready).

Kubernetes supports kubelets up to 3 minor versions older than the API server, never newer
(https://kubernetes.io/releases/version-skew-policy/).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date

from kube_tower.lifecycle import days_left, plain_version
from kube_tower.models import ClusterStatus, ImageReport, NodeInfo, PlatformVersion, Severity, Status

MAX_KUBELET_SKEW = 3  # minor versions a kubelet may be behind the API server
LEVELS = ("ok", "info", "warning", "error")
_VERSION = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?")


def k8s_version(version: str | None) -> tuple[int, int, int] | None:
    """(major, minor, patch) of a Kubernetes version, distribution suffixes ignored: v1.30.4-eks-a737599,
    v1.31.2+k3s1, v1.29.8-gke.1211000."""
    match = _VERSION.match((version or "").strip())
    return (int(match[1]), int(match[2]), int(match[3] or 0)) if match else None


def minor(version: str | None) -> str:
    """1.30 for v1.30.4-eks-a737599, "" when unknown."""
    parsed = k8s_version(version)
    return f"{parsed[0]}.{parsed[1]}" if parsed else ""


@dataclass
class Finding:
    level: str  # info | warning | error
    text: str
    node: str = ""  # the node concerned, "" for the whole cluster
    kind: str = ""  # what it is about, to count the nodes in the summary of the cluster (SUMMARY)


def worst(levels) -> str:
    return max(levels, key=LEVELS.index, default="ok")


def skew_findings(component: str, version: str, api_version: str | None, node: str) -> list[Finding]:
    """The kubelet or kube-proxy of a node against the API server."""
    mine, api = k8s_version(version), k8s_version(api_version)
    if mine is None or api is None or mine[0] != api[0]:
        return []
    behind = api[1] - mine[1]
    if behind < 0:
        return [
            Finding("error", f"{component} {version} newer than the API server {api_version}: not supported", node, "unsupported")
        ]
    if behind > MAX_KUBELET_SKEW:
        return [
            Finding(
                "error",
                f"{component} {version} is {behind} minor versions behind the API server {api_version}: "
                f"outside the supported skew ({MAX_KUBELET_SKEW})",
                node,
                "unsupported",
            )
        ]
    if behind:
        return [
            Finding(
                "warning",
                f"{component} {version} is {behind} minor version{'s' * (behind > 1)} behind the API server {api_version}",
                node,
                "behind",
            )
        ]
    return []


def node_findings(n: NodeInfo, api_version: str | None) -> list[Finding]:
    found = []
    if not n.ready:
        found.append(Finding("error", "not ready", n.name, "not-ready"))
    if n.unschedulable:
        found.append(Finding("warning", "cordoned: no new pod is scheduled on it", n.name, "cordoned"))
    found += [Finding("warning", problem, n.name, "pressure") for problem in n.problems]
    found += skew_findings("kubelet", n.kubelet_version, api_version, n.name)
    if n.kube_proxy_version and n.kube_proxy_version != n.kubelet_version:
        found += skew_findings("kube-proxy", n.kube_proxy_version, api_version, n.name)
    return found


# The sentence of each kind of node finding in the summary of a cluster, by number of nodes.
SUMMARY = {
    "not-ready": ("error", "not ready"),
    "eol": ("error", "with a kubelet at its end of life"),
    "unsupported": ("error", "with an unsupported kubelet version"),
    "behind": ("warning", "behind the API server"),
    "cordoned": ("warning", "cordoned"),
    "pressure": ("warning", "under pressure (memory, disk or PIDs)"),
}


@dataclass
class VersionSegment:
    """A kubelet version of a cluster in its version bar: how many nodes run it and how it compares to the API server."""

    version: str
    nodes: int
    level: str
    percent: float


@dataclass
class ImagesOn:
    """The images that pods run on a node (or in a cluster): how many are outdated, and their vulnerabilities
    by severity, each CVE counted once even when several images have it."""

    images: int = 0
    outdated: int = 0
    unscanned: int = 0  # no vulnerability report (not scanned yet, or the scan failed)
    vulnerabilities: dict[Severity, int] = field(default_factory=lambda: dict.fromkeys(Severity, 0))

    @property
    def level(self) -> str:
        if self.vulnerabilities[Severity.CRITICAL]:
            return "error"
        return "warning" if self.vulnerabilities[Severity.HIGH] else "ok"


def images_on(reports: list[ImageReport]) -> ImagesOn:
    found = ImagesOn(images=len(reports), outdated=sum(1 for r in reports if r.status == Status.OUTDATED))
    ids: dict[Severity, set[str]] = {s: set() for s in Severity}
    for r in reports:
        if r.vulnerabilities is None or r.vulnerabilities.message:
            found.unscanned += 1
            continue
        for v in r.vulnerabilities.vulnerabilities:
            ids[v.severity].add(v.id)
    found.vulnerabilities = {s: len(ids[s]) for s in Severity}
    return found


def platform_cves(found: list[PlatformVersion]) -> ImagesOn:
    """The vulnerabilities of some Kubernetes and containerd versions, each CVE counted once."""
    ids: dict[Severity, set[str]] = {s: set() for s in Severity}
    for p in found:
        for v in p.vulnerabilities:
            ids[v.severity].add(v.id)
    return ImagesOn(
        images=len(found),
        unscanned=sum(1 for p in found if p.message and not p.vulnerabilities),
        vulnerabilities={s: len(ids[s]) for s in Severity},
    )


def eol_findings(p: PlatformVersion | None, what: str, node: str, warn_days: int, today: date | None) -> list[Finding]:
    """End of life of the release cycle of a version, and a newer patch of the cycle."""
    if p is None or not p.cycle:
        return []
    found = []
    left = days_left(p.end_of_life, today)
    if left is not None and left < 0:
        found.append(
            Finding("error", f"{what} {p.cycle} is end of life since {p.end_of_life}: no more security fixes", node, "eol")
        )
    elif left is not None and left <= warn_days:
        found.append(Finding("warning", f"{what} {p.cycle} reaches its end of life on {p.end_of_life}", node, "eol-soon"))
    return found


def running_images(images: list[ImageReport], cluster: str) -> dict[str, list[ImageReport]]:
    """The images that pods run on each node of a cluster."""
    by_node: dict[str, list[ImageReport]] = {}
    for r in images:
        for node in {u.node for u in r.usages if u.cluster == cluster and u.kind == "Pod" and u.node}:
            by_node.setdefault(node, []).append(r)
    return by_node


ROLE_LABELS = {"control-plane": "Control plane", "worker": "Workers"}


@dataclass
class NodeGroup:
    """Nodes of one role and node group, shown together."""

    role: str
    pool: str
    nodes: list[NodeInfo] = field(default_factory=list)

    @property
    def label(self) -> str:
        role = ROLE_LABELS.get(self.role, self.role)
        return f"{role} · {self.pool}" if self.pool else role

    def values(self, attribute: str) -> list[tuple[str, int]]:
        """The values of an attribute in the group, most common first: [("v1.30.4", 11), ("v1.29.8", 1)]."""
        return Counter(getattr(n, attribute) or "unknown" for n in self.nodes).most_common()


@dataclass
class ClusterView:
    status: ClusterStatus
    nodes: list[NodeInfo]
    groups: list[NodeGroup]
    findings: list[Finding]
    node_levels: dict[str, str]  # worst level of each node
    node_images: dict[str, ImagesOn] = field(default_factory=dict)  # images run on each node
    images: ImagesOn = field(default_factory=ImagesOn)  # images run in the cluster
    platform: dict[tuple[str, str], PlatformVersion] = field(default_factory=dict)  # (component, version)
    warn_days: int = 90
    today: date | None = None

    def platform_of(self, component: str, version: str | None) -> PlatformVersion | None:
        return self.platform.get((component, plain_version(version)))

    @property
    def api(self) -> PlatformVersion | None:
        """End of life and vulnerabilities of the version of the API server."""
        return self.platform_of("kubernetes", self.status.version)

    def eol_days(self, p: PlatformVersion | None) -> int | None:
        return days_left(p.end_of_life, self.today) if p else None

    def node_platform(self, n: NodeInfo) -> ImagesOn:
        """The vulnerabilities of the kubelet and containerd versions of a node."""
        found = [self.platform_of("kubernetes", n.kubelet_version)]
        if n.runtime_name == "containerd":
            found.append(self.platform_of("containerd", n.runtime_version))
        return platform_cves([p for p in found if p])

    @property
    def platform_cves(self) -> ImagesOn:
        """The vulnerabilities of the Kubernetes and containerd versions the cluster runs."""
        found = {("kubernetes", plain_version(self.status.version))}
        for n in self.nodes:
            found.add(("kubernetes", plain_version(n.kubelet_version)))
            if n.runtime_name == "containerd":
                found.add(("containerd", plain_version(n.runtime_version)))
        return platform_cves([self.platform[k] for k in sorted(found) if k in self.platform])

    @property
    def level(self) -> str:
        if not self.status.reachable:
            return "error"
        return worst(f.level for f in self.findings)

    def versions(self, attribute: str) -> list[tuple[str, int]]:
        return Counter(getattr(n, attribute) or "unknown" for n in self.nodes).most_common()

    def node_findings(self, name: str) -> list[Finding]:
        return [f for f in self.findings if f.node == name]

    @property
    def not_ready(self) -> int:
        return sum(1 for n in self.nodes if not n.ready)

    def summary(self) -> list[tuple[str, str]]:
        """(level, sentence) of what to look at, most severe first: [("warning", "1 node behind the API server")]."""
        lines = []
        for kind, (level, text) in SUMMARY.items():
            if count := len({f.node for f in self.findings if f.kind == kind and f.node}):
                lines.append((level, f"{count} node{'s' * (count > 1)} {text}"))
        versions = len({n.kubelet_version for n in self.nodes if n.kubelet_version})
        if versions > 1 and not any(f.kind in ("behind", "unsupported") for f in self.findings):  # else said above
            lines.append(("warning", f"{versions} kubelet versions across the nodes"))
        return sorted(lines, key=lambda line: -LEVELS.index(line[0]))

    def kubelet_level(self, version: str) -> str:
        """ok, warning (behind the API server) or error (unsupported) for a kubelet version, info when unknown."""
        if not version:
            return "info"
        return worst(f.level for f in skew_findings("kubelet", version, self.status.version, ""))

    def donut(self) -> list[tuple[VersionSegment, float]]:
        """The kubelet segments with where each starts on the ring (in percent), for the SVG donut."""
        start, out = 0.0, []
        for segment in self.kubelet_segments():
            out.append((segment, start))
            start += segment.percent
        return out

    def kubelet_segments(self) -> list[VersionSegment]:
        """The kubelet versions of the nodes, newest first, for the version bar."""
        counts = Counter(n.kubelet_version or "unknown" for n in self.nodes)
        total = sum(counts.values())
        segments = [
            VersionSegment(
                version,
                count,
                worst(f.level for f in skew_findings("kubelet", version, self.status.version, ""))
                if version != "unknown"
                else "info",
                round(count * 100 / total, 1),
            )
            for version, count in counts.items()
        ]
        return sorted(segments, key=lambda s: k8s_version(s.version) or (0, 0, 0), reverse=True)

    @property
    def to_check(self) -> list[Finding]:
        """The warnings and errors, errors first."""
        found = [f for f in self.findings if f.level != "info"]
        return sorted(found, key=lambda f: -LEVELS.index(f.level))

    @property
    def details(self) -> list[Finding]:
        """The findings left out of the summary: versions of the OS, runtimes and kernels mixed across the nodes."""
        return [f for f in self.findings if f.level == "info"]


# Attributes that should be the same on every node of a cluster, and how a difference is shown.
MIXED = (
    ("kubelet_version", "kubelet versions", "warning"),
    ("os_image", "OS images", "info"),
    ("container_runtime", "container runtimes", "info"),
    ("kernel_version", "kernels", "info"),
)
ROLE_ORDER = {"control-plane": 0, "worker": 2}


def cluster_view(
    status: ClusterStatus,
    nodes: list[NodeInfo],
    images: list[ImageReport] | None = None,
    platform: list[PlatformVersion] | None = None,
    warn_days: int = 90,
    today: date | None = None,
) -> ClusterView:
    nodes = sorted(nodes, key=lambda n: (ROLE_ORDER.get(n.role, 1), n.role, n.pool, n.name))
    groups: dict[tuple[str, str], NodeGroup] = {}
    for n in nodes:
        groups.setdefault((n.role, n.pool), NodeGroup(n.role, n.pool)).nodes.append(n)
    findings: list[Finding] = []
    for attribute, what, level in MIXED:
        values = Counter(getattr(n, attribute) for n in nodes if getattr(n, attribute))
        if len(values) > 1:
            listed = ", ".join(f"{v} ({c})" for v, c in values.most_common())
            findings.append(Finding(level, f"{len(values)} {what} across the nodes: {listed}", kind=attribute))
    versions = {(p.component, p.version): p for p in platform or []}
    api = versions.get(("kubernetes", plain_version(status.version)))
    findings += eol_findings(api, "Kubernetes", "", warn_days, today)
    if api and api.latest and plain_version(api.latest) and api.latest != api.version:
        findings.append(Finding("info", f"Kubernetes {api.latest} is the latest patch of {api.cycle}", kind="patch"))
    for n in nodes:
        findings += node_findings(n, status.version)
        kubelet = versions.get(("kubernetes", plain_version(n.kubelet_version)))
        if kubelet and api and kubelet.cycle != api.cycle:  # the cycle of the API server is said once above
            findings += eol_findings(kubelet, "kubelet", n.name, warn_days, today)
    levels = {n.name: worst(f.level for f in findings if f.node == n.name) for n in nodes}
    per_node = running_images(images or [], status.name)
    in_cluster = {str(r.image): r for reports in per_node.values() for r in reports}
    return ClusterView(
        status,
        nodes,
        list(groups.values()),
        findings,
        levels,
        {n.name: images_on(per_node.get(n.name, [])) for n in nodes},
        images_on(list(in_cluster.values())),
        versions,
        warn_days,
        today,
    )


def cluster_views(
    statuses: list[ClusterStatus],
    nodes: list[NodeInfo],
    images: list[ImageReport] | None = None,
    platform: list[PlatformVersion] | None = None,
    warn_days: int = 90,
) -> list[ClusterView]:
    by_cluster: dict[str, list[NodeInfo]] = {}
    for n in nodes:
        by_cluster.setdefault(n.cluster, []).append(n)
    return [cluster_view(s, by_cluster.get(s.name, []), images, platform, warn_days) for s in statuses]
