"""What the Clusters page shows of each cluster: its nodes by group, and what differs or is wrong
(version skew between the kubelets and the API server, versions mixed across the nodes, nodes not ready).

Kubernetes supports kubelets up to 3 minor versions older than the API server, never newer
(https://kubernetes.io/releases/version-skew-policy/).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from kube_tower.models import ClusterStatus, NodeInfo

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
            if count := len({f.node for f in self.findings if f.kind == kind}):
                lines.append((level, f"{count} node{'s' * (count > 1)} {text}"))
        versions = len({n.kubelet_version for n in self.nodes if n.kubelet_version})
        if versions > 1 and not any(f.kind in ("behind", "unsupported") for f in self.findings):  # else said above
            lines.append(("warning", f"{versions} kubelet versions across the nodes"))
        return sorted(lines, key=lambda line: -LEVELS.index(line[0]))

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


def cluster_view(status: ClusterStatus, nodes: list[NodeInfo]) -> ClusterView:
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
    for n in nodes:
        findings += node_findings(n, status.version)
    levels = {n.name: worst(f.level for f in findings if f.node == n.name) for n in nodes}
    return ClusterView(status, nodes, list(groups.values()), findings, levels)


def cluster_views(statuses: list[ClusterStatus], nodes: list[NodeInfo]) -> list[ClusterView]:
    by_cluster: dict[str, list[NodeInfo]] = {}
    for n in nodes:
        by_cluster.setdefault(n.cluster, []).append(n)
    return [cluster_view(s, by_cluster.get(s.name, [])) for s in statuses]
