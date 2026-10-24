"""Figures of the Synthesis page, computed from the last snapshot."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from kube_tower.models import ImageReport, Severity, Snapshot, Status
from kube_tower.web.metrics import image_update

UPDATE_KINDS = ["major", "minor", "patch", "newer", "digest"]
# Worst severity buckets of the Synthesis bar, most severe first, then images without a result
WORST_PENDING = ("failed", "not scanned")
WORST_ORDER = [*(s.value for s in Severity), "none", *WORST_PENDING]


def worst_severity(report: ImageReport) -> str:
    v = report.vulnerabilities
    if v is None:
        return "not scanned"
    if v.message:
        return "failed"
    return v.worst.value if v.worst else "none"


def summarize_vulnerabilities(images: list[ImageReport], top: int = 5) -> VulnerabilitySummary:
    scanned = [r for r in images if r.vulnerabilities and not r.vulnerabilities.message]
    counts = {id(r): r.vulnerabilities.counts() for r in scanned}

    def rank(r: ImageReport) -> tuple:
        c = counts[id(r)]
        return (-c[Severity.CRITICAL], -c[Severity.HIGH], str(r.image))

    return VulnerabilitySummary(
        worst=Counter(worst_severity(r) for r in images),
        images_with=Counter(s for r in scanned for s in Severity if counts[id(r)][s]),
        fixable_critical_high=sum(
            1
            for r in scanned
            for v in r.vulnerabilities.vulnerabilities
            if v.fixed_version and v.severity in (Severity.CRITICAL, Severity.HIGH)
        ),
        eosl=sum(1 for r in scanned if r.vulnerabilities.os_eosl),
        top=[r for r in sorted(scanned, key=rank) if counts[id(r)][Severity.CRITICAL] or counts[id(r)][Severity.HIGH]][:top],
    )


@dataclass
class VulnerabilitySummary:
    worst: Counter  # worst severity of each image (or "none", "failed", "not scanned") -> number of images
    images_with: Counter  # severity -> number of images with at least one vulnerability of that severity
    fixable_critical_high: int  # critical and high vulnerabilities with a fixed version, all images
    eosl: int  # images whose OS release is end of life
    top: list  # most vulnerable images (critical first, then high)

    @property
    def scanned(self) -> int:
        return sum(n for k, n in self.worst.items() if k not in WORST_PENDING)


@dataclass
class ClusterSummary:
    name: str
    reachable: bool
    version: str | None
    images: Counter = field(default_factory=Counter)  # status value -> count
    charts: Counter = field(default_factory=Counter)
    critical_images: int = 0  # images with at least one critical vulnerability


@dataclass
class Summary:
    images: Counter  # status value -> count
    charts: Counter  # worst status value -> count
    subcharts: Counter
    updates: list[tuple[str, int]]  # (update kind, number of outdated images), major first
    update_of: dict[str, str]  # image reference -> update kind
    registries: list[tuple[str, int]]
    latest_images: int
    clusters: list[ClusterSummary]
    top_outdated: list  # outdated images used by the most workloads
    vulnerabilities: VulnerabilitySummary

    @property
    def images_total(self) -> int:
        return sum(self.images.values())

    @property
    def charts_total(self) -> int:
        return sum(self.charts.values())


def summarize(snap: Snapshot, top: int = 5, registries: int = 6) -> Summary:
    clusters = {c.name: ClusterSummary(c.name, c.reachable, c.version) for c in snap.clusters}
    for r in snap.images:
        for name in r.clusters:
            cluster = clusters.setdefault(name, ClusterSummary(name, True, None))
            cluster.images[r.status.value] += 1
            if r.vulnerabilities and r.vulnerabilities.counts()[Severity.CRITICAL]:
                cluster.critical_images += 1
    for c in snap.charts:
        clusters.setdefault(c.cluster, ClusterSummary(c.cluster, True, None)).charts[c.worst_status.value] += 1

    by_registry = Counter(r.image.registry for r in snap.images).most_common()
    if len(by_registry) > registries:  # keep the bars readable: the long tail becomes "other"
        by_registry = [*by_registry[: registries - 1], ("other", sum(n for _, n in by_registry[registries - 1 :]))]

    outdated = [r for r in snap.images if r.status == Status.OUTDATED]
    update_of = {str(r.image): image_update(r) for r in outdated}
    return Summary(
        images=Counter(r.status.value for r in snap.images),
        charts=Counter(c.worst_status.value for c in snap.charts),
        subcharts=Counter(d.status.value for c in snap.charts for _, d in c.walk()),
        updates=[(kind, n) for kind in UPDATE_KINDS if (n := sum(1 for k in update_of.values() if k == kind))],
        update_of=update_of,
        registries=by_registry,
        latest_images=sum(1 for r in snap.images if r.image.is_latest),
        clusters=sorted(clusters.values(), key=lambda c: c.name),
        top_outdated=sorted(outdated, key=lambda r: (-len(r.usages), str(r.image)))[:top],
        vulnerabilities=summarize_vulnerabilities(snap.images, top),
    )
