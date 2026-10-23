"""Figures of the Synthesis page, computed from the last snapshot."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from kube_tower.models import Snapshot, Status
from kube_tower.web.metrics import image_update

UPDATE_KINDS = ["major", "minor", "patch", "digest"]


@dataclass
class ClusterSummary:
    name: str
    reachable: bool
    version: str | None
    images: Counter = field(default_factory=Counter)  # status value -> count
    charts: Counter = field(default_factory=Counter)


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
            clusters.setdefault(name, ClusterSummary(name, True, None)).images[r.status.value] += 1
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
    )
