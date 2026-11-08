"""What the Resources page and the Clusters cards show of the krr recommendations: values in Kubernetes
units, totals per cluster, and the resources block to paste in a manifest."""

from __future__ import annotations

import dataclasses

import yaml

from kube_tower.models import Fit, ResourceRecommendation, ResourceScan, ResourceValue

# Worst first, as the chips and the sort show them
FIT_RANK = {fit: i for i, fit in enumerate(Fit)}
FIT_ICONS = {Fit.CRITICAL: "error", Fit.WARNING: "warning", Fit.OK: "ok", Fit.GOOD: "ok", Fit.UNKNOWN: "unknown"}
FIT_WORDS = {
    Fit.CRITICAL: "far from the usage",
    Fit.WARNING: "to adjust",
    Fit.OK: "close",
    Fit.GOOD: "fits",
    Fit.UNKNOWN: "not enough data",
}
_UNITS = (("Ti", 1024**4), ("Gi", 1024**3), ("Mi", 1024**2), ("Ki", 1024))


def cpu(value: float | None) -> str:
    """Cores as in a manifest: 50m, 250m, 1, 1.5."""
    if value is None:
        return ""
    if value < 1:
        return f"{max(1, round(value * 1000))}m"
    return f"{value:.2f}".rstrip("0").rstrip(".")


def memory(value: float | None) -> str:
    """Bytes as in a manifest: 128Mi, 1.5Gi (at most one decimal)."""
    if value is None:
        return ""
    for unit, size in _UNITS:
        if value >= size:
            return f"{value / size:.1f}".rstrip("0").rstrip(".") + unit
    return str(round(value))


def shown(resource: str, value: float | None) -> str:
    return cpu(value) if resource == "cpu" else memory(value)


def manifest(r: ResourceRecommendation) -> str:
    """The resources block of the container with the recommended values (the ones krr knows)."""
    block: dict[str, dict[str, str]] = {}
    for resource, kind, value in r.values:
        if value.known and value.recommended is not None:
            block.setdefault(f"{kind}s", {})[resource] = shown(resource, value.recommended)
    return yaml.safe_dump({"resources": block}, sort_keys=False) if block else ""


@dataclasses.dataclass
class ClusterResources:
    """The recommendations of a cluster at a glance (Clusters card, Resources page)."""

    scan: ResourceScan | None
    containers: int = 0
    fits: dict[Fit, int] = dataclasses.field(default_factory=lambda: dict.fromkeys(Fit, 0))
    # Requests of the containers with a recommendation for both: (current, recommended)
    cpu: tuple[float, float] = (0.0, 0.0)
    memory: tuple[float, float] = (0.0, 0.0)

    @property
    def to_fix(self) -> int:
        return self.fits[Fit.CRITICAL] + self.fits[Fit.WARNING]


def _requests(rows: list[ResourceRecommendation], pick) -> tuple[float, float]:
    pairs = [(v.current, v.recommended) for r in rows if (v := pick(r)).change is not None]
    return sum(c for c, _ in pairs), sum(n for _, n in pairs)


def summarize(rows: list[ResourceRecommendation], scan: ResourceScan | None = None) -> ClusterResources:
    found = ClusterResources(scan, len(rows))
    for r in rows:
        found.fits[r.fit] += 1
    found.cpu = _requests(rows, lambda r: r.cpu_request)
    found.memory = _requests(rows, lambda r: r.memory_request)
    return found


def by_cluster(rows: list[ResourceRecommendation], scans: list[ResourceScan]) -> dict[str, ClusterResources]:
    return {s.cluster: summarize([r for r in rows if r.cluster == s.cluster], s) for s in scans}


def text_of(r: ResourceRecommendation) -> str:
    """What the search box of the Resources page looks in."""
    return f"{r.cluster} {r.namespace} {r.kind} {r.name} {r.container}"


def change_text(resource: str, value: ResourceValue) -> str:
    """+150m, -312Mi: the change from the current value to the recommendation, "" when there is none."""
    change = value.change
    if change is None or abs(change) < (0.001 if resource == "cpu" else 1024**2):
        return ""
    return ("+" if change > 0 else "-") + shown(resource, abs(change))
