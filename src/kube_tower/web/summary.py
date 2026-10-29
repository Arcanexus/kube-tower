"""Figures of the Overview page, computed from the last snapshot."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from kube_tower.models import ImageReport, Severity, Snapshot, Status
from kube_tower.versions import update_kind
from kube_tower.web.metrics import image_update

UPDATE_KINDS = ["major", "minor", "patch", "newer", "digest"]
# Worst severity buckets of the vulnerability bar, most severe first, then images without a result
WORST_PENDING = ("failed", "not scanned")
WORST_ORDER = [*(s.value for s in Severity), "none", *WORST_PENDING]


def worst_severity(report: ImageReport) -> str:
    v = report.vulnerabilities
    if v is None:
        return "not scanned"
    if v.message:
        return "failed"
    return v.worst.value if v.worst else "none"


def workloads(report: ImageReport) -> int:
    """Workloads using an image (a Deployment and its pods count once; nodes caching it do not count)."""
    return len({(u.cluster, u.namespace, u.owner or f"{u.kind}/{u.name}") for u in report.usages if u.kind != "Node"})


def fixable_critical(report: ImageReport) -> int:
    """Critical vulnerabilities of an image that have a fixed version (the most urgent to act on)."""
    v = report.vulnerabilities
    if v is None or v.message:
        return 0
    return sum(1 for x in v.vulnerabilities if x.fixed_version and x.severity == Severity.CRITICAL)


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
        fixable_critical=sum(fixable_critical(r) for r in scanned),
        fixable_critical_images=sum(1 for r in scanned if fixable_critical(r)),
        eosl=sum(1 for r in scanned if r.vulnerabilities.os_eosl),
        top=[r for r in sorted(scanned, key=rank) if counts[id(r)][Severity.CRITICAL] or counts[id(r)][Severity.HIGH]][:top],
    )


@dataclass
class VulnerabilitySummary:
    worst: Counter  # worst severity of each image (or "none", "failed", "not scanned") -> number of images
    images_with: Counter  # severity -> number of images with at least one vulnerability of that severity
    fixable_critical_high: int  # critical and high vulnerabilities with a fixed version, all images
    fixable_critical: int  # critical vulnerabilities with a fixed version
    fixable_critical_images: int  # images with at least one of them
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
    charts_subchart_outdated: int  # charts up to date (or unknown) with an outdated subchart
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


def summarize(snap: Snapshot, top: int = 5, registries: int = 6, running: bool = False, cluster: str = "") -> Summary:
    """`running`: count only the images a pod runs (not those only declared by workloads without pods or cached on nodes).
    `cluster`: count only the images and charts of this cluster."""
    images = [r for r in snap.images if (not running or r.running) and (not cluster or cluster in r.clusters)]
    charts = [c for c in snap.charts if not cluster or c.cluster == cluster]
    clusters = {c.name: ClusterSummary(c.name, c.reachable, c.version) for c in snap.clusters}
    for r in images:
        for name in r.clusters:
            cluster = clusters.setdefault(name, ClusterSummary(name, True, None))
            cluster.images[r.status.value] += 1
            if r.vulnerabilities and r.vulnerabilities.counts()[Severity.CRITICAL]:
                cluster.critical_images += 1
    for c in charts:
        clusters.setdefault(c.cluster, ClusterSummary(c.cluster, True, None)).charts[c.worst_status.value] += 1

    by_registry = Counter(r.image.registry for r in images).most_common()
    if len(by_registry) > registries:  # keep the bars readable: the long tail becomes "other"
        by_registry = [*by_registry[: registries - 1], ("other", sum(n for _, n in by_registry[registries - 1 :]))]

    outdated = [r for r in images if r.status == Status.OUTDATED]
    update_of = {str(r.image): image_update(r) for r in outdated}
    return Summary(
        images=Counter(r.status.value for r in images),
        charts=Counter(c.worst_status.value for c in charts),
        subcharts=Counter(d.status.value for c in charts for _, d in c.walk()),
        charts_subchart_outdated=sum(1 for c in charts if c.status != Status.OUTDATED and c.worst_status == Status.OUTDATED),
        updates=[(kind, n) for kind in UPDATE_KINDS if (n := sum(1 for k in update_of.values() if k == kind))],
        update_of=update_of,
        registries=by_registry,
        latest_images=sum(1 for r in images if r.image.is_latest),
        clusters=sorted(clusters.values(), key=lambda c: c.name),
        top_outdated=sorted(outdated, key=lambda r: (-len(r.usages), str(r.image)))[:top],
        vulnerabilities=summarize_vulnerabilities(images, top),
    )


@dataclass
class Todo:
    """A line of the "To do" list of the Overview: what to act on, most urgent first."""

    tag: str  # short label of the badge: "9 critical", "major", "error"…
    level: str  # crit | warn | err: color of the badge
    title: str
    detail: str
    hint: str = ""  # right column: the version to go to, the page to open
    href: str = ""  # a page (relative link)
    detail_url: str = ""  # or a detail panel (htmx, into #detail)
    code: bool = True  # the title is an image reference (monospace)


def todo(snap: Snapshot, running: bool = False, cluster: str = "", limit: int = 10, per_kind: int = 3) -> tuple[list[Todo], int]:
    """The things to act on, most urgent first: unreachable clusters, fixable critical CVEs, failed checks,
    major updates of images and charts, floating tags pushed again, end of life OS. Returns the first `limit`
    (at most `per_kind` of each kind) and the number of items found in all."""
    from urllib.parse import quote, urlencode

    images = [r for r in snap.images if (not running or r.running) and (not cluster or cluster in r.clusters)]
    charts = [c for c in snap.charts if not cluster or c.cluster == cluster]

    def image_item(r: ImageReport, tag: str, level: str, detail: str, hint: str = "") -> Todo:
        where = ", ".join(r.clusters)
        n = workloads(r)
        detail = f"{detail} · {n} workload{'s' if n != 1 else ''}{' in ' + where if where else ''}"
        return Todo(tag, level, str(r.image), detail, hint, detail_url=f"images/detail?ref={quote(str(r.image), safe='')}")

    groups: list[list[Todo]] = [[], [], [], [], [], [], []]
    clusters, critical, errors, major, charts_major, latest, eol = groups
    for c in snap.clusters:
        if not c.reachable and (not cluster or c.name == cluster):
            clusters.append(
                Todo(
                    "cluster",
                    "err",
                    c.name,
                    f"Unreachable: {c.message or 'no answer'}",
                    "Clusters",
                    href="administration?tab=clusters",
                    code=False,
                )
            )
    for r in sorted(images, key=lambda r: (-fixable_critical(r), str(r.image))):
        if n := fixable_critical(r):
            hint = f"→ {r.latest_tag}" if r.status == Status.OUTDATED and r.latest_tag else ""
            critical.append(image_item(r, f"{n} critical", "crit", f"{n} critical CVE{'s' if n > 1 else ''} with a fix", hint))
    for r in images:
        v = r.vulnerabilities
        if r.status == Status.ERROR:
            errors.append(image_item(r, "error", "err", r.message or "The registry could not be queried"))
        if image_update(r) == "major":
            major.append(image_item(r, "major", "warn", "Major update available", f"{r.image.tag} → {r.latest_tag}"))
        if r.image.is_latest and r.status == Status.OUTDATED:
            latest.append(image_item(r, "latest", "warn", "Floating tag, a newer image was pushed: pin a version"))
        if v and not v.message and v.os_eosl:
            eol.append(image_item(r, "end of life", "warn", f"{v.os} gets no more security fixes: use a newer base image"))
    for c in charts:
        if update_kind(c.version, c.latest_version) == "major":
            query = urlencode({"q": c.chart})
            charts_major.append(
                Todo(
                    "major",
                    "warn",
                    f"{c.application} · {c.chart} chart",
                    f"Helm chart major update ({c.cluster})",
                    f"{c.version} → {c.latest_version}",
                    href=f"charts?{query}",
                    code=False,
                )
            )
    # A few of each kind, so that one kind (many images with critical CVEs) does not hide the others.
    items = [t for g in groups for t in g[:per_kind]]
    total = sum(len(g) for g in groups)
    return items[:limit], total
