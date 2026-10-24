"""Data structures exchanged between collectors, checkers, the store and the UI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum, StrEnum


class Status(StrEnum):
    UP_TO_DATE = "up-to-date"
    OUTDATED = "outdated"
    UNKNOWN = "unknown"  # floating tag, unsupported source...
    ERROR = "error"


@dataclass(frozen=True)
class ImageRef:
    """A normalized image reference: `registry/repository:tag@digest`."""

    registry: str
    repository: str
    tag: str | None = None
    digest: str | None = None

    @property
    def name(self) -> str:
        return f"{self.registry}/{self.repository}"

    @property
    def is_latest(self) -> bool:
        """`latest` (explicit, or implied by an image without tag): a bad practice, highlighted in the UI."""
        return self.tag == "latest"

    def __str__(self) -> str:
        out = self.name
        if self.tag:
            out += f":{self.tag}"
        if self.digest:
            out += f"@{self.digest}"
        return out


@dataclass
class Usage:
    """Where an image or chart was found."""

    cluster: str
    kind: str
    namespace: str | None
    name: str
    container: str | None = None


class Severity(StrEnum):
    """Trivy severities, most severe first."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, value: str | None) -> Severity:
        try:
            return cls((value or "").lower())
        except ValueError:
            return cls.UNKNOWN


@dataclass
class Vulnerability:
    id: str  # CVE-2024-1234, GHSA-..., DLA-...
    severity: Severity
    package: str
    installed_version: str
    fixed_version: str = ""
    title: str = ""
    url: str = ""
    score: float | None = None  # CVSS score, when known


@dataclass
class VulnerabilityReport:
    """Vulnerabilities of one image, read from a Trivy Operator VulnerabilityReport or scanned with Trivy."""

    source: str  # trivy-operator | trivy
    scanned_at: datetime | None = None
    digest: str | None = None  # digest of the scanned image, when known
    os: str = ""  # e.g. "debian 12.5"
    os_eosl: bool = False  # the OS release is end of life: no more security fixes
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    message: str | None = None  # scan error

    def counts(self) -> dict[Severity, int]:
        out = dict.fromkeys(Severity, 0)
        for v in self.vulnerabilities:
            out[v.severity] += 1
        return out

    @property
    def fixable(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.fixed_version)

    @property
    def worst(self) -> Severity | None:
        return min((v.severity for v in self.vulnerabilities), key=list(Severity).index, default=None)


@dataclass
class ImageReport:
    image: ImageRef
    usages: list[Usage] = field(default_factory=list)
    running_digests: set[str] = field(default_factory=set)
    status: Status = Status.UNKNOWN
    latest_tag: str | None = None
    latest_digest: str | None = None
    tag_digest: str | None = None  # digest published in the registry for the current tag
    message: str | None = None
    vulnerabilities: VulnerabilityReport | None = None  # None until scanned

    @property
    def clusters(self) -> list[str]:
        return sorted({u.cluster for u in self.usages})

    @property
    def running(self) -> bool:
        """Used by a pod; otherwise only declared by workloads without pods (scaled to zero, CronJob between
        two runs) or only cached on nodes."""
        return any(u.kind == "Pod" for u in self.usages)


@dataclass
class ChartDependency:
    name: str
    version: str
    repository: str
    status: Status = Status.UNKNOWN
    latest_version: str | None = None
    message: str | None = None
    dependencies: list[ChartDependency] = field(default_factory=list)  # subcharts of the subchart

    def walk(self, depth: int = 0):
        """Yield (depth, dependency) for this subchart and its own subcharts, depth first."""
        yield depth, self
        for d in self.dependencies:
            yield from d.walk(depth + 1)


def _worst(statuses: set[Status]) -> Status:
    for s in (Status.OUTDATED, Status.ERROR, Status.UNKNOWN):
        if s in statuses:
            return s
    return Status.UP_TO_DATE


@dataclass
class ChartReport:
    cluster: str
    application: str
    app_namespace: str
    chart: str
    repository: str
    version: str
    source_type: str  # helm | oci | git
    destination_namespace: str | None = None
    git_ref: str | None = None
    status: Status = Status.UNKNOWN
    latest_version: str | None = None
    message: str | None = None
    dependencies: list[ChartDependency] = field(default_factory=list)
    path: str | None = None  # git sources: path of the chart in the repository (`chart` becomes its name once read)

    @property
    def key(self) -> tuple[str, str, str, str]:
        """Identifies the chart in a snapshot (an Application can deploy several charts)."""
        return self.cluster, self.app_namespace, self.application, self.chart

    def walk(self):
        """Yield (depth, dependency) for the whole subchart tree, depth first (direct subcharts at depth 1)."""
        for d in self.dependencies:
            yield from d.walk(1)

    @property
    def worst_status(self) -> Status:
        return _worst({self.status, *(d.status for _, d in self.walk())})


@dataclass
class ClusterStatus:
    name: str
    server: str
    source: str  # in-cluster | secret | argocd-secret
    reachable: bool = False
    version: str | None = None
    message: str | None = None


@dataclass
class Snapshot:
    images: list[ImageReport] = field(default_factory=list)
    charts: list[ChartReport] = field(default_factory=list)
    clusters: list[ClusterStatus] = field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    # End of the vulnerability scan, which runs after the version checks
    vulnerabilities_finished_at: datetime | None = None
    errors: list[str] = field(default_factory=list)

    def image(self, ref: str) -> ImageReport | None:
        return self._index("images", lambda r: str(r.image)).get(ref)

    def chart(self, cluster: str, namespace: str, application: str, chart: str) -> ChartReport | None:
        return self._index("charts", lambda c: c.key).get((cluster, namespace, application, chart))

    def _index(self, name: str, key) -> dict:
        """The reports of the `images` or `charts` list by key, for the detail panels and the API (opened
        and polled often). Built again when the list is replaced or grows (rescans add the new images).
        Not a dataclass field: left out of to_dict().
        """
        reports = getattr(self, name)
        cached = self.__dict__.get(f"_{name}_index")
        if cached and cached[0] is reports and cached[1] == len(reports):
            return cached[2]
        index: dict = {}
        for report in reports:
            index.setdefault(key(report), report)  # the first one, as a linear search would find
        self.__dict__[f"_{name}_index"] = (reports, len(reports), index)
        return index

    def to_dict(self) -> dict:
        def enc(obj):
            if isinstance(obj, Enum):
                return obj.value
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, set):
                return sorted(obj)
            if isinstance(obj, dict):
                return {k: enc(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [enc(v) for v in obj]
            return obj

        data = enc(asdict(self))
        for img, raw in zip(self.images, data["images"], strict=True):
            raw["image"] = {**raw["image"], "ref": str(img.image)}
        return data
