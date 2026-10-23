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

    @property
    def clusters(self) -> list[str]:
        return sorted({u.cluster for u in self.usages})


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
    errors: list[str] = field(default_factory=list)

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
