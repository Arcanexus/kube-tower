"""Data structures exchanged between collectors, checkers, the store and the UI."""

from __future__ import annotations

import functools
import json
import types
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from datetime import datetime
from enum import Enum, StrEnum
from typing import Any, Union, get_args, get_origin, get_type_hints


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
    owner: str | None = None  # pods: their workload, `Deployment/web` (the ReplicaSet of a Deployment is skipped)
    node: str | None = None  # pods: the node they run on


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
    # Size in bytes reported by the nodes that pulled the image, by digest ("" when the node gives none).
    sizes: dict[str, int] = field(default_factory=dict)

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


class SecurityKind(StrEnum):
    """Kinds of Trivy Operator reports shown on the Security page (VulnerabilityReports go to the images)."""

    CONFIG_AUDIT = "config-audit"  # ConfigAuditReport, ClusterConfigAuditReport
    EXPOSED_SECRET = "exposed-secret"  # ExposedSecretReport
    RBAC = "rbac"  # RbacAssessmentReport, ClusterRbacAssessmentReport
    INFRA = "infra"  # InfraAssessmentReport, ClusterInfraAssessmentReport

    @property
    def label(self) -> str:
        return {
            "config-audit": "Config audit",
            "exposed-secret": "Exposed secrets",
            "rbac": "RBAC",
            "infra": "Infrastructure",
        }[self.value]

    @property
    def icon(self) -> str:
        """Icon of the UI (static/icons.svg)."""
        return {"config-audit": "clipboard-check", "exposed-secret": "key", "rbac": "users", "infra": "cpu"}[self.value]


@dataclass
class SecurityCheck:
    """A failed check of a security report, or a secret found in an image."""

    id: str  # KSV014, KCV0001... or the rule of an exposed secret (aws-access-key-id)
    title: str
    severity: Severity
    category: str = ""
    description: str = ""
    messages: list[str] = field(default_factory=list)
    remediation: str = ""
    target: str = ""  # exposed secrets: file of the image holding the secret
    match: str = ""  # exposed secrets: the line found, the secret masked by Trivy

    @property
    def url(self) -> str:
        """Page of the check in the Aqua vulnerability database, when it has one."""
        check = self.id.lower()
        if check.startswith(("ksv", "kcv", "avd-")):
            return f"https://avd.aquasec.com/misconfig/{check}"
        return ""


def _severity_counts(items) -> dict[Severity, int]:
    out = dict.fromkeys(Severity, 0)
    for item in items:
        out[item.severity] += 1
    return out


@dataclass
class SecurityReport:
    """A Trivy Operator report about one Kubernetes resource (or one container, for exposed secrets)."""

    cluster: str
    kind: SecurityKind
    resource_kind: str  # Deployment, Role, ClusterRole, Node...
    resource_name: str
    namespace: str | None = None  # None for cluster-scoped resources
    container: str | None = None  # exposed secrets: the container whose image holds them
    image: str | None = None  # exposed secrets: the image scanned
    scanned_at: datetime | None = None
    checks: list[SecurityCheck] = field(default_factory=list)  # failed checks only, most severe first
    passed: int = 0  # checks that passed

    @property
    def key(self) -> tuple[str, str, str, str, str, str]:
        """Identifies the report in a snapshot (detail panel)."""
        return self.cluster, self.kind.value, self.namespace or "", self.resource_kind, self.resource_name, self.container or ""

    def counts(self) -> dict[Severity, int]:
        return _severity_counts(self.checks)

    @property
    def worst(self) -> Severity | None:
        return min((c.severity for c in self.checks), key=list(Severity).index, default=None)


@dataclass
class ComplianceControl:
    """A control of a compliance framework that failed, and how many checks failed."""

    id: str  # 1.2.1, 5.1.3...
    name: str
    severity: Severity
    failed: int = 0


@dataclass
class ComplianceReport:
    """A ClusterComplianceReport of Trivy Operator (CIS Kubernetes Benchmark, NSA, Pod Security Standards...)."""

    cluster: str
    id: str  # k8s-cis-1.23, k8s-nsa-1.0...
    title: str
    description: str = ""
    passed: int = 0
    failed: int = 0
    scanned_at: datetime | None = None
    controls: list[ComplianceControl] = field(default_factory=list)  # failed controls, most severe first

    @property
    def key(self) -> tuple[str, str]:
        return self.cluster, self.id

    @property
    def score(self) -> int | None:
        """Percentage of passed controls, None when not evaluated yet."""
        total = self.passed + self.failed
        return round(self.passed * 100 / total) if total else None


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
    # Reports of Trivy Operator other than the VulnerabilityReports (Security page)
    security: list[SecurityReport] = field(default_factory=list)
    compliance: list[ComplianceReport] = field(default_factory=list)
    # Clusters where Trivy Operator is installed: the Security page only shows when there is one
    trivy_operator: list[str] = field(default_factory=list)

    def image(self, ref: str) -> ImageReport | None:
        return self._index("images", lambda r: str(r.image)).get(ref)

    def chart(self, cluster: str, namespace: str, application: str, chart: str) -> ChartReport | None:
        return self._index("charts", lambda c: c.key).get((cluster, namespace, application, chart))

    def security_report(self, key: tuple) -> SecurityReport | None:
        return self._index("security", lambda r: r.key).get(tuple(key))

    def compliance_report(self, cluster: str, id: str) -> ComplianceReport | None:
        return self._index("compliance", lambda r: r.key).get((cluster, id))

    def _index(self, name: str, key) -> dict:
        """The reports of the `images`, `charts`... list by key, for the detail panels and the API (opened
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
        data = encode(self)
        for img, raw in zip(self.images, data["images"], strict=True):
            raw["image"] = {**raw["image"], "ref": str(img.image)}
        return data

    @classmethod
    def from_dict(cls, data: dict) -> Snapshot:
        """The Snapshot that to_dict() encoded, e.g. sent by another kube-tower process."""
        return decode(cls, data)


def encode(obj: Any) -> Any:
    """A dataclass (or list, dict... of them) as JSON-ready data: enums by value, datetimes in ISO format, sets sorted."""
    if is_dataclass(obj) and not isinstance(obj, type):
        obj = asdict(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    if isinstance(obj, dict):
        return {k: encode(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [encode(v) for v in obj]
    return obj


@functools.cache
def _fields(cls: type) -> tuple[tuple[str, Any], ...]:
    """The fields of a dataclass and their types, resolved once (get_type_hints is slow, decode is called a lot)."""
    hints = get_type_hints(cls)
    return tuple((f.name, hints[f.name]) for f in fields(cls))


def to_json(obj: Any) -> bytes:
    """encode() as JSON bytes. CPU bound for a large snapshot: call it in a thread from an event loop."""
    return json.dumps(encode(obj), separators=(",", ":")).encode()


def decode(hint: Any, value: Any) -> Any:
    """Rebuild a value of type `hint` from its encode() form (keys unknown to a dataclass are ignored)."""
    if value is None:
        return None
    origin = get_origin(hint)
    if origin in (Union, types.UnionType):  # `X | None`: the only unions of the models
        return decode(next(a for a in get_args(hint) if a is not type(None)), value)
    if origin is list:
        return [decode(get_args(hint)[0], v) for v in value]
    if origin is set:
        return {decode(get_args(hint)[0], v) for v in value}
    if origin is tuple:
        return tuple(decode(h, v) for h, v in zip(get_args(hint), value, strict=True))
    if origin is dict:
        key, item = get_args(hint)
        return {decode(key, k): decode(item, v) for k, v in value.items()}
    if is_dataclass(hint):
        return hint(**{name: decode(field_hint, value[name]) for name, field_hint in _fields(hint) if name in value})
    if isinstance(hint, type) and issubclass(hint, Enum):
        return hint(value)
    if hint is datetime:
        return datetime.fromisoformat(value)
    if hint is float:
        return float(value)
    return value
