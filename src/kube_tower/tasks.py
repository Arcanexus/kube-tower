"""The units of work of a scan, which a worker or trivy role runs (ADR 0002).

A full scan is split in tasks: collect one cluster, check the versions of images or charts, scan
images with Trivy. Each task and each result is a dataclass made of models, so it can be sent to
another kube-tower process as JSON (encode_task / decode_task, encode_result / decode_result).

Today every role runs in the process: the LocalRunner hands the tasks to the Worker of the process,
without encoding them (the reports are updated in place, so the UI shows the results as they come).
The distributed mode adds a runner that queues them for the worker and trivy pods.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from kube_tower.models import ChartReport, ImageReport, VulnerabilityReport, decode, encode

if TYPE_CHECKING:
    from kube_tower.worker import Worker


# Tasks


@dataclass
class CollectTask:
    """Read the images, the Helm charts and the Trivy Operator reports of one cluster."""

    cluster: str


@dataclass
class CheckImagesTask:
    """Check the versions of images against their registries."""

    images: list[ImageReport]


@dataclass
class CheckChartsTask:
    """Check the versions of Helm charts and their subcharts."""

    charts: list[ChartReport]


@dataclass
class ScanVulnerabilitiesTask:
    """Scan images with Trivy. `full`: the images of a full scan, the Trivy cache forgets the others."""

    images: list[ImageReport]
    full: bool = False


# Results


@dataclass
class OperatorReport:
    """A Trivy Operator VulnerabilityReport found on a cluster, for the image `image` (reference)."""

    image: str
    report: VulnerabilityReport


@dataclass
class CollectResult:
    images: list[ImageReport] = field(default_factory=list)
    charts: list[ChartReport] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    operator_reports: list[OperatorReport] = field(default_factory=list)
    # Registry credentials of the image pull secrets of the cluster (registries.useImagePullSecrets)
    pull_secrets: dict[str, tuple[str, str]] = field(default_factory=dict)


@dataclass
class CheckImagesResult:
    images: list[ImageReport]


@dataclass
class CheckChartsResult:
    charts: list[ChartReport]


@dataclass
class ScanVulnerabilitiesResult:
    vulnerabilities: list[VulnerabilityReport | None]  # one per image of the task, in order
    errors: list[str] = field(default_factory=list)


type Task = CollectTask | CheckImagesTask | CheckChartsTask | ScanVulnerabilitiesTask
type Result = CollectResult | CheckImagesResult | CheckChartsResult | ScanVulnerabilitiesResult

# Task kind: its task and result types, and the role that runs it.
KINDS: dict[str, tuple[type, type, str]] = {
    "collect": (CollectTask, CollectResult, "worker"),
    "check-images": (CheckImagesTask, CheckImagesResult, "worker"),
    "check-charts": (CheckChartsTask, CheckChartsResult, "worker"),
    "scan-vulnerabilities": (ScanVulnerabilitiesTask, ScanVulnerabilitiesResult, "trivy"),
}


def kind_of(task: Task) -> str:
    return next(kind for kind, (task_type, _, _) in KINDS.items() if isinstance(task, task_type))


def role_of(task: Task) -> str:
    return KINDS[kind_of(task)][2]


def encode_task(task: Task) -> dict[str, Any]:
    return {"kind": kind_of(task), "task": encode(task)}


def decode_task(data: dict[str, Any]) -> Task:
    return decode(KINDS[data["kind"]][0], data["task"])


def encode_result(result: Result) -> dict[str, Any]:
    return encode(result)


def decode_result(kind: str, data: dict[str, Any]) -> Result:
    return decode(KINDS[kind][1], data)


class TaskRunner(Protocol):
    """Runs a task where its role runs and returns its result."""

    async def run(self, task: Task) -> Any: ...


class LocalRunner:
    """Every role in this process: the task runs on the Worker of the process, as it comes."""

    def __init__(self, worker: Worker):
        self.worker = worker

    async def run(self, task: Task) -> Any:
        return await self.worker.execute(task)
