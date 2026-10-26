"""The units of work of a scan, which a worker or trivy role runs (ADR 0002).

A full scan is split in tasks: collect one cluster, check the versions of images or charts, scan
images with Trivy. Each task and each result is a dataclass made of models, so it can be sent to
another kube-tower process as JSON (encode_task / decode_task, encode_result / decode_result).

When every role runs in the process, the LocalRunner hands the tasks to the Worker of the process,
without encoding them (the reports are updated in place, so the UI shows the results as they come).
In the distributed mode, the QueueRunner queues the tasks of the roles that run elsewhere: worker and
trivy processes pull them over the internal API of the controller (internal.py) and send the results back.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from kube_tower.models import ChartReport, ImageReport, VulnerabilityReport, decode, encode

if TYPE_CHECKING:
    from collections.abc import Callable

    from kube_tower.worker import Worker

log = logging.getLogger(__name__)


# Tasks


@dataclass
class CollectTask:
    """Read the images, the Helm charts and the Trivy Operator reports of one cluster (rescans read only
    some of them: `image_name` keeps the images of this name, registry/repository)."""

    cluster: str
    images: bool = True
    charts: bool = True
    operator_reports: bool = True
    image_name: str | None = None


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
    """Scan images with Trivy. `full`: the images of a full scan, the Trivy cache forgets the others.
    `fresh`: scanned again, not read from the Trivy cache (rescans)."""

    images: list[ImageReport]
    full: bool = False
    fresh: bool = False


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


class TaskFailed(Exception):
    """A worker or trivy process could not run a task."""


@dataclass
class _Queued:
    id: str
    role: str
    data: dict[str, Any]  # encode_task()
    future: asyncio.Future
    deadline: float | None = None  # while pulled: when it is given to another process


class QueueRunner:
    """The distributed mode: the tasks of the roles of this process run here, the others wait in a queue
    until a process with their role pulls them (next), then for its result (complete / fail).

    A task pulled and not answered within `timeout` (the process died) is queued again, first in line.
    The queue lives in the event loop of the internal API (`loop`): the scans, which run in their own
    threads and event loops, hand their tasks over to it.
    """

    def __init__(
        self,
        worker: Worker,
        local_roles: set[str],
        timeout: float = 30 * 60,
        context: Callable[[], dict[str, Any]] | None = None,
    ):
        self.worker = worker
        self.local_roles = local_roles
        self.timeout = timeout
        # What a process needs with each task, e.g. the credentials of the image pull secrets.
        self.context = context or dict
        self.queue: deque[_Queued] = deque()
        self.pulled: dict[str, _Queued] = {}
        self._ids = itertools.count(1)
        self._added = asyncio.Event()
        self.loop: asyncio.AbstractEventLoop | None = None  # set when the internal API starts

    async def run(self, task: Task) -> Any:
        if role_of(task) in self.local_roles:
            return await self.worker.execute(task)
        if self.loop is None or self.loop is asyncio.get_running_loop():
            return await self._queued(task)
        # Cancelling the scan cancels the queued task too.
        return await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(self._queued(task), self.loop))

    async def _queued(self, task: Task) -> Any:
        role, kind = role_of(task), kind_of(task)
        queued = _Queued(f"{kind}-{next(self._ids)}", role, encode_task(task), asyncio.get_running_loop().create_future())
        self.queue.append(queued)
        self._added.set()
        try:
            return decode_result(kind, await queued.future)
        finally:  # done, or the scan was cancelled: forget it
            if queued in self.queue:
                self.queue.remove(queued)
            self.pulled.pop(queued.id, None)

    def waiting(self) -> dict[str, int]:
        """Tasks queued and not pulled yet, by role."""
        counts = dict.fromkeys(sorted({q.role for q in self.queue}), 0)
        for q in self.queue:
            counts[q.role] += 1
        return counts

    async def next(self, roles: set[str], wait: float) -> dict[str, Any] | None:
        """The next task for a process with these roles, waiting up to `wait` seconds for one."""
        deadline = time.monotonic() + wait
        while True:
            self._requeue_expired()
            if queued := next((q for q in self.queue if q.role in roles), None):
                self.queue.remove(queued)
                queued.deadline = time.monotonic() + self.timeout
                self.pulled[queued.id] = queued
                return {"id": queued.id, **queued.data, "context": self.context()}
            if (left := deadline - time.monotonic()) <= 0:
                return None
            self._added.clear()
            try:
                await asyncio.wait_for(self._added.wait(), min(left, 5))  # 5: also look for expired tasks
            except TimeoutError:
                pass

    def complete(self, task_id: str, result: dict[str, Any]) -> bool:
        """Whether the task was still waiting for this result."""
        if (queued := self.pulled.pop(task_id, None)) is None or queued.future.done():
            return False
        queued.future.set_result(result)
        return True

    def fail(self, task_id: str, message: str) -> bool:
        if (queued := self.pulled.pop(task_id, None)) is None or queued.future.done():
            return False
        queued.future.set_exception(TaskFailed(f"task {task_id} failed: {message}"))
        return True

    def _requeue_expired(self) -> None:
        now = time.monotonic()
        for queued in [q for q in self.pulled.values() if q.deadline is not None and q.deadline < now]:
            log.warning("task %s not answered within %.0fs: given to another process", queued.id, self.timeout)
            del self.pulled[queued.id]
            queued.deadline = None
            self.queue.appendleft(queued)
