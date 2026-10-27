"""The units of work of a scan, which a worker or trivy role runs (ADR 0002).

A full scan is split in tasks: collect one cluster, check the versions of images or charts, scan
images with Trivy. Each task and each result is a dataclass made of models, so it can be sent to
another kube-tower process as JSON (encode_task / decode_task, encode_result / decode_result).

When every role runs in the process, the LocalRunner hands the tasks to the Worker of the process,
without encoding them (the reports are updated in place, so the UI shows the results as they come).
In the distributed mode, the QueueRunner queues the tasks of the roles that run elsewhere in Valkey
(bus.py, ADR 0003): worker and trivy processes read them there (internal.TaskPuller) and send the results back.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from redis.exceptions import RedisError

from kube_tower.bus import Bus, Message, pack, unpack
from kube_tower.models import ChartReport, ImageReport, VulnerabilityReport, decode, encode
from kube_tower.registry.auth import AuthResult
from kube_tower.trivy import TrivyStatus

if TYPE_CHECKING:
    from collections.abc import Callable

    from kube_tower.worker import Worker

log = logging.getLogger(__name__)

RETRY = (1, 2, 5, 10, 30)  # seconds before asking Valkey again after an error (the last one repeats)


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


@dataclass
class TrivyAdminTask:
    """Administration of Trivy in a trivy process: read its status, or (`update_db`) refresh its databases first."""

    update_db: bool = False


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
    # Whether the registries accepted the credentials, as seen by the process that ran the task
    registry_auth: list[AuthResult] = field(default_factory=list)


@dataclass
class CheckChartsResult:
    charts: list[ChartReport]
    registry_auth: list[AuthResult] = field(default_factory=list)


@dataclass
class ScanVulnerabilitiesResult:
    vulnerabilities: list[VulnerabilityReport | None]  # one per image of the task, in order
    errors: list[str] = field(default_factory=list)


@dataclass
class TrivyAdminResult:
    available: bool
    binary: str
    cached: int  # images whose results this process keeps
    status: TrivyStatus | None = None
    error: str | None = None  # why the databases could not be refreshed


type Task = CollectTask | CheckImagesTask | CheckChartsTask | ScanVulnerabilitiesTask | TrivyAdminTask
type Result = CollectResult | CheckImagesResult | CheckChartsResult | ScanVulnerabilitiesResult | TrivyAdminResult

# Task kind: its task and result types, and the role that runs it.
KINDS: dict[str, tuple[type, type, str]] = {
    "collect": (CollectTask, CollectResult, "worker"),
    "check-images": (CheckImagesTask, CheckImagesResult, "worker"),
    "check-charts": (CheckChartsTask, CheckChartsResult, "worker"),
    "scan-vulnerabilities": (ScanVulnerabilitiesTask, ScanVulnerabilitiesResult, "trivy"),
    "trivy-admin": (TrivyAdminTask, TrivyAdminResult, "trivy"),
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


TASK_GROUP = "processes"  # the consumer group of the task streams: the worker and trivy processes
RESULT_GROUP = "controller"  # the consumer group of the results: the active controller
ATTEMPTS = 3  # times a task lost with its process is queued, before its scan gets an error
WATCH = 5.0  # seconds between two looks at the tasks being run


def task_stream(role: str) -> str:
    return f"tasks:{role}"


class QueueRunner:
    """The distributed mode: the tasks of the roles of this process run here; the others go through Valkey
    (bus.py, ADR 0003) to the processes with their role, and this controller waits for their results.

    A task is a message of the stream of its role (`tasks:worker`, `tasks:trivy`), read by one process of
    the role (consumer group), which acknowledges it once it sent the result to the `results` stream. A task
    read and not answered within `timeout` (its process died) is queued again, ATTEMPTS times at most.

    Each controller has its own epoch: the one taking over empties the streams of the previous one, whose
    scans died with it, and ignores the results that come late for them.

    The futures of the tasks live in the event loop that runs `serve` (`loop`): the scans, which run in
    their own threads and event loops, hand their tasks over to it.
    """

    def __init__(
        self,
        worker: Worker,
        local_roles: set[str],
        bus: Bus,
        timeout: float = 30 * 60,
        context: Callable[[], dict[str, Any]] | None = None,
        on_task: Callable[[str, str], None] | None = None,
    ):
        self.worker = worker
        self.local_roles = local_roles
        self.bus = bus
        self.timeout = timeout
        # What a process needs with each task, e.g. the credentials of the image pull secrets.
        self.context = context or dict
        # Told which process runs a task (its kind), or finished one (empty kind): the Administration page.
        self.on_task = on_task or (lambda process, kind: None)
        self.epoch = uuid.uuid4().hex[:12]
        self.waiting: dict[str, asyncio.Future] = {}  # by task id, until its result came
        self.messages: dict[str, tuple[str, str, int]] = {}  # message id -> task id, role, attempt
        self._ids = itertools.count(1)
        self._ready = asyncio.Event()  # the streams of this epoch exist
        self.loop: asyncio.AbstractEventLoop | None = None  # set when the process starts

    async def run(self, task: Task) -> Any:
        if role_of(task) in self.local_roles:
            return await self.worker.execute(task)
        if self.loop is None or self.loop is asyncio.get_running_loop():
            return await self._queued(task)
        # Cancelling the scan cancels the queued task too.
        return await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(self._queued(task), self.loop))

    async def _queued(self, task: Task) -> Any:
        role, kind = role_of(task), kind_of(task)
        task_id = f"{kind}-{next(self._ids)}"
        future = self.waiting[task_id] = asyncio.get_running_loop().create_future()
        message_id = None
        try:
            # In a thread: encoding a large task (images and their usages) takes a while, and this event loop
            # also serves, in a process with the ui role, the pages.
            data = await asyncio.to_thread(pack, {**encode_task(task), "context": self.context()})
            await self._ready.wait()
            message_id = await self.bus.send(task_stream(role), data, id=task_id, kind=kind, epoch=self.epoch)
            self.messages[message_id] = (task_id, role, 1)
            answer = await future
            if "error" in answer:
                raise TaskFailed(f"task {task_id} failed: {answer['error']}")
            result = await asyncio.to_thread(decode_result, kind, answer["result"])
            # The registries answered the worker pod: the Administration page of the controller shows it.
            if auth := getattr(result, "registry_auth", None):
                self.worker.registry_auth.merge(auth)
            return result
        finally:  # done, or the scan was cancelled: forget it
            self.waiting.pop(task_id, None)
            for mid in [m for m, (tid, _, _) in self.messages.items() if tid == task_id]:
                del self.messages[mid]
                if not future.done() or future.cancelled():  # cancelled: no process needs to run it anymore
                    with contextlib.suppress(Exception):
                        await self.bus.done(task_stream(role), TASK_GROUP, mid)

    async def serve(self) -> None:
        """Run by the active controller: empty the streams of the previous one, then read the results and
        watch the tasks being run."""
        errors = 0
        while True:  # e.g. Valkey still starting along with the controller
            try:
                for role in ("worker", "trivy"):
                    await self.bus.reset(task_stream(role), TASK_GROUP)
                await self.bus.reset("results", RESULT_GROUP)
                break
            except RedisError as exc:
                await backoff(errors, "cannot prepare the task streams in Valkey, the scans wait", exc)
                errors += 1
        self._ready.set()
        log.info("tasks of the worker and trivy processes go through Valkey (epoch %s)", self.epoch)
        await asyncio.gather(self._read_results(), self._watch())

    async def _read_results(self) -> None:
        errors = 0
        while True:
            try:
                messages = await self.bus.receive("results", RESULT_GROUP, self.epoch, block=WATCH, count=10)
                errors = 0
            except RedisError as exc:
                await backoff(errors, "cannot read the results of the tasks from Valkey", exc)
                errors += 1
                continue
            for message in messages:
                await self._result(message)

    async def _result(self, message: Message) -> None:
        task_id, source = message.fields.get("id", ""), message.fields.get("source", "")
        self.on_task(source, "")
        future = self.waiting.get(task_id)
        if message.fields.get("epoch") != self.epoch or future is None or future.done():
            log.info(
                "result of task %s from %s not needed anymore (the scan is over, or a previous controller's)", task_id, source
            )
        else:
            try:
                future.set_result(await asyncio.to_thread(unpack, message.data))
            except Exception as exc:  # noqa: BLE001 - e.g. sent by another version of kube-tower
                future.set_result({"error": f"result not readable: {exc}"})
        with contextlib.suppress(RedisError):
            await self.bus.done("results", RESULT_GROUP, message.id)

    async def _watch(self) -> None:
        while True:
            try:
                await self.check_tasks()
            except RedisError as exc:
                log.warning("cannot read the tasks being run from Valkey: %s", exc)
            await asyncio.sleep(WATCH)

    async def check_tasks(self) -> None:
        """Tell which process runs which task, and queue again a task not answered within the timeout."""
        for role in ("worker", "trivy"):
            for pending in await self.bus.pending(task_stream(role), TASK_GROUP):
                if (known := self.messages.get(pending.id)) is None:
                    continue
                task_id, _, attempt = known
                self.on_task(pending.consumer, task_id.rsplit("-", 1)[0])
                if pending.idle < self.timeout:
                    continue
                del self.messages[pending.id]
                if attempt >= ATTEMPTS:
                    log.error("task %s not answered %d times: given up", task_id, attempt)
                    if (future := self.waiting.get(task_id)) is not None and not future.done():
                        future.set_result({"error": f"not answered within {self.timeout:.0f}s, {attempt} times"})
                    await self.bus.done(task_stream(role), TASK_GROUP, pending.id)
                    continue
                log.warning(
                    "task %s not answered by %s within %.0fs: given to another process", task_id, pending.consumer, self.timeout
                )
                if (new_id := await self.bus.requeue(task_stream(role), TASK_GROUP, pending.id)) is not None:
                    self.messages[new_id] = (task_id, role, attempt + 1)


async def backoff(errors: int, message: str, exc: Exception) -> None:
    delay = RETRY[min(errors, len(RETRY) - 1)]
    log.warning("%s (%s): trying again in %ss", message, exc, delay)
    await asyncio.sleep(delay)
