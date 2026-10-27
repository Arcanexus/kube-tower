"""The exchanges between the processes of the distributed mode, all through Valkey (bus.py, ADR 0003).

- Worker and trivy processes read their tasks from Valkey and send their results back there (TaskPuller;
  the controller side is tasks.QueueRunner).
- The active controller publishes the state that the `ui` processes show (its snapshot, what runs), and
  runs the actions of their users (Publisher; the ui side is backend.RemoteBackend).
- Every process tells it is alive and ships its new log lines (Reporter), for the Administration and Logs
  pages; the active controller reads the processes (Publisher).

No process calls another one: they only know the address of Valkey.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import time
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Any

from redis.exceptions import RedisError

from kube_tower import __version__
from kube_tower.bus import Bus, Message, id_of, pack, seq_of, unpack
from kube_tower.clusters import ClusterRegistry
from kube_tower.config import Settings
from kube_tower.logbuffer import LogBuffer, LogLine
from kube_tower.models import decode, encode, to_json
from kube_tower.processes import STARTED, process_name
from kube_tower.tasks import RETRY, TASK_GROUP, CollectTask, backoff, decode_task, encode_result, role_of, task_stream
from kube_tower.worker import Worker

if TYPE_CHECKING:
    from kube_tower.backend import LocalBackend

log = logging.getLogger(__name__)

WAIT = 20.0  # seconds a process waits for a task (or the controller for an action) before asking Valkey again
CLUSTERS_TTL = 300  # seconds before a worker reads the cluster list again
HEARTBEAT = 5.0  # seconds between two reports of a process
PRESENCE_TTL = 3 * HEARTBEAT  # seconds the key of a process lives without a new report
STOPPED_TTL = 60.0  # seconds the key of a stopped process tells it stopped
REPORT_LINES = 500  # log lines sent at most per report
LOG_LINES = 10000  # log lines kept in Valkey, of every process
PUBLISH = 2.0  # seconds between two publications of the state, when it changed
ACTION_GROUP = "controller"  # the consumer group of the actions: the active controller


async def read_log_lines(bus: Bus, after: int = 0) -> list[LogLine]:
    """The log lines of every process after this sequence number (the last LOG_LINES at first), oldest first."""
    messages = await (bus.read("logs", id_of(after), LOG_LINES) if after else bus.last("logs", LOG_LINES))

    def decoded() -> list[LogLine]:
        return [dataclasses.replace(decode(LogLine, json.loads(m.data)), seq=seq_of(m.id)) for m in messages]

    return await asyncio.to_thread(decoded)


class Publisher:
    """The active controller: publishes in Valkey the state that the ui processes show, runs the actions they
    send, and keeps the list of the processes from their keys (Administration page)."""

    def __init__(self, backend: LocalBackend, bus: Bus):
        self.backend, self.bus = backend, bus
        self.name = process_name()
        self._published: bytes | None = None
        self._snapshot_revision: int | None = None
        self._actions: set[asyncio.Task] = set()

    async def serve(self) -> None:
        errors = 0
        while True:  # e.g. Valkey still starting along with the controller
            try:
                await self.bus.reset("actions", ACTION_GROUP)  # those of a previous controller were not answered in time
                break
            except RedisError as exc:
                await backoff(errors, "cannot prepare the actions stream in Valkey, the ui processes wait", exc)
                errors += 1
        await asyncio.gather(self._loop(self.publish, PUBLISH), self._loop(self.read_processes, HEARTBEAT), self._read_actions())

    async def _loop(self, step: Callable[[], Any], every: float) -> None:
        failing = False
        while True:
            try:
                await step()
                failing = False
            except RedisError as exc:
                if not failing:
                    log.warning("cannot reach Valkey (%s): the ui processes show the last state published", exc)
                failing = True
            await asyncio.sleep(every)

    async def publish(self) -> None:
        """Publish the state when it changed, with the snapshot when it has a new revision."""
        backend = self.backend
        revision = backend.scanner.revision
        # Encoded in threads: a large snapshot would hold the event loop meanwhile.
        data = await asyncio.to_thread(lambda: to_json(backend.state(revision)))
        snapshot = None
        if revision != self._snapshot_revision:
            snapshot = await asyncio.to_thread(lambda: pack(encode(backend.snapshot)))
        elif data == self._published:
            return
        await self.bus.publish_state(data, snapshot)
        self._published, self._snapshot_revision = data, revision

    async def read_processes(self) -> None:
        for name, raw in (await self.bus.processes()).items():
            try:
                info = json.loads(raw)
                started = datetime.fromisoformat(info["started_at"]) if info.get("started_at") else None
                self.backend.process_registry.seen(name, info["roles"], info["state"], info.get("version", ""), started)
            except (ValueError, KeyError, TypeError) as exc:  # e.g. written by another version of kube-tower
                log.debug("process %s: unreadable report (%s)", name, exc)

    async def _read_actions(self) -> None:
        errors = 0
        while True:
            try:
                messages = await self.bus.receive("actions", ACTION_GROUP, self.name, block=WAIT, count=10)
                errors = 0
            except RedisError as exc:
                delay = RETRY[min(errors, len(RETRY) - 1)]
                errors += 1
                log.warning("cannot read the actions of the ui processes from Valkey (%s): trying again in %ss", exc, delay)
                await asyncio.sleep(delay)
                continue
            for message in messages:  # each apart: an action can wait for a trivy process
                task = asyncio.create_task(self.run_action(message))
                self._actions.add(task)
                task.add_done_callback(self._actions.discard)

    async def run_action(self, message: Message) -> None:
        try:
            asked = unpack(message.data)
            answer = {"result": await self.backend.action(asked["name"], asked.get("params") or {})}
        except Exception as exc:  # noqa: BLE001 - told to the ui process that asked
            answer = {"error": f"{type(exc).__name__}: {exc}"}
        with contextlib.suppress(RedisError):
            await self.publish()  # the page shows what the action started
        try:
            await self.bus.reply(message, pack(answer))
            await self.bus.done("actions", ACTION_GROUP, message.id)
        except RedisError as exc:
            log.warning("answer to the action of a ui process lost: %s", exc)


class TaskPuller:
    """A worker or trivy process: runs the tasks of its roles, read one at a time from Valkey (ADR 0003)."""

    def __init__(
        self,
        settings: Settings,
        worker: Worker,
        roles: list[str],
        bus: Bus,
        registry: ClusterRegistry | None = None,
    ):
        self.settings = settings
        self.worker = worker
        self.roles = [r for r in roles if r in ("worker", "trivy")]
        self.bus = bus
        self.registry = registry or ClusterRegistry(settings.clusters)
        self._clusters_read = 0.0
        self._errors = 0  # reads from Valkey that failed in a row
        self._generations: dict[str, int] | None = None  # of the Trivy actions, see apply_generations
        self.source = process_name()

    async def run_forever(self) -> None:
        log.info("reading %s tasks from Valkey", " and ".join(self.roles))
        while True:
            await self.pull()

    async def pull(self, wait: float = WAIT) -> bool:
        """Wait for a task of the roles of this process and run it. Whether one was run."""
        streams = [task_stream(role) for role in self.roles]
        try:
            messages = await self.bus.receive(streams, TASK_GROUP, self.source, block=wait)
        except RedisError as exc:
            delay = RETRY[min(self._errors, len(RETRY) - 1)]
            self._errors += 1
            log.warning("cannot read the tasks from Valkey (%s): trying again in %ss", exc, delay)
            await asyncio.sleep(delay)
            return False
        self._errors = 0
        for message in messages:
            await self.answer(message)
        return bool(messages)

    async def answer(self, message: Message) -> None:
        task_id = message.fields.get("id", message.id)
        try:
            data = await asyncio.to_thread(unpack, message.data)
            result = await self.execute(data)
            answer: dict[str, Any] = {"result": await asyncio.to_thread(encode_result, result)}
        except Exception as exc:  # noqa: BLE001 - reported to the controller, the loop goes on
            log.exception("task %s failed", task_id)
            answer = {"error": f"{type(exc).__name__}: {exc}"}
        payload = await asyncio.to_thread(pack, answer)
        fields = {"id": task_id, "epoch": message.fields.get("epoch", ""), "source": self.source}
        for delay in (*RETRY, None):
            try:
                await self.bus.send("results", payload, **fields)
                await self.bus.done(message.stream, TASK_GROUP, message.id)
                return
            except RedisError as exc:
                if delay is None:
                    log.error("result of task %s lost: %s (the controller gives the task to another process)", task_id, exc)
                    return
                log.warning("cannot send the result of task %s (%s): trying again in %ss", task_id, exc, delay)
                await asyncio.sleep(delay)

    async def execute(self, data: dict[str, Any]) -> Any:
        task = await asyncio.to_thread(decode_task, data)
        if role_of(task) not in self.roles:
            raise ValueError(f"a {role_of(task)} task was sent to a process with roles {', '.join(self.roles)}")
        context = data.get("context") or {}
        self.worker.pull_secrets = {host: tuple(pair) for host, pair in (context.get("pull_secrets") or {}).items()}
        self.apply_generations(context.get("trivy"))
        if isinstance(task, CollectTask):
            await self.read_clusters(task.cluster)
        return await self.worker.execute(task)

    def apply_generations(self, generations: dict[str, int] | None) -> None:
        """A newer generation than the last one seen: the Administration page cleared the Trivy results or
        asked for a database update (the first one seen is only noted)."""
        if not generations:
            return
        seen, self._generations = self._generations, dict(generations)
        if seen is None:
            return
        if generations.get("cache", 0) > seen.get("cache", 0):
            count = len(self.worker.trivy.cache)
            log.info("Trivy results cache cleared (%d image(s)), as asked on the Administration page", count)
            self.worker.trivy.cache.clear()
        if generations.get("db", 0) > seen.get("db", 0):
            log.info("the Trivy databases are refreshed before the next scan, as asked on the Administration page")
            self.worker.trivy.expire_databases()

    async def read_clusters(self, needed: str) -> None:
        """The clusters a collect task may name, read again when one is unknown or the list is old."""
        if needed in self.worker.clusters and time.monotonic() - self._clusters_read < CLUSTERS_TTL:
            return
        clusters, statuses = await asyncio.to_thread(self.registry.discover)
        reachable = {s.name for s in statuses if s.reachable}
        self.worker.clusters = {c.name: c for c in clusters if c.name in reachable}
        self._clusters_read = time.monotonic()


class Reporter:
    """Every process of the distributed mode: tells every HEARTBEAT seconds that it is alive, with its roles
    (Administration page), and ships its new log lines (Logs page of every UI) to Valkey."""

    def __init__(self, bus: Bus, buffer: LogBuffer, roles: list[str], state: Callable[[], str | None] = lambda: "ok"):
        self.bus, self.buffer, self.roles = bus, buffer, roles
        # The state to report, None when the process is not listed this way (the active controller lists itself).
        self.state = state
        self.name = process_name()
        self.sent = 0  # sequence number of the last log line sent

    async def run_forever(self) -> None:
        try:
            while True:
                await self.report()
                await asyncio.sleep(HEARTBEAT)
        except asyncio.CancelledError:  # the pod stops (e.g. a rollout): not lost, gone
            await self.report(stopped=True)
            raise

    async def report(self, stopped: bool = False) -> bool:
        """Whether Valkey got the report. Failures are not logged: the other loops of the process already
        tell when Valkey cannot be reached."""
        lines = self.buffer.since(self.sent)[:REPORT_LINES]
        state = "stopped" if stopped else self.state()
        try:
            if lines:
                await self.bus.send_many("logs", [json.dumps(encode(line)).encode() for line in lines], LOG_LINES)
            if state is not None:
                info = {"roles": self.roles, "state": state, "version": __version__, "started_at": STARTED.isoformat()}
                await self.bus.set_process(self.name, json.dumps(info).encode(), STOPPED_TTL if stopped else PRESENCE_TTL)
        except RedisError:
            return False
        if lines:
            self.sent = lines[-1].seq
        return True
