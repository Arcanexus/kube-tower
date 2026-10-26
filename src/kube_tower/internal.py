"""The internal API of the distributed mode (ADR 0002): worker and trivy processes pull tasks from the
controller and send their results back; `ui` processes read the state of the controller (its snapshot,
what runs) and send it the actions of the users (see backend.RemoteBackend).

The other processes also report to the controller every few seconds (Reporter): who they are, and their
new log lines, for the Administration and Logs pages.

The controller serves it on its own port (internal.port), apart from the UI, behind a token shared by
the processes: the tasks carry the credentials of image pull secrets, it must never be exposed.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import time
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

from kube_tower import __version__
from kube_tower.clusters import ClusterRegistry
from kube_tower.config import Settings, internal_token
from kube_tower.logbuffer import LogBuffer, LogLine
from kube_tower.models import decode, encode, to_json
from kube_tower.processes import STARTED, process_name
from kube_tower.tasks import CollectTask, QueueRunner, decode_task, encode_result, role_of
from kube_tower.worker import Worker

if TYPE_CHECKING:
    from kube_tower.backend import LocalBackend

log = logging.getLogger(__name__)

PREFIX = "/internal/v1"
WAIT = 20.0  # seconds a pull waits for a task before the worker asks again
RETRY = (1, 2, 5, 10, 30)  # seconds before asking the controller again after an error (the last one repeats)
CLUSTERS_TTL = 300  # seconds before a worker reads the cluster list again
HEARTBEAT = 5.0  # seconds between two reports of a process to the controller
REPORT_LINES = 500  # log lines sent at most per report


class Pull(BaseModel):
    roles: list[str]
    wait: float = WAIT
    source: str = ""  # the process asking (its pod name)


class StateRequest(BaseModel):
    revision: int = -1  # the revision of the snapshot the UI process has


class LogsRequest(BaseModel):
    after: int = 0  # the sequence number of the last line the UI process has


class Answer(BaseModel):
    result: dict[str, Any] | None = None
    error: str | None = None
    source: str = ""  # the process that ran the task (its pod name)


class Heartbeat(BaseModel):
    """A process tells the controller it is alive (Reporter), with its log lines since the last report."""

    name: str
    roles: list[str]
    state: str = "ok"  # standby for a controller waiting for the Lease, stopped when the process stops
    version: str = ""
    started_at: datetime | None = None
    logs: list[dict[str, Any]] = []


def create_internal_app(runner: QueueRunner, token: str, backend: LocalBackend | None = None) -> FastAPI:
    def authorized(request: Request) -> None:
        sent = request.headers.get("Authorization", "")
        if not hmac.compare_digest(sent.encode(), f"Bearer {token}".encode()):
            raise HTTPException(401, "invalid internal API token")

    app = FastAPI(title="kube-tower internal API", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.post(f"{PREFIX}/tasks/next", dependencies=[Depends(authorized)])
    async def next_task(pull: Pull) -> Any:
        task = await runner.next(set(pull.roles), min(max(pull.wait, 0), 60))
        if task is not None and backend is not None:
            backend.process_registry.task(pull.source, task["kind"])
        return task if task is not None else Response(status_code=204)

    @app.post(f"{PREFIX}/tasks/{{task_id}}/result", status_code=204, dependencies=[Depends(authorized)])
    async def task_result(task_id: str, request: Request) -> None:
        # Parsed in a thread: a result can weigh megabytes (the vulnerabilities of a batch of images).
        raw = await request.body()
        answer = await asyncio.to_thread(lambda: Answer.model_validate_json(raw))
        if backend is not None:
            backend.process_registry.task(answer.source)
        if answer.error is not None:
            done = runner.fail(task_id, answer.error)
        else:
            done = runner.complete(task_id, answer.result or {})
        if not done:  # given to another process meanwhile, or the scan is over
            raise HTTPException(404, f"task {task_id} is not waiting for a result")

    if backend is not None:

        @app.post(f"{PREFIX}/state", dependencies=[Depends(authorized)])
        async def state(asked: StateRequest) -> Response:
            # Encoded in a thread, to JSON too: a large snapshot would hold the event loop meanwhile.
            body = await asyncio.to_thread(lambda: to_json(backend.state(asked.revision)))
            return Response(body, media_type="application/json")

        @app.post(f"{PREFIX}/logs", dependencies=[Depends(authorized)])
        async def logs(asked: LogsRequest) -> list:
            return encode(await backend.log_lines(asked.after))

        @app.post(f"{PREFIX}/heartbeat", status_code=204, dependencies=[Depends(authorized)])
        async def heartbeat(beat: Heartbeat) -> None:
            backend.process_registry.seen(beat.name, beat.roles, beat.state, beat.version, beat.started_at)
            if beat.logs:
                backend.log_buffer.add(decode(list[LogLine], beat.logs), beat.name, beat.roles)

        @app.post(f"{PREFIX}/actions/{{name}}", dependencies=[Depends(authorized)])
        async def action(name: str, request: Request) -> dict:
            params = await request.json() if await request.body() else {}
            try:
                return {"result": await backend.action(name, params)}
            except ValueError as exc:
                raise HTTPException(404, str(exc)) from exc

    return app


class TaskPuller:
    """A worker or trivy process: runs the tasks of its roles, pulled from the controller one at a time."""

    def __init__(self, settings: Settings, worker: Worker, roles: list[str], registry: ClusterRegistry | None = None):
        self.settings = settings
        self.worker = worker
        self.roles = [r for r in roles if r in ("worker", "trivy")]
        self.registry = registry or ClusterRegistry(settings.clusters)
        self.url = settings.internal.controller_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {internal_token(settings)}", "User-Agent": "kube-tower"}
        self._clusters_read = 0.0
        self._errors = 0  # requests to the controller that failed in a row
        self._generations: dict[str, int] | None = None  # of the Trivy actions, see apply_generations
        self.source = process_name()

    async def run_forever(self) -> None:
        log.info("pulling %s tasks from the controller at %s", " and ".join(self.roles), self.url)
        async with httpx.AsyncClient(headers=self.headers, timeout=WAIT + 30) as http:
            while True:
                await self.pull(http)

    async def pull(self, http: httpx.AsyncClient, wait: float = WAIT) -> bool:
        """Ask the controller for a task and run it. Whether one was run."""
        try:
            pull = {"roles": self.roles, "wait": wait, "source": self.source}
            pulled = await http.post(f"{self.url}{PREFIX}/tasks/next", json=pull)
            pulled.raise_for_status()
        except httpx.HTTPError as exc:
            delay = RETRY[min(self._errors, len(RETRY) - 1)]
            self._errors += 1
            log.warning("cannot reach the controller at %s (%s): trying again in %ss", self.url, exc, delay)
            await asyncio.sleep(delay)
            return False
        self._errors = 0
        if pulled.status_code != 200:  # no task meanwhile
            return False
        await self.answer(http, pulled.json())
        return True

    async def answer(self, http: httpx.AsyncClient, data: dict[str, Any]) -> None:
        task_id = data["id"]
        try:
            result = await self.execute(data)
            answer: dict[str, Any] = {"result": await asyncio.to_thread(encode_result, result)}
        except Exception as exc:  # noqa: BLE001 - reported to the controller, the loop goes on
            log.exception("task %s failed", task_id)
            answer = {"error": f"{type(exc).__name__}: {exc}"}
        answer["source"] = self.source
        body = await asyncio.to_thread(lambda: json.dumps(answer).encode())
        headers = {"Content-Type": "application/json"}
        for delay in (*RETRY, None):
            try:
                sent = await http.post(f"{self.url}{PREFIX}/tasks/{task_id}/result", content=body, headers=headers)
                if sent.status_code == 404:
                    log.warning("result of task %s not needed anymore (given to another process, or the scan is over)", task_id)
                else:
                    sent.raise_for_status()
                return
            except httpx.HTTPError as exc:
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
    """A process other than the active controller: tells the controller every HEARTBEAT seconds that it is
    alive, with its roles and its new log lines (Administration and Logs pages of every UI)."""

    def __init__(
        self,
        settings: Settings,
        buffer: LogBuffer,
        roles: list[str],
        state: Callable[[], str | None] = lambda: "ok",
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.buffer, self.roles = buffer, roles
        # The state to report, None while there is nothing to report (e.g. this controller became active).
        self.state = state
        self.name = process_name()
        self.sent = 0  # sequence number of the last log line sent
        self.http = httpx.AsyncClient(
            base_url=settings.internal.controller_url.rstrip("/"),
            headers={"Authorization": f"Bearer {internal_token(settings)}", "User-Agent": "kube-tower"},
            timeout=10,
            transport=transport,
        )

    async def run_forever(self) -> None:
        try:
            while True:
                await self.report()
                await asyncio.sleep(HEARTBEAT)
        except asyncio.CancelledError:  # the pod stops (e.g. a rollout): not lost, gone
            await self.report(stopped=True)
            raise

    async def report(self, stopped: bool = False) -> bool:
        """Whether the controller got the report. Failures are not logged: the other loops of the process
        already tell when the controller cannot be reached."""
        if (state := self.state()) is None:
            self.sent = self.buffer.seq  # the active controller keeps its own lines
            return False
        lines = self.buffer.since(self.sent)[:REPORT_LINES]
        beat = {
            "name": self.name,
            "roles": self.roles,
            "state": "stopped" if stopped else state,
            "version": __version__,
            "started_at": STARTED.isoformat(),
            "logs": [encode(line) for line in lines],
        }
        try:
            answer = await self.http.post(f"{PREFIX}/heartbeat", json=beat)
            answer.raise_for_status()
        except httpx.HTTPError:
            return False
        if lines:
            self.sent = lines[-1].seq
        return True
