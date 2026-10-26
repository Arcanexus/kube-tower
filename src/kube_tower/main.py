"""FastAPI entrypoint: `uvicorn --factory kube_tower.main:create_app`."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import sys
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from kubernetes import client

from kube_tower.administration import Administration
from kube_tower.backend import LocalBackend, RemoteBackend
from kube_tower.clusters import current_namespace
from kube_tower.config import Settings, check_roles, internal_token, load_settings
from kube_tower.election import LeaderElection
from kube_tower.internal import TaskPuller, create_internal_app
from kube_tower.logbuffer import LogBuffer
from kube_tower.logger import get_logger
from kube_tower.models import encode
from kube_tower.scanner import Scanner
from kube_tower.store import redis_store
from kube_tower.tasks import QueueRunner
from kube_tower.web import api, metrics, ui
from kube_tower.web.csrf import add_csrf_protection
from kube_tower.worker import Worker

# The scans run in threads, which share the GIL with the web server: hand it over every millisecond
# (instead of 5) so that the pages keep answering quickly while a scan uses the CPU.
SWITCH_INTERVAL = 0.001
LAG_CHECK, LAG_WARNING = 0.5, 1.0  # seconds


async def watch_event_loop() -> None:
    """Log when the web server could not answer for a while (the pages and the API wait meanwhile)."""
    log = logging.getLogger(__name__)
    while True:
        start = time.monotonic()
        await asyncio.sleep(LAG_CHECK)
        if (lag := time.monotonic() - start - LAG_CHECK) > LAG_WARNING:
            log.warning(
                "the web server was blocked for %.1fs: pages and API calls answered late meanwhile (a scan using the "
                "CPU: give the pod more CPU, or report it with the logs around this line)",
                lag,
            )


class InternalServer(uvicorn.Server):
    """The internal API server, run next to the main one: the main server handles the signals."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield

    async def serve(self, sockets=None) -> None:
        try:
            await super().serve(sockets)
        except (OSError, SystemExit) as exc:  # e.g. the port is taken
            if not self.should_exit:
                # The workers and UIs could not reach this controller: stop, Kubernetes restarts the pod.
                logging.getLogger(__name__).critical("the internal API cannot listen, stopping: %s", exc)
                os.kill(os.getpid(), signal.SIGTERM)


def _election(settings: Settings, scanner: Scanner) -> LeaderElection:
    local = scanner.registry.local_client()
    if local is None:
        raise ValueError("internal.leaderElection needs the Kubernetes API of the cluster kube-tower runs in")
    return LeaderElection(settings.internal.lease_name, current_namespace(), client.CoordinationV1Api(local))


def create_app(
    settings: Settings | None = None,
    scanner: Scanner | None = None,
    background: bool = True,
    administration: Administration | None = None,
    election: LeaderElection | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    sys.setswitchinterval(SWITCH_INTERVAL)
    logger = get_logger("kube_tower", level=settings.logs.level.upper(), format_type=settings.logs.format)
    # Last log lines, shown on the Logs page of the UI.
    log_buffer = LogBuffer()
    logger.addHandler(log_buffer)
    roles = check_roles(settings.roles)
    runs: list = []  # what the process runs in the background: coroutine functions
    internal: InternalServer | None = None
    backend: LocalBackend | RemoteBackend | None = None
    if "controller" in roles:
        scanner = scanner or Scanner(settings, store=redis_store(settings) if settings.redis.url else None)
        runs.append(scanner.run_forever)
        administration = administration or Administration(scanner)
        backend = LocalBackend(scanner, administration, log_buffer)
        if settings.distributed:
            # The tasks of the roles that run elsewhere are pulled over the internal API.
            scanner.runner = runner = QueueRunner(
                scanner.worker,
                set(roles) & {"worker", "trivy"},
                settings.internal.task_timeout,
                context=lambda: {"pull_secrets": encode(scanner.pull_secrets), "trivy": administration.generations},
            )
            config = uvicorn.Config(
                create_internal_app(runner, internal_token(settings), backend),
                host="0.0.0.0",  # noqa: S104 - reached by the other pods; NetworkPolicies keep it internal
                port=settings.internal.port,
                log_level="warning",
                access_log=False,
                lifespan="off",
            )
            internal = InternalServer(config)
            runs.append(internal.serve)
        if settings.internal.leader_election:
            # Standby replicas run nothing until they hold the Lease (and are not ready: no Service routes to them).
            election = election or _election(settings, scanner)
            controller_runs, runs = runs, []

            async def lead() -> None:
                await asyncio.gather(*(run() for run in controller_runs))

            runs.append(lambda: election.run(lead))
    else:
        if pulled := [r for r in roles if r in ("worker", "trivy")]:
            runs.append(TaskPuller(settings, Worker(settings), pulled).run_forever)
        if "ui" in roles:  # the pages show the state of the controller, read over its internal API
            backend = RemoteBackend(settings)
            runs.append(backend.run_forever)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if isinstance(getattr(scanner, "runner", None), QueueRunner):
            scanner.runner.loop = asyncio.get_running_loop()
        tasks = [asyncio.create_task(run()) for run in [*runs, watch_event_loop]] if background else []
        yield
        if internal is not None:
            internal.should_exit = True
        for task in tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="kube-tower", lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.settings = settings
    app.state.log_buffer = log_buffer
    # The web layer only talks to this backend (see backend.py), never to the scanner directly.
    app.state.backend = backend
    app.state.election = election if "controller" in roles and settings.internal.leader_election else None
    if "controller" in roles:
        app.state.scanner, app.state.administration = scanner, administration
        app.include_router(metrics.router)  # the metrics of the snapshot: once, from the controller
    if "ui" in roles:
        app.include_router(api.router)
        ui.mount(app)
        add_csrf_protection(app)
    else:
        app.include_router(api.probes)  # no UI or API: only the health probes
    log = logging.getLogger(__name__)
    log.info("kube-tower started with roles %s (refresh every %ss)", ", ".join(roles), settings.refresh_interval)
    if internal is not None:
        log.info("internal API listening on port %s", settings.internal.port)
    return app
