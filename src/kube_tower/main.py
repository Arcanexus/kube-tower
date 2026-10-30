"""FastAPI entrypoint: `uvicorn --factory kube_tower.main:create_app`."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import sys
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from kubernetes import client

from kube_tower.administration import Administration
from kube_tower.auth import Authenticator, ensure_secret
from kube_tower.backend import LocalBackend, RemoteBackend
from kube_tower.bus import Bus, connect
from kube_tower.clusters import current_namespace
from kube_tower.config import Settings, check_roles, load_settings
from kube_tower.election import LeaderElection, PodLabel
from kube_tower.internal import Publisher, Reporter, TaskPuller
from kube_tower.logbuffer import LogBuffer
from kube_tower.logger import get_logger
from kube_tower.models import encode
from kube_tower.processes import Processes, process_name
from kube_tower.scanner import Scanner
from kube_tower.store import redis_store
from kube_tower.tasks import QueueRunner
from kube_tower.web import api, metrics, ui
from kube_tower.web.csrf import add_csrf_protection
from kube_tower.web.dex import add_dex_proxy
from kube_tower.web.login import add_login
from kube_tower.worker import Worker

# The scans run in threads, which share the GIL with the web server: hand it over every millisecond
# (instead of 5) so that the pages keep answering quickly while a scan uses the CPU.
SWITCH_INTERVAL = 0.001
LAG_CHECK, LAG_WARNING = 0.5, 1.0  # seconds


async def watch_event_loop(ui: bool = True) -> None:
    """Log when the event loop could not run for a while: in a process with the ui role, the pages and the API
    wait meanwhile (a warning); in a worker or trivy process only its task pulls and reports do."""
    log = logging.getLogger(__name__)
    while True:
        start = time.monotonic()
        await asyncio.sleep(LAG_CHECK)
        if (lag := time.monotonic() - start - LAG_CHECK) <= LAG_WARNING:
            continue
        if ui:
            log.warning(
                "the web server was blocked for %.1fs: pages and API calls answered late meanwhile (a scan using the "
                "CPU: give the pod more CPU, or report it with the logs around this line)",
                lag,
            )
        else:
            log.info("the event loop was busy for %.1fs (a task using the CPU): no page is served by this process", lag)


def _election(settings: Settings, scanner: Scanner) -> LeaderElection:
    local = scanner.registry.local_client()
    if local is None:
        raise ValueError("internal.leaderElection needs the Kubernetes API of the cluster kube-tower runs in")
    namespace, pod = current_namespace(), os.environ.get("POD_NAME") or socket.gethostname()
    label = PodLabel(client.CoreV1Api(local), namespace, pod) if settings.internal.label_pod else None
    return LeaderElection(settings.internal.lease_name, namespace, client.CoordinationV1Api(local), identity=pod, label=label)


AUTH_SECRET_RETRY = 30  # seconds


async def keep_auth_secret(settings: Settings, scanner: Scanner, auth: Authenticator | None) -> None:
    """Controller: create the auth Secret when it is missing (admin password, session key), then hand its
    values to the ui of this process until the kubelet mounts it."""
    log = logging.getLogger(__name__)
    local = scanner.registry.local_client()
    if local is None:
        log.warning(
            "auth.enabled: no Kubernetes API of the cluster kube-tower runs in, the auth Secret is not created: "
            "mount one in %s (keys admin.password and session.key)",
            settings.auth.secret_dir,
        )
        return
    core, namespace = client.CoreV1Api(local), current_namespace()
    while True:
        try:
            data = await asyncio.to_thread(ensure_secret, core, namespace, settings.auth.secret_name)
        except client.ApiException as exc:
            log.error(
                "cannot read or create the auth Secret %s/%s: %s %s - the ServiceAccount needs get and create on "
                "this Secret (Helm chart: rbac.create=true), retry in %ss",
                namespace,
                settings.auth.secret_name,
                exc.status,
                exc.reason,
                AUTH_SECRET_RETRY,
            )
            await asyncio.sleep(AUTH_SECRET_RETRY)
            continue
        if auth is not None:
            auth.fallback = data
        return


def create_app(
    settings: Settings | None = None,
    scanner: Scanner | None = None,
    background: bool = True,
    administration: Administration | None = None,
    election: LeaderElection | None = None,
    bus: Bus | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    sys.setswitchinterval(SWITCH_INTERVAL)
    logger = get_logger("kube_tower", level=settings.logs.level.upper(), format_type=settings.logs.format)
    roles = check_roles(settings.roles)
    # Last log lines of this process, shown on the Logs page of the UI (distributed mode: shipped to Valkey too).
    log_buffer = LogBuffer(2000, source=process_name(), roles=roles)
    logger.addHandler(log_buffer)
    runs: list = []  # what the process runs in the background: coroutine functions
    backend: LocalBackend | RemoteBackend | None = None
    # Distributed mode: every exchange with the other processes goes through Valkey (ADR 0003).
    bus = (bus or connect(settings)) if settings.distributed else None
    auth = Authenticator(settings.auth) if settings.auth.enabled and "ui" in roles else None
    if "controller" in roles:
        scanner = scanner or Scanner(settings, store=redis_store(settings) if settings.redis.url else None)
        runs.append(scanner.run_forever)
        if settings.auth.enabled:
            runs.append(lambda: keep_auth_secret(settings, scanner, auth))
        administration = administration or Administration(scanner)
        backend = LocalBackend(
            scanner,
            administration,
            log_buffer,
            Processes(roles),
            state=lambda: "active" if election is None or election.leader else "standby",
            bus=bus,
        )
        if bus is not None:
            scanner.runner = runner = QueueRunner(
                scanner.worker,
                set(roles) & {"worker", "trivy"},
                bus,
                settings.internal.task_timeout,
                context=lambda: {"pull_secrets": encode(scanner.pull_secrets), "trivy": administration.generations},
                on_task=backend.process_registry.task,
            )
            runs += [runner.serve, Publisher(backend, bus).serve]
        if settings.internal.leader_election:
            # Standby replicas run nothing until they hold the Lease (the Service routes to the active one only).
            election = election or _election(settings, scanner)
            controller_runs, runs = runs, []

            async def lead() -> None:
                await asyncio.gather(*(run() for run in controller_runs))

            runs.append(lambda: election.run(lead))
        if bus is not None:  # a standby tells it is there; the active controller lists itself
            state = lambda: None if election is None or election.leader else "standby"  # noqa: E731
            runs.append(Reporter(bus, log_buffer, roles, state).run_forever)
    elif bus is not None:
        runs.append(Reporter(bus, log_buffer, roles).run_forever)  # tells it is there, ships its log lines
        if pulled := [r for r in roles if r in ("worker", "trivy")]:
            runs.append(TaskPuller(settings, Worker(settings), pulled, bus).run_forever)
        if "ui" in roles:  # the pages show the state that the controller publishes
            backend = RemoteBackend(settings, bus)
            runs.append(backend.run_forever)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if isinstance(getattr(scanner, "runner", None), QueueRunner):
            scanner.runner.loop = asyncio.get_running_loop()
        watch = lambda: watch_event_loop(ui="ui" in roles)  # noqa: E731
        tasks = [asyncio.create_task(run()) for run in [*runs, watch]] if background else []
        yield
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
        if auth is not None:
            add_login(app, auth)
            if settings.auth.dex_url:
                add_dex_proxy(app, settings.auth.dex_url, settings.auth.oidc.issuer)
    else:
        app.include_router(api.probes)  # no UI or API: only the health probes
    log = logging.getLogger(__name__)
    log.info("kube-tower started with roles %s (refresh every %ss)", ", ".join(roles), settings.refresh_interval)
    return app
