"""FastAPI entrypoint: `uvicorn --factory kube_tower.main:create_app`."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI

from kube_tower.administration import Administration
from kube_tower.config import Settings, load_settings
from kube_tower.logbuffer import LogBuffer
from kube_tower.logger import get_logger
from kube_tower.scanner import Scanner
from kube_tower.web import api, metrics, ui
from kube_tower.web.csrf import add_csrf_protection

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


def create_app(
    settings: Settings | None = None,
    scanner: Scanner | None = None,
    background: bool = True,
    administration: Administration | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    sys.setswitchinterval(SWITCH_INTERVAL)
    logger = get_logger("kube_tower", level=settings.logs.level.upper(), format_type=settings.logs.format)
    # Last log lines, shown on the Logs page of the UI.
    log_buffer = LogBuffer()
    logger.addHandler(log_buffer)
    scanner = scanner or Scanner(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        tasks = [asyncio.create_task(scanner.run_forever()), asyncio.create_task(watch_event_loop())] if background else []
        yield
        for task in tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="kube-tower", lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.state.settings = settings
    app.state.scanner = scanner
    app.state.administration = administration or Administration(scanner)
    app.state.log_buffer = log_buffer
    app.include_router(api.router)
    app.include_router(metrics.router)
    ui.mount(app)
    add_csrf_protection(app)
    logging.getLogger(__name__).info("kube-tower started (refresh every %ss)", settings.refresh_interval)
    return app
