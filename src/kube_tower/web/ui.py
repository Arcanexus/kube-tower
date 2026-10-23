"""Server-rendered UI (Jinja2 templates + htmx, no JavaScript build step)."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import yaml
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from kube_tower import __version__
from kube_tower.models import Status
from kube_tower.registry.auth import resolve_credentials

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.globals["version"] = __version__
templates.env.globals["Status"] = Status


def _camel(data):
    """Show settings with the camelCase keys used in config.yaml / Helm values."""
    if isinstance(data, dict):
        return {re.sub(r"_([a-z])", lambda m: m[1].upper(), k): _camel(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_camel(v) for v in data]
    return data


def _matches(text: str, query: str) -> bool:
    return not query or query.lower() in text.lower()


def mount(app: FastAPI) -> None:
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    def render(request: Request, name: str, **context) -> HTMLResponse:
        scanner = request.app.state.scanner
        # htmx requests only get the table fragment, full page loads get the layout.
        partial = request.headers.get("HX-Request") == "true" and request.headers.get("HX-Target") == "results"
        return templates.TemplateResponse(
            request,
            f"{name}.html",
            {"snapshot": scanner.snapshot, "scanning": scanner.running, "partial": partial, **context},
        )

    def filters(request: Request) -> tuple[str, str, str]:
        p = request.query_params
        return p.get("q", ""), p.get("status", ""), p.get("cluster", "")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/images", response_class=HTMLResponse, include_in_schema=False)
    async def images(request: Request):
        q, status, cluster = filters(request)
        rows = [
            r
            for r in request.app.state.scanner.snapshot.images
            if _matches(str(r.image), q) and (not status or r.status.value == status) and (not cluster or cluster in r.clusters)
        ]
        return render(request, "images", tab="images", rows=rows, q=q, status=status, cluster=cluster)

    @app.get("/charts", response_class=HTMLResponse, include_in_schema=False)
    async def charts(request: Request):
        q, status, cluster = filters(request)
        rows = [
            c
            for c in request.app.state.scanner.snapshot.charts
            if _matches(f"{c.application} {c.chart} {c.repository}", q)
            and (not status or c.worst_status.value == status)
            and (not cluster or c.cluster == cluster)
        ]
        return render(request, "charts", tab="charts", rows=rows, q=q, status=status, cluster=cluster)

    @app.get("/clusters", response_class=HTMLResponse, include_in_schema=False)
    async def clusters(request: Request):
        return render(request, "clusters", tab="clusters")

    @app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
    async def settings(request: Request):
        # Settings only hold references to secrets (paths, env var names), never their values.
        settings = request.app.state.settings
        rendered = yaml.safe_dump(_camel(dataclasses.asdict(settings)), sort_keys=False)
        _, credentials = resolve_credentials(settings.registries)
        return render(request, "settings", tab="settings", settings_yaml=rendered, credentials=credentials)

    @app.get("/status", response_class=HTMLResponse, include_in_schema=False)
    async def scan_status(request: Request):
        return render(request, "_status")
