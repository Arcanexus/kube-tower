"""Server-rendered UI (Jinja2 templates + htmx, no JavaScript build step)."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import yaml
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from kube_tower import __version__
from kube_tower.models import ChartDependency, ImageRef, ImageReport, Severity, Status
from kube_tower.registry.auth import resolve_credentials
from kube_tower.web.summary import UPDATE_KINDS, summarize

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.globals["version"] = __version__
templates.env.globals["Status"] = Status
templates.env.globals["Severity"] = Severity

LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def _camel(data):
    """Show settings with the camelCase keys used in config.yaml / Helm values."""
    if isinstance(data, dict):
        return {re.sub(r"_([a-z])", lambda m: m[1].upper(), k): _camel(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_camel(v) for v in data]
    return data


def _matches(text: str, query: str) -> bool:
    return not query or query.lower() in text.lower()


def registry_links(ref: ImageRef) -> list[tuple[str, str]]:
    """Web pages of the image on its registry, for the registries that have one."""
    repo = ref.repository
    if ref.registry == "docker.io":
        page = (
            f"https://hub.docker.com/_/{repo.removeprefix('library/')}"
            if repo.startswith("library/")
            else f"https://hub.docker.com/r/{repo}"
        )
        return [("Docker Hub", page), ("Tags", f"{page}/tags")]
    if ref.registry == "ghcr.io":
        return [("GitHub Packages", f"https://ghcr.io/{repo}")]
    if ref.registry == "quay.io":
        return [("Quay", f"https://quay.io/repository/{repo}"), ("Tags", f"https://quay.io/repository/{repo}?tab=tags")]
    if ref.registry == "public.ecr.aws":
        return [("ECR Public Gallery", f"https://gallery.ecr.aws/{repo}")]
    if ref.registry == "mcr.microsoft.com":
        return [("Microsoft Artifact Registry", f"https://mcr.microsoft.com/artifact/mar/{repo}")]
    return []


def chart_links(chart) -> list[tuple[str, str]]:
    links = []
    repo = chart.repository
    if repo.startswith(("https://", "http://")):
        links.append(("Git repository" if chart.source_type == "git" else "Helm repository", repo.removesuffix(".git")))
    if chart.source_type != "git":
        links.append(("Search on Artifact Hub", f"https://artifacthub.io/packages/search?ts_query_web={chart.chart}"))
    return links


def dependency_tree(dependencies: list[ChartDependency], prefix: str = "") -> list[tuple[str, ChartDependency]]:
    """Flatten a subchart tree into (connector, dependency) rows: `├─ `, `│  └─ `..."""
    rows = []
    for i, dep in enumerate(dependencies):
        last = i == len(dependencies) - 1
        rows.append((prefix + ("└─ " if last else "├─ "), dep))
        rows += dependency_tree(dep.dependencies, prefix + ("   " if last else "│  "))
    return rows


def vulnerability_sort_key(report: ImageReport) -> tuple:
    """Most vulnerable images first, then failed scans, then images not scanned (yet), then by name."""
    vulns = report.vulnerabilities
    if vulns is None or vulns.message:
        return (2 if vulns is None else 1, [], str(report.image))
    counts = vulns.counts()
    return (0, [-counts[s] for s in Severity], str(report.image))


templates.env.globals.update(registry_links=registry_links, chart_links=chart_links, dependency_tree=dependency_tree)


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
    @app.get("/synthesis", response_class=HTMLResponse, include_in_schema=False)
    async def synthesis(request: Request):
        summary = summarize(request.app.state.scanner.snapshot)
        return render(request, "synthesis", tab="synthesis", summary=summary, update_kinds=UPDATE_KINDS)

    @app.get("/images", response_class=HTMLResponse, include_in_schema=False)
    async def images(request: Request):
        q, status, cluster = filters(request)
        # Counters ignore the status filter: they are the buttons that set it.
        matching = [
            r
            for r in request.app.state.scanner.snapshot.images
            if _matches(str(r.image), q) and (not cluster or cluster in r.clusters)
        ]
        rows = [r for r in matching if not status or r.status.value == status]
        return render(request, "images", tab="images", rows=rows, matching=matching, q=q, status=status, cluster=cluster)

    @app.get("/images/detail", response_class=HTMLResponse, include_in_schema=False)
    async def image_detail(request: Request, ref: str = ""):
        report = next((r for r in request.app.state.scanner.snapshot.images if str(r.image) == ref), None)
        if report is None:
            return Response(status_code=404)
        return render(request, "_image_detail", r=report)

    @app.get("/vulnerabilities", response_class=HTMLResponse, include_in_schema=False)
    async def vulnerabilities(request: Request):
        # The severity filter is named status, like on the other pages (counters set it).
        q, severity, cluster = filters(request)
        # Counters ignore the severity filter: they are the buttons that set it.
        matching = sorted(
            (
                r
                for r in request.app.state.scanner.snapshot.images
                if _matches(str(r.image), q) and (not cluster or cluster in r.clusters)
            ),
            key=vulnerability_sort_key,
        )
        counts = {id(r): r.vulnerabilities.counts() if r.vulnerabilities else {} for r in matching}
        affected = {s: sum(1 for r in matching if counts[id(r)].get(s)) for s in Severity}
        rows = [r for r in matching if not severity or counts[id(r)].get(Severity.parse(severity))]
        return render(
            request,
            "vulnerabilities",
            tab="vulnerabilities",
            rows=rows,
            matching=matching,
            q=q,
            severity=severity,
            cluster=cluster,
            affected=affected,
        )

    @app.get("/vulnerabilities/detail", response_class=HTMLResponse, include_in_schema=False)
    async def vulnerability_detail(request: Request, ref: str = ""):
        report = next((r for r in request.app.state.scanner.snapshot.images if str(r.image) == ref), None)
        if report is None:
            return Response(status_code=404)
        return render(request, "_vulnerability_detail", r=report)

    @app.get("/charts", response_class=HTMLResponse, include_in_schema=False)
    async def charts(request: Request):
        q, status, cluster = filters(request)
        matching = [
            c
            for c in request.app.state.scanner.snapshot.charts
            if _matches(f"{c.application} {c.chart} {c.repository}", q) and (not cluster or c.cluster == cluster)
        ]
        rows = [c for c in matching if not status or c.worst_status.value == status]
        return render(request, "charts", tab="charts", rows=rows, matching=matching, q=q, status=status, cluster=cluster)

    @app.get("/charts/detail", response_class=HTMLResponse, include_in_schema=False)
    async def chart_detail(request: Request, cluster: str = "", namespace: str = "", app: str = "", chart: str = ""):
        report = next(
            (
                c
                for c in request.app.state.scanner.snapshot.charts
                if (c.cluster, c.app_namespace, c.application, c.chart) == (cluster, namespace, app, chart)
            ),
            None,
        )
        if report is None:
            return Response(status_code=404)
        return render(request, "_chart_detail", c=report)

    def _log_lines(request: Request, after: int, level: str, q: str):
        """Lines after `after` matching the filters, and the sequence number to tail from."""
        minimum = LOG_LEVELS.index(level) if level in LOG_LEVELS else 0
        lines = request.app.state.log_buffer.since(after)
        matching = [
            line
            for line in lines
            if (LOG_LEVELS.index(line.level) if line.level in LOG_LEVELS else 0) >= minimum
            and _matches(f"{line.logger} {line.message}", q)
        ]
        return matching, lines[-1].seq if lines else after

    @app.get("/logs", response_class=HTMLResponse, include_in_schema=False)
    async def logs(request: Request, level: str = "INFO", q: str = ""):
        lines, after = _log_lines(request, 0, level, q)
        return render(request, "logs", tab="logs", lines=lines, after=after, level=level, q=q, levels=LOG_LEVELS)

    @app.get("/logs/tail", response_class=HTMLResponse, include_in_schema=False)
    async def logs_tail(request: Request, after: int = 0, level: str = "INFO", q: str = ""):
        lines, after = _log_lines(request, after, level, q)
        return render(request, "_log_tail", lines=lines, after=after, level=level, q=q)

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
        response = render(request, "_status")
        if request.query_params.get("polling") and not request.app.state.scanner.running:
            # The scan the page was waiting for is over: reload it to show the new results.
            response.headers["HX-Refresh"] = "true"
        return response
