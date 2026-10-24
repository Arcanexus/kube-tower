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
from kube_tower.maintenance import unused_node_images
from kube_tower.models import ChartDependency, ImageRef, ImageReport, Severity, Status
from kube_tower.registry.auth import resolve_credentials
from kube_tower.scanner import chart_key, image_key
from kube_tower.web.summary import UPDATE_KINDS, WORST_ORDER, summarize

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


# Sort order of the Status columns (kube-tower.js): what needs attention first.
STATUS_RANK = {Status.OUTDATED: 0, Status.ERROR: 1, Status.UNKNOWN: 2, Status.UP_TO_DATE: 3}


def cve_terms(value: str) -> list[str]:
    """`CVE-2025-68121, 2024-` -> ["cve-2025-68121", "2024-"]: each term matches all or part of an ID."""
    return [t for t in re.split(r"[\s,;]+", value.lower()) if t]


def matching_vulnerabilities(report: ImageReport, terms: list[str]) -> list:
    if not terms or report.vulnerabilities is None:
        return []
    return [v for v in report.vulnerabilities.vulnerabilities if any(t in v.id.lower() for t in terms)]


def vulnerability_score(report: ImageReport) -> int:
    """Sort value of the Vulnerabilities column: by count of the most severe first."""
    if report.vulnerabilities is None or report.vulnerabilities.message:
        return -1
    counts = report.vulnerabilities.counts()
    return sum(counts[s] * 1000 ** (len(Severity) - i) for i, s in enumerate(Severity))


templates.env.globals.update(status_rank=STATUS_RANK, vulnerability_score=vulnerability_score)
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

    def render_detail(request: Request, name: str, key: tuple, **context) -> HTMLResponse:
        """A detail panel. While its item is rescanned the panel polls itself (`polling=1`); the poll
        that sees the rescan over tells the page (event kt-rescanned) to reload its results.
        """
        scanner = request.app.state.scanner
        rescanning = key in scanner.rescanning
        response = render(request, name, rescanning=rescanning, **context)
        if request.query_params.get("polling") and not rescanning:
            response.headers["HX-Trigger"] = "kt-rescanned"
        return response

    def filters(request: Request) -> tuple[str, str, str]:
        p = request.query_params
        return p.get("q", ""), p.get("status", ""), p.get("cluster", "")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/synthesis", response_class=HTMLResponse, include_in_schema=False)
    async def synthesis(request: Request):
        summary = summarize(request.app.state.scanner.snapshot)
        return render(request, "synthesis", tab="synthesis", summary=summary, update_kinds=UPDATE_KINDS, worst_order=WORST_ORDER)

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
        scanner = request.app.state.scanner
        if (report := scanner.snapshot.image(ref)) is None:
            return Response(status_code=404)
        can_scan = scanner.can_rescan_vulnerabilities(report)
        same_name = len(scanner.same_name_images(report))
        return render_detail(
            request, "_image_detail", image_key(report), r=report, can_rescan_vulnerabilities=can_scan, same_name=same_name
        )

    @app.get("/vulnerabilities", response_class=HTMLResponse, include_in_schema=False)
    async def vulnerabilities(request: Request):
        # The severity filter is named status, like on the other pages (counters set it).
        q, severity, cluster = filters(request)
        cve = request.query_params.get("cve", "")
        terms = cve_terms(cve)
        found = {}  # image reference -> its vulnerabilities whose ID matches the CVE filter
        for r in request.app.state.scanner.snapshot.images:
            if terms and (hits := matching_vulnerabilities(r, terms)):
                # One badge per ID (a CVE often affects several packages), most severe first
                unique = {}
                for v in sorted(hits, key=lambda v: list(Severity).index(v.severity)):
                    unique.setdefault(v.id, v)
                found[str(r.image)] = list(unique.values())
        # Counters ignore the severity filter: they are the buttons that set it.
        matching = sorted(
            (
                r
                for r in request.app.state.scanner.snapshot.images
                if _matches(str(r.image), q) and (not cluster or cluster in r.clusters) and (not terms or str(r.image) in found)
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
            cve=cve,
            found=found,
        )

    @app.get("/vulnerabilities/detail", response_class=HTMLResponse, include_in_schema=False)
    async def vulnerability_detail(request: Request, ref: str = "", cve: str = ""):
        scanner = request.app.state.scanner
        if (report := scanner.snapshot.image(ref)) is None:
            return Response(status_code=404)
        can_scan = scanner.can_rescan_vulnerabilities(report)
        highlighted = {v.id for v in matching_vulnerabilities(report, cve_terms(cve))}
        return render_detail(
            request,
            "_vulnerability_detail",
            image_key(report),
            r=report,
            can_rescan_vulnerabilities=can_scan,
            same_name=len(scanner.same_name_images(report)),
            cve=cve,
            highlighted=highlighted,
        )

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
        if (report := request.app.state.scanner.snapshot.chart(cluster, namespace, app, chart)) is None:
            return Response(status_code=404)
        return render_detail(request, "_chart_detail", chart_key(report), c=report)

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

    def render_maintenance(request: Request, notice: str = "", error: str = "", full: bool = False) -> HTMLResponse:
        """The Maintenance page, or only its actions (`#maintenance`) for htmx. While an action runs the
        actions poll themselves (`polling=1`); the poll that sees them all over reloads the page.
        """
        scanner, maintenance = request.app.state.scanner, request.app.state.maintenance
        images, vulnerabilities, charts = scanner.failed_items()
        busy = bool(scanner.locked or scanner.rescanning or maintenance.running)
        response = templates.TemplateResponse(
            request,
            "maintenance.html" if full else "_maintenance.html",
            {
                "tab": "maintenance",
                "snapshot": scanner.snapshot,
                "scanning": scanner.running,
                "partial": False,
                "scanner": scanner,
                "m": maintenance,
                "busy": busy,
                "failed": {"images": images, "vulnerabilities": vulnerabilities, "charts": charts},
                "unused": unused_node_images(scanner.snapshot),
                "trivy_settings": request.app.state.settings.vulnerabilities,
                "notice": notice,
                "error": error,
            },
        )
        if request.query_params.get("polling") and not busy:
            response.headers["HX-Refresh"] = "true"
        return response

    @app.get("/maintenance", response_class=HTMLResponse, include_in_schema=False)
    async def maintenance(request: Request):
        m, trivy = request.app.state.maintenance, request.app.state.settings.vulnerabilities
        if m.trivy_status is None and trivy.enabled and trivy.trivy.enabled:
            await m.refresh_trivy_status()
        fragment = request.headers.get("HX-Request") == "true" and request.headers.get("HX-Target") == "maintenance"
        return render_maintenance(request, full=not fragment)

    @app.post("/maintenance/{action}", response_class=HTMLResponse, include_in_schema=False)
    async def maintenance_action(request: Request, action: str):
        scanner, m = request.app.state.scanner, request.app.state.maintenance
        notice = error = None
        if action == "scan":
            error = None if scanner.trigger() else "a scan or a maintenance action is already running"
            notice = "Full scan started."
        elif action == "retry-failed":
            error, notice = scanner.retry_failed(), "Retry of the failed items started."
        elif action == "trivy-db":
            error, notice = m.update_trivy_db(), "Trivy database update started."
        elif action == "trivy-status":
            await m.refresh_trivy_status()
            notice = "Trivy status read again."
        elif action in ("trivy-cache", "trivy-cache-scan"):
            notice = f"Trivy results cache cleared ({m.clear_trivy_cache()} image(s))."
            if action == "trivy-cache-scan":
                started = scanner.trigger()
                notice += " Full scan started." if started else " A scan is already running: the next one scans every image."
        elif action == "connectivity":
            error, notice = m.test_connectivity(), "Connectivity test started."
        else:
            return Response(status_code=404)
        return render_maintenance(request, "" if error else notice, error or "")

    @app.get("/status", response_class=HTMLResponse, include_in_schema=False)
    async def scan_status(request: Request):
        response = render(request, "_status")
        if request.query_params.get("polling") and not request.app.state.scanner.running:
            # The scan the page was waiting for is over: reload it to show the new results.
            response.headers["HX-Refresh"] = "true"
        return response
