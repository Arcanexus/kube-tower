"""Server-rendered UI (Jinja2 templates + htmx, no JavaScript build step)."""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from urllib.parse import urlencode

import yaml
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from kube_tower import __version__
from kube_tower.administration import unused_node_images
from kube_tower.config import Settings
from kube_tower.models import ChartDependency, ImageRef, ImageReport, Severity, Status, Usage
from kube_tower.registry.auth import resolve_credentials
from kube_tower.scanner import chart_key, image_key
from kube_tower.versions import versioning
from kube_tower.web.metrics import image_update
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


@dataclasses.dataclass
class UsageNode:
    """A line of the "Used by" tree: a cluster, a namespace, a workload, a pod or the nodes caching the image."""

    kind: str  # Cluster | Namespace | Deployment | ... | Pod | Nodes
    name: str
    containers: list[str] = dataclasses.field(default_factory=list)
    node: str | None = None  # pods: where they run
    children: list[UsageNode] = dataclasses.field(default_factory=list)

    def add(self, kind: str, name: str) -> UsageNode:
        child = next((c for c in self.children if (c.kind, c.name) == (kind, name)), None)
        if child is None:
            child = UsageNode(kind, name)
            self.children.append(child)
        return child

    @property
    def pods(self) -> int:
        return sum(c.pods for c in self.children) + (self.kind == "Pod")


_JOB_RE = re.compile(r"^(?P<cron>.+)-\d+$")  # Jobs of a CronJob are named <cronjob>-<scheduled time>


def usage_tree(usages: list[Usage]) -> list[UsageNode]:
    """Where an image is used, as a tree: cluster > namespace > workload > pods, then the nodes caching it.

    Pods hang under their workload (the Deployment of their ReplicaSet, the CronJob of their Job);
    a pod without a known workload is shown on its own. Several containers of a pod or workload using
    the image are listed on the same line.
    """
    clusters: dict[str, UsageNode] = {}
    for u in sorted(usages, key=lambda u: (u.cluster, u.namespace or "", u.kind == "Pod", u.kind, u.name)):
        cluster = clusters.setdefault(u.cluster, UsageNode("Cluster", u.cluster))
        if u.kind == "Node":
            cluster.add("Nodes", "image cached on").add("Node", u.name)
            continue
        namespace = cluster.add("Namespace", u.namespace or "")
        if u.kind != "Pod":
            item = namespace.add(u.kind, u.name)
        else:
            parent = namespace
            if u.owner:
                kind, _, name = u.owner.partition("/")
                if (
                    kind == "Job"
                    and (m := _JOB_RE.match(name))
                    and any((c.kind, c.name) == ("CronJob", m["cron"]) for c in namespace.children)
                ):
                    kind, name = "CronJob", m["cron"]
                parent = namespace.add(kind, name)
            item = parent.add("Pod", u.name)
            item.node = u.node
        if u.container and u.container not in item.containers:
            item.containers.append(u.container)
    for cluster in clusters.values():  # the nodes after the namespaces
        cluster.children.sort(key=lambda c: c.kind == "Nodes")
    return list(clusters.values())


# Lists load by pages of this many items while the user scrolls down (infinite scroll).
PAGE_SIZE = 30


@dataclasses.dataclass
class Column:
    """A sortable column of a list: the sort value of an item, and the first direction of a click."""

    key: Callable
    descending: bool = False


def natural(value) -> tuple:
    """Sort value that orders numbers by value inside text: "1.9" < "1.10", "v2" < "v10"."""
    return tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part) for part in re.split(r"(\d+)", str(value).lower()) if part
    )


@dataclasses.dataclass
class Listing:
    """One page of a list, sorted on the server: the items to show and the URL of the next page."""

    items: list
    total: int
    sort: str  # index of the sort column, "" for the default order
    direction: str  # ascending | descending
    more: str | None  # relative URL of the next page, None on the last one
    shown: int = 0  # rows shown once this page is added

    @property
    def remaining(self) -> int:
        return self.total - self.shown

    def aria_sort(self, index: int) -> str:
        return self.direction if self.sort == str(index) else ""


def list_page(request: Request, path: str, items: Sequence, columns: list[Column]) -> Listing:
    """Sort `items` as asked (`sort` = column index, `dir`), and keep the page at `offset`."""
    params = request.query_params
    sort, direction = params.get("sort", ""), params.get("dir", "")
    items = list(items)
    if sort.isdigit() and int(sort) < len(columns):
        column = columns[int(sort)]
        if direction not in ("ascending", "descending"):
            direction = "descending" if column.descending else "ascending"
        values = [(column.key(item), item) for item in items]
        # Empty values last, whatever the direction (like the previous client-side sort).
        filled = [v for v in values if v[0] not in ("", None, ())]
        empty = [item for key, item in values if key in ("", None, ())]
        filled.sort(key=lambda v: v[0], reverse=direction == "descending")
        items = [item for _, item in filled] + empty
    else:
        sort, direction = "", ""
    offset = int(params["offset"]) if params.get("offset", "").isdigit() else 0
    more = None
    if offset + PAGE_SIZE < len(items):
        query = {k: v for k, v in params.items() if k != "offset"} | {"offset": offset + PAGE_SIZE}
        more = f"{path}?{urlencode(query)}"
    page = items[offset : offset + PAGE_SIZE]
    return Listing(page, len(items), sort, direction, more, offset + len(page))


def _fixable(r: ImageReport) -> int:
    return r.vulnerabilities.fixable if r.vulnerabilities and not r.vulnerabilities.message else -1


# Sortable columns of the lists, in the order of their headers.
IMAGE_COLUMNS = [
    Column(lambda r: str(r.image)),
    Column(lambda r: natural(r.image.tag or "")),
    Column(lambda r: natural(r.latest_tag or "")),
    Column(lambda r: STATUS_RANK[r.status]),
    Column(lambda r: len(r.usages), descending=True),
]
CHART_COLUMNS = [
    Column(lambda c: natural(c.application)),
    Column(lambda c: natural(c.chart)),
    Column(lambda c: natural(c.version or "")),
    Column(lambda c: natural(c.latest_version or "")),
    Column(lambda c: STATUS_RANK[c.worst_status]),
]
VULNERABILITY_COLUMNS = [
    Column(lambda r: r.image.name),
    Column(lambda r: natural(r.image.tag or "")),
    Column(lambda r: vulnerability_score(r), descending=True),
    Column(_fixable, descending=True),
    Column(lambda r: r.vulnerabilities.source if r.vulnerabilities else ""),
    Column(lambda r: len(r.usages), descending=True),
]


def vulnerability_sort_key(report: ImageReport) -> tuple:
    """Most vulnerable images first, then failed scans, then images not scanned (yet), then by name."""
    vulns = report.vulnerabilities
    if vulns is None or vulns.message:
        return (2 if vulns is None else 1, [], str(report.image))
    counts = vulns.counts()
    return (0, [-counts[s] for s in Severity], str(report.image))


def plural(n: int, word: str, many: str = "") -> str:
    """`3 | plural("image")` -> "3 images", `1 | plural("image")` -> "1 image"."""
    return f"{n} {word if n == 1 else many or word + 's'}"


def duration(seconds: float) -> str:
    """Human duration: 42 s, 3 min, 6 h, 2 days."""
    seconds = round(seconds)
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{round(seconds / 60)} min"
    if seconds < 172800:
        hours = seconds / 3600
        return f"{hours:g} h" if hours == int(hours) else f"{hours:.1f} h"
    return f"{round(seconds / 86400)} days"


def short_digest(value: str | None) -> str:
    """sha256:0123456789abcdef… -> sha256:0123456789ab (enough to compare at a glance)."""
    if not value:
        return ""
    algo, _, hexa = value.partition(":")
    return f"{algo}:{hexa[:12]}" if hexa else value[:19]


def image_versions(r: ImageReport) -> tuple[tuple[str, str], tuple[str, str]]:
    """((current tag, current digest), (latest tag, latest digest)) of an image, to show both side by side.
    The current digest is the pinned one, else the running one, else the one published for the tag.
    The latest is unknown ("") when the registry could not tell.
    """
    tag = r.image.tag or ""
    running = sorted(r.running_digests)
    current = (tag, r.image.digest or (running[0] if running else "") or r.tag_digest or "")
    if r.latest_tag:
        latest = (r.latest_tag, r.latest_digest or "")
    elif r.status == Status.OUTDATED and r.latest_digest:  # same tag pushed again (latest, 1.25...)
        latest = (tag, r.latest_digest)
    elif r.status == Status.UP_TO_DATE:
        latest = (tag, r.tag_digest or current[1])
    else:
        latest = ("", "")
    return current, latest


# Settings shown as durations on the Settings page (values in seconds).
DURATION_KEYS = {"refreshInterval", "requestTimeout", "timeout", "rescanInterval"}


def _flatten(data, prefix: str = "") -> list[tuple[str, object]]:
    rows = []
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict) and value:
            rows += _flatten(value, path)
        else:
            rows.append((path, value))
    return rows


def _show(key: str, value) -> str:
    if value in ("", None, [], {}):
        return "—"
    if key.rsplit(".", 1)[-1] in DURATION_KEYS and isinstance(value, int | float):
        return f"{duration(value)} ({value} s)"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list | dict):
        return yaml.safe_dump(value, default_flow_style=True, width=1000).strip()
    return str(value)


def settings_sections(settings: Settings) -> list[tuple[str, list[tuple[str, str, bool]]]]:
    """Settings grouped by top-level section: (section, [(key, shown value, changed from the default)])."""
    current, default = _camel(dataclasses.asdict(settings)), dict(_flatten(_camel(dataclasses.asdict(Settings()))))
    general = [(k, v) for k, v in current.items() if not isinstance(v, dict)]
    sections = [("general", general)] if general else []
    sections += [(k, _flatten(v)) for k, v in current.items() if isinstance(v, dict)]
    return [
        (
            name,
            [
                (key, _show(key, value), default.get(key if name == "general" else f"{name}.{key}", value) != value)
                for key, value in rows
            ],
        )
        for name, rows in sections
    ]


def warnings(request: Request) -> list[str]:
    """Problems of kube-tower itself (not of the last scan), shown with the scan errors of the status pill."""
    found = []
    vulns = request.app.state.settings.vulnerabilities
    scanner, administration = request.app.state.scanner, request.app.state.administration
    if vulns.enabled and vulns.trivy.enabled:
        status = administration.trivy_status
        if not scanner.trivy.available:
            found.append(
                f"Trivy: binary {scanner.trivy.settings.binary!r} not found, images without a Trivy Operator report "
                "are not scanned for vulnerabilities (see Administration)."
            )
        elif status and status.message:
            found.append(f"Trivy: {status.message} (see Administration).")
    return found


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
templates.env.globals.update(versioning=versioning, image_versions=image_versions, usage_tree=usage_tree)
templates.env.filters.update(plural=plural, duration=duration, short_digest=short_digest)


def mount(app: FastAPI) -> None:
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    def render(request: Request, name: str, **context) -> HTMLResponse:
        scanner = request.app.state.scanner
        # htmx requests only get the table fragment, full page loads get the layout.
        partial = request.headers.get("HX-Request") == "true" and request.headers.get("HX-Target") == "results"
        # The next page of a list (infinite scroll): only its rows.
        offset = request.query_params.get("offset", "")
        rows_only = offset.isdigit() and int(offset) > 0
        return templates.TemplateResponse(
            request,
            f"{name}.html",
            {
                "snapshot": scanner.snapshot,
                "scanning": scanner.running,
                "checking_versions": scanner.checking_versions,
                "warnings": warnings(request),
                "partial": partial,
                "rows_only": rows_only,
                **context,
            },
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
        running = bool(request.query_params.get("running"))
        # Set by the links of the Synthesis: a registry, a kind of pending update (major, minor...).
        registry, update = request.query_params.get("registry", ""), request.query_params.get("update", "")
        chips = [
            (name, label, value)
            for name, label, value in (("registry", "Registry", registry), ("update", "Update", update))
            if value
        ]
        # Counters ignore the status filter: they are the buttons that set it.
        matching = [
            r
            for r in request.app.state.scanner.snapshot.images
            if _matches(str(r.image), q)
            and (not cluster or cluster in r.clusters)
            and (not running or r.running)
            and (not registry or r.image.registry == registry)
            and (not update or image_update(r) == update)
        ]
        listing = list_page(request, "images", [r for r in matching if not status or r.status.value == status], IMAGE_COLUMNS)
        return render(
            request,
            "images",
            tab="images",
            listing=listing,
            rows=listing.items,
            matching=matching,
            q=q,
            status=status,
            cluster=cluster,
            running=running,
            chips=chips,
        )

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
        listing = list_page(request, "vulnerabilities", rows, VULNERABILITY_COLUMNS)
        return render(
            request,
            "vulnerabilities",
            tab="vulnerabilities",
            listing=listing,
            rows=listing.items,
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
        listing = list_page(
            request, "charts", [c for c in matching if not status or c.worst_status.value == status], CHART_COLUMNS
        )
        return render(
            request,
            "charts",
            tab="charts",
            listing=listing,
            rows=listing.items,
            matching=matching,
            q=q,
            status=status,
            cluster=cluster,
        )

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
        summaries = {c.name: c for c in summarize(request.app.state.scanner.snapshot).clusters}
        return render(request, "clusters", tab="clusters", summaries=summaries)

    @app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
    async def settings(request: Request):
        # Settings only hold references to secrets (paths, env var names), never their values.
        settings = request.app.state.settings
        rendered = yaml.safe_dump(_camel(dataclasses.asdict(settings)), sort_keys=False)
        scanner = request.app.state.scanner
        _, credentials = resolve_credentials(settings.registries, pull_secrets=scanner.pull_secrets)
        auth = {c.registry: scanner.registry_auth.get(c.registry) for c in credentials}
        return render(
            request,
            "settings",
            tab="settings",
            settings_yaml=rendered,
            sections=settings_sections(settings),
            credentials=credentials,
            auth=auth,
        )

    def render_administration(request: Request, notice: str = "", error: str = "", full: bool = False) -> HTMLResponse:
        """The Administration page, or only its actions (`#administration`) for htmx. While an action runs the
        actions poll themselves (`polling=1`); the poll that sees them all over reloads the page.
        """
        scanner, administration = request.app.state.scanner, request.app.state.administration
        images, vulnerabilities, charts = scanner.failed_items()
        busy = bool(scanner.locked or scanner.rescanning or administration.running)
        response = templates.TemplateResponse(
            request,
            "administration.html" if full else "_administration.html",
            {
                "tab": "administration",
                "snapshot": scanner.snapshot,
                "scanning": scanner.running,
                "checking_versions": scanner.checking_versions,
                "warnings": warnings(request),
                "partial": False,
                "scanner": scanner,
                "m": administration,
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

    @app.get("/administration", response_class=HTMLResponse, include_in_schema=False)
    async def administration(request: Request):
        m, trivy = request.app.state.administration, request.app.state.settings.vulnerabilities
        if m.trivy_status is None and trivy.enabled and trivy.trivy.enabled:
            await m.refresh_trivy_status()
        fragment = request.headers.get("HX-Request") == "true" and request.headers.get("HX-Target") == "administration"
        return render_administration(request, full=not fragment)

    @app.get("/maintenance", include_in_schema=False)
    async def maintenance():
        """Former name of the Administration page: bookmarks still work (relative, whatever the sub-path)."""
        return RedirectResponse("administration", status_code=301)

    @app.post("/administration/{action}", response_class=HTMLResponse, include_in_schema=False)
    async def administration_action(request: Request, action: str):
        scanner, m = request.app.state.scanner, request.app.state.administration
        notice = error = None
        if action == "scan":
            error = None if scanner.trigger() else "a scan or an administration action is already running"
            notice = "Full scan started."
        elif action == "retry-failed":
            error, notice = scanner.retry_failed(), "Retry of the failed items started."
        elif action == "trivy-db":
            error, notice = m.update_trivy_db(), "Trivy database update started."
        elif action == "trivy-status":
            await m.refresh_trivy_status()
            notice = "Trivy status read again."
        elif action in ("trivy-cache", "trivy-cache-scan"):
            notice = f"Trivy results cache cleared ({plural(m.clear_trivy_cache(), 'image')})."
            if action == "trivy-cache-scan":
                started = scanner.trigger()
                notice += " Full scan started." if started else " A scan is already running: the next one scans every image."
        elif action == "connectivity":
            error, notice = m.test_connectivity(), "Connectivity test started."
        else:
            return Response(status_code=404)
        return render_administration(request, "" if error else notice, error or "")

    @app.get("/status", response_class=HTMLResponse, include_in_schema=False)
    async def scan_status(request: Request):
        response = render(request, "_status")
        if request.query_params.get("polling") and not request.app.state.scanner.running:
            # The scan the page was waiting for is over: reload it to show the new results.
            response.headers["HX-Refresh"] = "true"
        return response
