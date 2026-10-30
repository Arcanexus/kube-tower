"""Server-rendered UI (Jinja2 templates + htmx, no JavaScript build step)."""

from __future__ import annotations

import dataclasses
import hashlib
import os
import platform
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from urllib.parse import urlencode

import fastapi
import yaml
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.gzip import GZipMiddleware

from kube_tower import __version__
from kube_tower.config import DEFAULT_CONFIG_PATH, ROLES, Settings
from kube_tower.models import ChartDependency, ImageRef, ImageReport, SecurityKind, SecurityReport, Severity, Status, Usage
from kube_tower.processes import roles_status
from kube_tower.scanner import chart_key, image_key
from kube_tower.versions import versioning
from kube_tower.web.metrics import image_update
from kube_tower.web.summary import UPDATE_KINDS, fixable_critical, summarize, todo, workloads

HERE = Path(__file__).parent
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.globals["version"] = __version__
templates.env.globals["Status"] = Status
templates.env.globals["Severity"] = Severity
templates.env.globals["SecurityKind"] = SecurityKind
# Static files are cached by browsers for a year: their URLs change with their content (see asset()).
STATIC_VERSION = hashlib.sha256(b"".join(f.read_bytes() for f in sorted((HERE / "static").iterdir()) if f.is_file())).hexdigest()[
    :12
]
templates.env.globals["asset"] = lambda name: f"static/{name}?v={STATIC_VERSION}"


class CachedStaticFiles(StaticFiles):
    """Static files: versioned URLs (asset()) are immutable, the others are checked again each time."""

    async def get_response(self, path, scope):
        response = await super().get_response(path, scope)
        versioned = b"v=" in scope.get("query_string", b"")
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable" if versioned else "no-cache"
        return response


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
    Column(lambda r: vulnerability_score(r), descending=True),
    Column(lambda r: workloads(r), descending=True),
]
CHART_COLUMNS = [
    Column(lambda c: natural(c.chart)),
    Column(lambda c: natural(c.version or "")),
    Column(lambda c: natural(c.latest_version or "")),
    Column(lambda c: STATUS_RANK[c.worst_status]),
    Column(lambda c: c.repository),
    Column(lambda c: natural(c.application)),
]


def severity_score(counts: dict[Severity, int]) -> int:
    """Sort value of severity counts: by count of the most severe first."""
    return sum(counts[s] * 1000 ** (len(Severity) - i) for i, s in enumerate(Severity))


SECURITY_COLUMNS = [
    Column(lambda r: (r.resource_kind, natural(r.resource_name))),
    Column(lambda r: r.namespace or ""),
    Column(lambda r: r.kind.label),
    Column(lambda r: severity_score(r.counts()), descending=True),
    Column(lambda r: r.cluster),
    Column(lambda r: r.scanned_at.timestamp() if r.scanned_at else None, descending=True),
]


@dataclasses.dataclass
class SecurityBreakdown:
    """A tile of the Security page: the resources checked by one kind of report, and those with findings."""

    kind: SecurityKind
    total: int
    failing: int

    @property
    def pass_rate(self) -> int | None:
        return round((self.total - self.failing) * 100 / self.total) if self.total else None


def security_summary(reports: list[SecurityReport], cluster: str = "", top: int = 5) -> dict:
    """The Security card of the Overview: findings by severity, and the namespaces with the most severe ones."""
    findings = dict.fromkeys(Severity, 0)
    namespaces: dict[tuple[str, str], dict[Severity, int]] = {}
    for r in reports:
        if cluster and r.cluster != cluster:
            continue
        counts = r.counts()
        ns = namespaces.setdefault((r.cluster, r.namespace or ""), dict.fromkeys(Severity, 0))
        for s, n in counts.items():
            findings[s] += n
            ns[s] += n
    ranked = sorted(((k, v) for k, v in namespaces.items() if any(v.values())), key=lambda kv: (-severity_score(kv[1]), kv[0]))
    return {"findings": findings, "namespaces": ranked[:top]}


def security_urgency(report: SecurityReport) -> tuple:
    """Default order of the Security page: the most severe findings first."""
    return (-severity_score(report.counts()), report.cluster, report.namespace or "", report.resource_kind, report.resource_name)


def security_text(report: SecurityReport) -> str:
    """What the search of the Security page looks in: the resource, and the IDs and titles of its findings."""
    checks = " ".join(f"{c.id} {c.title}" for c in report.checks)
    resource = " ".join(filter(None, [report.namespace, report.container, report.image]))
    return f"{report.resource_kind}/{report.resource_name} {resource} {checks}"


def urgency(report: ImageReport) -> tuple:
    """Default order of the Images page: critical CVEs with a fix first, then outdated images (major first), then
    failed checks, then the most vulnerable, then by name."""
    update = image_update(report)
    rank = UPDATE_KINDS.index(update) if update in UPDATE_KINDS else len(UPDATE_KINDS)
    return (-fixable_critical(report), STATUS_RANK[report.status], rank, -vulnerability_score(report), str(report.image))


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


def image_size(r: ImageReport) -> tuple[int, int] | None:
    """(smallest, largest) size in bytes of an image as its nodes report it, None when no node pulled it.
    The sizes of the running digests when known: a tag pushed again, or another architecture, has its own size.
    """
    sizes = [r.sizes[d] for d in r.running_digests if d in r.sizes] or list(r.sizes.values())
    return (min(sizes), max(sizes)) if sizes else None


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
    backend = request.app.state.backend
    if vulns.enabled and vulns.trivy.enabled:
        status = backend.trivy_status
        if not backend.trivy_available:
            found.append(
                f"Trivy: binary {backend.trivy_binary!r} not found, images without a Trivy Operator report "
                "are not scanned for vulnerabilities (see Administration)."
            )
        elif status and status.message:
            found.append(f"Trivy: {status.message} (see Administration).")
    return found


# Sort order of the Status columns (kube-tower.js): what needs attention first.
STATUS_RANK = {Status.OUTDATED: 0, Status.ERROR: 1, Status.UNKNOWN: 2, Status.UP_TO_DATE: 3}


# Words of the Images search that look for vulnerability IDs: CVE-2025-68121, GHSA-…, 2024-…
VULNERABILITY_ID = re.compile(r"^(cve|ghsa|go|pysec|rustsec|gms|osv)-|^\d{4}-")


def split_query(value: str) -> tuple[list[str], list[str]]:
    """`nginx CVE-2025-68121, 2024-` -> (["nginx"], ["cve-2025-68121", "2024-"]): words that the image reference must
    all contain, and vulnerability IDs of which the image must have one (all or part of an ID)."""
    terms = [t for t in re.split(r"[\s,;]+", value.lower()) if t]
    return [t for t in terms if not VULNERABILITY_ID.match(t)], [t for t in terms if VULNERABILITY_ID.match(t)]


def global_filters(request: Request) -> tuple[str, bool]:
    """The Cluster and "Running only" filters of the top bar, common to every page. The browser keeps them in
    cookies (kube-tower.js); a query parameter (a link, a bookmark) wins. "Running only" is on by default, the
    last value wins (forms send running=0 before the checkbox)."""
    params, cookies = request.query_params, request.cookies
    cluster = params.get("cluster")
    if cluster is None:
        cluster = cookies.get("kt-cluster", "")
        if cluster not in {c.name for c in request.app.state.backend.snapshot.clusters}:
            cluster = ""  # a cluster that is gone
    return cluster, params.get("running", cookies.get("kt-running", "1")) != "0"


def _url(path: str, query: dict) -> str:
    """Relative URL with the non-empty parameters only."""
    query = {k: v for k, v in query.items() if v}
    return f"{path}?{urlencode(query)}" if query else path


# Tabs of the Administration page: (key, label, icon); Logs last.
ADMIN_TABS = {
    "scans": ("Scans and Trivy", "refresh"),
    "clusters": ("Clusters", "clusters"),
    "pods": ("Pods", "server"),
    "settings": ("Credentials and settings", "key"),
    "api": ("API", "box"),
    "logs": ("Logs", "logs"),
}
# Versions of the vendored front-end libraries (static/), shown on the About page.
HTMX_VERSION = (m := re.search(r'version:"([\d.]+)"', (HERE / "static" / "htmx.min.js").read_text())) and m[1] or ""


def matching_vulnerabilities(report: ImageReport, terms: list[str]) -> list:
    if not terms or report.vulnerabilities is None:
        return []
    return [v for v in report.vulnerabilities.vulnerabilities if any(t in v.id.lower() for t in terms)]


def vulnerability_score(report: ImageReport) -> int:
    """Sort value of the Vulnerabilities column: by count of the most severe first."""
    if report.vulnerabilities is None or report.vulnerabilities.message:
        return -1
    return severity_score(report.vulnerabilities.counts())


templates.env.globals.update(status_rank=STATUS_RANK, vulnerability_score=vulnerability_score, workloads=workloads)
templates.env.globals.update(image_update=image_update, fixable_critical=fixable_critical)
templates.env.globals.update(registry_links=registry_links, chart_links=chart_links, dependency_tree=dependency_tree)
templates.env.globals.update(versioning=versioning, image_versions=image_versions, image_size=image_size, usage_tree=usage_tree)
templates.env.filters.update(plural=plural, duration=duration, short_digest=short_digest)


def mount(app: FastAPI) -> None:
    app.add_middleware(GZipMiddleware, minimum_size=1000)  # pages and static files are mostly text
    app.mount("/static", CachedStaticFiles(directory=HERE / "static"), name="static")

    def render(request: Request, name: str, **context) -> HTMLResponse:
        backend = request.app.state.backend
        # htmx requests only get the table fragment, full page loads get the layout.
        partial = request.headers.get("HX-Request") == "true" and request.headers.get("HX-Target") == "results"
        # The next page of a list (infinite scroll): only its rows.
        offset = request.query_params.get("offset", "")
        rows_only = offset.isdigit() and int(offset) > 0
        cluster, running = global_filters(request)
        return templates.TemplateResponse(
            request,
            f"{name}.html",
            {
                "cluster": cluster,
                "running": running,
                "snapshot": backend.snapshot,
                "scanning": backend.running,
                "checking_versions": backend.checking_versions,
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
        backend = request.app.state.backend
        rescanning = key in backend.rescanning
        response = render(request, name, rescanning=rescanning, **context)
        if request.query_params.get("polling") and not rescanning:
            response.headers["HX-Trigger"] = "kt-rescanned"
        return response

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def overview(request: Request):
        cluster, running = global_filters(request)
        snapshot = request.app.state.backend.snapshot
        summary = summarize(snapshot, running=running, cluster=cluster)
        items, total = todo(snapshot, running=running, cluster=cluster)
        return render(
            request,
            "overview",
            tab="overview",
            summary=summary,
            todo=items,
            todo_total=total,
            update_kinds=UPDATE_KINDS,
            security=security_summary(snapshot.security, cluster),
        )

    @app.get("/images", response_class=HTMLResponse, include_in_schema=False)
    async def images(request: Request):
        p = request.query_params
        q, status, severity, fixable = p.get("q", ""), p.get("status", ""), p.get("severity", ""), p.get("fixable", "") == "1"
        cluster, running = global_filters(request)
        # Set by the links of the Overview: a registry, a kind of pending update (major, minor...).
        registry, update = p.get("registry", ""), p.get("update", "")
        chips = [
            (name, label, value)
            for name, label, value in (("registry", "Registry", registry), ("update", "Update", update))
            if value
        ]
        words, terms = split_query(q)
        found = {}  # image reference -> its vulnerabilities whose ID matches a CVE of the search
        matching = []
        for r in request.app.state.backend.snapshot.images:
            text = str(r.image)
            if (
                all(w in text.lower() for w in words)
                and (not cluster or cluster in r.clusters)
                and (not running or r.running)
                and (not registry or r.image.registry == registry)
                and (not update or image_update(r) == update)
            ):
                if terms:
                    if not (hits := matching_vulnerabilities(r, terms)):
                        continue
                    # One badge per ID (a CVE often affects several packages), most severe first
                    unique = {}
                    for v in sorted(hits, key=lambda v: list(Severity).index(v.severity)):
                        unique.setdefault(v.id, v)
                    found[text] = list(unique.values())
                matching.append(r)
        # Counters ignore the filters they set: they are the buttons that set them.
        counts = {id(r): r.vulnerabilities.counts() if _fixable(r) >= 0 else {} for r in matching}
        affected = {s: sum(1 for r in matching if counts[id(r)].get(s)) for s in Severity}
        with_fix = sum(1 for r in matching if _fixable(r) > 0)
        level = Severity.parse(severity) if severity in Severity._value2member_map_ else None
        rows = [
            r
            for r in sorted(matching, key=urgency)
            if (not status or r.status.value == status)
            and (level is None or counts[id(r)].get(level))
            and (not fixable or _fixable(r) > 0)
        ]
        listing = list_page(request, "images", rows, IMAGE_COLUMNS)
        return render(
            request,
            "images",
            tab="images",
            listing=listing,
            rows=listing.items,
            matching=matching,
            q=q,
            status=status,
            severity=severity,
            fixable=fixable,
            affected=affected,
            with_fix=with_fix,
            found=found,
            chips=chips,
        )

    @app.get("/images/detail", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/vulnerabilities/detail", response_class=HTMLResponse, include_in_schema=False)
    async def image_detail(request: Request, ref: str = "", cve: str = ""):
        """One panel per image: versions, vulnerabilities and where it is used. `cve`: the CVEs searched on the
        Images page, listed first and highlighted."""
        backend = request.app.state.backend
        if (report := backend.snapshot.image(ref)) is None:
            return Response(status_code=404)
        _, terms = split_query(cve)
        return render_detail(
            request,
            "_image_detail",
            image_key(report),
            r=report,
            can_rescan_vulnerabilities=backend.can_rescan_vulnerabilities(report),
            same_name=len(backend.same_name_images(report)),
            cve=cve,
            highlighted={v.id for v in matching_vulnerabilities(report, terms)},
        )

    @app.get("/charts", response_class=HTMLResponse, include_in_schema=False)
    async def charts(request: Request):
        q, status = request.query_params.get("q", ""), request.query_params.get("status", "")
        cluster, _ = global_filters(request)
        matching = [
            c
            for c in request.app.state.backend.snapshot.charts
            if _matches(f"{c.application} {c.chart} {c.repository}", q) and (not cluster or c.cluster == cluster)
        ]
        listing = list_page(
            request, "charts", [c for c in matching if not status or c.worst_status.value == status], CHART_COLUMNS
        )
        subcharts = sum(1 for c in matching if c.status != Status.OUTDATED and c.worst_status == Status.OUTDATED)
        return render(
            request,
            "charts",
            tab="charts",
            listing=listing,
            rows=listing.items,
            matching=matching,
            q=q,
            status=status,
            outdated_subcharts=subcharts,
        )

    @app.get("/charts/detail", response_class=HTMLResponse, include_in_schema=False)
    async def chart_detail(request: Request, cluster: str = "", namespace: str = "", app: str = "", chart: str = ""):
        if (report := request.app.state.backend.snapshot.chart(cluster, namespace, app, chart)) is None:
            return Response(status_code=404)
        return render_detail(request, "_chart_detail", chart_key(report), c=report)

    @app.get("/security", response_class=HTMLResponse, include_in_schema=False)
    async def security(request: Request):
        p = request.query_params
        q, kind, severity = p.get("q", ""), p.get("kind", ""), p.get("severity", "")
        clean = p.get("all", "") == "1"  # also list the resources that pass every check
        cluster, _ = global_filters(request)
        snapshot = request.app.state.backend.snapshot
        matching = [r for r in snapshot.security if (not cluster or r.cluster == cluster) and _matches(security_text(r), q)]
        # The tiles and counters ignore the filter they set: they are the buttons that set it.
        level = Severity.parse(severity) if severity in Severity._value2member_map_ else None
        breakdown = [
            SecurityBreakdown(k, sum(1 for r in matching if r.kind == k), sum(1 for r in matching if r.kind == k and r.checks))
            for k in SecurityKind
        ]
        of_kind = [r for r in matching if not kind or r.kind.value == kind]
        by_severity = {s: sum(1 for r in of_kind if r.counts()[s]) for s in Severity}
        passing = sum(1 for r in of_kind if not r.checks)
        rows = [r for r in sorted(of_kind, key=security_urgency) if (clean or r.checks) and (level is None or r.counts()[level])]
        listing = list_page(request, "security", rows, SECURITY_COLUMNS)
        compliance = sorted(
            (c for c in snapshot.compliance if not cluster or c.cluster == cluster), key=lambda c: (c.title, c.cluster)
        )
        return render(
            request,
            "security",
            tab="security",
            listing=listing,
            rows=listing.items,
            q=q,
            kind=kind,
            severity=severity,
            clean=clean,
            breakdown=breakdown,
            by_severity=by_severity,
            passing=passing,
            compliance=compliance,
        )

    @app.get("/security/detail", response_class=HTMLResponse, include_in_schema=False)
    async def security_detail(
        request: Request,
        cluster: str = "",
        kind: str = "",
        namespace: str = "",
        rkind: str = "",
        name: str = "",
        container: str = "",
    ):
        snapshot = request.app.state.backend.snapshot
        if (report := snapshot.security_report((cluster, kind, namespace, rkind, name, container))) is None:
            return Response(status_code=404)
        return render(request, "_security_detail", r=report)

    @app.get("/security/compliance", response_class=HTMLResponse, include_in_schema=False)
    async def compliance_detail(request: Request, cluster: str = "", id: str = ""):
        if (report := request.app.state.backend.snapshot.compliance_report(cluster, id)) is None:
            return Response(status_code=404)
        return render(request, "_compliance_detail", c=report)

    @app.get("/about", response_class=HTMLResponse, include_in_schema=False)
    async def about(request: Request):
        backend, settings = request.app.state.backend, request.app.state.settings
        processes = backend.processes()
        return render(
            request,
            "about",
            tab="about",
            settings=settings,
            processes=processes,
            roles_status=roles_status(processes),
            started_at=processes[0].started_at if processes else None,
            config_path=os.environ.get("KUBE_TOWER_CONFIG", DEFAULT_CONFIG_PATH),
            trivy_status=backend.trivy_status,
            components=[
                ("Python", platform.python_version()),
                ("FastAPI", fastapi.__version__),
                ("htmx", HTMX_VERSION),
            ],
        )

    # Former pages, merged into the four pages: bookmarks still work (relative links, whatever the sub-path).
    @app.get("/synthesis", include_in_schema=False)
    async def synthesis():
        return RedirectResponse("./", status_code=301)

    @app.get("/vulnerabilities", include_in_schema=False)
    async def vulnerabilities(request: Request):
        p = request.query_params
        query = {
            "q": " ".join(v for v in (p.get("q", ""), p.get("cve", "")) if v),
            "severity": p.get("status", ""),
            "cluster": p.get("cluster", ""),
            "running": p.get("running", ""),
        }
        return RedirectResponse(_url("images", query), status_code=301)

    @app.get("/clusters", include_in_schema=False)
    @app.get("/settings", include_in_schema=False)
    @app.get("/logs", include_in_schema=False)
    async def administration_page(request: Request):
        tab = request.url.path.rstrip("/").rsplit("/", 1)[-1]
        query = [("tab", tab), *((k, v) for k, v in request.query_params.multi_items() if k != "tab")]
        return RedirectResponse(f"administration?{urlencode(query)}", status_code=301)

    async def _log_lines(request: Request, after: int, level: str, q: str, roles: list[str]):
        """Lines after `after` matching the filters, and the sequence number to tail from. With roles, the
        lines of the processes running one of them (distributed mode: every pod sends its lines to the controller)."""
        minimum = LOG_LEVELS.index(level) if level in LOG_LEVELS else 0
        lines = await request.app.state.backend.log_lines(after)
        matching = [
            line
            for line in lines
            if (LOG_LEVELS.index(line.level) if line.level in LOG_LEVELS else 0) >= minimum
            and _matches(f"{line.source} {line.logger} {line.message}", q)
            and (not roles or set(roles) & set(line.roles))
        ]
        return matching, lines[-1].seq if lines else after

    def _log_context(request: Request, level: str, q: str, roles: list[str]) -> dict:
        roles = [r for r in roles if r in ROLES]
        return {
            "level": level,
            "q": q,
            "roles": roles,
            "role_query": "".join(f"&role={r}" for r in roles),
            "distributed": request.app.state.settings.distributed,
        }

    @app.get("/logs/tail", response_class=HTMLResponse, include_in_schema=False)
    async def logs_tail(request: Request, after: int = 0, level: str = "INFO", q: str = "", role: list[str] = Query(default=[])):  # noqa: B008
        context = _log_context(request, level, q, role)
        lines, after = await _log_lines(request, after, level, q, context["roles"])
        return render(request, "_log_tail", lines=lines, after=after, **context)

    def scans_context(request: Request) -> dict:
        """What the Scans and Trivy tab of the Administration shows (`#administration`, polled while an action runs)."""
        backend = request.app.state.backend
        images, vulnerabilities, charts = backend.failed_items()
        return {
            "backend": backend,
            "busy": bool(backend.locked or backend.rescanning or backend.admin_running),
            "failed": {"images": images, "vulnerabilities": vulnerabilities, "charts": charts},
            "trivy_settings": request.app.state.settings.vulnerabilities,
        }

    def render_administration(request: Request, notice: str = "", error: str = "") -> HTMLResponse:
        """The actions of the Scans tab (`#administration`) for htmx. While an action runs they poll themselves
        (`polling=1`); the poll that sees them all over reloads the page.
        """
        context = scans_context(request)
        response = render(request, "_administration", notice=notice, error=error, **context)
        if request.query_params.get("polling") and not context["busy"]:
            response.headers["HX-Refresh"] = "true"
        return response

    @app.get("/administration", response_class=HTMLResponse, include_in_schema=False)
    async def administration(
        request: Request,
        tab: str = "scans",
        level: str = "INFO",
        q: str = "",
        role: list[str] = Query(default=[]),  # noqa: B008
    ):
        backend, settings = request.app.state.backend, request.app.state.settings
        tab = tab if tab in ADMIN_TABS else "scans"
        # The actions of the Scans tab only: asked by htmx, or polled while an action runs
        fragment = bool(request.query_params.get("polling")) or (
            request.headers.get("HX-Request") == "true" and request.headers.get("HX-Target") == "administration"
        )
        context: dict = {}
        if tab == "scans" or fragment:
            trivy = settings.vulnerabilities
            if backend.trivy_status is None and trivy.enabled and trivy.trivy.enabled:
                await backend.refresh_trivy_status()
            if fragment:
                return render_administration(request)
            context = scans_context(request)
        elif tab == "clusters":
            _, running = global_filters(request)
            context = {"summaries": {c.name: c for c in summarize(backend.snapshot, running=running).clusters}}
        elif tab == "pods":
            processes = backend.processes()
            context = {"processes": processes, "roles_status": roles_status(processes)}
        elif tab == "settings":
            # Settings only hold references to secrets (paths, env var names), never their values.
            credentials, auth = backend.registry_credentials(settings)
            context = {
                "credentials": credentials,
                "auth": auth,
                "settings_yaml": yaml.safe_dump(_camel(dataclasses.asdict(settings)), sort_keys=False),
                "sections": settings_sections(settings),
            }
        elif tab == "logs":
            context = _log_context(request, level, q, role)
            lines, after = await _log_lines(request, 0, level, q, context["roles"])
            context |= {"lines": lines, "after": after, "levels": LOG_LEVELS, "all_roles": ROLES}
        return render(request, "administration", tab="administration", admin_tab=tab, admin_tabs=ADMIN_TABS, **context)

    @app.get("/administration/processes", response_class=HTMLResponse, include_in_schema=False)
    async def administration_processes(request: Request):
        processes = request.app.state.backend.processes()
        return templates.TemplateResponse(
            request, "_processes.html", {"processes": processes, "roles_status": roles_status(processes)}
        )

    @app.get("/maintenance", include_in_schema=False)
    async def maintenance():
        """Former name of the Administration page: bookmarks still work (relative, whatever the sub-path)."""
        return RedirectResponse("administration", status_code=301)

    @app.post("/administration/{action}", response_class=HTMLResponse, include_in_schema=False)
    async def administration_action(request: Request, action: str):
        backend = request.app.state.backend
        notice = error = None
        if action == "scan":
            error = None if await backend.trigger() else "a scan or an administration action is already running"
            notice = "Full scan started."
        elif action == "retry-failed":
            error, notice = await backend.retry_failed(), "Retry of the failed items started."
        elif action == "trivy-db":
            error, notice = await backend.update_trivy_db(), "Trivy database update started."
        elif action == "trivy-status":
            await backend.refresh_trivy_status()
            notice = "Trivy status read again."
        elif action in ("trivy-cache", "trivy-cache-scan"):
            cleared = await backend.clear_trivy_cache()
            notice = (
                "Trivy results cache cleared: each trivy process forgets its results at its next task."
                if cleared < 0
                else f"Trivy results cache cleared ({plural(cleared, 'image')})."
            )
            if action == "trivy-cache-scan":
                started = await backend.trigger()
                notice += " Full scan started." if started else " A scan is already running: the next one scans every image."
        elif action == "connectivity":
            error, notice = await backend.test_connectivity(), "Connectivity test started."
        else:
            return Response(status_code=404)
        return render_administration(request, "" if error else notice, error or "")

    @app.get("/status", response_class=HTMLResponse, include_in_schema=False)
    async def scan_status(request: Request):
        response = render(request, "_status")
        if request.query_params.get("polling") and not request.app.state.backend.running:
            # The scan the page was waiting for is over: the page reloads its content (see kube-tower.js).
            response.headers["HX-Trigger"] = "kt-scan-done"
        return response
