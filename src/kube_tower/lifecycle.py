"""End of life and vulnerabilities of the Kubernetes and containerd versions run by the clusters.

- Release cycles and their end of life: the endoflife.date API (`kubernetesVersions.endOfLifeUrl`).
- Vulnerabilities: the OSV API (`kubernetesVersions.osvUrl`), Go packages k8s.io/kubernetes and
  github.com/containerd/containerd. OSV lists the same flaw under several IDs (GO-…, GHSA-…, CVE-…):
  they are merged under the CVE ID when there is one.

Looked up once per scan by the controller, for the distinct versions of the API servers, kubelets and
container runtimes. A source that cannot be reached leaves a message, never fails the scan.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import date

import httpx

from kube_tower.config import KubernetesVersionsSettings
from kube_tower.models import ClusterStatus, NodeInfo, PlatformVersion, Severity, Vulnerability

log = logging.getLogger(__name__)

PACKAGES = {"kubernetes": "k8s.io/kubernetes", "containerd": "github.com/containerd/containerd"}
_VERSION = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")
# Severities of the GitHub advisories in OSV (database_specific.severity)
_SEVERITY = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM}
_SEVERITY |= {"LOW": Severity.LOW}


def plain_version(version: str | None) -> str:
    """1.30.4 for v1.30.4-eks-a737599, v1.31.2+k3s1 or containerd 1.7.13-1; "" when there is none."""
    match = _VERSION.match((version or "").strip())
    return f"{match[1]}.{match[2]}.{match[3]}" if match else ""


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def platform_versions(clusters: list[ClusterStatus], nodes: list[NodeInfo]) -> set[tuple[str, str]]:
    """The distinct (component, version) the clusters run: API servers, kubelets, containerd."""
    found = {("kubernetes", plain_version(c.version)) for c in clusters if c.reachable}
    found |= {("kubernetes", plain_version(n.kubelet_version)) for n in nodes}
    found |= {("containerd", plain_version(n.runtime_version)) for n in nodes if n.runtime_name == "containerd"}
    return {(component, version) for component, version in found if version}


def end_of_life(cycles: list[dict], version: str) -> tuple[str, str, str, str]:
    """(cycle, end of life, latest patch of the cycle, newest cycle) of a version, from endoflife.date."""
    cycle = ".".join(version.split(".")[:2])
    newest = max(
        (str(c.get("cycle", "")) for c in cycles), key=lambda c: _key(c) if re.fullmatch(r"\d+(\.\d+)*", c) else (0,), default=""
    )
    for c in cycles:
        if str(c.get("cycle")) == cycle:
            eol = c.get("eol")
            return cycle, eol if isinstance(eol, str) else "", str(c.get("latest") or ""), newest
    return cycle, "", "", newest


def _fixed_in(entry: dict, package: str, version: str) -> str:
    """The first fixed version after `version`, in its own cycle when there is one."""
    fixed = [
        plain_version(event["fixed"])
        for affected in entry.get("affected", [])
        if affected.get("package", {}).get("name") == package
        for r in affected.get("ranges", [])
        for event in r.get("events", [])
        if event.get("fixed")
    ]
    later = sorted({f for f in fixed if f and _key(f) > _key(version)}, key=_key)
    same_cycle = [f for f in later if f.split(".")[:2] == version.split(".")[:2]]
    return (same_cycle or later or [""])[0]


def osv_vulnerabilities(entries: list[dict], package: str, version: str) -> list[Vulnerability]:
    """The OSV entries of a version, merged by CVE ID (an advisory can be a GO-, a GHSA- and a CVE- entry)."""
    merged: dict[str, Vulnerability] = {}
    for entry in entries:
        ids = [entry.get("id", ""), *entry.get("aliases", [])]
        key = next((i for i in ids if i.startswith("CVE-")), ids[0])
        severity = _SEVERITY.get(str(entry.get("database_specific", {}).get("severity", "")).upper(), Severity.UNKNOWN)
        found = Vulnerability(
            key,
            severity,
            package,
            version,
            _fixed_in(entry, package, version),
            entry.get("summary", "") or entry.get("details", "")[:200],
            f"https://osv.dev/vulnerability/{entry.get('id', key)}",
        )
        known = merged.get(key)
        if known is None:
            merged[key] = found
            continue
        if list(Severity).index(found.severity) < list(Severity).index(known.severity):
            known.severity = found.severity
        known.fixed_version = known.fixed_version or found.fixed_version
        known.title = known.title or found.title
    return sorted(merged.values(), key=lambda v: (list(Severity).index(v.severity), v.id))


async def lookup(
    settings: KubernetesVersionsSettings, versions: set[tuple[str, str]], http: httpx.AsyncClient | None = None
) -> list[PlatformVersion]:
    """End of life and vulnerabilities of each (component, version)."""
    if not settings.enabled or not versions:
        return []
    own = http is None
    http = http or httpx.AsyncClient(timeout=settings.timeout, headers={"User-Agent": "kube-tower"})
    try:
        cycles: list[dict] = []
        eol_error = None
        if any(component == "kubernetes" for component, _ in versions):
            try:
                response = await http.get(settings.end_of_life_url)
                response.raise_for_status()
                cycles = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                eol_error = f"cannot read the end of life of Kubernetes from {settings.end_of_life_url}: {exc}"
                log.warning("%s", eol_error)

        async def one(component: str, version: str) -> PlatformVersion:
            found = PlatformVersion(component, version, message=eol_error if component == "kubernetes" else None)
            if component == "kubernetes" and cycles:
                found.cycle, found.end_of_life, found.latest, found.newest_cycle = end_of_life(cycles, version)
            package = PACKAGES[component]
            try:
                response = await http.post(
                    settings.osv_url, json={"package": {"name": package, "ecosystem": "Go"}, "version": version}
                )
                response.raise_for_status()
                found.vulnerabilities = osv_vulnerabilities(response.json().get("vulns", []), package, version)
            except (httpx.HTTPError, ValueError) as exc:
                found.message = f"cannot read the vulnerabilities of {component} {version} from {settings.osv_url}: {exc}"
                log.warning("%s", found.message)
            return found

        found = await asyncio.gather(*(one(c, v) for c, v in sorted(versions)))
        log.info("platform versions looked up: %s", ", ".join(f"{p.component} {p.version}" for p in found))
        return list(found)
    finally:
        if own:
            await http.aclose()


def days_left(end: str, today: date | None = None) -> int | None:
    """Days until an end of life date (negative once passed), None when unknown."""
    try:
        return (date.fromisoformat(end) - (today or date.today())).days
    except ValueError:
        return None
