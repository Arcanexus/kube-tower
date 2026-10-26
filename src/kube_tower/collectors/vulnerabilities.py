"""VulnerabilityReports of Trivy Operator (aquasecurity.github.io/v1alpha1), when it runs in a cluster.

Trivy Operator writes one report per workload container: the reports of an image are merged
into one, the newest report of the digest that actually runs winning.
"""

from __future__ import annotations

import logging
from datetime import datetime

from kubernetes import client

from kube_tower.clusters import Cluster
from kube_tower.models import ImageRef, Severity, Vulnerability, VulnerabilityReport
from kube_tower.registry.oci import parse_image_ref

log = logging.getLogger(__name__)

GROUP, VERSION, PLURAL = "aquasecurity.github.io", "v1alpha1", "vulnerabilityreports"
# Reports are large (one entry per vulnerability), and a page is parsed in one go holding the GIL, which
# stalls the web pages meanwhile: small pages.
PAGE_SIZE = 25


def _timestamp(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def dedupe_vulnerabilities(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    """One entry per (id, package, installed version), sorted most severe first."""
    unique = {(v.id, v.package, v.installed_version): v for v in vulnerabilities}
    order = list(Severity)
    return sorted(unique.values(), key=lambda v: (order.index(v.severity), -(v.score or 0), v.id, v.package))


def parse_operator_report(item: dict) -> tuple[ImageRef, VulnerabilityReport] | None:
    """(image key, report) of a VulnerabilityReport object, None when it has no image reference."""
    report = item.get("report") or {}
    artifact = report.get("artifact") or {}
    repository = artifact.get("repository")
    if not repository:
        return None
    server = (report.get("registry") or {}).get("server") or "docker.io"
    tag, digest = artifact.get("tag"), artifact.get("digest")
    ref = parse_image_ref(f"{server}/{repository}" + (f":{tag}" if tag else "") + (f"@{digest}" if digest else ""))
    key = ImageRef(ref.registry, ref.repository, ref.tag, None if ref.tag else ref.digest)
    os_info = report.get("os") or {}
    vulnerabilities = [
        Vulnerability(
            id=v.get("vulnerabilityID", ""),
            severity=Severity.parse(v.get("severity")),
            package=v.get("resource", ""),
            installed_version=v.get("installedVersion", ""),
            fixed_version=v.get("fixedVersion", "") or "",
            title=v.get("title", "") or "",
            url=v.get("primaryLink", "") or "",
            score=v.get("score"),
        )
        for v in report.get("vulnerabilities") or []
    ]
    return key, VulnerabilityReport(
        source="trivy-operator",
        scanned_at=_timestamp(report.get("updateTimestamp")),
        digest=digest,
        os=" ".join(filter(None, [os_info.get("family"), os_info.get("name")])),
        os_eosl=bool(os_info.get("eosl")),
        vulnerabilities=dedupe_vulnerabilities(vulnerabilities),
    )


def collect_operator_reports(cluster: Cluster) -> tuple[list[tuple[ImageRef, VulnerabilityReport]], list[str]]:
    """Every VulnerabilityReport of the cluster. Nothing (and no error) when Trivy Operator is not installed."""
    api = client.CustomObjectsApi(cluster.api_client)
    reports, token = [], None
    try:
        while True:
            kwargs = {"limit": PAGE_SIZE, **({"_continue": token} if token else {})}
            page = api.list_cluster_custom_object(GROUP, VERSION, PLURAL, **kwargs)
            for item in page.get("items") or []:
                if parsed := parse_operator_report(item):
                    reports.append(parsed)
            token = (page.get("metadata") or {}).get("continue")
            if not token:
                break
    except client.ApiException as exc:
        if exc.status == 404:  # CRD not installed
            log.debug("[%s] Trivy Operator is not installed", cluster.name)
            return [], []
        return reports, [f"[{cluster.name}] cannot list VulnerabilityReports: {exc.status} {exc.reason}"]
    log.info("[%s] %d Trivy Operator VulnerabilityReports", cluster.name, len(reports))
    return reports, []


def pick_report(candidates: list[VulnerabilityReport], running_digests: set[str]) -> VulnerabilityReport:
    """The report to show for an image: the newest one of a running digest, else the newest one."""
    oldest = datetime.min.replace(tzinfo=None)

    def newest(r: VulnerabilityReport):
        return r.scanned_at.replace(tzinfo=None) if r.scanned_at else oldest

    running = [r for r in candidates if r.digest and r.digest in running_digests]
    return max(running or candidates, key=newest)
