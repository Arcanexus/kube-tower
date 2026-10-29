"""Security reports of Trivy Operator (aquasecurity.github.io/v1alpha1), when it runs in a cluster.

Besides the VulnerabilityReports (read for the images, see vulnerabilities.py), Trivy Operator checks the
configuration of the workloads (ConfigAuditReport), the secrets left in images (ExposedSecretReport), the
RBAC roles (RbacAssessmentReport), the nodes and control plane (InfraAssessmentReport) and the cluster
against compliance frameworks (ClusterComplianceReport). Each report names its resource with labels.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from kubernetes import client

from kube_tower.clusters import Cluster
from kube_tower.collectors.vulnerabilities import GROUP, VERSION, _timestamp
from kube_tower.models import ComplianceControl, ComplianceReport, SecurityCheck, SecurityKind, SecurityReport, Severity

log = logging.getLogger(__name__)

# Plural of each report CRD (namespaced and cluster-scoped), and the kind of report it holds.
PLURALS: dict[str, SecurityKind] = {
    "configauditreports": SecurityKind.CONFIG_AUDIT,
    "clusterconfigauditreports": SecurityKind.CONFIG_AUDIT,
    "exposedsecretreports": SecurityKind.EXPOSED_SECRET,
    "rbacassessmentreports": SecurityKind.RBAC,
    "clusterrbacassessmentreports": SecurityKind.RBAC,
    "infraassessmentreports": SecurityKind.INFRA,
    "clusterinfraassessmentreports": SecurityKind.INFRA,
}
COMPLIANCE = "clustercompliancereports"
# Reports hold one entry per check: moderate pages (parsed holding the GIL, see vulnerabilities.py).
PAGE_SIZE = 50
SEVERITY_ORDER = list(Severity)


@dataclass
class SecurityFindings:
    """What collect_security_reports found on one cluster."""

    installed: bool = False  # one of the report CRDs exists: Trivy Operator is installed
    reports: list[SecurityReport] = field(default_factory=list)
    compliance: list[ComplianceReport] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _by_severity(items: list, severity=lambda item: item.severity) -> list:
    return sorted(items, key=lambda item: (SEVERITY_ORDER.index(severity(item)), item.id))


def _resource(item: dict) -> tuple[str, str, str | None]:
    """(kind, name, namespace) of the resource of a report: its labels, else its owner, else the report itself."""
    meta = item.get("metadata") or {}
    labels = meta.get("labels") or {}
    owner = next(iter(meta.get("ownerReferences") or []), {})
    kind = labels.get("trivy-operator.resource.kind") or owner.get("kind") or ""
    name = labels.get("trivy-operator.resource.name") or owner.get("name") or meta.get("name", "")
    namespace = labels.get("trivy-operator.resource.namespace") or meta.get("namespace") or None
    return kind, name, namespace


def parse_security_report(cluster: str, kind: SecurityKind, item: dict) -> SecurityReport:
    report = item.get("report") or {}
    resource_kind, resource_name, namespace = _resource(item)
    labels = (item.get("metadata") or {}).get("labels") or {}
    out = SecurityReport(
        cluster=cluster,
        kind=kind,
        resource_kind=resource_kind,
        resource_name=resource_name,
        namespace=namespace,
        scanned_at=_timestamp(report.get("updateTimestamp")),
    )
    if kind == SecurityKind.EXPOSED_SECRET:
        artifact = report.get("artifact") or {}
        if repository := artifact.get("repository"):
            server = (report.get("registry") or {}).get("server") or ""
            tag = artifact.get("tag")
            out.image = "/".join(filter(None, [server, repository])) + (f":{tag}" if tag else "")
        out.container = labels.get("trivy-operator.container.name") or None
        out.checks = _by_severity(
            [
                SecurityCheck(
                    id=s.get("ruleID", ""),
                    title=s.get("title", "") or "",
                    severity=Severity.parse(s.get("severity")),
                    category=s.get("category", "") or "",
                    target=s.get("target", "") or "",
                    match=s.get("match", "") or "",
                )
                for s in report.get("secrets") or []
            ]
        )
        return out
    checks = report.get("checks") or []
    out.checks = _by_severity(
        [
            SecurityCheck(
                id=c.get("checkID", ""),
                title=c.get("title", "") or "",
                severity=Severity.parse(c.get("severity")),
                category=c.get("category", "") or "",
                description=c.get("description", "") or "",
                messages=[m for m in c.get("messages") or [] if m],
                remediation=c.get("remediation", "") or "",
            )
            for c in checks
            if not c.get("success", False)
        ]
    )
    out.passed = sum(1 for c in checks if c.get("success", False))
    return out


def parse_compliance_report(cluster: str, item: dict) -> ComplianceReport:
    spec = item.get("spec") or {}
    framework = spec.get("compliance") or spec  # older Trivy Operator versions: the fields are in spec
    status = item.get("status") or {}
    summary = status.get("summary") or {}
    controls = []
    if checks := (status.get("summaryReport") or {}).get("controlCheck"):
        for c in checks:
            if failed := c.get("totalFail") or 0:
                controls.append(ComplianceControl(c.get("id", ""), c.get("name", ""), Severity.parse(c.get("severity")), failed))
    else:  # `all` report type: the detail of each control
        for r in (status.get("detailReport") or {}).get("results") or []:
            if failed := sum(1 for c in r.get("checks") or [] if not c.get("success", False)):
                controls.append(ComplianceControl(r.get("id", ""), r.get("name", ""), Severity.parse(r.get("severity")), failed))
    return ComplianceReport(
        cluster=cluster,
        id=framework.get("id") or (item.get("metadata") or {}).get("name", ""),
        title=framework.get("title") or framework.get("id") or (item.get("metadata") or {}).get("name", ""),
        description=framework.get("description", "") or "",
        passed=summary.get("passCount") or 0,
        failed=summary.get("failCount") or 0,
        scanned_at=_timestamp(status.get("updateTimestamp")),
        controls=_by_severity(controls),
    )


def _list(api: client.CustomObjectsApi, plural: str):
    """Every object of a report CRD, page by page."""
    token = None
    while True:
        kwargs = {"limit": PAGE_SIZE, **({"_continue": token} if token else {})}
        page = api.list_cluster_custom_object(GROUP, VERSION, plural, **kwargs)
        yield from page.get("items") or []
        if not (token := (page.get("metadata") or {}).get("continue")):
            return


def collect_security_reports(cluster: Cluster) -> SecurityFindings:
    """The security reports of Trivy Operator in a cluster. A CRD that is not found is skipped (older
    versions lack some): Trivy Operator is installed when at least one of them is found."""
    api = client.CustomObjectsApi(cluster.api_client)
    found = SecurityFindings()
    for plural in [*PLURALS, COMPLIANCE]:
        try:
            for item in _list(api, plural):
                if plural == COMPLIANCE:
                    found.compliance.append(parse_compliance_report(cluster.name, item))
                else:
                    found.reports.append(parse_security_report(cluster.name, PLURALS[plural], item))
            found.installed = True
        except client.ApiException as exc:
            if exc.status == 404:  # CRD not installed
                continue
            found.installed = True
            hint = " (kube-tower needs `list` on it, see the chart RBAC)" if exc.status == 403 else ""
            found.errors.append(f"[{cluster.name}] cannot list Trivy Operator {plural}: {exc.status} {exc.reason}{hint}")
    if found.installed:
        log.info(
            "[%s] Trivy Operator: %d security reports, %d compliance reports",
            cluster.name,
            len(found.reports),
            len(found.compliance),
        )
    else:
        log.debug("[%s] Trivy Operator is not installed", cluster.name)
    return found
