"""Prometheus exporter: the last snapshot rendered as metrics (e.g. for a Grafana dashboard).

Metrics are computed on each scrape from the in-memory snapshot, so a series disappears
as soon as the image, chart or cluster is no longer found. To keep cardinality bounded:
- images are reported once (they are deduplicated across clusters), their usages separately;
- pods are only reported when no controller (Deployment, StatefulSet...) runs the same
  container in the same namespace, so pod names (which change on every rollout) are avoided;
- node images are reported as a count of nodes per cluster, not one series per node.
"""

from __future__ import annotations

import asyncio
from collections import Counter

from fastapi import APIRouter, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client.registry import Collector

from kube_tower import __version__
from kube_tower.models import ImageReport, Severity, Snapshot, Status
from kube_tower.versions import update_kind

router = APIRouter()


def image_update(r: ImageReport) -> str:
    if r.status != Status.OUTDATED:
        return ""
    return update_kind(r.image.tag, r.latest_tag) or ("digest" if r.latest_digest else "")


def _workload_usages(r: ImageReport) -> set[tuple[str, str, str, str, str]]:
    """(cluster, namespace, kind, workload, container) running the image, without pods owned by a controller."""
    controllers = {(u.cluster, u.namespace, u.container) for u in r.usages if u.kind not in ("Pod", "Node")}
    return {
        (u.cluster, u.namespace or "", u.kind, u.name, u.container or "")
        for u in r.usages
        if u.kind != "Node" and (u.kind != "Pod" or (u.cluster, u.namespace, u.container) not in controllers)
    }


class SnapshotCollector(Collector):
    def __init__(self, backend):
        self.backend = backend

    def describe(self):
        return []  # labels depend on the snapshot: nothing to check at registration

    def collect(self):
        snap: Snapshot = self.backend.snapshot
        yield from self._images(snap)
        yield from self._vulnerabilities(snap)
        yield from self._security(snap)
        yield from self._charts(snap)
        yield from self._clusters(snap)
        yield from self._scan(snap)

    def _images(self, snap: Snapshot):
        outdated = GaugeMetricFamily(
            "kube_tower_image_outdated",
            "1 if a newer version of the image is available, else 0 (one series per image, all clusters together)",
            labels=["image", "tag", "latest", "status", "update"],
        )
        workload = GaugeMetricFamily(
            "kube_tower_image_workload_info",
            "Workloads running the image (always 1); join with kube_tower_image_outdated on image and tag",
            labels=["cluster", "namespace", "kind", "workload", "container", "image", "tag"],
        )
        nodes = GaugeMetricFamily(
            "kube_tower_image_nodes",
            "Number of nodes of the cluster where the image is present (node.status.images)",
            labels=["cluster", "image", "tag"],
        )
        for r in snap.images:
            name, tag = r.image.name, r.image.tag or ""
            latest = r.latest_tag or (r.latest_digest or "" if r.status == Status.OUTDATED else "")
            outdated.add_metric([name, tag, latest, r.status.value, image_update(r)], r.status == Status.OUTDATED)
            for usage in sorted(_workload_usages(r)):
                workload.add_metric([*usage, name, tag], 1)
            for cluster, count in sorted(Counter(u.cluster for u in r.usages if u.kind == "Node").items()):
                nodes.add_metric([cluster, name, tag], count)
        return outdated, workload, nodes

    def _vulnerabilities(self, snap: Snapshot):
        total = GaugeMetricFamily(
            "kube_tower_image_vulnerabilities",
            "Known vulnerabilities of the image by severity (one series per image, all clusters together)",
            labels=["image", "tag", "severity", "source"],
        )
        fixable = GaugeMetricFamily(
            "kube_tower_image_vulnerabilities_fixable",
            "Vulnerabilities of the image fixed in a newer version of the package, by severity",
            labels=["image", "tag", "severity"],
        )
        eosl = GaugeMetricFamily(
            "kube_tower_image_os_eosl",
            "1 if the OS of the image is end of life (no more security fixes), else 0",
            labels=["image", "tag", "os"],
        )
        failed = GaugeMetricFamily(
            "kube_tower_image_vulnerability_scan_failed",
            "1 if the vulnerability scan of the image failed",
            labels=["image", "tag"],
        )
        for r in snap.images:
            v = r.vulnerabilities
            if v is None:
                continue
            name, tag = r.image.name, r.image.tag or ""
            failed.add_metric([name, tag], bool(v.message))
            if v.message:
                continue
            counts = v.counts()
            fixed = {s: sum(1 for x in v.vulnerabilities if x.severity == s and x.fixed_version) for s in Severity}
            for s in Severity:
                total.add_metric([name, tag, s.value, v.source], counts[s])
                fixable.add_metric([name, tag, s.value], fixed[s])
            if v.os:
                eosl.add_metric([name, tag, v.os], v.os_eosl)
        return total, fixable, eosl, failed

    def _security(self, snap: Snapshot):
        findings = GaugeMetricFamily(
            "kube_tower_security_findings",
            "Failed checks (and exposed secrets) of the Trivy Operator security reports, by namespace, type and severity",
            labels=["cluster", "namespace", "type", "severity"],
        )
        resources = GaugeMetricFamily(
            "kube_tower_security_resources",
            "Resources checked by Trivy Operator, by type, and whether they have findings",
            labels=["cluster", "type", "result"],
        )
        compliance = GaugeMetricFamily(
            "kube_tower_compliance_controls",
            "Controls of a Trivy Operator compliance report (CIS, NSA, PSS...), passed or failed",
            labels=["cluster", "compliance", "title", "result"],
        )
        totals: dict[tuple[str, str, str, str], int] = {}
        checked: dict[tuple[str, str, str], int] = {}
        for r in snap.security:
            for s, n in r.counts().items():
                key = (r.cluster, r.namespace or "", r.kind.value, s.value)
                totals[key] = totals.get(key, 0) + n
            key = (r.cluster, r.kind.value, "fail" if r.checks else "pass")
            checked[key] = checked.get(key, 0) + 1
        for labels, n in sorted(totals.items()):
            findings.add_metric(list(labels), n)
        for labels, n in sorted(checked.items()):
            resources.add_metric(list(labels), n)
        for c in snap.compliance:
            compliance.add_metric([c.cluster, c.id, c.title, "pass"], c.passed)
            compliance.add_metric([c.cluster, c.id, c.title, "fail"], c.failed)
        return findings, resources, compliance

    def _charts(self, snap: Snapshot):
        chart = GaugeMetricFamily(
            "kube_tower_chart_outdated",
            "1 if a newer version of the chart or of one of its subcharts is available, else 0",
            labels=[
                "cluster",
                "application",
                "destination_namespace",
                "chart",
                "source",
                "version",
                "latest",
                "status",
                "update",
            ],
        )
        dependency = GaugeMetricFamily(
            "kube_tower_chart_dependency_outdated",
            "1 if a newer version of the subchart is available, else 0",
            labels=["cluster", "application", "chart", "dependency", "version", "latest", "status", "update"],
        )
        for c in snap.charts:
            status = c.worst_status
            chart.add_metric(
                [
                    c.cluster,
                    c.application,
                    c.destination_namespace or "",
                    c.chart,
                    c.source_type,
                    c.version,
                    c.latest_version or "",
                    status.value,
                    update_kind(c.version, c.latest_version),
                ],
                status == Status.OUTDATED,
            )
            for d in c.dependencies:
                dependency.add_metric(
                    [
                        c.cluster,
                        c.application,
                        c.chart,
                        d.name,
                        d.version,
                        d.latest_version or "",
                        d.status.value,
                        update_kind(d.version, d.latest_version),
                    ],
                    d.status == Status.OUTDATED,
                )
        return chart, dependency

    def _clusters(self, snap: Snapshot):
        reachable = GaugeMetricFamily("kube_tower_cluster_reachable", "1 if the cluster answered", labels=["cluster"])
        info = GaugeMetricFamily(
            "kube_tower_cluster_info", "Registered clusters (always 1)", labels=["cluster", "source", "version"]
        )
        for c in snap.clusters:
            reachable.add_metric([c.name], c.reachable)
            info.add_metric([c.name, c.source, c.version or ""], 1)
        return reachable, info

    def _scan(self, snap: Snapshot):
        build = GaugeMetricFamily("kube_tower_build_info", "kube-tower version (always 1)", labels=["version"])
        build.add_metric([__version__], 1)
        yield build
        last = GaugeMetricFamily("kube_tower_last_scan_timestamp_seconds", "End of the last scan (Unix time)")
        duration = GaugeMetricFamily("kube_tower_last_scan_duration_seconds", "Duration of the last scan")
        errors = GaugeMetricFamily(
            "kube_tower_last_scan_errors",
            "Non fatal errors of the last scan (e.g. a forbidden resource, a registry that cannot be queried)",
        )
        vulnerabilities = GaugeMetricFamily(
            "kube_tower_last_vulnerability_scan_timestamp_seconds", "End of the last vulnerability scan (Unix time)"
        )
        if snap.vulnerabilities_finished_at:
            vulnerabilities.add_metric([], snap.vulnerabilities_finished_at.timestamp())
        if snap.finished_at:
            last.add_metric([], snap.finished_at.timestamp())
            if snap.started_at:
                duration.add_metric([], (snap.finished_at - snap.started_at).total_seconds())
            errors.add_metric([], len(snap.errors))
        yield from (last, duration, errors, vulnerabilities)
        yield GaugeMetricFamily("kube_tower_scan_in_progress", "1 while a scan is running", value=int(bool(self.backend.running)))
        scans = CounterMetricFamily("kube_tower_scans", "Scans since start, by result", labels=["result"])
        for result, count in sorted(self.backend.scans_total.items()):
            scans.add_metric([result], count)
        yield scans


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    registry = CollectorRegistry(auto_describe=False)
    registry.register(SnapshotCollector(request.app.state.backend))
    # In a thread: one series per image, chart and vulnerability count, the pages wait for nothing.
    return Response(await asyncio.to_thread(generate_latest, registry), media_type=CONTENT_TYPE_LATEST)
