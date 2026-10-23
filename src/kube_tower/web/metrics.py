"""Prometheus metrics computed from the last snapshot (e.g. for a Grafana dashboard)."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest

from kube_tower.models import Status

router = APIRouter()


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    snap = request.app.state.scanner.snapshot
    registry = CollectorRegistry()
    image = Gauge(
        "kube_tower_image_outdated",
        "1 if a newer version of the image is available",
        ["image", "tag", "latest", "status"],
        registry=registry,
    )
    chart = Gauge(
        "kube_tower_chart_outdated",
        "1 if a newer version of the chart (or one of its subcharts) is available",
        ["cluster", "application", "chart", "version", "latest", "status"],
        registry=registry,
    )
    last = Gauge("kube_tower_last_scan_timestamp_seconds", "End of the last scan", registry=registry)
    reachable = Gauge("kube_tower_cluster_reachable", "1 if the cluster answered", ["cluster"], registry=registry)

    for r in snap.images:
        image.labels(r.image.name, r.image.tag or "", r.latest_tag or "", r.status.value).set(r.status == Status.OUTDATED)
    for c in snap.charts:
        status = c.worst_status
        chart.labels(c.cluster, c.application, c.chart, c.version, c.latest_version or "", status.value).set(
            status == Status.OUTDATED
        )
    for c in snap.clusters:
        reachable.labels(c.name).set(c.reachable)
    if snap.finished_at:
        last.set(snap.finished_at.timestamp())
    return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
