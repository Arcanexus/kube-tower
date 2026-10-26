"""JSON API, also used for health probes."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Request, Response

from kube_tower.administration import unused_node_images

router = APIRouter()
# Processes without the ui role (controller, worker, trivy) only answer the probes: alive once started.
probes = APIRouter()


def _standby(request: Request) -> bool:
    """A controller replica waiting for the Lease (internal.leaderElection): no Service routes to it."""
    election = getattr(request.app.state, "election", None)
    return election is not None and not election.leader


@probes.get("/healthz", include_in_schema=False)
async def alive() -> dict:
    return {"status": "ok"}


@probes.get("/readyz", include_in_schema=False)
async def ready(request: Request, response: Response) -> dict:
    if _standby(request):
        response.status_code = 503
        return {"ready": False, "standby": True}
    return {"status": "ok"}


@router.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False)
async def readyz(request: Request, response: Response) -> dict:
    # Ready once the first scan finished, so the UI never shows an empty inventory.
    ready = request.app.state.backend.snapshot.finished_at is not None and not _standby(request)
    response.status_code = 200 if ready else 503
    return {"ready": ready}


@router.get("/api/snapshot")
async def snapshot(request: Request) -> dict:
    return request.app.state.backend.snapshot.to_dict()


@router.post("/api/refresh", status_code=202)
async def refresh(request: Request) -> dict:
    return {"started": await request.app.state.backend.trigger()}


def _rescan_answer(response: Response, error: str | None) -> dict:
    if error:
        response.status_code = 409
        return {"started": False, "reason": error}
    return {"started": True}


@router.post("/api/rescan/image", status_code=202)
async def rescan_image(
    request: Request, response: Response, ref: str, versions: bool = True, vulnerabilities: bool = True
) -> dict:
    """Check one image again (its version and/or its vulnerabilities), in the background."""
    backend = request.app.state.backend
    if (report := backend.snapshot.image(ref)) is None:
        raise HTTPException(404, f"image {ref!r} not found in the last scan")
    return _rescan_answer(response, await backend.rescan_image(report, versions, vulnerabilities))


@router.post("/api/rescan/chart", status_code=202)
async def rescan_chart(request: Request, response: Response, cluster: str, namespace: str, app: str, chart: str) -> dict:
    """Check one Helm chart and its subcharts again, in the background."""
    backend = request.app.state.backend
    if (report := backend.snapshot.chart(cluster, namespace, app, chart)) is None:
        raise HTTPException(
            404, f"chart {chart!r} of application {namespace}/{app} in cluster {cluster!r} not found in the last scan"
        )
    return _rescan_answer(response, await backend.rescan_chart(report))


@router.post("/api/administration/retry-failed", status_code=202)
async def retry_failed(request: Request, response: Response) -> dict:
    """Check again everything that failed in the last scan (image versions, vulnerability scans, charts)."""
    return _rescan_answer(response, await request.app.state.backend.retry_failed())


@router.post("/api/administration/trivy-db", status_code=202)
async def update_trivy_db(request: Request, response: Response) -> dict:
    """Download the Trivy databases when a newer one is published (standalone mode)."""
    return _rescan_answer(response, await request.app.state.backend.update_trivy_db())


@router.delete("/api/administration/trivy-cache")
async def clear_trivy_cache(request: Request) -> dict:
    """Forget the cached Trivy results: the next scan scans every image again."""
    return {"cleared": await request.app.state.backend.clear_trivy_cache()}


@router.post("/api/administration/connectivity", status_code=202)
async def test_connectivity(request: Request, response: Response) -> dict:
    """Test the clusters, registries, Helm repositories and Trivy server; results in GET /api/administration/connectivity."""
    return _rescan_answer(response, await request.app.state.backend.test_connectivity())


@router.get("/api/administration/connectivity")
async def connectivity(request: Request) -> dict:
    backend = request.app.state.backend
    report = backend.connectivity
    return {
        "running": "connectivity" in backend.admin_running,
        "startedAt": report.started_at.isoformat() if report else None,
        "finishedAt": report.finished_at.isoformat() if report and report.finished_at else None,
        "checks": [asdict(c) for c in report.checks] if report else [],
    }


@router.get("/api/administration/unused-images")
async def unused_images(request: Request) -> list[dict]:
    """Images cached on nodes that no workload of their cluster uses."""
    return [asdict(u) for u in unused_node_images(request.app.state.backend.snapshot)]
