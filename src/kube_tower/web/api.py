"""JSON API, also used for health probes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response

router = APIRouter()


@router.get("/healthz", include_in_schema=False)
async def healthz() -> dict:
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False)
async def readyz(request: Request, response: Response) -> dict:
    # Ready once the first scan finished, so the UI never shows an empty inventory.
    ready = request.app.state.scanner.snapshot.finished_at is not None
    response.status_code = 200 if ready else 503
    return {"ready": ready}


@router.get("/api/snapshot")
async def snapshot(request: Request) -> dict:
    return request.app.state.scanner.snapshot.to_dict()


@router.post("/api/refresh", status_code=202)
async def refresh(request: Request) -> dict:
    return {"started": request.app.state.scanner.trigger()}


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
    scanner = request.app.state.scanner
    if (report := scanner.snapshot.image(ref)) is None:
        raise HTTPException(404, f"image {ref!r} not found in the last scan")
    return _rescan_answer(response, scanner.rescan_image(report, versions, vulnerabilities))


@router.post("/api/rescan/chart", status_code=202)
async def rescan_chart(request: Request, response: Response, cluster: str, namespace: str, app: str, chart: str) -> dict:
    """Check one Helm chart and its subcharts again, in the background."""
    scanner = request.app.state.scanner
    if (report := scanner.snapshot.chart(cluster, namespace, app, chart)) is None:
        raise HTTPException(
            404, f"chart {chart!r} of application {namespace}/{app} in cluster {cluster!r} not found in the last scan"
        )
    return _rescan_answer(response, scanner.rescan_chart(report))
