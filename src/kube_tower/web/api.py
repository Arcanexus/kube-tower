"""JSON API, also used for health probes."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

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
