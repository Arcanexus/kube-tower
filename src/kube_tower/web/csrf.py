"""Cross-site request forgery protection, without state nor token.

Without login (auth.enabled false) anyone who can reach kube-tower can start scans or clear the Trivy
cache; with it, a session cookie does. A page on another site must not do it through the browser of
someone who can reach it (or is logged in). Browsers say where a
request comes from (`Sec-Fetch-Site`, else `Origin`): requests that change something are refused when
they come from another site. Clients that are not browsers (curl, scripts) send neither and are allowed.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

log = logging.getLogger(__name__)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def cross_site(request: Request) -> str | None:
    """Why the request comes from another site, None when it comes from the UI itself or a non-browser client."""
    headers = request.headers
    if site := headers.get("sec-fetch-site"):
        return None if site in ("same-origin", "none") else f"Sec-Fetch-Site: {site}"
    origin = headers.get("origin")
    if origin is None:
        return None
    # Behind a proxy the browser's host is in X-Forwarded-Host (first one when chained).
    host = (headers.get("x-forwarded-host") or headers.get("host") or "").split(",")[0].strip()
    if origin == "null" or urlsplit(origin).netloc.lower() != host.lower():
        return f"Origin {origin} is not {host}"
    return None


def add_csrf_protection(app: FastAPI) -> None:
    @app.middleware("http")
    async def refuse_cross_site(request: Request, call_next):
        if request.method not in SAFE_METHODS and (reason := cross_site(request)):
            log.warning("cross-site %s %s refused (%s)", request.method, request.url.path, reason)
            return JSONResponse({"detail": "cross-site request refused"}, status_code=403)
        return await call_next(request)
