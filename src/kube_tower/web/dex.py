"""Dex served by kube-tower on <url>api/dex, like ArgoCD (auth.dexUrl, Helm chart dex.enabled).

The browser only talks to kube-tower: its requests under /api/dex/ are passed to the Dex Service, whose
issuer is <url>api/dex. Dex logs users in with its connectors (GitHub, GitLab, LDAP, SAML, OIDC...) and
kube-tower is its OIDC client.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response

log = logging.getLogger(__name__)

PREFIX = "/api/dex/"
TIMEOUT = 30
# Headers of a hop, or that httpx sets again (the body is sent decoded)
HOP_HEADERS = {"connection", "keep-alive", "transfer-encoding", "te", "upgrade", "host", "content-length", "content-encoding"}


def add_dex_proxy(app: FastAPI, dex_url: str, issuer: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
    # Dex serves its issuer path (/api/dex, or /<sub-path>/api/dex when kube-tower is under a sub-path the ingress strips)
    base = dex_url.rstrip("/") + urlsplit(issuer).path.rstrip("/")
    client = httpx.AsyncClient(timeout=TIMEOUT, transport=transport, follow_redirects=False)

    @app.api_route(PREFIX + "{path:path}", methods=["GET", "POST", "HEAD"], include_in_schema=False)
    async def dex(request: Request, path: str):
        url = f"{base}/{path}" + (f"?{request.url.query}" if request.url.query else "")
        headers = [(k, v) for k, v in request.headers.items() if k.lower() not in HOP_HEADERS]
        try:
            resp = await client.request(request.method, url, headers=headers, content=await request.body())
        except httpx.HTTPError as exc:
            log.warning("Dex not reachable at %s: %r", dex_url, exc)
            return Response(f"Dex is not reachable ({exc!r}): check the Dex pod of kube-tower", 502, media_type="text/plain")
        out = Response(resp.content, resp.status_code)
        for key, value in resp.headers.multi_items():
            if key.lower() not in HOP_HEADERS:
                out.headers.append(key, value)
        return out
