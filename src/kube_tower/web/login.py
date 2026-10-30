"""Login page, sessions and roles on every request (auth.enabled).

Without a session a page leads to the login page, the API answers 401. A `readonly` user gets 403 on
every request that changes something (POST, DELETE): scans, rescans, retries, connectivity tests, Trivy
actions. The requests of the users that change something are logged with their name.
"""

from __future__ import annotations

import asyncio
import logging
import re
from contextvars import ContextVar
from urllib.parse import parse_qs, quote

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from kube_tower.auth import COOKIE, Authenticator, User

log = logging.getLogger(__name__)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Reached without a session: probes, static files, the login page itself.
OPEN_PATHS = ("/healthz", "/readyz", "/leaderz", "/login", "/static/")
FAILED_LOGIN_DELAY = 1.0  # seconds: slows down password guessing
# Who sends the request being served, for the templates: (login on, user).
current: ContextVar[tuple[bool, User | None]] = ContextVar("kube_tower_user", default=(False, None))


def can_act() -> bool:
    """The request may change something: login off, or an admin."""
    enabled, user = current.get()
    return not enabled or (user is not None and user.admin)


def current_user() -> User | None:
    return current.get()[1]


# The page to go back to after the login: relative, without scheme nor host (no redirection to another site).
_NEXT = re.compile(r"(?!/)(?!.*//)(?!.*\.\.)[\w\-./]*(\?[\w\-.~%=&+]*)?")


def safe_next(value: str) -> str:
    return value if _NEXT.fullmatch(value or "") else ""


def _to_root(request: Request) -> str:
    """Relative path from the requested URL to the root of the UI, whatever the sub-path it is exposed under."""
    return "../" * (request.url.path.count("/") - 1) or ""


def _client(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() or (request.client.host if request.client else "?")


def add_login(app: FastAPI, auth: Authenticator) -> None:
    from kube_tower.web.ui import templates  # the layout and its assets

    settings = auth.settings

    def user_of(request: Request) -> User | None:
        if (cookie := request.cookies.get(COOKIE)) and (user := auth.from_session(cookie)):
            return user
        if (header := request.headers.get("authorization")) and (user := auth.from_basic(header)):
            return user
        return auth.anonymous

    def unauthenticated(request: Request) -> Response:
        path = request.url.path
        if path.startswith("/api/") or path == "/metrics":
            headers = {} if request.headers.get("HX-Request") else {"WWW-Authenticate": 'Basic realm="kube-tower"'}
            return JSONResponse({"detail": "login required: a session, or Basic auth of a local user"}, 401, headers)
        if request.headers.get("HX-Request"):  # polls and panels: the whole page goes to the login
            return Response(status_code=401, headers={"HX-Redirect": "login"})
        target = path.lstrip("/") + (f"?{request.url.query}" if request.url.query else "")
        return RedirectResponse(f"{_to_root(request)}login" + (f"?next={quote(target)}" if target else ""), 303)

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        path = request.url.path
        user = user_of(request)
        current.set((True, user))
        if path.startswith(OPEN_PATHS) or (path == "/metrics" and settings.metrics_public):
            return await call_next(request)
        if user is None:
            return unauthenticated(request)
        if request.method not in SAFE_METHODS and path != "/logout":
            if not user.admin:
                log.warning("%s (%s) not allowed to %s %s: admin role needed", user.name, user.role, request.method, path)
                return JSONResponse({"detail": "the admin role is needed"}, status_code=403)
            log.info("%s (%s): %s %s", user.name, user.role, request.method, path)
        return await call_next(request)

    def login_page(request: Request, error: str = "", status: int = 200, name: str = "") -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": error, "name": name, "next": safe_next(request.query_params.get("next", "")), "ready": auth.ready()},
            status_code=status,
        )

    @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
    async def login_form(request: Request):
        return login_page(request)

    @app.post("/login", include_in_schema=False)
    async def login(request: Request):
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode(errors="replace")).items()}
        name, password = form.get("username", "").strip(), form.get("password", "")
        if not auth.ready():
            return login_page(request, "kube-tower is creating its auth Secret: try again in a minute.", 503, name)
        user = auth.check_password(name, password)
        if user is None:
            log.warning("failed login for %r from %s", name, _client(request))
            await asyncio.sleep(FAILED_LOGIN_DELAY)
            return login_page(request, "Wrong username or password.", 401, name)
        log.info("%s (%s) logged in from %s", user.name, user.role, _client(request))
        response = RedirectResponse(f"./{safe_next(form.get('next', ''))}", status_code=303)
        response.set_cookie(
            COOKIE,
            auth.session(user),
            max_age=settings.session_duration,
            path="/",
            httponly=True,
            samesite="lax",
            secure=request.url.scheme == "https",
        )
        return response

    @app.post("/logout", include_in_schema=False)
    async def logout(request: Request):
        if user := current_user():
            log.info("%s logged out", user.name)
        response = RedirectResponse("login", status_code=303)
        response.delete_cookie(COOKIE, path="/")
        return response
