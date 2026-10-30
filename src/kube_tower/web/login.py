"""Login page, sessions and roles on every request (auth.enabled).

Without a session a page leads to the login page, the API answers 401. A `readonly` user gets 403 on
every request that changes something (POST, DELETE): scans, rescans, retries, connectivity tests, Trivy
actions. The requests of the users that change something are logged with their name.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from contextvars import ContextVar
from urllib.parse import parse_qs, quote

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from kube_tower.auth import COOKIE, Authenticator, User
from kube_tower.oidc import OidcClient, OidcError, pkce

log = logging.getLogger(__name__)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Reached without a session: probes, static files, the login page itself.
OPEN_PATHS = ("/healthz", "/readyz", "/leaderz", "/login", "/auth/", "/api/dex/", "/static/")
OIDC_COOKIE = "kube_tower_oidc"  # state of a login with the provider, while the user is there
OIDC_LOGIN_TIME = 600  # seconds to log in with the provider
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


def add_login(app: FastAPI, auth: Authenticator, oidc: OidcClient | None = None) -> None:
    from kube_tower.web.ui import templates  # the layout and its assets

    settings = auth.settings
    if oidc is None and settings.oidc.issuer:
        oidc = OidcClient(settings)

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
            {
                "error": error,
                "name": name,
                "next": safe_next(request.query_params.get("next", "")),
                "ready": auth.ready(),
                "local_accounts": auth.local_accounts,
                "sso": settings.oidc.name if oidc else "",
            },
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
        return logged_in(request, user, f"./{safe_next(form.get('next', ''))}")

    def logged_in(request: Request, user: User, target: str) -> Response:
        response = RedirectResponse(target, status_code=303)
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

    @app.get("/auth/login", include_in_schema=False)
    async def sso_login(request: Request):
        """To the provider, with the state of this login in a signed cookie (state, nonce, PKCE verifier)."""
        if oidc is None:
            return Response(status_code=404)
        if not auth.ready():
            return login_page(request, "kube-tower is creating its auth Secret: try again in a minute.", 503)
        state, nonce, (verifier, challenge) = secrets.token_urlsafe(24), secrets.token_urlsafe(24), pkce()
        try:
            url = await oidc.authorization_url(state, nonce, challenge)
        except OidcError as exc:
            log.warning("SSO login not started: %s", exc)
            return login_page(request, f"Single sign-on unavailable: {exc}", 502)
        payload = {"st": state, "n": nonce, "v": verifier, "x": safe_next(request.query_params.get("next", ""))}
        response = RedirectResponse(url, status_code=303)
        response.set_cookie(
            OIDC_COOKIE,
            auth.sign(payload | {"e": int(time.time() + OIDC_LOGIN_TIME)}),
            max_age=OIDC_LOGIN_TIME,
            path="/",
            httponly=True,
            samesite="lax",  # sent when the provider sends the user back (a top-level GET)
            secure=request.url.scheme == "https",
        )
        return response

    @app.get("/auth/callback", include_in_schema=False)
    async def sso_callback(request: Request):
        if oidc is None:
            return Response(status_code=404)
        params = request.query_params
        flow = auth.unsign(request.cookies.get(OIDC_COOKIE, ""))
        try:
            if error := params.get("error"):
                raise OidcError(f"the provider refused the login: {error} {params.get('error_description', '')}".strip())
            if flow is None or not secrets.compare_digest(params.get("state", ""), str(flow.get("st", ""))):
                raise OidcError("this login was not started here or took more than 10 minutes: log in again")
            user = await oidc.user(params.get("code", ""), flow["v"], flow["n"])
        except OidcError as exc:
            log.warning("SSO login failed from %s: %s", _client(request), exc)
            response = login_page(request, f"Single sign-on failed: {exc}", 401)
        else:
            log.info("%s (%s) logged in with %s from %s", user.name, user.role, settings.oidc.name, _client(request))
            response = logged_in(request, user, f"../{flow.get('x', '')}")  # from auth/callback to the root
        response.delete_cookie(OIDC_COOKIE, path="/")
        return response

    @app.post("/logout", include_in_schema=False)
    async def logout(request: Request):
        if user := current_user():
            log.info("%s logged out", user.name)
        response = RedirectResponse("login", status_code=303)
        response.delete_cookie(COOKIE, path="/")
        return response
