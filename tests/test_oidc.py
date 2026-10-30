import base64
import json
import logging
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from kube_tower.auth import User
from kube_tower.config import AuthSettings, OidcSettings, Settings, check_auth
from kube_tower.main import create_app
from kube_tower.oidc import OidcClient, OidcError, jwt_claims, pkce
from test_web import FakeScanner

ISSUER = "https://idp.example.com/application/o/kube-tower/"
METADATA = {
    "issuer": ISSUER,
    "authorization_endpoint": "https://idp.example.com/authorize/",
    "token_endpoint": "https://idp.example.com/token/",
    "userinfo_endpoint": "https://idp.example.com/userinfo/",
}


def _jwt(**claims) -> str:
    def part(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'RS256'})}.{part(claims)}.c2ln"


def _claims(**extra):
    return {"iss": ISSUER, "aud": "kube-tower", "exp": time.time() + 300, "nonce": "n1", "sub": "u1", **extra}


def _settings(**oidc) -> AuthSettings:
    return AuthSettings(
        enabled=True,
        url="https://kt.example.com/tools/",
        oidc=OidcSettings(**({"name": "Authentik", "issuer": ISSUER, "client_id": "kube-tower", "admin_groups": ["ops"]} | oidc)),
    )


@pytest.fixture
def idp(monkeypatch):
    monkeypatch.setenv("KUBE_TOWER_OIDC_CLIENT_SECRET", "cs")
    with respx.mock(assert_all_called=False) as mock:
        mock.get(ISSUER.rstrip("/") + "/.well-known/openid-configuration").respond(json=METADATA)
        yield mock


def test_check_oidc_settings():
    check_auth(_settings())
    with pytest.raises(ValueError, match="clientId is required"):
        check_auth(AuthSettings(oidc=OidcSettings(issuer=ISSUER)))
    with pytest.raises(ValueError, match="auth.url is required"):
        check_auth(AuthSettings(oidc=OidcSettings(issuer=ISSUER, client_id="x")))
    with pytest.raises(ValueError, match="defaultRole 'root'"):
        check_auth(AuthSettings(url="https://x/", oidc=OidcSettings(issuer=ISSUER, client_id="x", default_role="root")))
    # SSO only: no local account needed
    check_auth(AuthSettings(enabled=True, admin=False, url="https://x/", oidc=OidcSettings(issuer=ISSUER, client_id="x")))


def test_helpers():
    verifier, challenge = pkce()
    assert len(verifier) > 43 and "=" not in challenge
    assert jwt_claims(_jwt(sub="a")) == {"sub": "a"}
    for bad in ("nope", "a.!!!.c", "a." + base64.urlsafe_b64encode(b"[1]").decode() + ".c"):
        with pytest.raises(OidcError, match="not a JWT"):
            jwt_claims(bad)


async def test_login(idp):
    oidc = OidcClient(_settings())
    assert oidc.redirect_uri == "https://kt.example.com/tools/auth/callback"
    url = await oidc.authorization_url("st", "n1", "ch")
    split = urlsplit(url)
    query = {k: v[0] for k, v in parse_qs(split.query).items()}
    assert url.startswith("https://idp.example.com/authorize/?")
    assert query == {
        "response_type": "code",
        "client_id": "kube-tower",
        "redirect_uri": "https://kt.example.com/tools/auth/callback",
        "scope": "openid profile email groups",
        "state": "st",
        "nonce": "n1",
        "code_challenge": "ch",
        "code_challenge_method": "S256",
    }

    token = idp.post(METADATA["token_endpoint"]).respond(
        json={"id_token": _jwt(**_claims(preferred_username="alice", groups=["ops", "dev"])), "access_token": "at"}
    )
    assert await oidc.user("code1", "ver1", "n1") == User("alice", "admin", "oidc")
    sent = token.calls.last.request
    assert parse_qs(sent.content.decode()) == {
        "grant_type": ["authorization_code"],
        "code": ["code1"],
        "redirect_uri": ["https://kt.example.com/tools/auth/callback"],
        "code_verifier": ["ver1"],
    }
    assert sent.headers["authorization"] == "Basic " + base64.b64encode(b"kube-tower:cs").decode()
    # The metadata is read once
    assert len(idp.calls) == 2


async def test_roles_and_userinfo(idp, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("cs2\n")
    oidc = OidcClient(_settings(readonly_groups=["dev"], default_role="", client_secret_file=str(secret)))
    assert (oidc.role(["ops"]), oidc.role(["dev"]), oidc.role(["x"])) == ("admin", "readonly", "")
    # No groups in the ID token: read from userinfo, the email names the user without preferred_username
    idp.post(METADATA["token_endpoint"]).respond(json={"id_token": _jwt(**_claims(email="bob@x")), "access_token": "at"})
    info = idp.get(METADATA["userinfo_endpoint"]).respond(json={"sub": "u1", "groups": "dev"})
    assert await oidc.user("c", "v", "n1") == User("bob@x", "readonly", "oidc")
    assert info.calls.last.request.headers["authorization"] == "Bearer at"
    assert idp.calls[1].request.headers["authorization"] == "Basic " + base64.b64encode(b"kube-tower:cs2").decode()
    # In none of the groups: refused
    info.respond(json={"sub": "u1", "groups": ["x"]})
    with pytest.raises(OidcError, match="bob@x is in none of the groups allowed"):
        await oidc.user("c", "v", "n1")


@pytest.mark.parametrize(
    "claims, error",
    [
        (_claims(iss="https://other/"), "comes from 'https://other/'"),
        (_claims(aud="other"), "is for 'other'"),
        (_claims(aud=["kube-tower", "other"]), "is for"),
        (_claims(exp=time.time() - 3600), "has expired"),
        (_claims(nonce="n2"), "not the answer to this login"),
    ],
)
async def test_id_token_checks(idp, claims, error):
    idp.post(METADATA["token_endpoint"]).respond(json={"id_token": _jwt(**claims)})
    with pytest.raises(OidcError, match=error):
        await OidcClient(_settings()).user("c", "v", "n1")


async def test_provider_errors(idp, tmp_path, caplog):
    oidc = OidcClient(_settings())
    idp.post(METADATA["token_endpoint"]).respond(400, json={"error": "invalid_client", "error_description": "bad secret"})
    with pytest.raises(OidcError, match=r"refused the login code: HTTP 400 Bad Request \(invalid_client: bad secret\) - check"):
        await oidc.user("c", "v", "n1")
    idp.post(METADATA["token_endpoint"]).respond(500, text="oops")
    with pytest.raises(OidcError, match="HTTP 500 Internal Server Error$"):
        await oidc.user("c", "v", "n1")
    idp.post(METADATA["token_endpoint"]).respond(200, text="not json")
    with pytest.raises(OidcError, match="not JSON"):
        await oidc.user("c", "v", "n1")
    idp.post(METADATA["token_endpoint"]).mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(OidcError, match="cannot reach the provider"):
        await oidc.user("c", "v", "n1")

    discovery = ISSUER.rstrip("/") + "/.well-known/openid-configuration"
    for response, error in (
        (httpx.Response(404), "cannot read the provider metadata at .*HTTP 404"),
        (httpx.Response(200, text="<html>"), "is not JSON"),
        (httpx.Response(200, json=METADATA | {"issuer": "https://idp.example.com/"}), "says its issuer is"),
    ):
        idp.get(discovery).mock(return_value=response)
        with pytest.raises(OidcError, match=error):
            await OidcClient(_settings()).metadata()
    idp.get(discovery).mock(side_effect=httpx.ConnectTimeout("slow"))
    with pytest.raises(OidcError, match="cannot reach the provider at"):
        await OidcClient(_settings()).metadata()

    with pytest.raises(OidcError, match="client secret is not readable"):
        OidcClient(_settings(client_secret_file=str(tmp_path / "missing")))._client_secret()
    OidcClient(_settings(issuer="http://dex:5556/dex"))
    assert "is plain http" in caplog.text
    ca = tmp_path / "ca.pem"
    ca.write_text("garbage")
    with pytest.raises(Exception):  # noqa: B017 - the CA file is loaded
        OidcClient(_settings(ca_file=str(ca)))._client()


def _app(tmp_path, **auth):
    (tmp_path / "session.key").write_text("k" * 40)
    (tmp_path / "admin.password").write_text("pw")
    settings = Settings()
    settings.auth = _settings(**auth.pop("oidc", {}))
    settings.auth.secret_dir = str(tmp_path)
    for key, value in auth.items():
        setattr(settings.auth, key, value)
    return TestClient(create_app(settings, FakeScanner(), background=False), base_url="https://kt.example.com")


def test_sso_flow(idp, tmp_path, caplog):
    c = _app(tmp_path)
    page = c.get("/login?next=images").text
    assert 'href="auth/login?next=images"' in page and "Log in with Authentik" in page and 'action="login"' in page

    r = c.get("/auth/login?next=images", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("https://idp.example.com/authorize/?")
    query = parse_qs(urlsplit(r.headers["location"]).query)
    state, nonce = query["state"][0], query["nonce"][0]
    assert "kube_tower_oidc" in r.cookies

    idp.post(METADATA["token_endpoint"]).respond(
        json={"id_token": _jwt(**_claims(nonce=nonce, preferred_username="alice", groups=["ops"]))}
    )
    with caplog.at_level(logging.INFO):
        r = c.get(f"/auth/callback?code=c1&state={state}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "../images"
    assert "alice (admin) logged in with Authentik" in caplog.text
    page = c.get("/").text
    assert "alice <small>admin</small>" in page and "Scan now" in page
    assert c.post("/api/refresh").status_code == 202

    # The same state cannot be used twice: its cookie is gone
    r = c.get(f"/auth/callback?code=c1&state={state}")
    assert r.status_code == 401 and "was not started here" in r.text
    assert 'href="../static/kube-tower.css' in r.text and 'href="../auth/login"' in r.text


def test_sso_errors(idp, tmp_path):
    c = _app(tmp_path, admin=False)
    page = c.get("/login").text
    assert "Log in with Authentik" in page and 'action="login"' not in page
    r = c.get("/auth/callback?error=access_denied&error_description=no+way")
    assert r.status_code == 401 and "the provider refused the login: access_denied no way" in r.text
    c.get("/auth/login", follow_redirects=False)
    assert "was not started here" in c.get("/auth/callback?code=x&state=forged").text

    idp.get(ISSUER.rstrip("/") + "/.well-known/openid-configuration").respond(503)
    c = _app(tmp_path, admin=False)  # the metadata read above is kept an hour
    r = c.get("/auth/login")
    assert r.status_code == 502 and "Single sign-on unavailable" in r.text

    # Without the session key
    (tmp_path / "session.key").unlink()
    assert c.get("/auth/login").status_code == 503


def test_sso_session_needs_sso(tmp_path, idp):
    from kube_tower.auth import Authenticator

    auth = Authenticator(_settings())
    auth.fallback = {"session.key": "k"}
    cookie = auth.session(User("alice", "readonly", "oidc"))
    assert auth.from_session(cookie) == User("alice", "readonly", "oidc")
    auth.settings.oidc.issuer = ""
    assert auth.from_session(cookie) is None


def test_no_sso_routes_without_issuer(tmp_path):
    (tmp_path / "session.key").write_text("k")
    settings = Settings()
    settings.auth = AuthSettings(enabled=True, secret_dir=str(tmp_path))
    c = TestClient(create_app(settings, FakeScanner(), background=False))
    assert c.get("/auth/login").status_code == 404 and c.get("/auth/callback").status_code == 404
    assert "Log in with" not in c.get("/login").text
