import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from kube_tower.auth import generate_secret
from kube_tower.config import AuthSettings, OidcSettings, Settings, check_auth
from kube_tower.main import create_app
from kube_tower.oidc import OidcClient
from test_web import FakeScanner

ISSUER = "https://kt.example.com/tools/api/dex"
DEX = "http://kt-dex:5556"


def _auth(tmp_path) -> AuthSettings:
    (tmp_path / "session.key").write_text("k" * 40)
    return AuthSettings(
        enabled=True,
        admin=False,
        url="https://kt.example.com/tools/",
        secret_dir=str(tmp_path),
        dex_url=DEX,
        oidc=OidcSettings(name="Dex", issuer=ISSUER, client_id="kube-tower", provider_url=DEX + "/tools/api/dex"),
    )


def _client(tmp_path):
    settings = Settings()
    settings.auth = _auth(tmp_path)
    return TestClient(create_app(settings, FakeScanner(), background=False), base_url="https://kt.example.com")


def test_settings_and_secret():
    with pytest.raises(ValueError, match="auth.dexUrl: set auth.oidc.issuer"):
        check_auth(AuthSettings(dex_url=DEX))
    assert set(generate_secret()) == {"admin.password", "session.key", "dex.clientSecret"}


def test_dex_proxy(tmp_path):
    c = _client(tmp_path)
    with respx.mock(assert_all_called=True) as dex:
        # Without a session, under the sub-path that the ingress strips: Dex gets its issuer path
        discovery = dex.get(f"{DEX}/tools/api/dex/.well-known/openid-configuration").respond(
            json={"issuer": ISSUER}, headers={"Set-Cookie": "a=1", "X-Dex": "yes"}
        )
        r = c.get("/api/dex/.well-known/openid-configuration")
        assert r.status_code == 200 and r.json() == {"issuer": ISSUER} and r.headers["x-dex"] == "yes"
        assert r.headers["set-cookie"] == "a=1" and discovery.calls.last.request.headers["host"] == "kt-dex:5556"
        # A connector answering with a POST from another site (SAML), redirects passed as they are
        callback = dex.post(f"{DEX}/tools/api/dex/callback/saml?x=1").respond(
            302, headers={"Location": "/tools/api/dex/approval"}
        )
        r = c.post(
            "/api/dex/callback/saml?x=1",
            content=b"SAMLResponse=abc",
            headers={"Origin": "https://idp.example.org"},
            follow_redirects=False,
        )
        assert r.status_code == 302 and r.headers["location"] == "/tools/api/dex/approval"
        assert callback.calls.last.request.content == b"SAMLResponse=abc"
    with respx.mock() as dex:
        dex.get(f"{DEX}/tools/api/dex/auth").mock(side_effect=httpx.ConnectError("refused"))
        r = c.get("/api/dex/auth")
        assert r.status_code == 502 and "Dex is not reachable" in r.text
    # The login page offers Dex only
    assert "Log in with Dex" in c.get("/login").text and 'action="login"' not in c.get("/login").text


async def test_provider_url(tmp_path):
    oidc = OidcClient(_auth(tmp_path))
    with respx.mock() as dex:
        dex.get(f"{DEX}/tools/api/dex/.well-known/openid-configuration").respond(
            json={
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/auth",
                "token_endpoint": f"{ISSUER}/token",
                "userinfo_endpoint": f"{ISSUER}/userinfo",
            }
        )
        metadata = await oidc.metadata()
    # The browser goes to the issuer, kube-tower to the Dex Service
    assert metadata["authorization_endpoint"] == f"{ISSUER}/auth"
    assert metadata["token_endpoint"] == f"{DEX}/tools/api/dex/token"
    assert metadata["userinfo_endpoint"] == f"{DEX}/tools/api/dex/userinfo"
