import asyncio
import base64
import logging
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from kubernetes import client

from kube_tower import main as main_module
from kube_tower.auth import COOKIE, Authenticator, User, ensure_secret
from kube_tower.config import AuthSettings, LocalUser, Settings, check_auth, load_settings
from kube_tower.main import create_app, keep_auth_secret
from kube_tower.web import login as login_module
from kube_tower.web.login import safe_next
from test_web import FakeScanner


@pytest.fixture
def secret_dir(tmp_path):
    (tmp_path / "admin.password").write_text("s3cret\n")
    (tmp_path / "session.key").write_text("k" * 40)
    return tmp_path


def _settings(secret_dir, **auth) -> Settings:
    settings = Settings()
    settings.auth = AuthSettings(enabled=True, secret_dir=str(secret_dir), **auth)
    return settings


def _client(settings: Settings):
    scanner = FakeScanner()
    return TestClient(create_app(settings, scanner, background=False)), scanner


def _login(c: TestClient, name: str, password: str, next: str = ""):
    return c.post("/login", data={"username": name, "password": password, "next": next}, follow_redirects=False)


def test_check_auth(tmp_path):
    check_auth(AuthSettings())
    with pytest.raises(ValueError, match="role must be one of readonly, admin"):
        check_auth(AuthSettings(users=[LocalUser("bob", "root")]))
    with pytest.raises(ValueError, match="anonymousRole 'admin'"):
        check_auth(AuthSettings(anonymous_role="admin"))
    with pytest.raises(ValueError, match="each name once"):
        check_auth(AuthSettings(users=[LocalUser("admin")]))
    with pytest.raises(ValueError, match="no account to log in with"):
        check_auth(AuthSettings(enabled=True, admin=False))
    config = tmp_path / "config.yaml"
    config.write_text("auth:\n  enabled: true\n  sessionDuration: 8h\n  users:\n    - name: alice\n      passwordEnv: ALICE\n")
    settings = load_settings(str(config))
    assert settings.auth.session_duration == 8 * 3600 and settings.auth.users == [LocalUser("alice", password_env="ALICE")]


def test_authenticator(secret_dir, monkeypatch):
    (secret_dir / "bob").write_text("bobpw")
    monkeypatch.setenv("CAROL_PASSWORD", "carolpw")
    auth = Authenticator(
        AuthSettings(
            enabled=True,
            secret_dir=str(secret_dir),
            users=[
                LocalUser("bob", password_file=str(secret_dir / "bob")),
                LocalUser("carol", "admin", password_env="CAROL_PASSWORD"),
                LocalUser("dave", password_file=str(secret_dir / "missing")),
                LocalUser("erin"),
            ],
        )
    )
    assert auth.ready()
    assert auth.check_password("admin", "s3cret") == User("admin", "admin")
    assert auth.check_password("admin", "wrong") is None
    assert auth.check_password("bob", "bobpw") == User("bob", "readonly")
    assert auth.check_password("carol", "carolpw") == User("carol", "admin")
    assert auth.check_password("dave", "") is None and auth.check_password("erin", "") is None
    assert auth.check_password("nobody", "s3cret") is None

    cookie = auth.session(User("bob", "readonly"), now=1000)
    assert auth.from_session(cookie, now=1000) == User("bob", "readonly")
    assert auth.from_session(cookie, now=1000 + 24 * 3600 + 1) is None  # expired
    body, _, signature = cookie.partition(".")
    assert auth.from_session(f"{body}x.{signature}", now=1000) is None  # tampered
    assert auth.from_session("garbage", now=1000) is None
    assert auth.from_session(body + ".", now=1000) is None
    # The role of now applies to the open sessions
    auth.settings.users[0].role = "admin"
    assert auth.from_session(cookie, now=1000) == User("bob", "admin")
    # A new password closes the sessions opened with the old one
    (secret_dir / "bob").write_text("newpw")
    assert auth.from_session(cookie, now=1000) is None
    # A session of a removed user is refused
    gone = auth.session(User("carol", "admin"), now=1000)
    auth.settings.users = auth.settings.users[:1]
    assert auth.from_session(gone, now=1000) is None

    basic = "Basic " + base64.b64encode(b"admin:s3cret").decode()
    assert auth.from_basic(basic) == User("admin", "admin")
    assert auth.from_basic("Bearer x") is None and auth.from_basic("Basic !!!") is None
    assert auth.anonymous is None
    auth.settings.anonymous_role = "readonly"
    assert auth.anonymous == User("anonymous", "readonly", "anonymous")


def test_authenticator_without_secret(tmp_path):
    auth = Authenticator(AuthSettings(enabled=True, secret_dir=str(tmp_path)))
    assert not auth.ready() and auth.check_password("admin", "") is None
    # The values read by the controller of the process, until the kubelet mounts the Secret
    auth.fallback = {"admin.password": "pw", "session.key": "key"}
    assert auth.ready() and auth.check_password("admin", "pw") == User("admin", "admin")
    auth.settings.admin = False
    assert auth.check_password("admin", "pw") is None


def _secret(**data):
    return client.V1Secret(data={k: base64.b64encode(v.encode()).decode() for k, v in data.items()})


def test_ensure_secret(caplog):
    core = MagicMock()
    core.read_namespaced_secret.return_value = _secret(**{"admin.password": "a", "session.key": "k"})
    assert ensure_secret(core, "ns", "kt-auth") == {"admin.password": "a", "session.key": "k"}
    assert not core.create_namespaced_secret.called

    # Missing: created with random values
    core = MagicMock()
    core.read_namespaced_secret.side_effect = client.ApiException(status=404)

    def create(namespace, body):
        assert namespace == "ns" and body.metadata.name == "kt-auth"
        assert len(body.string_data["admin.password"]) >= 20 and len(body.string_data["session.key"]) >= 60
        return _secret(**body.string_data)

    core.create_namespaced_secret.side_effect = create
    with caplog.at_level(logging.INFO):
        data = ensure_secret(core, "ns", "kt-auth")
    assert set(data) == {"admin.password", "session.key", "dex.clientSecret"} and "auth Secret ns/kt-auth created" in caplog.text

    # Created meanwhile by another controller
    core = MagicMock()
    core.read_namespaced_secret.side_effect = [client.ApiException(status=404), _secret(**{"admin.password": "b"})]
    core.create_namespaced_secret.side_effect = client.ApiException(status=409)
    assert ensure_secret(core, "ns", "kt-auth") == {"admin.password": "b"}
    assert "has no session.key key" in caplog.text

    core.read_namespaced_secret.side_effect = client.ApiException(status=403)
    with pytest.raises(client.ApiException):
        ensure_secret(core, "ns", "kt-auth")
    core.read_namespaced_secret.side_effect = client.ApiException(status=404)
    core.create_namespaced_secret.side_effect = client.ApiException(status=403)
    with pytest.raises(client.ApiException):
        ensure_secret(core, "ns", "kt-auth")


async def test_keep_auth_secret(monkeypatch, caplog, tmp_path):
    settings = _settings(tmp_path)
    scanner = MagicMock()
    scanner.registry.local_client.return_value = None
    await keep_auth_secret(settings, scanner, None)
    assert "the auth Secret is not created" in caplog.text

    scanner.registry.local_client.return_value = object()
    monkeypatch.setattr(main_module.client, "CoreV1Api", lambda _: "core")
    monkeypatch.setattr(main_module, "current_namespace", lambda: "ns")
    monkeypatch.setattr(main_module, "AUTH_SECRET_RETRY", 0)
    calls = []

    def ensure(core, namespace, name):
        calls.append((core, namespace, name))
        if len(calls) == 1:
            raise client.ApiException(status=403, reason="Forbidden")
        return {"session.key": "k"}

    monkeypatch.setattr(main_module, "ensure_secret", ensure)
    auth = Authenticator(settings.auth)
    await asyncio.wait_for(keep_auth_secret(settings, scanner, auth), 5)
    assert calls == [("core", "ns", "kube-tower-auth")] * 2 and auth.fallback == {"session.key": "k"}
    assert "cannot read or create the auth Secret ns/kube-tower-auth: 403 Forbidden" in caplog.text


def test_safe_next():
    assert safe_next("images?q=nginx&running=0") == "images?q=nginx&running=0"
    assert safe_next("images/detail?ref=docker.io%2Fnginx") == "images/detail?ref=docker.io%2Fnginx"
    for bad in ("/images", "//evil.example", "https://evil.example", "images/../../x", "a b", "images?x=<b>"):
        assert safe_next(bad) == "", bad


def test_login_flow(secret_dir, monkeypatch, caplog):
    monkeypatch.setattr(login_module, "FAILED_LOGIN_DELAY", 0)
    c, scanner = _client(_settings(secret_dir))
    # Without a session: pages lead to the login page (relative, whatever the sub-path), the API answers 401
    r = c.get("/images?q=nginx", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "login?next=images%3Fq%3Dnginx"
    r = c.get("/images/detail?ref=x", follow_redirects=False)
    assert r.headers["location"] == "../login?next=images/detail%3Fref%3Dx"
    assert c.get("/", follow_redirects=False).headers["location"] == "login"
    r = c.get("/status", headers={"HX-Request": "true"})
    assert r.status_code == 401 and r.headers["HX-Redirect"] == "login"
    r = c.get("/api/snapshot")
    assert r.status_code == 401 and r.headers["WWW-Authenticate"] == 'Basic realm="kube-tower"'
    assert "WWW-Authenticate" not in c.post("/api/refresh", headers={"HX-Request": "true"}).headers
    assert c.get("/healthz").status_code == 200 and c.get("/metrics").status_code == 200
    assert c.get("/static/kube-tower.css").status_code == 200
    page = c.get("/login?next=charts").text
    assert 'name="next" value="charts"' in page and 'action="login"' in page

    # Wrong password
    with caplog.at_level(logging.INFO):
        r = _login(c, "admin", "nope")
    assert r.status_code == 401 and "Wrong username or password" in r.text and 'value="admin"' in r.text
    assert "failed login for 'admin'" in caplog.text and COOKIE not in r.cookies

    # Admin: back to the page asked for, every action allowed and logged with the name
    r = _login(c, "admin", "s3cret", "charts?cluster=c1")
    assert r.status_code == 303 and r.headers["location"] == "./charts?cluster=c1"
    assert "HttpOnly" in r.headers["set-cookie"] and "SameSite=lax" in r.headers["set-cookie"]
    page = c.get("/").text
    assert "Scan now" in page and "admin <small>admin</small>" in page and 'action="logout"' in page
    with caplog.at_level(logging.INFO):
        assert c.post("/api/refresh").status_code == 202
    assert scanner.triggered == 1 and "admin (admin): POST /api/refresh" in caplog.text
    assert "Rescans need the admin role" not in c.get("/images/detail?ref=docker.io/library/nginx:1.25").text

    # Log out
    r = c.post("/logout", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "login"
    c.cookies.clear()
    assert c.get("/", follow_redirects=False).status_code == 303


def test_readonly_user(secret_dir, monkeypatch):
    monkeypatch.setenv("BOB_PASSWORD", "bobpw")
    c, scanner = _client(_settings(secret_dir, users=[LocalUser("bob", password_env="BOB_PASSWORD")]))
    assert _login(c, "bob", "bobpw").status_code == 303
    page = c.get("/").text
    assert "bob <small>readonly</small>" in page and "Scan now" not in page
    assert "Rescans need the admin role" in c.get("/images/detail?ref=docker.io/library/nginx:1.25").text
    page = c.get("/administration").text
    assert 'disabled title="The admin role is needed"' in page and "Read-only: the actions of this page" in page
    r = c.post("/api/refresh")
    assert r.status_code == 403 and r.json() == {"detail": "the admin role is needed"}
    assert c.post("/administration/scan").status_code == 403 and scanner.triggered == 0
    assert c.get("/api/snapshot").status_code == 200  # reading is allowed


def test_basic_auth_anonymous_and_metrics(secret_dir):
    c, scanner = _client(_settings(secret_dir, anonymous_role="readonly", metrics_public=False))
    # Anonymous visitors read, and are invited to log in to act
    page = c.get("/").text
    assert 'href="login"' in page and "Scan now" not in page
    assert c.post("/api/refresh").status_code == 403
    assert c.get("/metrics").status_code == 200  # anonymous readonly is a user
    # Scripts: Basic auth of a local user
    assert c.post("/api/refresh", auth=("admin", "s3cret")).status_code == 202 and scanner.triggered == 1

    c, _ = _client(_settings(secret_dir, metrics_public=False))
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", auth=("admin", "s3cret")).status_code == 200


def test_login_without_secret(tmp_path):
    c, _ = _client(_settings(tmp_path))
    r = _login(c, "admin", "x")
    assert r.status_code == 503 and "creating its auth Secret" in r.text


def test_auth_off_by_default():
    c, scanner = _client(Settings())
    assert c.get("/").status_code == 200 and 'action="logout"' not in c.get("/").text
    assert c.post("/api/refresh").status_code == 202
    assert c.get("/login").status_code == 404
