"""Login: local accounts and sessions kept in signed cookies.

A session is a cookie signed with a key shared by every `ui` process (HMAC-SHA256): no session is stored,
any ui replica serves any request (ADR 0002). The built-in `admin` password and the signing key live in
one Secret, created with random values by the controller when it is missing, like the
`argocd-initial-admin-secret` of ArgoCD. The chart mounts it in every pod with the ui role.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from kubernetes import client

from kube_tower.config import USER_ROLES, AuthSettings, LocalUser

log = logging.getLogger(__name__)

COOKIE = "kube_tower_session"
ADMIN = "admin"
PASSWORD_KEY, SESSION_KEY = "admin.password", "session.key"


@dataclass(frozen=True)
class User:
    name: str
    role: str  # readonly | admin
    source: str = "local"  # local | oidc | anonymous

    @property
    def admin(self) -> bool:
        return self.role == "admin"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_secret() -> dict[str, str]:
    """Values of a new auth Secret: a random admin password and a random signing key."""
    return {PASSWORD_KEY: secrets.token_urlsafe(18), SESSION_KEY: secrets.token_urlsafe(48)}


def ensure_secret(core: client.CoreV1Api, namespace: str, name: str) -> dict[str, str]:
    """The values of the auth Secret, created with random ones when it does not exist. A Secret made by
    someone else (ExternalSecret, values of the chart) is used as it is."""
    try:
        secret = core.read_namespaced_secret(name, namespace)
        log.debug("auth Secret %s/%s found", namespace, name)
    except client.ApiException as exc:
        if exc.status != 404:
            raise
        body = client.V1Secret(
            metadata=client.V1ObjectMeta(name=name, labels={"app.kubernetes.io/part-of": "kube-tower"}),
            type="Opaque",
            string_data=generate_secret(),
        )
        try:
            secret = core.create_namespaced_secret(namespace, body)
            log.info(
                "auth Secret %s/%s created: the password of the admin account is its key %s "
                "(kubectl -n %s get secret %s -o jsonpath='{.data.admin\\.password}' | base64 -d)",
                namespace,
                name,
                PASSWORD_KEY,
                namespace,
                name,
            )
        except client.ApiException as again:
            if again.status != 409:  # 409: another controller created it meanwhile
                raise
            secret = core.read_namespaced_secret(name, namespace)
    data = {k: base64.b64decode(v).decode() for k, v in (secret.data or {}).items()}
    if SESSION_KEY not in data:
        log.error("auth Secret %s/%s has no %s key: nobody can log in until it is added", namespace, name, SESSION_KEY)
    return data


class Authenticator:
    """Checks passwords and session cookies for one process with the ui role."""

    def __init__(self, settings: AuthSettings):
        self.settings = settings
        # Values of the auth Secret read from the Kubernetes API by a process running the controller: used until
        # the kubelet has mounted the Secret (about a minute after it is created).
        self.fallback: dict[str, str] = {}

    @property
    def enabled(self) -> bool:
        return self.settings.enabled

    def _secret(self, key: str) -> str:
        path = Path(self.settings.secret_dir) / key
        try:
            if value := path.read_text().strip():
                return value
        except OSError:
            pass
        return self.fallback.get(key, "")

    def _key(self) -> bytes:
        return self._secret(SESSION_KEY).encode()

    def ready(self) -> bool:
        """The signing key is known: sessions can be opened."""
        return bool(self._key())

    def _local(self, name: str) -> LocalUser | None:
        if name == ADMIN and self.settings.admin:
            return LocalUser(ADMIN, "admin")
        return next((u for u in self.settings.users if u.name == name), None)

    def _password(self, user: LocalUser) -> str:
        if user.name == ADMIN and self.settings.admin:
            return self._secret(PASSWORD_KEY)
        if user.password_file:
            try:
                return Path(user.password_file).read_text().strip()
            except OSError as exc:
                log.warning("password of user %r not readable from %s: %s", user.name, user.password_file, exc)
                return ""
        return os.environ.get(user.password_env, "") if user.password_env else ""

    def _fingerprint(self, password: str) -> str:
        """Ties a session to the password it was opened with: a new password closes the sessions."""
        return hmac.new(self._key(), b"password:" + password.encode(), hashlib.sha256).hexdigest()[:16]

    def check_password(self, name: str, password: str) -> User | None:
        user = self._local(name)
        expected = self._password(user) if user else ""
        # compare_digest on every attempt: the time taken does not tell whether the account exists
        valid = hmac.compare_digest(password.encode(), (expected or secrets.token_hex(16)).encode())
        return User(user.name, user.role) if user and expected and valid else None

    def sign(self, payload: dict) -> str:
        """`payload` as a cookie value signed with the session key."""
        body = _b64(json.dumps(payload, separators=(",", ":")).encode())
        return f"{body}.{_b64(hmac.new(self._key(), body.encode(), hashlib.sha256).digest())}"

    def unsign(self, value: str, now: float | None = None) -> dict | None:
        """The payload of a value made by sign(), None when it is forged or expired (its `e`)."""
        key = self._key()
        body, _, signature = value.partition(".")
        if not key or not signature:
            return None
        expected = _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature.encode(), expected.encode()):
            return None
        try:
            payload = json.loads(_unb64(body))
        except (ValueError, binascii.Error):
            return None
        if not isinstance(payload, dict) or payload.get("e", 0) < (now or time.time()):
            return None
        return payload

    def session(self, user: User, now: float | None = None) -> str:
        """The cookie value of a new session."""
        payload = {"u": user.name, "e": int((now or time.time()) + self.settings.session_duration)}
        if user.source == "oidc":  # the role from the groups at login: a change applies at the next login
            payload |= {"s": "oidc", "r": user.role}
        else:
            local = self._local(user.name)
            payload["f"] = self._fingerprint(self._password(local)) if local else ""
        return self.sign(payload)

    def from_session(self, value: str, now: float | None = None) -> User | None:
        """The user of a session cookie, None when it is forged, expired, or its password changed."""
        payload = self.unsign(value, now)
        if payload is None:
            return None
        if payload.get("s") == "oidc":
            role = payload.get("r")
            return User(payload.get("u", ""), role, "oidc") if self.settings.oidc.issuer and role in USER_ROLES else None
        local = self._local(payload.get("u", ""))
        if local is None:
            return None
        password = self._password(local)
        if not password or not hmac.compare_digest(payload.get("f", ""), self._fingerprint(password)):
            return None
        return User(local.name, local.role)  # the role of now: a change applies to the open sessions

    def from_basic(self, header: str) -> User | None:
        """The user of an `Authorization: Basic` header (scripts calling the API)."""
        scheme, _, credentials = header.partition(" ")
        if scheme.lower() != "basic":
            return None
        try:
            name, _, password = base64.b64decode(credentials).decode().partition(":")
        except (ValueError, binascii.Error):
            return None
        return self.check_password(name, password)

    @property
    def local_accounts(self) -> bool:
        """Some account logs in with a password (else the login page only offers the SSO)."""
        return self.settings.admin or bool(self.settings.users)

    @property
    def anonymous(self) -> User | None:
        return User("anonymous", self.settings.anonymous_role, "anonymous") if self.settings.anonymous_role else None
