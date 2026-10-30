"""Single sign-on with OpenID Connect: authorization code flow with PKCE, kube-tower being a confidential client.

The ID token comes straight from the token endpoint of the provider, over a connection kube-tower opened:
its issuer, audience, expiry and nonce are checked, not its signature (OpenID Connect Core 3.1.3.7, the
client authenticates the server with TLS). The role comes from the groups of the user.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import secrets
import ssl
import time
from pathlib import Path
from urllib.parse import urlencode

import httpx

from kube_tower.auth import User
from kube_tower.config import AuthSettings

log = logging.getLogger(__name__)

DISCOVERY_TTL = 3600  # seconds: the provider metadata is read again after this
CLOCK_SKEW = 60  # seconds tolerated on the expiry of the ID token
TIMEOUT = 10


class OidcError(Exception):
    """Why a login with the provider failed, said to the user and logged."""


def _http_error(what: str, resp: httpx.Response) -> str:
    """`<what>: HTTP 400 Bad Request (invalid_client: <description>)`, with the OAuth error the provider gives."""
    message = f"{what}: HTTP {resp.status_code} {resp.reason_phrase}".rstrip()
    try:
        body = resp.json()
    except ValueError:
        body = {}
    if isinstance(body, dict) and body.get("error"):
        message += f" ({body['error']}" + (f": {body['error_description']}" if body.get("error_description") else "") + ")"
    if resp.status_code == 401 or (isinstance(body, dict) and body.get("error") == "invalid_client"):
        message += " - check auth.oidc.clientId and the client secret"
    return message


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def pkce() -> tuple[str, str]:
    """(code_verifier, code_challenge) of PKCE with S256."""
    verifier = secrets.token_urlsafe(48)
    return verifier, _b64(hashlib.sha256(verifier.encode()).digest())


def jwt_claims(token: str) -> dict:
    """The claims of a JWT, without checking its signature (see the module docstring)."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError, binascii.Error) as exc:
        raise OidcError("the provider sent an ID token that is not a JWT") from exc
    if not isinstance(claims, dict):
        raise OidcError("the provider sent an ID token that is not a JWT")
    return claims


class OidcClient:
    def __init__(self, settings: AuthSettings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.oidc = settings.oidc
        self.redirect_uri = settings.url.rstrip("/") + "/auth/callback"
        self._transport = transport
        self._metadata: dict | None = None
        self._metadata_at = 0.0
        if self.oidc.issuer.startswith("http://"):
            log.warning(
                "auth.oidc.issuer %s is plain http: the ID tokens are trusted as the provider sends them, use https "
                "outside a cluster network",
                self.oidc.issuer,
            )

    def _client(self) -> httpx.AsyncClient:
        verify: ssl.SSLContext | bool = True
        if self.oidc.ca_file:
            verify = ssl.create_default_context()
            verify.load_verify_locations(self.oidc.ca_file)
        return httpx.AsyncClient(timeout=TIMEOUT, verify=verify, transport=self._transport)

    def _client_secret(self) -> str:
        if self.oidc.client_secret_file:
            try:
                return Path(self.oidc.client_secret_file).read_text().strip()
            except OSError as exc:
                raise OidcError(f"the client secret is not readable from {self.oidc.client_secret_file}: {exc}") from exc
        return os.environ.get(self.oidc.client_secret_env, "") if self.oidc.client_secret_env else ""

    async def metadata(self) -> dict:
        """The provider metadata (/.well-known/openid-configuration), kept an hour."""
        if self._metadata is not None and time.monotonic() - self._metadata_at < DISCOVERY_TTL:
            return self._metadata
        url = self.oidc.issuer.rstrip("/") + "/.well-known/openid-configuration"
        try:
            async with self._client() as client:
                resp = await client.get(url)
        except httpx.HTTPError as exc:
            raise OidcError(f"cannot reach the provider at {url}: {exc!r}") from exc
        if resp.status_code != 200:
            raise OidcError(_http_error(f"cannot read the provider metadata at {url}", resp))
        try:
            metadata = resp.json()
        except ValueError as exc:
            raise OidcError(f"the provider metadata at {url} is not JSON") from exc
        if metadata.get("issuer", "").rstrip("/") != self.oidc.issuer.rstrip("/"):
            raise OidcError(
                f"the provider says its issuer is {metadata.get('issuer')!r}, not {self.oidc.issuer!r}: "
                "copy it exactly into auth.oidc.issuer"
            )
        self._metadata, self._metadata_at = metadata, time.monotonic()
        return metadata

    async def authorization_url(self, state: str, nonce: str, challenge: str) -> str:
        metadata = await self.metadata()
        query = {
            "response_type": "code",
            "client_id": self.oidc.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": " ".join(self.oidc.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{metadata['authorization_endpoint']}?{urlencode(query)}"

    def role(self, groups: list[str]) -> str:
        """The role of a user in these groups, "" when none."""
        if set(groups) & set(self.oidc.admin_groups):
            return "admin"
        if set(groups) & set(self.oidc.readonly_groups):
            return "readonly"
        return self.oidc.default_role

    async def user(self, code: str, verifier: str, nonce: str) -> User:
        """The user who logged in: exchanges the code for the tokens, checks the ID token, maps the groups."""
        metadata = await self.metadata()
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri, "code_verifier": verifier}
        try:
            async with self._client() as client:
                resp = await client.post(metadata["token_endpoint"], data=form, auth=(self.oidc.client_id, self._client_secret()))
                if resp.status_code != 200:
                    raise OidcError(_http_error("the provider refused the login code", resp))
                tokens = resp.json()
                claims = self._check(jwt_claims(tokens.get("id_token", "")), metadata, nonce)
                if self.oidc.groups_claim not in claims and metadata.get("userinfo_endpoint") and tokens.get("access_token"):
                    info = await client.get(
                        metadata["userinfo_endpoint"], headers={"Authorization": f"Bearer {tokens['access_token']}"}
                    )
                    if info.status_code == 200 and info.json().get("sub") == claims.get("sub"):
                        claims = {**info.json(), **claims}
        except httpx.HTTPError as exc:
            raise OidcError(f"cannot reach the provider: {exc!r}") from exc
        except ValueError as exc:
            raise OidcError("the provider answered something that is not JSON") from exc
        name = str(claims.get(self.oidc.username_claim) or claims.get("email") or claims.get("sub") or "")
        groups = claims.get(self.oidc.groups_claim) or []
        groups = [groups] if isinstance(groups, str) else [str(g) for g in groups]
        role = self.role(groups)
        if not role:
            raise OidcError(f"{name} is in none of the groups allowed in kube-tower (auth.oidc.adminGroups, readonlyGroups)")
        log.debug("OIDC user %s, groups %s: role %s", name, ", ".join(groups) or "none", role)
        return User(name, role, "oidc")

    def _check(self, claims: dict, metadata: dict, nonce: str) -> dict:
        if claims.get("iss", "").rstrip("/") != metadata["issuer"].rstrip("/"):
            raise OidcError(f"the ID token comes from {claims.get('iss')!r}, not from {metadata['issuer']!r}")
        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience or []
        if self.oidc.client_id not in audiences or (len(audiences) > 1 and claims.get("azp") != self.oidc.client_id):
            raise OidcError(f"the ID token is for {audience!r}, not for the client {self.oidc.client_id!r}")
        if claims.get("exp", 0) < time.time() - CLOCK_SKEW:
            raise OidcError("the ID token has expired: check the clock of the provider and of kube-tower")
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise OidcError("the ID token is not the answer to this login (nonce): log in again")
        return claims
