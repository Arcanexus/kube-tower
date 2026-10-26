"""Minimal OCI distribution (registry v2) client: list tags and resolve digests.

Works with any registry implementing the distribution API: Docker Hub, ghcr.io, quay.io,
registry.k8s.io, Amazon ECR, Artifact Registry, ACR, Harbor, Artifactory, Nexus, GitLab... using
the standard challenges, Bearer token or basic auth (anonymous or with the credentials of auth.py).
"""

from __future__ import annotations

import base64
import fnmatch
import json
import logging
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from kube_tower.errors import http_error_message
from kube_tower.models import ImageRef

if TYPE_CHECKING:
    from kube_tower.registry.auth import AuthResults, Credentials

log = logging.getLogger(__name__)

DOCKER_HUB = "docker.io"
DOCKER_HUB_API = "registry-1.docker.io"
DOCKER_HUB_ALIASES = {"docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"}

MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
_CHALLENGE_RE = re.compile(r'(\w+)="([^"]*)"')
_LINK_RE = re.compile(r"<([^>]+)>;\s*rel=\"next\"")


def parse_image_ref(image: str) -> ImageRef:
    """Normalize `nginx`, `bitnami/redis:7`, `ghcr.io/x/y@sha256:...` into an ImageRef."""
    digest = None
    if "@" in image:
        image, digest = image.split("@", 1)
    tag = None
    last = image.rsplit("/", 1)[-1]
    if ":" in last:
        image, tag = image.rsplit(":", 1)
    parts = image.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, repository = parts
    else:
        registry, repository = DOCKER_HUB, image
    if registry in DOCKER_HUB_ALIASES:
        registry = DOCKER_HUB
    if registry == DOCKER_HUB and "/" not in repository:
        repository = f"library/{repository}"
    if tag is None and digest is None:
        tag = "latest"
    return ImageRef(registry=registry, repository=repository, tag=tag, digest=digest)


def load_docker_credentials(path: str) -> dict[str, tuple[str, str]]:
    """Read a docker config.json and return {registry_host: (username, password)}."""
    file = Path(path)
    if not file.is_file():
        return {}
    data = json.loads(file.read_text())
    if data.get("credsStore") or data.get("credHelpers"):
        log.warning(
            "%s: credsStore/credHelpers are not supported (no helper binaries in the image), use registries.credentials", path
        )
    return parse_docker_config(data)


def parse_docker_config(data: dict) -> dict[str, tuple[str, str]]:
    """{registry_host: (username, password)} of a docker config.json, or of the legacy .dockercfg format
    (the `auths` map itself), as found in image pull secrets."""
    auths = data.get("auths") if isinstance(data.get("auths"), dict) else data
    creds: dict[str, tuple[str, str]] = {}
    for host, entry in auths.items():
        if not isinstance(entry, dict):
            continue
        host = re.sub(r"^https?://", "", host).split("/")[0].lower()
        if host in DOCKER_HUB_ALIASES:
            host = DOCKER_HUB
        if entry.get("identitytoken"):
            # A refresh token (e.g. `az acr login`), sent as the password of a fixed user.
            user, pwd = "00000000-0000-0000-0000-000000000000", entry["identitytoken"]
        elif entry.get("auth"):
            user, _, pwd = base64.b64decode(entry["auth"]).decode().partition(":")
        else:
            user, pwd = entry.get("username", ""), entry.get("password", "")
        if pwd:
            creds[host] = (user, pwd)
    return creds


MAX_REDIRECTS = 5
# A token is renewed this long before the end of its lifetime (`expires_in`), so a request never sends it expired.
TOKEN_EXPIRY_MARGIN = 30


class RegistryError(Exception):
    """A registry, Helm repository or git host answered, but not with what was asked: the message says why."""


def require_https(url: str | httpx.URL, what: str) -> None:
    """Credentials and tokens are never sent over plain http://: anyone on the path could read them."""
    if httpx.URL(str(url)).scheme != "https":
        raise RegistryError(f"{what} uses {httpx.URL(str(url)).copy_with(query=None)}: refused, only https:// is allowed")


class OCIClient:
    def __init__(
        self,
        http: httpx.AsyncClient,
        credentials: Credentials | dict[str, tuple[str, str]] | None = None,
        mirrors: dict[str, str] | None = None,
        max_tag_pages: int = 50,
        insecure: list[str] | None = None,
        insecure_http: httpx.AsyncClient | None = None,
        auth_results: AuthResults | None = None,
    ):
        from kube_tower.registry.auth import AuthResults, Credentials

        self.http = http
        self.credentials = credentials if isinstance(credentials, Credentials) else Credentials(credentials)
        self.mirrors = mirrors or {}
        self.max_tag_pages = max_tag_pages
        # Hosts (or patterns) whose TLS certificate is not verified (registries.insecure), with their client.
        self.insecure = insecure or []
        self.insecure_http = insecure_http
        self._schemes: dict[str, str] = {}  # insecure hosts found to answer in plain http://
        # (host, scope) -> (token, monotonic time it expires at, None when the registry gives no lifetime)
        self._tokens: dict[tuple[str, str], tuple[str, float | None]] = {}
        # Whether each registry accepted the credentials (shown on the Settings page), kept between scans.
        self.auth_results = auth_results if auth_results is not None else AuthResults()

    def is_insecure(self, host: str) -> bool:
        return any(fnmatch.fnmatch(host.lower(), pattern) for pattern in self.insecure)

    def client_for(self, host: str) -> httpx.AsyncClient:
        """The HTTP client for a host: one that does not verify TLS certificates for insecure hosts."""
        return self.insecure_http if self.insecure_http is not None and self.is_insecure(host) else self.http

    def _url(self, registry: str, path: str) -> str:
        host = self._api_host(registry)
        return f"{self._schemes.get(host, 'https')}://{host}{path}"

    async def _send(self, method: str, url: str, **kwargs) -> httpx.Response:
        """One request; an insecure host that does not answer in https:// is tried (and then used) in http://."""
        target = httpx.URL(url)
        try:
            return await self.client_for(target.host).request(method, url, **kwargs)
        except httpx.ConnectError:
            if target.scheme != "https" or not self.is_insecure(target.host):
                raise
        host = target.netloc.decode()
        log.info("%s does not answer in https://, using http:// (registries.insecure)", host)
        self._schemes[host] = "http"
        return await self.client_for(target.host).request(method, str(target.copy_with(scheme="http")), **kwargs)

    def _api_host(self, registry: str) -> str:
        if registry in self.mirrors:
            return self.mirrors[registry]
        return DOCKER_HUB_API if registry == DOCKER_HUB else registry

    def _credentials_host(self, registry: str, host: str) -> str:
        """The registry whose credentials go to `host`, chosen by that host like Docker and containerd do.

        The registry's own credentials go to its API host (or its mirror) only. After a redirect to
        another host (e.g. registry.k8s.io to Artifact Registry), that host gets the credentials
        configured for it, or none: the registry's credentials are never sent elsewhere.
        """
        if host in (registry, self._api_host(registry)):
            return registry
        host = host.lower()
        return DOCKER_HUB if host in DOCKER_HUB_ALIASES else host

    async def _credentials_for(self, registry: str, host: str) -> tuple[str, str] | None:
        """Credentials for a request to `host` (see _credentials_host)."""
        target = self._credentials_host(registry, host)
        try:
            return await self.credentials.get(target)
        except RegistryError as exc:  # a cloud provider that cannot get a token
            self.auth_results.record(target, False, str(exc))
            raise

    def _record_auth(self, registry: str, host: str, resp: httpx.Response) -> None:
        """Note whether a request that sent credentials was accepted (401 and 403 mean refused)."""
        ok = resp.status_code not in (401, 403)
        message = "" if ok else http_error_message(f"{registry} refused the credentials", resp)
        self.auth_results.record(self._credentials_host(registry, host), ok, message)

    def _cached_token(self, host: str, scope: str) -> str | None:
        """The token got earlier for this host and scope, unless it has expired (or is about to)."""
        cached = self._tokens.get((host, scope))
        if cached is None:
            return None
        token, expires_at = cached
        if expires_at is not None and time.monotonic() >= expires_at:
            del self._tokens[(host, scope)]
            return None
        return token

    async def _renew_token(self, registry: str, host: str, challenge: str, scope: str) -> str | None:
        """A new token after a 401: the cached one (if any) was refused, e.g. it expired during a long scan."""
        self._tokens.pop((host, scope), None)
        return await self._token(registry, host, challenge, scope)

    async def _token(self, registry: str, host: str, challenge: str, scope: str) -> str | None:
        key = (host, scope)
        if token := self._cached_token(host, scope):
            return token
        scheme, _, params = challenge.partition(" ")
        if scheme.lower() != "bearer":
            return None
        fields = dict(_CHALLENGE_RE.findall(params))
        query = {"service": fields.get("service", "")}
        if scope := fields.get("scope", scope):
            query["scope"] = scope
        # The credentials of the host that sent the challenge, even when its token service is elsewhere
        # (auth.docker.io for Docker Hub, gitlab.com for registry.gitlab.com).
        auth = await self._credentials_for(registry, host)
        # The token (and the credentials asking for it) would travel in clear text.
        require_https(fields.get("realm", ""), f"the token service of {registry}")
        log.debug(
            "requesting an %s token for %s%s (%s)",
            "authenticated" if auth else "anonymous",
            registry,
            f" from {host}" if host != self._api_host(registry) else "",
            query.get("scope", "no scope"),
        )
        resp = await self.client_for(httpx.URL(fields["realm"]).host).get(fields["realm"], params=query, auth=auth)
        if auth:
            self._record_auth(registry, host, resp)
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot get a pull token for {registry}", resp))
        body = resp.json()
        token = body.get("token") or body.get("access_token")
        expires_at = None
        if isinstance(expires_in := body.get("expires_in"), int | float) and expires_in > 0:
            expires_at = time.monotonic() + max(expires_in - TOKEN_EXPIRY_MARGIN, expires_in / 2)
        self._tokens[key] = (token, expires_at)
        return token

    async def _request(self, method: str, registry: str, repository: str, url: str, **kwargs) -> httpx.Response:
        """A registry API request, authenticated on demand (bearer token or basic auth).

        Registry redirects (e.g. registry.k8s.io to a regional Artifact Registry) are followed
        here, authenticating against the target registry. Callers that pass `follow_redirects`
        (blob downloads to object storage) let httpx follow them, without credentials.
        """
        scope = f"repository:{repository}:pull"
        base_headers = kwargs.pop("headers", {})
        manual_redirects = "follow_redirects" not in kwargs
        for _ in range(MAX_REDIRECTS + 1):
            host = httpx.URL(url).host
            headers = dict(base_headers)
            if token := self._cached_token(host, scope):
                headers["Authorization"] = f"Bearer {token}"
            resp = await self._send(method, url, headers=headers, **kwargs)
            url = str(resp.request.url)  # http:// for an insecure registry without TLS
            if resp.status_code == 401 and "www-authenticate" in resp.headers:
                challenge = resp.headers["www-authenticate"]
                if challenge.lower().startswith("basic"):
                    # Basic auth sends the password itself: only over https://.
                    if resp.request.url.scheme == "https" and (auth := await self._credentials_for(registry, host)):
                        resp = await self._send(method, url, headers=headers, auth=auth, **kwargs)
                        self._record_auth(registry, host, resp)
                elif token := await self._renew_token(registry, host, challenge, scope):
                    headers["Authorization"] = f"Bearer {token}"
                    resp = await self._send(method, url, headers=headers, **kwargs)
            if not (manual_redirects and resp.is_redirect and "location" in resp.headers):
                return resp
            url = str(resp.url.join(resp.headers["location"]))
            # The next request carries a token or the registry credentials.
            require_https(url, f"a redirect of {registry}/{repository}")
            log.debug("%s redirected to %s", resp.request.url.copy_with(query=None), httpx.URL(url).copy_with(query=None))
        raise RegistryError(f"too many redirects for {registry}/{repository} (more than {MAX_REDIRECTS})")

    async def ping(self, registry: str, repository: str | None = None) -> str:
        """Check that the registry answers and accepts kube-tower's credentials (or anonymous access).
        With a repository, the token asked for is a pull token for it (some registries, like ghcr.io,
        refuse anonymous tokens without scope). Returns what was checked, raises RegistryError when it fails.
        """
        scope = f"repository:{repository}:pull" if repository else ""
        host = self._api_host(registry)
        auth = "with credentials" if registry in self.credentials else "anonymously"
        resp = await self._send("GET", self._url(registry, "/v2/"))
        if resp.request.url.scheme == "http":
            auth += " over plain http://"
        if resp.status_code == 401 and "www-authenticate" in resp.headers:
            challenge = resp.headers["www-authenticate"]
            if challenge.lower().startswith("basic"):
                if registry not in self.credentials:
                    raise RegistryError(f"{registry} requires credentials and none are configured (registries.credentials)")
                require_https(resp.request.url, f"{registry}, which asks for a password,")
                resp = await self._send("GET", str(resp.request.url), auth=await self._credentials_for(registry, host))
                self._record_auth(registry, host, resp)
            else:
                # Getting a token proves that the credentials (if any) are accepted.
                if await self._renew_token(registry, host, challenge, scope):
                    return f"pull token for {repository} obtained {auth}" if repository else f"token obtained {auth}"
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"{registry} refused the connection test", resp))
        return f"answers {auth}"

    async def list_tags(self, registry: str, repository: str) -> list[str]:
        url: str | None = self._url(registry, f"/v2/{repository}/tags/list?n=1000")
        tags: list[str] = []
        for _ in range(self.max_tag_pages):
            if url is None:
                break
            resp = await self._request("GET", registry, repository, url)
            if resp.status_code != 200:
                raise RegistryError(http_error_message(f"cannot list the tags of {registry}/{repository}", resp))
            tags.extend(resp.json().get("tags") or [])
            log.debug("%s/%s: %d tag(s) so far", registry, repository, len(tags))
            match = _LINK_RE.search(resp.headers.get("link", ""))
            url = str(resp.url.join(match[1])) if match else None
        if url is not None:
            log.warning(
                "%s/%s has more than %d tags: only the first %d pages were read, the latest version can be missed "
                "(raise images.maxTagPages)",
                registry,
                repository,
                len(tags),
                self.max_tag_pages,
            )
        return tags

    async def get_digest(self, registry: str, repository: str, reference: str) -> str | None:
        url = self._url(registry, f"/v2/{repository}/manifests/{reference}")
        resp = await self._request("HEAD", registry, repository, url, headers={"Accept": MANIFEST_ACCEPT})
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot read the digest of {registry}/{repository}:{reference}", resp))
        return resp.headers.get("docker-content-digest")

    async def get_manifest(self, registry: str, repository: str, reference: str, accept: str) -> dict:
        url = self._url(registry, f"/v2/{repository}/manifests/{reference}")
        resp = await self._request("GET", registry, repository, url, headers={"Accept": accept})
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot read the manifest of {registry}/{repository}:{reference}", resp))
        return resp.json()

    async def get_blob(self, registry: str, repository: str, digest: str) -> bytes:
        url = self._url(registry, f"/v2/{repository}/blobs/{digest}")
        resp = await self._request("GET", registry, repository, url, follow_redirects=True)
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot download {registry}/{repository}@{digest}", resp))
        return resp.content
