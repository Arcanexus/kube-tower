"""Minimal OCI distribution (registry v2) client: list tags and resolve digests.

Works with Docker Hub, ghcr.io, quay.io, registry.k8s.io, Harbor, GitLab... using the
standard Bearer token challenge (anonymous or with credentials from a docker config.json).
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from pathlib import Path

import httpx

from kube_tower.errors import http_error_message
from kube_tower.models import ImageRef

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
    creds: dict[str, tuple[str, str]] = {}
    for host, entry in (data.get("auths") or {}).items():
        host = re.sub(r"^https?://", "", host).split("/")[0]
        if host in DOCKER_HUB_ALIASES:
            host = DOCKER_HUB
        if entry.get("auth"):
            user, _, pwd = base64.b64decode(entry["auth"]).decode().partition(":")
        else:
            user, pwd = entry.get("username", ""), entry.get("password", "")
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
        credentials: dict[str, tuple[str, str]] | None = None,
        mirrors: dict[str, str] | None = None,
        max_tag_pages: int = 10,
    ):
        self.http = http
        self.credentials = credentials or {}
        self.mirrors = mirrors or {}
        self.max_tag_pages = max_tag_pages
        # (host, scope) -> (token, monotonic time it expires at, None when the registry gives no lifetime)
        self._tokens: dict[tuple[str, str], tuple[str, float | None]] = {}

    def _api_host(self, registry: str) -> str:
        if registry in self.mirrors:
            return self.mirrors[registry]
        return DOCKER_HUB_API if registry == DOCKER_HUB else registry

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
        auth = self.credentials.get(registry)
        # The token (and the credentials asking for it) would travel in clear text.
        require_https(fields.get("realm", ""), f"the token service of {registry}")
        log.debug(
            "requesting an %s token for %s (%s)",
            "authenticated" if auth else "anonymous",
            registry,
            query.get("scope", "no scope"),
        )
        resp = await self.http.get(fields["realm"], params=query, auth=auth)
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
            resp = await self.http.request(method, url, headers=headers, **kwargs)
            if resp.status_code == 401 and "www-authenticate" in resp.headers:
                challenge = resp.headers["www-authenticate"]
                if challenge.lower().startswith("basic") and registry in self.credentials:
                    resp = await self.http.request(method, url, headers=headers, auth=self.credentials[registry], **kwargs)
                elif token := await self._renew_token(registry, host, challenge, scope):
                    headers["Authorization"] = f"Bearer {token}"
                    resp = await self.http.request(method, url, headers=headers, **kwargs)
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
        url = f"https://{host}/v2/"
        auth = "with credentials" if registry in self.credentials else "anonymously"
        resp = await self.http.get(url)
        if resp.status_code == 401 and "www-authenticate" in resp.headers:
            challenge = resp.headers["www-authenticate"]
            if challenge.lower().startswith("basic"):
                if registry not in self.credentials:
                    raise RegistryError(f"{registry} requires credentials and none are configured (registries.credentials)")
                resp = await self.http.get(url, auth=self.credentials[registry])
            else:
                # Getting a token proves that the credentials (if any) are accepted.
                if await self._renew_token(registry, host, challenge, scope):
                    return f"pull token for {repository} obtained {auth}" if repository else f"token obtained {auth}"
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"{registry} refused the connection test", resp))
        return f"answers {auth}"

    async def list_tags(self, registry: str, repository: str) -> list[str]:
        host = self._api_host(registry)
        url: str | None = f"https://{host}/v2/{repository}/tags/list?n=1000"
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
        return tags

    async def get_digest(self, registry: str, repository: str, reference: str) -> str | None:
        host = self._api_host(registry)
        url = f"https://{host}/v2/{repository}/manifests/{reference}"
        resp = await self._request("HEAD", registry, repository, url, headers={"Accept": MANIFEST_ACCEPT})
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot read the digest of {registry}/{repository}:{reference}", resp))
        return resp.headers.get("docker-content-digest")

    async def get_manifest(self, registry: str, repository: str, reference: str, accept: str) -> dict:
        host = self._api_host(registry)
        url = f"https://{host}/v2/{repository}/manifests/{reference}"
        resp = await self._request("GET", registry, repository, url, headers={"Accept": accept})
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot read the manifest of {registry}/{repository}:{reference}", resp))
        return resp.json()

    async def get_blob(self, registry: str, repository: str, digest: str) -> bytes:
        host = self._api_host(registry)
        url = f"https://{host}/v2/{repository}/blobs/{digest}"
        resp = await self._request("GET", registry, repository, url, follow_redirects=True)
        if resp.status_code != 200:
            raise RegistryError(http_error_message(f"cannot download {registry}/{repository}@{digest}", resp))
        return resp.content
