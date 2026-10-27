"""Registry credentials: per registry entries from the settings, an optional docker config.json, the
image pull secrets of the workloads (opt-in) and short-lived tokens of cloud registries (cloud.py).
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import os
import re
import time
import weakref
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from kube_tower.config import RegistriesSettings, RegistryCredential
from kube_tower.registry.cloud import HttpFactory, default_http, identity_status, make_provider
from kube_tower.registry.oci import DOCKER_HUB, DOCKER_HUB_ALIASES, load_docker_credentials

log = logging.getLogger(__name__)

Pair = tuple[str, str]
# A token is fetched again this long before it expires: a scan never uses one that expires midway.
TOKEN_RENEW_MARGIN = 15 * 60


def normalize_host(registry: str) -> str:
    """`https://index.docker.io/v1/` -> `docker.io`, `oci://ghcr.io/org` -> `ghcr.io`."""
    host = re.sub(r"^[a-z]+://", "", registry.strip()).split("/")[0].lower()
    return DOCKER_HUB if host in DOCKER_HUB_ALIASES else host


def is_pattern(registry: str) -> bool:
    return any(c in registry for c in "*?[")


@dataclass
class CredentialStatus:
    """What the Settings page shows: never the secret itself."""

    registry: str
    source: str  # credentials | docker-config | image-pull-secret | aws | gcp | azure
    username: str
    ok: bool
    message: str = ""


@dataclass
class AuthResult:
    """The last time a registry accepted or refused kube-tower's credentials."""

    host: str
    ok: bool
    at: datetime
    message: str = ""


class AuthResults:
    """Whether each registry accepted the credentials, as seen by the scans and the connectivity tests.

    Only requests that sent credentials count: an anonymous pull says nothing about them.
    """

    def __init__(self) -> None:
        self._results: dict[str, AuthResult] = {}

    def record(self, host: str, ok: bool, message: str = "") -> None:
        if not ok:
            log.warning("%s refused the credentials: %s", host, message)
        self._results[host.lower()] = AuthResult(host.lower(), ok, datetime.now(UTC), message)

    def all(self) -> list[AuthResult]:
        return list(self._results.values())

    def merge(self, results: list[AuthResult]) -> None:
        """Results seen by another process (a worker pod): the latest of each host wins."""
        for result in results:
            known = self._results.get(result.host)
            if known is None or known.at < result.at:
                self._results[result.host] = result

    def get(self, registry: str) -> AuthResult | None:
        """The result for a configured registry; for a pattern, the latest refusal of a matching host,
        else its latest success."""
        if not is_pattern(registry):
            return self._results.get(registry.lower())
        matching = [r for host, r in self._results.items() if fnmatch.fnmatch(host, registry.lower())]
        return max(matching, key=lambda r: (not r.ok, r.at), default=None)


class TokenCache:
    """Short-lived tokens by (provider, registry), kept between scans until shortly before they expire.

    Scans, rescans and Trivy scans run in different threads, each with its own event loop: the
    lock that makes concurrent requests wait for one fetch is per event loop.
    """

    def __init__(self) -> None:
        self.tokens: dict[tuple[str, str], tuple[Pair, float | None]] = {}
        # By event loop (forgotten with it: each rescan runs in a new one), then by (provider, registry).
        self._locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[tuple[str, str], asyncio.Lock]] = (
            weakref.WeakKeyDictionary()
        )

    def _valid(self, key: tuple[str, str]) -> Pair | None:
        cached = self.tokens.get(key)
        if cached and (cached[1] is None or cached[1] - TOKEN_RENEW_MARGIN > time.time()):
            return cached[0]
        return None

    async def get(self, provider, registry: str) -> Pair:
        key = (provider.name, registry)
        if pair := self._valid(key):
            return pair
        lock = self._locks.setdefault(asyncio.get_running_loop(), {}).setdefault(key, asyncio.Lock())
        async with lock:
            if pair := self._valid(key):
                return pair
            log.debug("fetching a %s registry token for %s", provider.name, registry)
            pair, expires_at = await provider.fetch(registry)
            self.tokens[key] = (pair, expires_at)
            log.info(
                "%s registry token obtained for %s%s",
                provider.name,
                registry,
                f", valid {int((expires_at - time.time()) / 60)} min" if expires_at else "",
            )
            return pair


class Credentials:
    """Registry credentials by host.

    Exact hosts first (per registry entries, then the docker config.json, then image pull secrets),
    then the entries whose registry is a pattern (e.g. `*.dkr.ecr.*.amazonaws.com`), in their order.
    An entry is either a username/password or a cloud provider fetching short-lived tokens.
    """

    def __init__(
        self,
        static: dict[str, Pair] | None = None,
        providers: dict[str, object] | None = None,
        patterns: list[tuple[str, Pair | object]] | None = None,
        tokens: TokenCache | None = None,
    ):
        self.static = dict(static or {})
        self.providers = dict(providers or {})  # host -> provider
        self.patterns = list(patterns or [])
        self.tokens = tokens or TokenCache()

    def _source(self, host: str) -> Pair | object | None:
        host = host.lower()
        if host in self.providers:
            return self.providers[host]
        if host in self.static:
            return self.static[host]
        return next((source for pattern, source in self.patterns if fnmatch.fnmatch(host, pattern)), None)

    def __contains__(self, host: str) -> bool:
        return self._source(host) is not None

    def __iter__(self):
        """The hosts with credentials (not the patterns)."""
        return iter(sorted({*self.static, *self.providers}))

    def __bool__(self) -> bool:
        return bool(self.static or self.providers or self.patterns)

    def describe(self) -> list[str]:
        return [*self, *(pattern for pattern, _ in self.patterns)]

    async def get(self, host: str) -> Pair | None:
        """The username and password for `host`, None for anonymous access. Raises RegistryError when a
        cloud provider cannot get a token (the message says why)."""
        source = self._source(host)
        if source is None or isinstance(source, tuple):
            return source
        return await self.tokens.get(source, host.lower())

    def with_pull_secrets(self, pull_secrets: dict[str, Pair]) -> Credentials:
        """These credentials, plus those of image pull secrets for the hosts that have none."""
        static = {**pull_secrets, **self.static}
        return Credentials(static, self.providers, self.patterns, self.tokens)


def _read(file: str, env: str) -> str:
    if file:
        return Path(file).read_text().strip()
    if env:
        if env not in os.environ:
            raise KeyError(f"env var {env} is not set")
        return os.environ[env]
    return ""


def _resolve_one(cred: RegistryCredential) -> Pair:
    username = cred.username or _read(cred.username_file, cred.username_env)
    password = _read(cred.password_file, cred.password_env)
    if not password:
        raise ValueError("no password/token configured")
    # Registries ignore the username for token auth but basic auth needs one.
    return username or "kube-tower", password


def resolve_credentials(
    settings: RegistriesSettings,
    tokens: TokenCache | None = None,
    pull_secrets: dict[str, Pair] | None = None,
    http: HttpFactory = default_http,
) -> tuple[Credentials, list[CredentialStatus]]:
    """Read the credentials again (Secrets may have been rotated) and a status line per configured registry."""
    static: dict[str, Pair] = {}
    providers: dict[str, object] = {}
    patterns: list[tuple[str, Pair | object]] = []
    statuses: list[CredentialStatus] = []
    try:
        for host, pair in load_docker_credentials(settings.docker_config_path).items():
            static[host] = pair
            statuses.append(CredentialStatus(host, "docker-config", pair[0], True))
    except (OSError, ValueError) as exc:
        statuses.append(CredentialStatus("*", "docker-config", "", False, str(exc)))
    for cred in settings.credentials:
        host = normalize_host(cred.registry) if not is_pattern(cred.registry) else cred.registry.strip().lower()
        provider = cred.provider or "static"
        try:
            if provider == "static":
                source: Pair | object = _resolve_one(cred)
                status = CredentialStatus(host, "credentials", source[0], True)
            else:
                source = make_provider(provider, http)
                ok, message = identity_status(provider)
                status = CredentialStatus(host, provider, "", ok, message)
        except (OSError, KeyError, ValueError) as exc:
            log.warning("credentials for %s ignored: %s", host, exc)
            statuses.append(
                CredentialStatus(host, provider if provider != "static" else "credentials", cred.username, False, str(exc))
            )
            continue
        statuses.append(status)
        if is_pattern(host):
            patterns.append((host, source))
        elif isinstance(source, tuple):
            static[host] = source
            providers.pop(host, None)
        else:
            providers[host] = source
            static.pop(host, None)
    for host, pair in sorted((pull_secrets or {}).items()):
        statuses.append(CredentialStatus(host, "image-pull-secret", pair[0], True))
    credentials = Credentials(static, providers, patterns, tokens).with_pull_secrets(pull_secrets or {})
    return credentials, statuses
