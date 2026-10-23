"""Registry credentials: per registry entries from the settings, plus an optional docker config.json."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from kube_tower.config import RegistriesSettings, RegistryCredential
from kube_tower.registry.oci import DOCKER_HUB, DOCKER_HUB_ALIASES, load_docker_credentials

log = logging.getLogger(__name__)


def normalize_host(registry: str) -> str:
    """`https://index.docker.io/v1/` -> `docker.io`, `oci://ghcr.io/org` -> `ghcr.io`."""
    host = re.sub(r"^[a-z]+://", "", registry.strip()).split("/")[0].lower()
    return DOCKER_HUB if host in DOCKER_HUB_ALIASES else host


@dataclass
class CredentialStatus:
    """What the Settings page shows: never the secret itself."""

    registry: str
    source: str  # credentials | docker-config
    username: str
    ok: bool
    message: str = ""


def _read(file: str, env: str) -> str:
    if file:
        return Path(file).read_text().strip()
    if env:
        if env not in os.environ:
            raise KeyError(f"env var {env} is not set")
        return os.environ[env]
    return ""


def _resolve_one(cred: RegistryCredential) -> tuple[str, str]:
    username = cred.username or _read(cred.username_file, cred.username_env)
    password = _read(cred.password_file, cred.password_env)
    if not password:
        raise ValueError("no password/token configured")
    # Registries ignore the username for token auth but basic auth needs one.
    return username or "kube-tower", password


def resolve_credentials(settings: RegistriesSettings) -> tuple[dict[str, tuple[str, str]], list[CredentialStatus]]:
    """Return {registry_host: (username, password)} and a status line per configured registry."""
    creds: dict[str, tuple[str, str]] = {}
    statuses: list[CredentialStatus] = []
    try:
        for host, pair in load_docker_credentials(settings.docker_config_path).items():
            creds[host] = pair
            statuses.append(CredentialStatus(host, "docker-config", pair[0], True))
    except (OSError, ValueError) as exc:
        statuses.append(CredentialStatus("*", "docker-config", "", False, str(exc)))
    for cred in settings.credentials:
        host = normalize_host(cred.registry)
        try:
            creds[host] = _resolve_one(cred)
            statuses.append(CredentialStatus(host, "credentials", creds[host][0], True))
        except (OSError, KeyError, ValueError) as exc:
            log.warning("credentials for %s ignored: %s", host, exc)
            statuses.append(CredentialStatus(host, "credentials", cred.username, False, str(exc)))
    return creds, statuses
