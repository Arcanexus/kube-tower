import base64
import json

from kube_tower.config import RegistriesSettings, RegistryCredential
from kube_tower.registry.auth import normalize_host, resolve_credentials


def test_normalize_host():
    assert normalize_host("https://index.docker.io/v1/") == "docker.io"
    assert normalize_host("oci://ghcr.io/org/charts") == "ghcr.io"
    assert normalize_host("Charts.Example.com") == "charts.example.com"


def test_resolve_credentials(tmp_path, monkeypatch):
    (tmp_path / "user").write_text("bob\n")
    (tmp_path / "pass").write_text("s3cret\n")
    docker = tmp_path / "config.json"
    docker.write_text(
        json.dumps(
            {
                "auths": {
                    "quay.io": {"auth": base64.b64encode(b"q:qp").decode()},
                    "ghcr.io": {"auth": base64.b64encode(b"old:old").decode()},
                }
            }
        )
    )
    monkeypatch.setenv("GHCR_TOKEN", "tok")
    settings = RegistriesSettings(
        docker_config_path=str(docker),
        credentials=[
            RegistryCredential("docker.io", username_file=str(tmp_path / "user"), password_file=str(tmp_path / "pass")),
            RegistryCredential("https://ghcr.io", password_env="GHCR_TOKEN"),
            RegistryCredential("charts.example.com", username="me", password_file=str(tmp_path / "missing")),
            RegistryCredential("nopass.example.com", username="me"),
            RegistryCredential("env.example.com", password_env="UNSET_VAR"),
        ],
    )
    creds, statuses = resolve_credentials(settings)
    assert creds.static == {"quay.io": ("q", "qp"), "docker.io": ("bob", "s3cret"), "ghcr.io": ("kube-tower", "tok")}
    by_host = {(s.registry, s.source): s for s in statuses}
    assert by_host[("ghcr.io", "credentials")].ok  # per registry entry overrides docker config
    assert not by_host[("charts.example.com", "credentials")].ok
    assert "no password" in by_host[("nopass.example.com", "credentials")].message
    assert "UNSET_VAR" in by_host[("env.example.com", "credentials")].message


def test_invalid_docker_config(tmp_path):
    docker = tmp_path / "config.json"
    docker.write_text("not json")
    creds, statuses = resolve_credentials(RegistriesSettings(docker_config_path=str(docker)))
    assert not creds and statuses[0].ok is False
