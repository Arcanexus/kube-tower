import pytest

from kube_tower.config import load_settings, parse_duration


def test_parse_duration():
    assert parse_duration("90") == 90
    assert parse_duration("15m") == 900
    assert parse_duration("6h") == 21600
    assert parse_duration(30) == 30
    with pytest.raises(ValueError):
        parse_duration("abc")


def test_defaults_without_file(tmp_path):
    settings = load_settings(str(tmp_path / "none.yaml"))
    assert settings.refresh_interval == 6 * 3600
    assert settings.clusters.in_cluster is True


def test_load_camel_case_yaml(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "refreshInterval: 1h\n"
        "clusters:\n  useArgocdSecrets: true\n"
        "images:\n  ignore: ['registry.k8s.io/pause*']\n"
        "registries:\n  mirrors: {docker.io: mirror.local}\n"
    )
    monkeypatch.setenv("KUBE_TOWER_LOG_LEVEL", "DEBUG")
    settings = load_settings(str(cfg))
    assert settings.refresh_interval == 3600
    assert settings.clusters.use_argocd_secrets is True
    assert settings.images.ignore == ["registry.k8s.io/pause*"]
    assert settings.registries.mirrors == {"docker.io": "mirror.local"}
    assert settings.logs.level == "DEBUG"


def test_unknown_key(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("images:\n  typo: true\n")
    with pytest.raises(ValueError, match="typo"):
        load_settings(str(cfg))


def test_roles_default_to_all_and_partial_roles_are_refused(tmp_path, monkeypatch):
    monkeypatch.delenv("KUBE_TOWER_ROLES", raising=False)
    every = ["ui", "controller", "worker", "trivy"]
    assert load_settings(str(tmp_path / "missing.yaml")).roles == every
    monkeypatch.setenv("KUBE_TOWER_ROLES", "trivy, worker,ui,controller")  # every role, listed: same as all
    assert load_settings(str(tmp_path / "missing.yaml")).roles == every
    monkeypatch.setenv("KUBE_TOWER_ROLES", "worker,trivy")
    with pytest.raises(ValueError, match="roles trivy, worker: running only some roles .* not available yet"):
        load_settings(str(tmp_path / "missing.yaml"))
    monkeypatch.delenv("KUBE_TOWER_ROLES")
    (tmp_path / "config.yaml").write_text("roles: [ui, scanner]\n")
    with pytest.raises(ValueError, match="unknown role\\(s\\) 'scanner'"):
        load_settings(str(tmp_path / "config.yaml"))
    (tmp_path / "config.yaml").write_text("roles: []\n")
    with pytest.raises(ValueError, match="no role"):
        load_settings(str(tmp_path / "config.yaml"))
