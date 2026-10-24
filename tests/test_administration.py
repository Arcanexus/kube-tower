import asyncio
import logging
from datetime import UTC, datetime

import httpx
import pytest
import respx

from kube_tower import administration as administration_module
from kube_tower.administration import Administration, unused_node_images
from kube_tower.config import Settings
from kube_tower.models import (
    ChartDependency,
    ChartReport,
    ClusterStatus,
    ImageRef,
    ImageReport,
    Snapshot,
    Usage,
    VulnerabilityReport,
)
from kube_tower.scanner import Scanner
from kube_tower.trivy import TrivyDatabase, TrivyScanner, TrivyStatus


class FakeRegistry:
    def discover(self):
        return [], [
            ClusterStatus("up", "https://up", "in-cluster", True, "v1.31.0"),
            ClusterStatus("down", "https://down", "secret", False, message="cannot reach https://down: timeout"),
        ]


def _image(registry, repository, tag, *usages):
    return ImageReport(ImageRef(registry, repository, tag), list(usages))


def test_unused_node_images():
    snap = Snapshot(
        images=[
            # used by a Pod in c1, only cached on a node of c2
            _image(
                "docker.io",
                "library/nginx",
                "1.25",
                Usage("c1", "Pod", "default", "web"),
                Usage("c1", "Node", None, "n1"),
                Usage("c2", "Node", None, "m2"),
                Usage("c2", "Node", None, "m1"),
            ),
            _image("ghcr.io", "org/old", "1", Usage("c1", "Node", None, "n1")),
            _image("ghcr.io", "org/job", "1", Usage("c1", "CronJob", "default", "backup")),
        ]
    )
    assert [(u.cluster, u.image, u.nodes) for u in unused_node_images(snap)] == [
        ("c1", "ghcr.io/org/old:1", ["n1"]),
        ("c2", "docker.io/library/nginx:1.25", ["m1", "m2"]),
    ]


def _administration(settings=None):
    scanner = Scanner(settings or Settings(), FakeRegistry())
    return Administration(scanner), scanner


async def _done(administration):
    await asyncio.gather(*administration._tasks)
    assert not administration.running


def test_clear_trivy_cache(caplog):
    caplog.set_level(logging.INFO, logger="kube_tower")
    m, scanner = _administration()
    scanner.trivy.cache = {"a": VulnerabilityReport("trivy"), "b": VulnerabilityReport("trivy")}
    assert m.clear_trivy_cache() == 2 and scanner.trivy.cache == {}
    assert "Trivy results cache cleared (2 image(s))" in caplog.text


async def test_update_trivy_db_refused(monkeypatch):
    m, scanner = _administration()
    monkeypatch.setattr(TrivyScanner, "available", False)
    assert m.update_trivy_db() == "Trivy is disabled or its binary 'trivy' is not found"
    monkeypatch.setattr(TrivyScanner, "available", True)
    async with scanner._lock:
        assert m.update_trivy_db() == "a scan is running: it updates the Trivy database itself"
    scanner.rescanning.add(("image", "x"))
    assert m.update_trivy_db() == "rescans are running: try again when they are over"
    scanner.settings.vulnerabilities.trivy.server_url = "http://trivy:4954"
    assert m.update_trivy_db().startswith("client/server mode")


@pytest.mark.parametrize(
    "error,downloaded,message",
    [
        (None, datetime(2026, 10, 23, tzinfo=UTC), "database downloaded"),
        (None, None, "already up to date: no newer database published yet"),
        ("cannot download the Trivy database: 403", None, "cannot download the Trivy database: 403"),
    ],
)
async def test_update_trivy_db(monkeypatch, error, downloaded, message):
    m, scanner = _administration()
    seen = []

    async def prepare(self):
        seen.append((scanner.busy, scanner.locked, scanner.running))
        return error

    async def status(self):
        return TrivyStatus(datetime.now(UTC), "0.75.0", TrivyDatabase(2, downloaded_at=downloaded))

    monkeypatch.setattr(TrivyScanner, "available", True)
    monkeypatch.setattr(TrivyScanner, "prepare", prepare)
    monkeypatch.setattr(TrivyScanner, "status", status)
    assert m.update_trivy_db() is None
    assert m.update_trivy_db() == "the Trivy database is already being updated"
    await _done(m)
    # scans wait for the update, which is not shown as a scan
    assert seen == [("the Trivy database is being updated", True, False)]
    assert m.trivy_message == message and m.trivy_status.version == "0.75.0"
    assert scanner.busy is None


@respx.mock
async def test_connectivity():
    settings = Settings()
    settings.vulnerabilities.trivy.server_url = "http://trivy:4954"
    m, scanner = _administration(settings)
    scanner.snapshot = Snapshot(
        images=[_image("ghcr.io", "org/app", "1", Usage("up", "Pod", "default", "web"))],
        charts=[
            ChartReport(
                "up",
                "app",
                "argocd",
                "app",
                "https://charts.example.com/",
                "1.0.0",
                "helm",
                dependencies=[ChartDependency("common", "1.0.0", "oci://registry.example.com/charts")],
            ),
            ChartReport("up", "git", "argocd", "git", "https://github.com/org/repo.git", "1.0.0", "git"),
        ],
    )
    respx.get("https://ghcr.io/v2/").respond(200)
    respx.get("https://registry.example.com/v2/").respond(403)
    respx.get("https://charts.example.com/index.yaml").respond(200, text="entries: {}")
    respx.get("http://trivy:4954/healthz").respond(200, text="ok")
    assert m.test_connectivity() is None
    assert m.test_connectivity() == "a connectivity test is already running"
    await _done(m)
    report = m.connectivity
    assert report.finished_at and report.failed == 2
    checks = {(c.kind, c.target): (c.ok, c.detail) for c in report.checks}
    assert checks == {
        ("cluster", "up (https://up)"): (True, "v1.31.0"),
        ("cluster", "down (https://down)"): (False, "cannot reach https://down: timeout"),
        ("registry", "ghcr.io"): (True, "answers anonymously"),
        ("registry", "registry.example.com"): (
            False,
            "registry.example.com refused the connection test: HTTP 403 Forbidden - access denied by registry.example.com: "
            "the credentials used for it are not allowed to pull this repository",
        ),
        ("helm-repository", "https://charts.example.com"): (True, "index.yaml served anonymously"),
        ("trivy-server", "http://trivy:4954"): (True, "healthy"),
    }


@respx.mock
async def test_connectivity_network_errors():
    m, scanner = _administration()
    scanner.snapshot = Snapshot(images=[_image("ghcr.io", "org/app", "1", Usage("up", "Pod", "default", "web"))])
    respx.get("https://ghcr.io/v2/").mock(side_effect=httpx.ConnectError("boom"))
    m.test_connectivity()
    await _done(m)
    (registry,) = [c for c in m.connectivity.checks if c.kind == "registry"]
    assert not registry.ok and registry.detail.startswith("cannot connect to ghcr.io: boom")


@respx.mock
async def test_trivy_server_unhealthy():
    respx.get("http://trivy:4954/healthz").respond(503)
    async with httpx.AsyncClient() as http:
        with pytest.raises(administration_module.RegistryError, match="HTTP 503"):
            await administration_module._ping_trivy_server(http, "http://trivy:4954/")


async def test_refresh_trivy_status_and_failed_action(monkeypatch, caplog):
    m, _ = _administration()

    async def status(self):
        return TrivyStatus(datetime.now(UTC), message="trivy binary 'trivy' not found")

    monkeypatch.setattr(TrivyScanner, "status", status)
    assert (await m.refresh_trivy_status()).message.endswith("not found")

    async def broken():
        raise RuntimeError("bug")

    m._start("broken", broken)
    await _done(m)
    assert "administration action broken failed" in caplog.text
