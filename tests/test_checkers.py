import io
import tarfile

import yaml

from kube_tower.checkers import ChartChecker, ImageChecker
from kube_tower.config import GitSettings, HelmSettings, ImagesSettings
from kube_tower.models import ChartReport, ImageRef, ImageReport, Status
from kube_tower.registry.helm import chart_yaml_from_archive, split_oci
from kube_tower.registry.oci import RegistryError


class FakeOCI:
    def __init__(self, tags=None, digests=None):
        self.tags, self.digests, self.calls = tags or {}, digests or {}, 0

    async def list_tags(self, registry, repository):
        self.calls += 1
        if repository not in self.tags:
            raise RegistryError("not found")
        return self.tags[repository]

    async def get_digest(self, registry, repository, tag):
        digest = self.digests[repository]
        return digest[tag] if isinstance(digest, dict) else digest


def _img(repo, tag, digests=()):
    return ImageReport(image=ImageRef("docker.io", repo, tag), running_digests=set(digests))


async def test_image_checker(caplog):
    oci = FakeOCI(tags={"library/nginx": ["1.25.3", "1.26.0", "latest"]}, digests={"library/redis": "sha256:new"})
    reports = [
        _img("library/nginx", "1.25.3"),
        _img("library/nginx", "1.26.0"),
        _img("library/redis", "latest", ["sha256:old"]),
        _img("library/redis", "latest"),
        _img("library/missing", "1.0"),
        ImageReport(image=ImageRef("docker.io", "library/x", None, "sha256:abc")),
    ]
    await ImageChecker(oci, ImagesSettings()).check_all(reports)
    assert [r.status for r in reports] == [
        Status.OUTDATED,
        Status.UP_TO_DATE,
        Status.OUTDATED,
        Status.UNKNOWN,
        Status.ERROR,
        Status.UNKNOWN,
    ]
    assert reports[0].latest_tag == "1.26.0"
    assert oci.calls == 2  # nginx tags fetched once for both reports
    assert "cannot check image docker.io/library/missing:1.0: not found" in caplog.text


async def test_image_checker_tag_digests():
    oci = FakeOCI(
        tags={"library/nginx": ["1.25.3", "1.26.0"], "library/redis": ["7.0.0"]},
        digests={"library/nginx": {"1.25.3": "sha256:a", "1.26.0": "sha256:b"}},
    )
    outdated, broken = _img("library/nginx", "1.25.3", ["sha256:old"]), _img("library/redis", "7.0.0", ["sha256:r"])
    await ImageChecker(oci, ImagesSettings()).check_all([outdated, broken])
    assert (outdated.tag_digest, outdated.latest_digest) == ("sha256:a", "sha256:b")
    assert broken.status == Status.UP_TO_DATE and broken.tag_digest is None  # digest errors do not change the status

    disabled = _img("library/nginx", "1.25.3", ["sha256:old"])
    await ImageChecker(oci, ImagesSettings(fetch_tag_digests=False)).check(disabled)
    assert disabled.tag_digest is None and disabled.latest_digest is None


def _chart_archive(chart: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = yaml.safe_dump(chart).encode()
        info = tarfile.TarInfo(f"{chart['name']}/Chart.yaml")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_chart_archive_and_oci_split():
    assert chart_yaml_from_archive(_chart_archive({"name": "x", "version": "1.0.0"}))["version"] == "1.0.0"
    assert split_oci("oci://ghcr.io/org/charts", "app") == ("ghcr.io", "org/charts/app")
    assert split_oci("registry-1.docker.io/bitnamicharts", "redis") == ("registry-1.docker.io", "bitnamicharts/redis")


class FakeHelm:
    versions = {
        ("https://charts.example.com", "app"): ["1.0.0", "1.1.0"],
        ("https://charts.bitnami.com/bitnami", "redis"): ["18.0.0", "19.0.0"],
        ("https://charts.bitnami.com/bitnami", "common"): ["2.0.0", "2.1.0"],
    }
    dependencies = {
        "app": [{"name": "redis", "version": "18.0.0", "repository": "https://charts.bitnami.com/bitnami"}],
        "redis": [{"name": "common", "version": "2.0.0", "repository": "https://charts.bitnami.com/bitnami"}],
        "common": [{"name": "common", "version": "2.0.0", "repository": "https://charts.bitnami.com/bitnami"}],  # endless
    }

    async def list_versions(self, repository, chart):
        return self.versions[(repository, chart)]

    async def chart_metadata(self, repository, chart, version):
        return {
            "name": chart,
            "version": version,
            "dependencies": self.dependencies.get(chart, []),
        }

    async def git_chart_metadata(self, repository, ref, path):
        return {
            "name": "monitoring",
            "version": "0.3.0",
            "dependencies": [{"name": "common", "version": "1.0.0", "repository": "file://../common"}],
        }


async def test_chart_checker():
    reports = [
        ChartReport("c1", "app", "argocd", "app", "https://charts.example.com", "1.0.0", "helm"),
        ChartReport("c1", "app2", "argocd", "app", "https://charts.example.com", "1.x", "helm"),
        ChartReport(
            "c1", "mon", "argocd", "monitoring", "https://github.com/Arcanexus/helm-charts.git", "", "git", git_ref="HEAD"
        ),
    ]
    await ChartChecker(FakeHelm(), HelmSettings()).check_all(reports)
    app, app2, mon = reports
    assert (app.status, app.latest_version) == (Status.OUTDATED, "1.1.0")
    assert app.dependencies[0].status == Status.OUTDATED and app.dependencies[0].latest_version == "19.0.0"
    # subcharts of subcharts, down to MAX_DEPENDENCY_DEPTH levels
    assert [(depth, d.name, d.status) for depth, d in app.walk()] == [
        (1, "redis", Status.OUTDATED),
        (2, "common", Status.OUTDATED),
        (3, "common", Status.OUTDATED),
    ]
    assert app2.status == Status.UNKNOWN
    assert (mon.status, mon.version, mon.chart) == (Status.UP_TO_DATE, "0.3.0", "monitoring")
    assert mon.dependencies[0].status == Status.UNKNOWN
    assert mon.worst_status == Status.UNKNOWN


def test_git_raw_url(monkeypatch):
    import asyncio

    import httpx
    import respx

    from kube_tower.registry.helm import HelmClient

    async def run():
        with respx.mock:
            route = respx.get("https://raw.githubusercontent.com/Arcanexus/helm-charts/HEAD/monitoring/Chart.yaml").respond(
                200, text="name: monitoring\nversion: 0.3.0\n"
            )
            async with httpx.AsyncClient() as http:
                meta = await HelmClient(http, None, GitSettings()).git_chart_metadata(
                    "https://github.com/Arcanexus/helm-charts.git", "HEAD", "monitoring"
                )
            assert route.calls[0].request.headers["authorization"] == "Bearer secret"
            return meta

    monkeypatch.setenv("GIT_TOKEN", "secret")
    assert asyncio.run(run())["version"] == "0.3.0"
