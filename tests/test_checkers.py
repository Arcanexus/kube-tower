import io
import logging
import tarfile

import yaml

from kube_tower.checkers import ChartChecker, ImageChecker
from kube_tower.config import GitSettings, HelmSettings, ImagesSettings
from kube_tower.models import ChartDependency, ChartReport, ImageRef, ImageReport, Status, ValueFile
from kube_tower.registry.helm import ChartFiles, chart_yaml_from_archive, split_oci
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


async def test_image_release_dates(caplog):
    from datetime import UTC, datetime

    class DatedOCI(FakeOCI):
        created = 0

        async def get_created(self, registry, repository, tag):
            self.created += 1
            if repository == "library/redis":
                raise RegistryError("refused")
            return datetime(2026, 10, 12, tzinfo=UTC)

    oci = DatedOCI(
        tags={"library/nginx": ["1.25.3", "1.26.0"], "library/redis": ["7.0.0"]},
        digests={"library/nginx": "sha256:b", "library/redis": "sha256:r"},
    )
    caplog.set_level(logging.DEBUG)
    reports = [_img("library/nginx", "1.25.3"), _img("library/nginx", "1.26.0"), _img("library/redis", "7.0.0")]
    await ImageChecker(oci, ImagesSettings()).check_all(reports)
    assert [r.latest_released for r in reports] == [datetime(2026, 10, 12, tzinfo=UTC)] * 2 + [None]
    assert [r.current_released for r in reports] == [datetime(2026, 10, 12, tzinfo=UTC)] * 2 + [None]
    assert oci.created == 3  # 1.25.3, and 1.26.0 asked once for both reports
    assert "no release date for image docker.io library/redis 7.0.0" in caplog.text
    # kept for the next scans, not the failures
    again = [_img("library/nginx", "1.25.3"), _img("library/redis", "7.0.0")]
    await ImageChecker(oci, ImagesSettings()).check_all(again)
    assert again[0].latest_released and again[0].current_released and oci.created == 4
    disabled = _img("library/nginx", "1.25.3")
    await ImageChecker(oci, ImagesSettings(fetch_release_dates=False)).check(disabled)
    assert disabled.latest_released is None and disabled.current_released is None


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

    async def release_date(self, repository, chart, version):
        from datetime import UTC, datetime

        return datetime(2026, 10, 12, tzinfo=UTC)

    values: dict = {}  # chart -> default values
    files: dict = {}  # path -> content, in the chart or in git

    async def chart_metadata(self, repository, chart, version):
        return {
            "name": chart,
            "version": version,
            "dependencies": self.dependencies.get(chart, []),
        }

    async def chart_files(self, repository, chart, version, extra=()):
        files = {p: self.files[p] for p in extra if p in self.files}
        return ChartFiles(await self.chart_metadata(repository, chart, version), self.values.get(chart, {}), files)

    async def git_chart_values(self, repository, ref, path):
        return self.values.get("monitoring", {})

    async def git_file(self, repository, ref, path, missing_ok=False):
        if path.startswith("forbidden/"):
            raise RegistryError("cannot read forbidden/values.yaml at main in https://github.com/o/r.git: HTTP 403")
        return self.files.get(path)

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
    assert app.latest_released.isoformat() == "2026-10-12T00:00:00+00:00"
    assert app.dependencies[0].latest_released.isoformat().startswith("2026-10-12")
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


async def test_checkers_log_results(caplog):
    caplog.set_level(logging.DEBUG, logger="kube_tower")
    oci = FakeOCI(tags={"library/nginx": ["1.25.3", "1.26.0"]})
    await ImageChecker(oci, ImagesSettings()).check_all([_img("library/nginx", "1.25.3"), _img("library/missing", "1.0")])
    messages = [(r.levelname, r.getMessage()) for r in caplog.records]
    assert ("INFO", "checking 2 image(s) against their registries") in messages
    assert ("DEBUG", "image docker.io/library/nginx:1.25.3: outdated (latest 1.26.0)") in messages
    assert ("WARNING", "cannot check image docker.io/library/missing:1.0: not found") in messages
    assert ("INFO", "images checked: 1 outdated, 1 error") in messages


async def test_git_chart_checked_again_from_its_path():
    paths = []

    class Helm(FakeHelm):
        async def git_chart_metadata(self, repository, ref, path):
            paths.append(path)
            return {"name": "monitoring", "version": "0.3.0"}

    report = ChartReport(
        "c1", "mon", "argocd", "charts/mon", "https://github.com/o/r.git", "", "git", git_ref="HEAD", path="charts/mon"
    )
    await ChartChecker(Helm(), HelmSettings()).check(report)
    assert report.chart == "monitoring"
    await ChartChecker(Helm(), HelmSettings()).check(report)  # rescan: Chart.yaml read from the same path
    assert paths == ["charts/mon", "charts/mon"]


async def test_charts_of_an_http_index_pointing_to_oci_urls():
    """Bitnami's index.yaml points its recent versions to oci:// URLs (#159): a chart deployed from that repository
    keeps its version status and its subchart tree instead of going to error, and so do its subcharts.
    """
    import httpx
    import respx

    from kube_tower.registry.helm import HELM_CHART_LAYER, HelmClient
    from kube_tower.registry.oci import OCIClient

    repo = "https://charts.bitnami.com/bitnami"

    def entry(name, version):
        return {"version": version, "urls": [f"oci://registry-1.docker.io/bitnamicharts/{name}:{version}"]}

    def published(name, version, dependencies=()):
        chart = {
            "name": name,
            "version": version,
            "dependencies": [{"name": d, "version": v, "repository": repo} for d, v in dependencies],
        }
        base = f"https://registry-1.docker.io/v2/bitnamicharts/{name}"
        digest = f"sha256:{name}{version}".replace(".", "")
        respx.get(f"{base}/manifests/{version}").respond(
            200, json={"layers": [{"mediaType": HELM_CHART_LAYER, "digest": digest}]}
        )
        respx.get(f"{base}/blobs/{digest}").respond(200, content=_chart_archive(chart))

    index = {
        "entries": {
            "redis": [entry("redis", "21.0.0"), entry("redis", "20.3.0")],
            "common": [entry("common", "2.30.0"), entry("common", "2.29.0")],
            "postgresql": [entry("postgresql", "16.7.0")],
        }
    }
    with respx.mock:
        respx.get(f"{repo}/index.yaml").respond(200, text=yaml.safe_dump(index))
        published("redis", "21.0.0", [("common", "2.29.0")])
        published("postgresql", "16.7.0", [("redis", "20.3.0")])
        published("redis", "20.3.0", [("common", "2.30.0")])
        published("common", "2.29.0")
        published("common", "2.30.0")
        redis = ChartReport("c1", "cache", "argocd", "redis", repo, "21.0.0", "helm")
        pg = ChartReport("c1", "db", "argocd", "postgresql", repo, "16.7.0", "helm")
        async with httpx.AsyncClient() as http:
            await ChartChecker(HelmClient(http, OCIClient(http), GitSettings()), HelmSettings()).check_all([redis, pg])

    # The chart deployed directly: its own status, not "unsupported protocol 'oci://'".
    assert (redis.status, redis.message, redis.latest_version) == (Status.UP_TO_DATE, None, "21.0.0")
    assert [(depth, d.name, d.version, d.status) for depth, d in redis.walk()] == [(1, "common", "2.29.0", Status.OUTDATED)]
    # A subchart of that repository: the subcharts it includes itself are read too.
    assert [(depth, d.name, d.version, d.status) for depth, d in pg.walk()] == [
        (1, "redis", "20.3.0", Status.OUTDATED),
        (2, "common", "2.30.0", Status.UP_TO_DATE),
    ]
    assert pg.worst_status == Status.OUTDATED


class DeploymentHelm(FakeHelm):
    """external-secrets: bitwarden-sdk-server left out by its condition; redis with a disabled subchart."""

    versions = {
        **FakeHelm.versions,
        ("https://charts.external-secrets.io", "external-secrets"): ["2.14.0"],
        ("oci://ghcr.io/external-secrets/charts", "bitwarden-sdk-server"): ["v0.6.0", "v0.8.1"],
        ("https://charts.bitnami.com/bitnami", "metrics"): ["1.0.0"],
    }
    dependencies = {
        "external-secrets": [
            {
                "name": "bitwarden-sdk-server",
                "version": "v0.6.0",
                "repository": "oci://ghcr.io/external-secrets/charts",
                "condition": "bitwarden-sdk-server.enabled",
            },
            {"name": "redis", "version": "19.0.0", "repository": "https://charts.bitnami.com/bitnami", "alias": "cache"},
            {"name": "metrics", "version": "1.0.0", "repository": "https://charts.bitnami.com/bitnami", "tags": ["metrics"]},
        ],
        "redis": [
            {
                "name": "common",
                "version": "2.0.0",
                "repository": "https://charts.bitnami.com/bitnami",
                "condition": "common.enabled",
            },
        ],
        "bitwarden-sdk-server": [{"name": "common", "version": "2.0.0", "repository": "https://charts.bitnami.com/bitnami"}],
    }
    values = {
        "external-secrets": {"bitwarden-sdk-server": {"enabled": False}, "tags": {"metrics": True}},
        "redis": {"common": {"enabled": True}},
    }
    files = {
        "apps/external-secrets/values.yaml": "cache:\n  common:\n    enabled: false\n",
        "values-prod.yaml": "tags:\n  metrics: false\n",
    }


def _eso(**kwargs) -> ChartReport:
    repository = "https://charts.external-secrets.io"
    return ChartReport("c1", "eso", "argocd", "external-secrets", repository, "2.14.0", "helm", **kwargs)


async def test_subcharts_left_out_by_the_values_are_not_deployed(caplog):
    values = ValueFile("apps/external-secrets/values.yaml", "https://github.com/freuds/mediaserver.git", "main")
    report = _eso(value_files=[values, ValueFile("values-prod.yaml", in_chart=True)])
    await ChartChecker(DeploymentHelm(), HelmSettings()).check(report)
    bitwarden, redis, metrics = report.dependencies
    # its version is still checked, but it does not count in the status of the chart
    assert (bitwarden.status, bitwarden.latest_version) == (Status.OUTDATED, "v0.8.1")
    assert bitwarden.not_deployed == "bitwarden-sdk-server.enabled is false" and bitwarden.dependencies == []
    # the value file of the Application, under the alias of redis, disables common (enabled by redis' defaults)
    assert redis.deployed and redis.dependencies[0].not_deployed == "common.enabled is false"
    assert metrics.not_deployed == "tags.metrics false"  # the value file of the chart overrides its defaults
    # bitwarden-sdk-server and common are outdated, but not deployed: the chart is up to date
    assert (report.status, redis.status, report.worst_status) == (Status.UP_TO_DATE,) * 3

    # inline values (parameters) come last
    report = _eso(inline_values={"bitwarden-sdk-server": {"enabled": True}})
    await ChartChecker(DeploymentHelm(), HelmSettings()).check(report)
    assert report.dependencies[0].deployed and report.dependencies[0].dependencies[0].name == "common"


async def test_only_the_values_leave_the_subchart_out():
    # the same external-secrets report without values (no value file, no defaults turning it off):
    # bitwarden-sdk-server is deployed and outdated, so the chart is outdated
    class Helm(DeploymentHelm):
        values = {}

    report = _eso()
    await ChartChecker(Helm(), HelmSettings()).check(report)
    assert all(d.deployed for _, d in report.walk())
    assert report.dependencies[0].status == Status.OUTDATED
    assert (report.status, report.worst_status) == (Status.UP_TO_DATE, Status.OUTDATED)
    # with the values of test_subcharts_left_out_by_the_values_are_not_deployed, the chart is up to date
    values = ValueFile("apps/external-secrets/values.yaml", "https://github.com/freuds/mediaserver.git", "main")
    report = _eso(value_files=[values, ValueFile("values-prod.yaml", in_chart=True)])
    await ChartChecker(DeploymentHelm(), HelmSettings()).check(report)
    assert not report.dependencies[0].deployed and report.worst_status == Status.UP_TO_DATE


def test_not_deployed_subchart_in_error_leaves_the_chart_up_to_date():
    report = _eso(status=Status.UP_TO_DATE)
    report.dependencies = [
        ChartDependency("bitwarden-sdk-server", "v0.6.0", "oci://x", status=Status.ERROR, not_deployed="condition false"),
        ChartDependency("redis", "19.0.0", "https://x", status=Status.UP_TO_DATE),
    ]
    assert report.worst_status == Status.UP_TO_DATE
    report.dependencies[0].not_deployed = None  # deployed: its error counts again
    assert report.worst_status == Status.ERROR


async def test_unreadable_values_leave_every_subchart_deployed(caplog):
    for value_file in (
        ValueFile("forbidden/values.yaml", "https://github.com/o/r.git", "main"),
        ValueFile("missing.yaml", "https://github.com/o/r.git", "main"),
        ValueFile("https://example.com/values.yaml"),
    ):
        report = _eso(value_files=[value_file])
        await ChartChecker(DeploymentHelm(), HelmSettings()).check(report)
        assert all(d.deployed for _, d in report.walk())
    assert "cannot read the Helm values of application eso, every subchart of external-secrets is considered deployed" in (
        caplog.text
    )
    assert (
        "HTTP 403" in caplog.text
        and (
            "value file missing.yaml not found in https://github.com/o/r.git at main (private repository without "
            "git.token / git.existingSecret?)"
        )
        in caplog.text
    )
    assert "value file https://example.com/values.yaml cannot be read by kube-tower" in caplog.text

    # ignoreMissingValueFiles: the missing file is skipped, the defaults apply
    report = _eso(value_files=[ValueFile("missing.yaml", "https://github.com/o/r.git", "main")], ignore_missing_value_files=True)
    await ChartChecker(DeploymentHelm(), HelmSettings()).check(report)
    assert not report.dependencies[0].deployed


async def test_git_chart_defaults_decide_the_subcharts():
    class Helm(DeploymentHelm):
        values = {"monitoring": {"common": {"enabled": False}}}

        async def git_chart_metadata(self, repository, ref, path):
            deps = [{"name": "common", "version": "2.0.0", "repository": "https://charts.bitnami.com/bitnami"}]
            return {"name": "monitoring", "version": "0.3.0", "dependencies": [{**deps[0], "condition": "common.enabled"}]}

    report = ChartReport("c1", "mon", "argocd", "mon", "https://github.com/o/r.git", "", "git", git_ref="HEAD", path="mon")
    await ChartChecker(Helm(), HelmSettings()).check(report)
    assert report.dependencies[0].not_deployed == "common.enabled is false"
    assert report.worst_status == Status.UP_TO_DATE  # common 2.0.0 is outdated, but not deployed
