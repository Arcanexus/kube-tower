from kube_tower.models import ChartReport, ImageRef, ImageReport, Snapshot, Usage


def _chart(name: str) -> ChartReport:
    return ChartReport("c1", name, "argocd", name, "https://charts.example.com", "1.0.0", "helm")


def test_snapshot_lookups_follow_list_changes():
    nginx = ImageReport(ImageRef("docker.io", "library/nginx", "1.25"))
    snap = Snapshot(images=[nginx], charts=[_chart("app")])
    assert snap.image("docker.io/library/nginx:1.25") is nginx and snap.image("nope") is None
    assert snap.chart("c1", "argocd", "app", "app") is snap.charts[0]
    # A rescan replaces the list with the new images added
    redis = ImageReport(ImageRef("docker.io", "library/redis", "7"))
    snap.images = sorted([*snap.images, redis], key=lambda r: str(r.image))
    assert snap.image("docker.io/library/redis:7") is redis
    snap.charts.append(other := _chart("other"))  # grown in place
    assert snap.chart("c1", "argocd", "other", "other") is other
    assert "_images_index" not in snap.to_dict()


def test_snapshot_lookup_keeps_the_first_duplicate():
    first, second = (ImageReport(ImageRef("docker.io", "library/nginx", "1.25")) for _ in range(2))
    assert Snapshot(images=[first, second]).image("docker.io/library/nginx:1.25") is first


def test_snapshot_round_trips_through_to_dict():
    from datetime import UTC, datetime

    from kube_tower.models import (
        ChartDependency,
        ClusterStatus,
        Severity,
        Status,
        Usage,
        Vulnerability,
        VulnerabilityReport,
    )

    now = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
    image = ImageReport(
        ImageRef("docker.io", "library/nginx", "1.25", "sha256:abc"),
        usages=[Usage("c1", "Deployment", "web", "nginx", "app"), Usage("c1", "Node", None, "node-1")],
        running_digests={"sha256:abc", "sha256:def"},
        status=Status.OUTDATED,
        latest_tag="1.27",
        vulnerabilities=VulnerabilityReport(
            "trivy",
            scanned_at=now,
            os="debian 12.5",
            vulnerabilities=[Vulnerability("CVE-2024-1", Severity.HIGH, "openssl", "3.0.1", "3.0.2", score=7.5)],
        ),
    )
    chart = _chart("app")
    chart.status = Status.ERROR
    chart.dependencies = [
        ChartDependency("redis", "18.0.0", "oci://r", dependencies=[ChartDependency("common", "2.0.0", "oci://c")])
    ]
    snap = Snapshot(
        images=[image, ImageReport(ImageRef("ghcr.io", "a/b"))],
        charts=[chart],
        clusters=[ClusterStatus("c1", "https://k", "in-cluster", reachable=True, version="v1.31")],
        started_at=now,
        finished_at=now,
        errors=["boom"],
    )
    data = snap.to_dict()
    back = Snapshot.from_dict(data)
    assert back == snap
    assert back.image("docker.io/library/nginx:1.25@sha256:abc").vulnerabilities.counts()[Severity.HIGH] == 1
    assert back.to_dict() == data
    assert Snapshot.from_dict(Snapshot().to_dict()) == Snapshot()


def test_image_running():
    report = ImageReport(ImageRef("docker.io", "library/nginx", "1.25"), [Usage("c1", "Deployment", "default", "web", "nginx")])
    assert not report.running  # scaled to zero: declared, no pod
    report.usages.append(Usage("c1", "Node", None, "n1"))
    assert not report.running
    report.usages.append(Usage("c1", "Pod", "default", "web-1", "nginx"))
    assert report.running
