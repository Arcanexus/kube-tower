import pytest

from kube_tower.config import AuthSettings, RoleSettings
from kube_tower.models import (
    ChartReport,
    ClusterStatus,
    ComplianceReport,
    ImageRef,
    ImageReport,
    SecurityKind,
    SecurityReport,
    Snapshot,
    Usage,
)
from kube_tower.scope import cluster_matcher, scope_snapshot


def _snapshot() -> Snapshot:
    return Snapshot(
        images=[
            ImageReport(
                ImageRef("docker.io", "library/nginx", "1.25"),
                [Usage("prod-eu", "Pod", "a", "web"), Usage("dev", "Pod", "a", "web")],
            ),
            ImageReport(ImageRef("docker.io", "library/redis", "7"), [Usage("dev", "Pod", "a", "cache")]),
            ImageReport(ImageRef("docker.io", "library/busybox", "1"), [Usage("prod-us", "Node", None, "n1")]),
        ],
        charts=[
            ChartReport("dev", "argocd", "app", "redis", "", "1.0.0", "helm"),
            ChartReport("prod-eu", "argocd", "app", "web", "", "1.0.0", "helm"),
        ],
        clusters=[
            ClusterStatus("prod-eu", "https://eu", "secret"),
            ClusterStatus("prod-us", "https://us", "secret"),
            ClusterStatus("dev", "https://dev", "secret"),
        ],
        errors=[
            "[dev] chart redis of application app: timeout",
            "cluster dev unreachable",
            "[prod-eu] boom",
            "registry docker.io: 429",
            "devices: odd",
        ],
        security=[
            SecurityReport("dev", SecurityKind.CONFIG_AUDIT, "Pod", "a", "x"),
            SecurityReport("prod-us", SecurityKind.CONFIG_AUDIT, "Pod", "a", "y"),
        ],
        compliance=[ComplianceReport("dev", "cis", "CIS"), ComplianceReport("prod-eu", "cis", "CIS")],
        trivy_operator=["dev", "prod-eu"],
    )


def test_scope_snapshot():
    snapshot = _snapshot()
    assert scope_snapshot(snapshot, None) is snapshot and cluster_matcher(None) is None
    prod = scope_snapshot(snapshot, ("prod-*",))
    assert [c.name for c in prod.clusters] == ["prod-eu", "prod-us"]
    # An image used in several clusters keeps only the usages the user sees; the original is untouched
    assert [(str(r.image), r.clusters) for r in prod.images] == [
        ("docker.io/library/nginx:1.25", ["prod-eu"]),
        ("docker.io/library/busybox:1", ["prod-us"]),
    ]
    assert snapshot.images[0].clusters == ["dev", "prod-eu"] and len(snapshot.images) == 3
    assert prod.image("docker.io/library/redis:7") is None and prod.image("docker.io/library/nginx:1.25")
    assert [c.chart for c in prod.charts] == ["web"] and prod.chart("dev", "argocd", "app", "redis") is None
    # Scan errors naming a hidden cluster are left out ("devices" is not the cluster dev)
    assert prod.errors == ["[prod-eu] boom", "registry docker.io: 429", "devices: odd"]
    assert [r.cluster for r in prod.security] == ["prod-us"] and [c.cluster for c in prod.compliance] == ["prod-eu"]
    assert prod.trivy_operator == ["prod-eu"]
    dev = scope_snapshot(snapshot, ("dev", "nope"))
    assert [str(r.image) for r in dev.images] == ["docker.io/library/nginx:1.25", "docker.io/library/redis:7"]
    assert dev.images[1] is snapshot.images[1]  # all its usages visible: not copied
    assert scope_snapshot(snapshot, ()).images == []  # a role whose patterns match nothing sees nothing


@pytest.mark.parametrize(
    ("roles", "expected"),
    [
        (["team"], ("prod-*",)),
        (["team", "eu"], ("prod-*", "eu-*")),
        (["team", "readonly"], None),  # a role without clusters shows them all
        (["team", "open"], None),
        (["admin"], None),
        (["gone"], ()),
    ],
)
def test_role_clusters(roles, expected):
    auth = AuthSettings(
        roles={
            "team": RoleSettings(["rescan"], ["prod-*"]),
            "eu": RoleSettings([], ["eu-*", "prod-*"]),
            "open": RoleSettings(["scan"]),
        }
    )
    assert auth.clusters(roles) == expected
