from kube_tower.models import ChartReport, ImageRef, ImageReport, Snapshot


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
