"""The pods of the Helm release on the Pods tab of the Administration page."""

from datetime import UTC, datetime

from kubernetes import client

from kube_tower import chartpods
from kube_tower.chartpods import ChartPod, chart_pod, chart_pods

STARTED = datetime(2026, 11, 9, 10, 0, tzinfo=UTC)


def _pod(name, labels, image="docker.io/valkey/valkey:9.1.3", ready=True, waiting=None, restarts=0, deleted=False):
    state = client.V1ContainerState(waiting=client.V1ContainerStateWaiting(reason=waiting)) if waiting else None
    return client.V1Pod(
        metadata=client.V1ObjectMeta(name=name, labels=labels, deletion_timestamp=STARTED if deleted else None),
        spec=client.V1PodSpec(containers=[client.V1Container(name="c", image=image)]),
        status=client.V1PodStatus(
            phase="Running" if ready or waiting else "Pending",
            start_time=STARTED,
            container_statuses=[
                client.V1ContainerStatus(name="c", image=image, image_id="", ready=ready, restart_count=restarts, state=state)
            ]
            if ready or waiting
            else None,
        ),
    )


def test_chart_pod():
    valkey = chart_pod(_pod("kt-valkey-0", {"app.kubernetes.io/name": "kube-tower-valkey"}), "kt")
    assert valkey == ChartPod("kt-valkey-0", "valkey", True, "ok", 0, "9.1.3", STARTED)
    krr = chart_pod(
        _pod("kt-krr-1", {"app.kubernetes.io/component": "krr"}, "robustadev/krr:v1.31.3", False, "CrashLoopBackOff", 4),
        "kt",
    )
    assert (krr.component, krr.ready, krr.state, krr.restarts, krr.version) == ("krr", False, "crashloopbackoff", 4, "v1.31.3")
    pending = chart_pod(_pod("kt-dex-1", {"app.kubernetes.io/name": "kt-dex"}, "ghcr.io/dexidp/dex@sha256:ab", False), "kt")
    assert (pending.component, pending.state, pending.version) == ("dex", "pending", "")
    gone = chart_pod(_pod("kt-1", {"app.kubernetes.io/name": "other"}, "localhost:5000/kt", deleted=True), "kt")
    assert (gone.component, gone.state, gone.version) == ("other", "terminating", "")
    assert chart_pod(_pod("x", {}), "kt").component == "pod"


async def test_chart_pods(monkeypatch):
    listed = []

    def fake_list(namespace, release):
        listed.append((namespace, release))
        if release == "broken":
            raise RuntimeError("forbidden")
        return [ChartPod("kt-valkey-0", "valkey", True, "ok")]

    monkeypatch.setattr(chartpods, "_list", fake_list)
    monkeypatch.setattr(chartpods, "_cache", (0.0, None))
    monkeypatch.delenv("KUBE_TOWER_RELEASE", raising=False)
    monkeypatch.setenv("POD_NAMESPACE", "kube-tower")
    assert await chart_pods() is None and listed == []  # not deployed by the chart
    monkeypatch.setenv("KUBE_TOWER_RELEASE", "kt")
    assert [p.name for p in await chart_pods()] == ["kt-valkey-0"]
    assert [p.name for p in await chart_pods()] == ["kt-valkey-0"] and listed == [("kube-tower", "kt")]  # cached
    monkeypatch.setattr(chartpods, "_cache", (0.0, None))
    monkeypatch.setenv("KUBE_TOWER_RELEASE", "broken")
    assert await chart_pods() is None
