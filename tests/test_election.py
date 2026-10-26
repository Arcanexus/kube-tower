import asyncio
import copy
import signal
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from kubernetes import client
from kubernetes.client.rest import ApiException

from kube_tower import election as election_module
from kube_tower.config import Settings
from kube_tower.election import ACTIVE_LABEL, LeaderElection, PodLabel
from kube_tower.main import create_app
from kube_tower.worker import Worker
from test_web import FakeScanner


class FakeLeases:
    """CoordinationV1Api keeping one Lease, with resourceVersion checks like the API server."""

    def __init__(self):
        self.lease: client.V1Lease | None = None
        self.version = 0
        self.down = False

    def _check(self):
        if self.down:
            raise ApiException(status=503, reason="unavailable")

    def read_namespaced_lease(self, name, namespace):
        self._check()
        if self.lease is None:
            raise ApiException(status=404, reason="not found")
        return copy.deepcopy(self.lease)

    def create_namespaced_lease(self, namespace, body):
        self._check()
        if self.lease is not None:
            raise ApiException(status=409, reason="exists")
        self.version += 1
        body.metadata.resource_version = str(self.version)
        self.lease = copy.deepcopy(body)
        return body

    def replace_namespaced_lease(self, name, namespace, body):
        self._check()
        if body.metadata.resource_version != self.lease.metadata.resource_version:
            raise ApiException(status=409, reason="conflict")
        self.version += 1
        body.metadata.resource_version = str(self.version)
        self.lease = copy.deepcopy(body)
        return body


class FakePods:
    def __init__(self):
        self.labels = {}
        self.fail = False

    def patch_namespaced_pod(self, name, namespace, body):
        if self.fail:
            raise ApiException(status=403, reason="forbidden")
        self.labels[name] = body["metadata"]["labels"][ACTIVE_LABEL]


def test_pod_label_errors_are_logged(caplog):
    pods = FakePods()
    pods.fail = True
    PodLabel(pods, "tools", "a").set(True)
    assert "cannot label pod tools/a kube-tower.arcanexus.com/active-controller=true" in caplog.text


def _election(api, identity, **kwargs):
    return LeaderElection("kube-tower-controller", "tools", api, identity=identity, **kwargs)


def test_first_replica_creates_and_holds_the_lease():
    api = FakeLeases()
    a, b = _election(api, "a"), _election(api, "b")
    assert a.try_acquire()
    assert api.lease.spec.holder_identity == "a"
    assert api.lease.spec.lease_transitions == 0
    assert not b.try_acquire()  # held and valid
    acquired = api.lease.spec.acquire_time
    assert a.try_acquire()  # renewed
    assert api.lease.spec.acquire_time == acquired
    assert api.lease.spec.holder_identity == "a"


def test_standby_takes_an_expired_lease():
    api = FakeLeases()
    a, b = _election(api, "a"), _election(api, "b")
    assert a.try_acquire()
    api.lease.spec.renew_time = datetime.now(UTC) - timedelta(seconds=60)
    assert b.try_acquire()
    assert api.lease.spec.holder_identity == "b" and b.holder == "b"
    assert api.lease.spec.lease_transitions == 1
    assert not a.try_acquire()


def test_lease_without_holder_or_times_is_free():
    api = FakeLeases()
    api.lease = client.V1Lease(metadata=client.V1ObjectMeta(name="kube-tower-controller", resource_version="1"))
    assert _election(api, "a").try_acquire()
    api.lease.spec = client.V1LeaseSpec(holder_identity="b", lease_duration_seconds=15)
    api.lease.spec.renew_time = datetime.now().replace(tzinfo=None) - timedelta(hours=3)  # naive: read as UTC
    assert _election(api, "a").try_acquire()
    api.lease.spec = client.V1LeaseSpec(holder_identity="b")
    assert _election(api, "a").try_acquire()


def test_conflicts_mean_not_acquired(monkeypatch):
    api = FakeLeases()
    a = _election(api, "a")
    original = api.read_namespaced_lease

    def raced_read(name, namespace):  # another replica creates the Lease right after our read
        api.read_namespaced_lease = original
        api.lease = client.V1Lease(metadata=client.V1ObjectMeta(name=name, resource_version="7"))
        raise ApiException(status=404)

    api.read_namespaced_lease = raced_read
    assert not a.try_acquire()

    def raced_replace(name, namespace, body):
        raise ApiException(status=409)

    api.replace_namespaced_lease = raced_replace
    assert not a.try_acquire()


def test_other_api_errors_are_raised():
    api = FakeLeases()
    api.down = True
    with pytest.raises(ApiException):
        _election(api, "a").try_acquire()
    api.down = False
    api.create_namespaced_lease = lambda namespace, body: (_ for _ in ()).throw(ApiException(status=403))
    with pytest.raises(ApiException):
        _election(api, "a").try_acquire()
    api.lease = client.V1Lease(metadata=client.V1ObjectMeta(resource_version="1"), spec=client.V1LeaseSpec())
    api.replace_namespaced_lease = lambda name, namespace, body: (_ for _ in ()).throw(ApiException(status=403))
    with pytest.raises(ApiException):
        _election(api, "a").try_acquire()


def test_standby_waits_then_leads(monkeypatch):
    api = FakeLeases()
    holder = _election(api, "a")
    assert holder.try_acquire()
    pods = FakePods()
    standby = _election(api, "b", renew=0.01, label=PodLabel(pods, "tools", "b"))
    started = asyncio.Event()

    async def lead():
        started.set()
        await asyncio.Event().wait()

    async def scenario():
        task = asyncio.create_task(standby.run(lead))
        await asyncio.sleep(0.05)
        assert not standby.leader and not started.is_set()
        assert pods.labels == {"b": "false"}  # e.g. a restarted container of the previous active controller
        api.lease.spec.renew_time = datetime.now(UTC) - timedelta(seconds=60)  # the holder stopped
        await asyncio.wait_for(started.wait(), 1)
        assert standby.leader and api.lease.spec.holder_identity == "b"
        assert pods.labels == {"b": "true"}  # the internal Service selects this pod now
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())


def test_leader_stops_when_the_lease_is_lost(monkeypatch, caplog):
    api = FakeLeases()
    leader = _election(api, "a", duration=1, renew=0.01)
    killed = []
    monkeypatch.setattr(election_module.os, "kill", lambda pid, sig: killed.append(sig))
    cancelled = asyncio.Event()

    async def lead():
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    async def scenario():
        task = asyncio.create_task(leader.run(lead))
        await asyncio.sleep(0.05)
        assert leader.leader
        api.down = True  # renewals fail for a while: still the leader
        await asyncio.sleep(0.1)
        assert leader.leader and not killed
        await asyncio.wait_for(task, 2)  # until the Lease could expire
        await asyncio.sleep(0)
        assert cancelled.is_set()

    asyncio.run(scenario())
    assert killed == [signal.SIGTERM] and not leader.leader
    assert "cannot read or renew" in caplog.text and "is lost" in caplog.text


def test_leader_stops_when_another_replica_took_the_lease(monkeypatch):
    api = FakeLeases()
    leader = _election(api, "a", duration=1, renew=0.01)
    killed = []
    monkeypatch.setattr(election_module.os, "kill", lambda pid, sig: killed.append(sig))

    async def scenario():
        task = asyncio.create_task(leader.run(asyncio.Event().wait))
        await asyncio.sleep(0.05)
        api.lease.spec.holder_identity = "b"
        await asyncio.wait_for(task, 2)

    asyncio.run(scenario())
    assert killed == [signal.SIGTERM]


class FixedElection:
    def __init__(self, leader):
        self.leader = leader
        self.ran = False

    async def run(self, on_leader):
        self.ran = True
        if self.leader:
            await on_leader()


@pytest.mark.parametrize("roles", [["controller"], ["all"]])
def test_standby_is_not_ready(monkeypatch, roles):
    monkeypatch.setenv("KUBE_TOWER_INTERNAL_TOKEN", "secret")
    settings = Settings(roles=roles)
    settings.internal.leader_election = True
    election = FixedElection(leader=False)
    scanner = FakeScanner()
    scanner.worker = Worker(settings)
    app = create_app(settings, scanner=scanner, background=False, election=election)
    with TestClient(app) as http:
        assert http.get("/healthz").status_code == 200
        answer = http.get("/readyz")
        assert answer.status_code == 503
        assert http.get("/leaderz").json() == {"leader": False}
        election.leader = True
        assert http.get("/leaderz").status_code == 200  # whatever the UI shows
        if roles == ["controller"]:
            assert http.get("/readyz").status_code == 200


def test_leader_runs_the_controller(monkeypatch):
    settings = Settings(roles=["all"])
    settings.internal.leader_election = True
    election = FixedElection(leader=True)
    scanner = FakeScanner()
    ran = []

    async def run_forever():
        ran.append(True)

    scanner.run_forever = run_forever
    app = create_app(settings, scanner=scanner, election=election)
    with TestClient(app):
        pass
    assert election.ran and ran


def test_election_needs_the_kubernetes_api(monkeypatch):
    settings = Settings(roles=["all"])
    settings.internal.leader_election = True
    scanner = FakeScanner()
    scanner.registry = type("NoCluster", (), {"local_client": lambda self: None})()
    with pytest.raises(ValueError, match="leaderElection"):
        create_app(settings, scanner=scanner, background=False)
    scanner.registry = type("Cluster", (), {"local_client": lambda self: client.ApiClient()})()
    app = create_app(settings, scanner=scanner, background=False)
    assert isinstance(app.state.election, LeaderElection)
    assert app.state.election.name == "kube-tower-controller" and app.state.election.label is None
    monkeypatch.setenv("POD_NAME", "kube-tower-controller-abc")
    settings.internal.label_pod = True
    election = create_app(settings, scanner=scanner, background=False).state.election
    assert election.identity == "kube-tower-controller-abc" and election.label.pod == "kube-tower-controller-abc"


def test_processes_that_report_to_the_controller(monkeypatch):
    from kube_tower import main as main_module

    reporters = []

    class Recorder:
        def __init__(self, settings, buffer, roles, state=lambda: "ok"):
            reporters.append((roles, state))

        async def run_forever(self):
            pass

    monkeypatch.setattr(main_module, "Reporter", Recorder)
    monkeypatch.setenv("KUBE_TOWER_INTERNAL_TOKEN", "secret")
    settings = Settings(roles=["worker"])
    settings.internal.controller_url = "http://kube-tower-internal:8081"
    create_app(settings, background=False)
    assert [(roles, state()) for roles, state in reporters] == [(["worker"], "ok")]
    create_app(Settings(roles=["all"]), scanner=FakeScanner(), background=False)  # one process: nothing to report
    assert len(reporters) == 1

    # a standby controller reports until it becomes the active one
    settings = Settings(roles=["controller"])
    settings.internal.leader_election = True
    settings.internal.controller_url = "http://kube-tower-internal:8081"
    election = FixedElection(leader=False)
    scanner = FakeScanner()
    scanner.worker = Worker(settings)
    app = create_app(settings, scanner=scanner, background=False, election=election)
    roles, state = reporters[-1]
    assert roles == ["controller"] and state() == "standby" and app.state.backend.processes()[0].state == "standby"
    election.leader = True
    assert state() is None and app.state.backend.processes()[0].state == "active"
