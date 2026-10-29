import asyncio
import contextlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta

import fakeredis
import pytest
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError as RedisConnectionError

from kube_tower import administration as administration_module
from kube_tower import backend as backend_module
from kube_tower import internal
from kube_tower import processes as processes_module
from kube_tower import tasks as tasks_module
from kube_tower import worker as worker_module
from kube_tower.administration import Administration
from kube_tower.backend import UNREACHABLE, LocalBackend, RemoteBackend
from kube_tower.bus import Bus, Message, pack, unpack
from kube_tower.config import Settings
from kube_tower.internal import Publisher, Reporter, TaskPuller
from kube_tower.logbuffer import LogBuffer
from kube_tower.main import create_app
from kube_tower.models import ChartReport, ImageRef, ImageReport, Snapshot, Status, Usage, VulnerabilityReport, decode, encode
from kube_tower.processes import Processes
from kube_tower.scanner import Scanner
from kube_tower.tasks import (
    TASK_GROUP,
    CheckImagesTask,
    CollectTask,
    QueueRunner,
    ScanVulnerabilitiesTask,
    TaskFailed,
    task_stream,
)
from kube_tower.trivy import TrivyStatus, scans_failed
from kube_tower.worker import Worker
from test_scanner import TwoClusters, fakes  # noqa: F401 - fixture

TOKEN = "secret"


class FakeBus(Bus):
    """fakeredis answers a blocking read at once: wait for a message as Valkey does."""

    async def receive(self, streams, group, consumer, block, count=1):
        deadline = asyncio.get_running_loop().time() + block
        while not (messages := await super().receive(streams, group, consumer, 0.001, count)):
            if asyncio.get_running_loop().time() >= deadline:
                break
            await asyncio.sleep(0.005)
        return messages

    async def request(self, stream, data, timeout, **fields):
        reply = self.key("reply", uuid.uuid4().hex)
        await self.send(stream, data, reply=reply, **fields)
        deadline = asyncio.get_running_loop().time() + timeout
        while (answer := await self.redis.lpop(reply)) is None and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.005)
        return answer


@pytest.fixture
async def bus(monkeypatch):
    monkeypatch.setattr(tasks_module, "WATCH", 0.02)  # the controller looks at the results and tasks often
    monkeypatch.setattr(internal, "PUBLISH", 0.02)  # and publishes its state often
    monkeypatch.setattr(internal, "WAIT", 0.05)  # the blocking reads end often
    bus = FakeBus(fakeredis.FakeAsyncRedis(), "kt-test")
    yield bus
    await bus.close()


def _settings(roles):
    settings = Settings(roles=roles)
    settings.internal.controller_url = "http://controller:8081"
    settings.redis.url = "redis://valkey:6379/0"
    return settings


def _runner(worker, local_roles, bus, **kwargs):
    runner = QueueRunner(worker, local_roles, bus, **kwargs)
    runner.loop = asyncio.get_running_loop()  # the scans run in their own threads and loops
    return runner


@contextlib.asynccontextmanager
async def _serving(runner):
    """The controller reads the results and watches the tasks meanwhile."""
    serving = asyncio.create_task(runner.serve())
    await runner._ready.wait()
    try:
        yield
    finally:
        serving.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serving


def _puller(monkeypatch, bus, roles=("worker", "trivy"), registry=None, source="kube-tower-worker-1"):
    monkeypatch.setenv("KUBE_TOWER_INTERNAL_TOKEN", TOKEN)
    settings = _settings(list(roles))
    puller = TaskPuller(settings, Worker(settings), list(roles), bus, registry or TwoClusters())
    puller.source = source
    return puller


async def _until_done(task, *pullers):
    while not task.done():
        await asyncio.gather(*(p.pull(wait=0.02) for p in pullers))
    return task.result()


async def test_distributed_scan_through_valkey(fakes, monkeypatch, bus):  # noqa: F811 - fixture
    settings = _settings(["ui", "controller"])
    scanner = Scanner(settings, TwoClusters())
    scanner.pull_secrets = {"ghcr.io": ("user", "token")}  # sent with each task
    scanner.runner = runner = _runner(scanner.worker, set(), bus, context=lambda: {"pull_secrets": encode(scanner.pull_secrets)})
    puller = _puller(monkeypatch, bus)
    async with _serving(runner):
        snap = await _until_done(asyncio.create_task(scanner.scan()), puller)
    # Every task ran in the puller: the collect tasks with the clusters it read itself.
    assert sorted(puller.worker.clusters) == ["a", "b"]
    assert puller.worker.pull_secrets == {"ghcr.io": ("user", "token")}
    assert [str(r.image) for r in snap.images] == ["docker.io/library/nginx:1.25"]
    assert [u.cluster for u in snap.images[0].usages] == ["a", "b"] and snap.images[0].status == Status.OUTDATED
    assert [c.status for c in snap.charts] == [Status.UP_TO_DATE, Status.UP_TO_DATE]
    # nothing left in Valkey: every task and result was deleted once handled
    assert not runner.waiting and not runner.messages
    assert [await bus.length(s) for s in ("tasks:worker", "tasks:trivy", "results")] == [0, 0, 0]


async def test_queue_runner(monkeypatch, caplog, bus):
    caplog.set_level(logging.INFO, logger="kube_tower")
    monkeypatch.setattr(tasks_module, "WATCH", 3600)  # the tasks are looked at by the test only
    worker = Worker(Settings())
    seen = []
    runner = _runner(worker, {"trivy"}, bus, timeout=0, on_task=lambda process, kind: seen.append((process, kind)))
    # a role of this process: run here
    assert (await runner.run(ScanVulnerabilitiesTask([]))).vulnerabilities == []
    async with _serving(runner):
        # read by a process that dies: given to another one, ATTEMPTS times
        waiting = asyncio.create_task(runner.run(CollectTask("a")))
        [first] = await bus.receive(task_stream("worker"), TASK_GROUP, "pod-dead", block=1)
        assert first.fields["id"] == "collect-1" and first.fields["epoch"] == runner.epoch
        assert unpack(first.data)["task"] == {
            "cluster": "a",
            "images": True,
            "charts": True,
            "operator_reports": True,
            "security": True,
            "image_name": None,
        }
        await runner.check_tasks()
        assert ("pod-dead", "collect") in seen
        assert "task collect-1 not answered by pod-dead within 0s: given to another process" in caplog.text
        [second] = await bus.receive(task_stream("worker"), TASK_GROUP, "pod-dead-too", block=1)
        await runner.check_tasks()
        [third] = await bus.receive(task_stream("worker"), TASK_GROUP, "pod-also-dead", block=1)
        assert first.data == second.data == third.data
        await runner.check_tasks()
        with pytest.raises(TaskFailed, match="task collect-1 failed: not answered within 0s, 3 times"):
            await waiting
        assert "task collect-1 not answered 3 times: given up" in caplog.text
        assert await bus.pending(task_stream("worker"), TASK_GROUP) == []

        # the scan is cancelled: the task is deleted, nobody runs it
        waiting = asyncio.create_task(runner.run(CheckImagesTask([])))
        while not await bus.length(task_stream("worker")):
            await asyncio.sleep(0.01)
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        assert await bus.length(task_stream("worker")) == 0 and not runner.waiting

        # the result of a previous controller, or of a task forgotten: ignored and deleted
        await bus.send("results", pack({"result": {}}), id="collect-9", epoch="another", source="pod-a")
        await bus.send("results", pack({"result": {}}), id="collect-9", epoch=runner.epoch, source="pod-a")
        while await bus.length("results"):
            await asyncio.sleep(0.01)
        assert "result of task collect-9 from pod-a not needed anymore" in caplog.text

        # a result that cannot be read fails its task
        waiting = asyncio.create_task(runner.run(CheckImagesTask([])))
        [task] = await bus.receive(task_stream("worker"), TASK_GROUP, "pod-a", block=1)
        await bus.send("results", b"not compressed", id=task.fields["id"], epoch=runner.epoch, source="pod-a")
        with pytest.raises(TaskFailed, match="result not readable"):
            await waiting
        assert seen[-1] == ("pod-a", "")


async def test_a_new_controller_empties_the_streams_of_the_previous_one(bus):
    old = _runner(Worker(Settings()), set(), bus)
    async with _serving(old):
        asyncio.create_task(old.run(CollectTask("a")))
        while not await bus.length(task_stream("worker")):
            await asyncio.sleep(0.01)
    new = _runner(Worker(Settings()), set(), bus)
    async with _serving(new):
        assert await bus.length(task_stream("worker")) == 0 and new.epoch != old.epoch


async def test_the_controller_waits_while_valkey_cannot_be_reached(monkeypatch, caplog, bus):
    slept = []
    real_sleep = asyncio.sleep

    async def sleep(delay):
        slept.append(delay)
        await real_sleep(0)

    calls = {"receive": 0, "pending": 0}

    async def receive(*args, **kwargs):
        calls["receive"] += 1
        if calls["receive"] > 2:
            await real_sleep(1)
        raise RedisConnectionError("connection refused")

    async def pending(*args, **kwargs):
        calls["pending"] += 1
        raise RedisConnectionError("connection refused")

    runner = _runner(Worker(Settings()), set(), bus)
    async with _serving(runner):
        monkeypatch.setattr(asyncio, "sleep", sleep)
        monkeypatch.setattr(bus, "receive", receive)
        monkeypatch.setattr(bus, "pending", pending)
        while calls["receive"] < 3 or calls["pending"] < 1:
            await real_sleep(0.01)
    assert "cannot read the results of the tasks from Valkey (connection refused): trying again in 1s" in caplog.text
    assert "cannot read the tasks being run from Valkey: connection refused" in caplog.text
    assert slept[:1] == [1] and 2 in slept


async def test_puller_errors(monkeypatch, caplog, bus):
    slept, real_sleep = [], asyncio.sleep

    async def sleep(delay):
        if delay:
            slept.append(delay)
        await real_sleep(0)

    runner = _runner(Worker(Settings()), set(), bus)
    trivy = _puller(monkeypatch, bus, roles=["trivy"])

    # a task for another role, or that fails: the error goes back to the controller
    async with _serving(runner):
        await bus.ensure_group(task_stream("trivy"), TASK_GROUP)
        task = asyncio.create_task(runner.run(CheckImagesTask([])))
        [message] = await bus.receive(task_stream("worker"), TASK_GROUP, "nobody", block=1)
        await bus.send(task_stream("trivy"), message.data, **message.fields)  # sent to the wrong process
        assert await trivy.pull(wait=1)
        with pytest.raises(TaskFailed, match="ValueError: a worker task was sent to a process with roles trivy"):
            await task
        assert not await trivy.pull(wait=0.01)  # no task meanwhile

    # Valkey cannot be reached: the next tries wait longer
    monkeypatch.setattr(asyncio, "sleep", sleep)

    async def unreachable(*args, **kwargs):
        raise RedisConnectionError("connection refused")

    monkeypatch.setattr(bus, "receive", unreachable)
    assert not await trivy.pull() and not await trivy.pull()
    assert slept == [1, 2] and "cannot read the tasks from Valkey (connection refused): trying again in 1s" in caplog.text

    # the result cannot be sent: tried again, then lost (the controller gives the task to another process)
    monkeypatch.setattr(bus, "send", unreachable)
    image = ImageReport(ImageRef("docker.io", "library/nginx", "1.25"))
    data = pack({"id": "scan-vulnerabilities-1", "kind": "scan-vulnerabilities", "task": {"images": [encode(image)]}})
    await trivy.answer(Message("1-1", data, {"id": "scan-vulnerabilities-1", "epoch": "e"}, task_stream("trivy")))
    assert slept[2:] == list(tasks_module.RETRY)
    assert "result of task scan-vulnerabilities-1 lost" in caplog.text


def test_processes_by_role():
    # worker or trivy alone: no UI, API or metrics, only the probes
    client = TestClient(create_app(_settings(["worker", "trivy"]), background=False))
    assert client.get("/healthz").status_code == client.get("/readyz").status_code == 200
    assert client.get("/").status_code == client.get("/api/snapshot").status_code == 404
    # ui and controller: the other roles get their tasks through the queue
    app = create_app(_settings(["ui", "controller"]), background=False)
    assert isinstance(app.state.scanner.runner, QueueRunner) and app.state.scanner.runner.local_roles == set()
    assert TestClient(app).get("/healthz").status_code == 200
    # controller alone: the metrics of the snapshot, no UI
    client = TestClient(create_app(_settings(["controller"]), background=False))
    assert client.get("/metrics").status_code == 200 and client.get("/").status_code == 404
    # ui alone: the pages show what the controller publishes, no metrics (they would be duplicated)
    app = create_app(_settings(["ui"]), background=False)
    assert isinstance(app.state.backend, RemoteBackend)
    client = TestClient(app)
    assert client.get("/readyz").status_code == 503  # no snapshot from the controller yet
    assert client.get("/metrics").status_code == 404


def test_processes_run_their_roles(monkeypatch):
    ran = []

    async def run_forever(self):
        ran.append(type(self).__name__)

    for cls in (Scanner, TaskPuller, Reporter):
        monkeypatch.setattr(cls, "run_forever", run_forever)
    for cls in (QueueRunner, Publisher):
        monkeypatch.setattr(cls, "serve", run_forever)
    with TestClient(create_app(_settings(["controller", "worker"]))):
        pass
    assert sorted(ran) == ["Publisher", "QueueRunner", "Reporter", "Scanner"]
    ran.clear()
    with TestClient(create_app(_settings(["trivy"]))):
        pass
    assert sorted(ran) == ["Reporter", "TaskPuller"]


async def test_distributed_scan_in_batches(fakes, monkeypatch, bus):  # noqa: F811 - fixture
    def collect(self, cluster):
        for image in ("nginx:1.25", "nginx:1.26", "redis:7", "alpine:3"):
            self.add(image, Usage(cluster.name, "Pod", "default", "web"))
        return []

    async def scan_many(self, reports, prepared_for=0):
        for r in reports:
            r.vulnerabilities = VulnerabilityReport("trivy", datetime.now(UTC), message="boom")
        return [scans_failed(len(reports))]

    monkeypatch.setattr(worker_module.ImageInventory, "collect", collect)
    monkeypatch.setattr(worker_module.TrivyScanner, "available", True)
    monkeypatch.setattr(worker_module.TrivyScanner, "scan_many", scan_many)
    settings = _settings(["ui", "controller"])
    settings.internal.batch_size = 2
    scanner = Scanner(settings, TwoClusters())
    scanner.runner = runner = _runner(scanner.worker, set(), bus)
    # two processes share the tasks
    pullers = [_puller(monkeypatch, bus, source="worker-1"), _puller(monkeypatch, bus, source="worker-2")]
    pulled = []
    for puller in pullers:

        async def execute(data, run=puller.execute):
            if data["kind"] in ("check-images", "scan-vulnerabilities"):
                pulled.append((data["kind"], [i["image"]["repository"] for i in data["task"]["images"]]))
            return await run(data)

        puller.execute = execute

    async def scanned():
        await scanner.scan()
        return scanner.snapshot

    async with _serving(runner):
        snap = await _until_done(asyncio.create_task(scanned()), *pullers)
    # the images of one name stay together, the results come back in the order of the snapshot
    checks = sorted(names for kind, names in pulled if kind == "check-images")
    assert checks == [["library/alpine"], ["library/nginx", "library/nginx"], ["library/redis"]]
    assert sorted(names for kind, names in pulled if kind == "scan-vulnerabilities") == checks
    assert [str(r.image) for r in snap.images] == [
        "docker.io/library/alpine:3",
        "docker.io/library/nginx:1.25",
        "docker.io/library/nginx:1.26",
        "docker.io/library/redis:7",
    ]
    assert all(r.status == Status.OUTDATED and r.vulnerabilities.message == "boom" for r in snap.images)
    assert snap.errors.count(scans_failed(4)) == 1  # the failed scans of the batches, counted together


def _controller(bus, settings=None):
    """A controller process with a snapshot, and its publisher."""
    scanner = Scanner(settings or _settings(["controller", "worker", "trivy"]), TwoClusters())
    image = ImageReport(ImageRef("docker.io", "library/nginx", "1.25"), [Usage("a", "Pod", "default", "web")])
    chart = ChartReport("a", "app", "argocd", "app", "https://charts.example.com", "1.0.0", "helm")
    scanner.snapshot = Snapshot(images=[image], charts=[chart], started_at=datetime.now(UTC), finished_at=datetime.now(UTC))
    backend = LocalBackend(scanner, Administration(scanner), bus=bus)
    return scanner, backend, Publisher(backend, bus)


@contextlib.asynccontextmanager
async def _publishing(publisher):
    """The controller publishes its state and runs the actions meanwhile."""
    serving = asyncio.create_task(publisher.serve())
    while not await publisher.bus.state_revision():
        await asyncio.sleep(0.01)
    try:
        yield
    finally:
        serving.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serving


async def test_ui_process_reads_the_controller(monkeypatch, bus):
    now = datetime.now(UTC)
    monkeypatch.setattr(processes_module, "_now", lambda: now)  # the state does not change by itself
    scanner, _, publisher = _controller(bus)
    remote = RemoteBackend(_settings(["ui"]), bus)
    await remote.refresh()  # nothing published yet
    assert remote.snapshot.finished_at is None and remote.state.revision == -1
    await publisher.publish()
    await remote.refresh()
    assert [str(r.image) for r in remote.snapshot.images] == ["docker.io/library/nginx:1.25"]
    assert remote.state.revision == scanner.revision and not remote.running and not remote.locked
    assert remote.scans_total == {"success": 0, "failure": 0} and remote.activities() == []
    assert remote.trivy_binary == "trivy" and remote.trivy_cached == 0 and remote.admin_running == set()
    assert remote.registry_credentials(Settings()) == ([], {})
    report = remote.snapshot.images[0]
    assert remote.same_name_images(report) == [report] and remote.can_rescan_vulnerabilities(report)
    assert remote.failed_items() == ([], [], [])
    # the state is published again only when it changed, the snapshot only with a new revision
    published, snapshot = await bus.state_revision(), remote.snapshot
    await publisher.publish()
    assert await bus.state_revision() == published
    await remote.refresh()
    assert remote.snapshot is snapshot
    scanner.snapshot = Snapshot(finished_at=datetime.now(UTC))
    await publisher.publish()
    await remote.refresh()
    assert remote.snapshot.images == []

    # the pages of a ui process
    ui = create_app(_settings(["ui"]), background=False, bus=bus)
    ui.state.backend = remote
    scanner.snapshot = Snapshot(images=[report], started_at=datetime.now(UTC), finished_at=datetime.now(UTC))
    await publisher.publish()
    await remote.refresh()
    client = TestClient(ui)
    assert client.get("/readyz").status_code == 200
    assert "library/nginx" in client.get("/images").text
    assert client.get("/api/snapshot").json()["images"][0]["image"]["ref"] == "docker.io/library/nginx:1.25"


async def test_ui_process_actions(monkeypatch, fakes, bus):  # noqa: F811 - fixture
    monkeypatch.setattr(Administration, "test_connectivity", lambda self: None)  # no network
    scanner, _, publisher = _controller(bus)
    remote = RemoteBackend(_settings(["ui"]), bus)
    async with _publishing(publisher):
        await remote.refresh()
        image, chart = remote.snapshot.images[0], remote.snapshot.charts[0]
        assert await remote.rescan_chart(chart) is None
        assert ("chart", "a", "argocd", "app", "app") in remote.rescanning  # the state is published at once
        await asyncio.gather(*scanner._rescans)
        assert await remote.rescan_image(image, vulnerabilities=False) is None
        await asyncio.gather(*scanner._rescans)
        assert await remote.retry_failed() == "nothing failed in the last scan"
        assert await remote.clear_trivy_cache() == 0
        assert (await remote.refresh_trivy_status()).message == "trivy binary 'trivy' not found"
        assert "binary 'trivy' is not found" in await remote.update_trivy_db() and await remote.test_connectivity() is None
        assert await remote.trigger() is True
        assert remote.checking_versions  # the page shows the scan at once: no second click on "Scan now"
        await scanner._task
        # gone from the controller meanwhile
        gone = ChartReport("b", "app", "argocd", "gone", "https://charts.example.com", "1.0.0", "helm")
        assert "not found in the last scan" in await remote.rescan_chart(gone)
        gone = ImageReport(ImageRef("docker.io", "library/gone", "1"))
        assert "not found in the last scan" in await remote.rescan_image(gone)
        assert await remote._action("reboot") == UNREACHABLE.format("ValueError: unknown action 'reboot'")
        assert await bus.length("actions") == 0  # every action answered was deleted


async def test_ui_process_without_controller_or_valkey(monkeypatch, caplog, bus):
    monkeypatch.setattr(backend_module, "ACTION_TIMEOUT", 0.05)
    remote = RemoteBackend(_settings(["ui"]), bus)
    # no controller answers
    assert await remote.trigger() is False
    assert await remote.retry_failed() == UNREACHABLE.format("no answer within 0s")

    # Valkey cannot be reached: the pages show the last known state
    async def unreachable(*args, **kwargs):
        raise RedisConnectionError("connection refused")

    for name in ("state_revision", "request", "read", "last"):
        monkeypatch.setattr(bus, name, unreachable)
    await remote.refresh()
    await remote.refresh()
    assert caplog.text.count("Valkey cannot be reached (connection refused)") == 1  # once until it answers again
    assert remote.snapshot.finished_at is None
    assert await remote.clear_trivy_cache() == 0
    assert await remote.retry_failed() == UNREACHABLE.format("connection refused")
    assert (await remote.refresh_trivy_status()).message == "the controller cannot be reached"
    assert await remote.log_lines() == [] and "log lines not read from Valkey: connection refused" in caplog.text
    monkeypatch.undo()
    _, _, publisher = _controller(bus)
    await publisher.publish()
    await remote.refresh()
    assert "Valkey answers again" in caplog.text and remote.snapshot.finished_at is not None


async def test_the_publisher_while_valkey_cannot_be_reached(monkeypatch, caplog, bus):
    _, backend, publisher = _controller(bus)

    async def unreachable(*args, **kwargs):
        raise RedisConnectionError("connection refused")

    calls = []
    real_sleep = asyncio.sleep

    async def sleep(delay):
        calls.append(delay)
        await real_sleep(0.001)

    async with _publishing(publisher):
        monkeypatch.setattr(asyncio, "sleep", sleep)
        for name in ("publish_state", "processes", "receive", "reply"):
            monkeypatch.setattr(bus, name, unreachable)
        while "cannot read the actions" not in caplog.text or len(calls) < 20:
            await real_sleep(0.01)
        # an action answered while Valkey is away: the answer is lost, the ui process says it got none
        await publisher.run_action(Message("1-1", pack({"name": "reboot"}), {"reply": "r"}, "actions"))
    assert "cannot reach Valkey (connection refused): the ui processes show the last state" in caplog.text
    assert "cannot read the actions of the ui processes from Valkey (connection refused): trying again in 1s" in caplog.text
    assert "answer to the action of a ui process lost: connection refused" in caplog.text


async def test_trivy_administration_in_trivy_processes(monkeypatch, caplog, bus):
    caplog.set_level(logging.INFO, logger="kube_tower")
    monkeypatch.setenv("KUBE_TOWER_INTERNAL_TOKEN", TOKEN)
    downloads = []

    async def prepare(self, max_age=0):
        downloads.append(max_age)

    async def status(self):
        return TrivyStatus(datetime.now(UTC), version="0.60.0")

    monkeypatch.setattr(worker_module.TrivyScanner, "available", True)
    monkeypatch.setattr(worker_module.TrivyScanner, "prepare", prepare)
    monkeypatch.setattr(worker_module.TrivyScanner, "status", status)
    scanner = Scanner(_settings(["ui", "controller", "worker"]), TwoClusters())
    administration = Administration(scanner)
    scanner.runner = runner = _runner(scanner.worker, {"worker"}, bus, context=lambda: {"trivy": administration.generations})
    backend = LocalBackend(scanner, administration)
    assert backend.trivy_remote and backend.trivy_available and backend.trivy_cached == 0  # unknown yet
    trivy = _puller(monkeypatch, bus, roles=["trivy"])
    trivy.worker.trivy.cache["docker.io/library/nginx:1.25"] = VulnerabilityReport("trivy", datetime.now(UTC))
    async with _serving(runner):
        # the status of the trivy process that answered
        status = await _until_done(asyncio.create_task(backend.refresh_trivy_status()), trivy)
        assert status.version == "0.60.0" and backend.trivy_status is status and backend.trivy_cached == 1
        # a database update runs in one trivy process, the others refresh theirs before their next task
        assert await backend.update_trivy_db() is None and administration.generations == {"db": 1, "cache": 0}
        await _until_done(next(iter(administration._tasks)), trivy)
        assert downloads == [0] and "database refreshed in one trivy process" in backend.trivy_message
        # the cache is forgotten by each trivy process at its next task
        assert await backend.clear_trivy_cache() == -1 and administration.generations == {"db": 1, "cache": 1}
        await _until_done(asyncio.create_task(backend.refresh_trivy_status()), trivy)
        assert trivy.worker.trivy.cache == {} and backend.trivy_cached == 0
        assert "Trivy results cache cleared (1 image(s)), as asked on the Administration page" in caplog.text
        administration.generations["db"] += 1
        await _until_done(asyncio.create_task(backend.refresh_trivy_status()), trivy)
        assert trivy.worker.trivy._prepared_at is None and "the Trivy databases are refreshed before the next scan" in caplog.text

    # no trivy process answers
    monkeypatch.setattr(administration_module, "REMOTE_STATUS_TIMEOUT", 0.05)
    monkeypatch.setattr(administration_module, "REMOTE_UPDATE_TIMEOUT", 0.05)
    assert (await backend.refresh_trivy_status()).message == "no trivy process answered within 0s"
    assert await backend.update_trivy_db() is None
    await asyncio.gather(*administration._tasks)
    assert backend.trivy_message.startswith("no trivy process answered")

    async def broken(self, max_age=0):
        return "cannot download the Trivy database: 403"

    monkeypatch.setattr(worker_module.TrivyScanner, "prepare", broken)
    async with _serving(runner):
        assert await backend.update_trivy_db() is None
        await _until_done(next(iter(administration._tasks)), trivy)
    assert backend.trivy_message == "cannot download the Trivy database: 403"


async def test_logs_and_state_of_the_remote_processes(monkeypatch, fakes, bus):  # noqa: F811 - fixture
    monkeypatch.setenv("POD_NAME", "kube-tower-controller-0")
    scanner = Scanner(_settings(["ui", "controller"]), TwoClusters())
    buffer = LogBuffer(source="kube-tower-controller-0", roles=["ui", "controller"])
    buffer.emit(logging.LogRecord("kube_tower.scanner", logging.INFO, "", 0, "scan finished", None, None))
    backend = LocalBackend(scanner, Administration(scanner), buffer, Processes(["ui", "controller"]), bus=bus)
    publisher = Publisher(backend, bus)
    seen = []

    def task(name, kind=""):
        seen.append((name, kind))
        backend.process_registry.task(name, kind)

    scanner.runner = runner = _runner(scanner.worker, set(), bus, on_task=task)
    worker = _puller(monkeypatch, bus)
    async with _serving(runner):
        await _until_done(asyncio.create_task(scanner.scan()), worker)
    # the controller knows which process sent the last result
    assert seen[-1] == ("kube-tower-worker-1", "")

    # the active controller ships its lines, without listing itself (it does)
    controller = Reporter(bus, buffer, ["ui", "controller"], lambda: None)
    assert await controller.report() and await bus.processes() == {}
    # a worker tells it is there and ships its lines, with the pod and its roles
    monkeypatch.setenv("POD_NAME", "kube-tower-worker-1")
    worker_buffer = LogBuffer(source="kube-tower-worker-1", roles=["worker"])
    worker_buffer.emit(
        logging.LogRecord("kube_tower.collectors.images", logging.WARNING, "", 0, "[a] cannot list CronJob", None, None)
    )
    reporter = Reporter(bus, worker_buffer, ["worker"])
    assert await reporter.report()
    lines = await backend.log_lines()
    assert [(line.source, line.roles, line.level, line.message) for line in lines][-1] == (
        "kube-tower-worker-1",
        ["worker"],
        "WARNING",
        "[a] cannot list CronJob",
    )
    assert ("kube-tower-controller-0", "scan finished") in [(line.source, line.message) for line in lines]
    assert await reporter.report() and await backend.log_lines(lines[-1].seq) == []  # only the new lines are sent
    await publisher.read_processes()
    processes = backend.processes()
    assert [(p.name, p.roles, p.state) for p in processes] == [
        ("kube-tower-controller-0", ["ui", "controller"], "active"),
        ("kube-tower-worker-1", ["worker"], "ok"),
    ]
    assert processes[1].version == "dev" and processes[1].task == "" and processes[1].alive

    # a standby controller reports as such; once active it only ships its lines
    monkeypatch.setenv("POD_NAME", "kube-tower-controller-1")
    standby_state = ["standby"]
    standby = Reporter(
        bus, LogBuffer(source="kube-tower-controller-1", roles=["controller"]), ["controller"], lambda: standby_state[0]
    )
    assert await standby.report()
    await publisher.read_processes()
    assert backend.processes()[1].state == "standby"
    standby_state[0] = None
    standby.buffer.emit(logging.LogRecord("kube_tower.scanner", logging.INFO, "", 0, "now active", None, None))
    assert await standby.report() and standby.sent == standby.buffer.seq
    # a report that cannot be read is skipped
    await bus.set_process("kube-tower-old", b"not json", 60)
    await publisher.read_processes()
    assert "kube-tower-old" not in [p.name for p in backend.processes()]

    # processes not heard of for a while are lost, then forgotten
    later = datetime.now(UTC) + timedelta(seconds=processes_module.LOST + 1)
    monkeypatch.setattr(processes_module, "_now", lambda: later)
    assert [p.state for p in backend.processes()] == ["active", "lost", "lost"]
    much_later = datetime.now(UTC) + timedelta(seconds=processes_module.FORGET + 1)
    monkeypatch.setattr(processes_module, "_now", lambda: much_later)
    assert [p.name for p in backend.processes()] == ["kube-tower-controller-0"]

    # the ui processes get the processes and the lines of every process
    ui_backend = RemoteBackend(_settings(["ui"]), bus)
    monkeypatch.setattr(processes_module, "_now", lambda: datetime.now(UTC))
    await publisher.read_processes()
    await publisher.publish()
    await ui_backend.refresh()
    assert [p.name for p in ui_backend.processes()] == [
        "kube-tower-controller-0",
        "kube-tower-controller-1",
        "kube-tower-worker-1",
    ]
    lines = await ui_backend.log_lines()
    assert [(line.source, line.message) for line in lines] == [
        ("kube-tower-controller-0", "scan finished"),
        ("kube-tower-worker-1", "[a] cannot list CronJob"),
        ("kube-tower-controller-1", "now active"),
    ]
    assert await ui_backend.log_lines(lines[-1].seq) == []
    ui = create_app(_settings(["ui"]), background=False, bus=bus)
    ui.state.backend = ui_backend
    assert "scan finished" in TestClient(ui).get("/logs").text

    # Valkey is away: tried again at the next report
    async def unreachable(*args, **kwargs):
        raise RedisConnectionError("connection refused")

    with monkeypatch.context() as patched:
        patched.setattr(bus, "set_process", unreachable)
        assert not await reporter.report()

    # a process that stops says so: gone at once, not shown as lost
    monkeypatch.setattr(internal, "HEARTBEAT", 0.01)
    running = asyncio.create_task(reporter.run_forever())
    await asyncio.sleep(0.05)
    await publisher.read_processes()
    assert "kube-tower-worker-1" in [p.name for p in backend.processes()]
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    await publisher.read_processes()
    assert "kube-tower-worker-1" not in [p.name for p in backend.processes()]


async def test_large_results_and_states_stay_off_the_event_loop(fakes, monkeypatch, bus):  # noqa: F811 - fixture
    import threading

    on_loop = []
    decode_result = tasks_module.decode_result

    def spy(kind, data):
        on_loop.append(threading.current_thread() is threading.main_thread())
        return decode_result(kind, data)

    monkeypatch.setattr(tasks_module, "decode_result", spy)
    settings = _settings(["ui", "controller"])
    scanner = Scanner(settings, TwoClusters())
    scanner.runner = runner = _runner(scanner.worker, set(), bus)
    backend = LocalBackend(scanner, Administration(scanner), bus=bus)
    puller = _puller(monkeypatch, bus)
    async with _serving(runner):
        await _until_done(asyncio.create_task(scanner.scan()), puller)
    # the results of the worker were decoded in threads, never on the event loop of the controller
    assert on_loop and not any(on_loop)
    # the snapshot is published with a new revision only, even while something runs
    published = []
    publish_state = bus.publish_state

    async def spy_publish(data, snapshot=None):
        published.append((json.loads(data), snapshot is not None))
        return await publish_state(data, snapshot)

    monkeypatch.setattr(bus, "publish_state", spy_publish)
    publisher = Publisher(backend, bus)
    await publisher.publish()
    monkeypatch.setattr(LocalBackend, "activities", lambda self: ["a rescan"])
    await publisher.publish()
    assert [(state["activities"], with_snapshot) for state, with_snapshot in published] == [([], True), (["a rescan"], False)]
    assert all(state["snapshot"] is None for state, _ in published)
    assert decode(Snapshot, unpack(await bus.published_snapshot())).images[0].image == scanner.snapshot.images[0].image


async def test_registry_authentication_seen_by_the_workers_reaches_the_controller(bus):
    """The controller shows on its Administration page whether the registries accepted the credentials:
    the check results of the worker pods carry what the registries answered them."""
    from datetime import UTC, datetime, timedelta

    from kube_tower.registry.auth import AuthResult
    from kube_tower.tasks import CheckImagesResult, CheckImagesTask, encode_result

    controller = Worker(Settings())
    runner = _runner(controller, set(), bus)
    old = datetime.now(UTC) - timedelta(hours=1)
    controller.registry_auth.record("ghcr.io", True)  # newer than what the worker saw: kept
    pod = Worker(Settings())
    pod.registry_auth.record("docker.io", False, "HTTP 401")
    pod.registry_auth._results["ghcr.io"] = AuthResult("ghcr.io", False, old, "old refusal")
    async with _serving(runner):
        running = asyncio.create_task(runner.run(CheckImagesTask([])))
        [task] = await bus.receive(task_stream("worker"), TASK_GROUP, "pod", block=1)
        answer = pack({"result": encode_result(CheckImagesResult([], pod.registry_auth.all()))})
        await bus.send("results", answer, id=task.fields["id"], epoch=runner.epoch, source="pod")
        result = await running
    assert [a.host for a in result.registry_auth] == ["docker.io", "ghcr.io"]
    assert controller.registry_auth.get("docker.io").message == "HTTP 401"
    assert controller.registry_auth.get("ghcr.io").ok  # the latest answer wins
    # The worker side sends what it saw with each check
    assert (await pod.execute(CheckImagesTask([]))).registry_auth == pod.registry_auth.all()


async def test_the_controller_waits_for_valkey_at_startup(monkeypatch, caplog, bus):
    slept, real_sleep, real_reset = [], asyncio.sleep, bus.reset
    failures = iter([True, True])

    async def sleep(delay):
        slept.append(delay)
        await real_sleep(0)

    async def reset(*args):
        if next(failures, False):  # Valkey still starting
            raise RedisConnectionError("connection refused")
        await real_reset(*args)

    monkeypatch.setattr(bus, "reset", reset)
    runner = _runner(Worker(Settings()), set(), bus)
    monkeypatch.setattr(asyncio, "sleep", sleep)
    async with _serving(runner):
        pass
    assert "cannot prepare the task streams in Valkey, the scans wait (connection refused): trying again in 1s" in caplog.text
    assert slept[:2] == [1, 2]


async def test_the_publisher_waits_for_valkey_at_startup(monkeypatch, caplog, bus):
    slept, real_sleep, real_reset = [], asyncio.sleep, bus.reset
    failures = iter([True])

    async def sleep(delay):
        slept.append(delay)
        await real_sleep(0)

    async def reset(*args):
        if next(failures, False):  # Valkey still starting
            raise RedisConnectionError("connection refused")
        await real_reset(*args)

    monkeypatch.setattr(bus, "reset", reset)
    _, _, publisher = _controller(bus)
    monkeypatch.setattr(asyncio, "sleep", sleep)
    async with _publishing(publisher):
        pass
    assert "cannot prepare the actions stream in Valkey, the ui processes wait (connection refused)" in caplog.text
    assert 1 in slept  # the first delay of RETRY
