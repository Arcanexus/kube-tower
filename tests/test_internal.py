import asyncio
import logging
from datetime import UTC, datetime

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from kube_tower import internal
from kube_tower import worker as worker_module
from kube_tower.config import Settings
from kube_tower.internal import TaskPuller, create_internal_app
from kube_tower.main import create_app
from kube_tower.models import ImageRef, ImageReport, Status, Usage, VulnerabilityReport, encode
from kube_tower.scanner import Scanner
from kube_tower.tasks import CheckImagesTask, CollectTask, QueueRunner, ScanVulnerabilitiesTask, TaskFailed
from kube_tower.trivy import scans_failed
from kube_tower.worker import Worker
from test_scanner import TwoClusters, fakes  # noqa: F401 - fixture

TOKEN = "secret"


def _settings(roles):
    settings = Settings(roles=roles)
    settings.internal.controller_url = "http://controller:8081"
    return settings


def _puller(monkeypatch, roles=("worker", "trivy"), registry=None):
    monkeypatch.setenv("KUBE_TOWER_INTERNAL_TOKEN", TOKEN)
    settings = _settings(list(roles))
    return TaskPuller(settings, Worker(settings), list(roles), registry or TwoClusters())


def _client(runner, puller, token=TOKEN):
    transport = httpx.ASGITransport(create_internal_app(runner, TOKEN))
    return httpx.AsyncClient(transport=transport, base_url=puller.url, headers={"Authorization": f"Bearer {token}"})


async def _until_done(task, puller, http):
    while not task.done():
        await puller.pull(http, wait=0.05)
    return task.result()


async def test_distributed_scan_through_the_internal_api(fakes, monkeypatch):  # noqa: F811 - fixture
    settings = _settings(["ui", "controller"])
    scanner = Scanner(settings, TwoClusters())
    scanner.pull_secrets = {"ghcr.io": ("user", "token")}  # sent with each task
    scanner.runner = runner = QueueRunner(scanner.worker, set(), context=lambda: {"pull_secrets": encode(scanner.pull_secrets)})
    runner.loop = asyncio.get_running_loop()  # the scans run in their own threads and loops
    puller = _puller(monkeypatch)
    async with _client(runner, puller) as http:
        snap = await _until_done(asyncio.create_task(scanner.scan()), puller, http)
    # Every task ran in the puller: the collect tasks with the clusters it read itself.
    assert sorted(puller.worker.clusters) == ["a", "b"]
    assert puller.worker.pull_secrets == {"ghcr.io": ("user", "token")}
    assert [str(r.image) for r in snap.images] == ["docker.io/library/nginx:1.25"]
    assert [u.cluster for u in snap.images[0].usages] == ["a", "b"] and snap.images[0].status == Status.OUTDATED
    assert [c.status for c in snap.charts] == [Status.UP_TO_DATE, Status.UP_TO_DATE]
    assert not runner.queue and not runner.pulled


async def test_internal_api_token_and_unknown_tasks(monkeypatch):
    runner = QueueRunner(Worker(Settings()), set())
    puller = _puller(monkeypatch)
    async with _client(runner, puller, token="wrong") as http:
        assert (await http.post("/internal/v1/tasks/next", json={"roles": ["worker"]})).status_code == 401
    async with _client(runner, puller) as http:
        assert (await http.get("/healthz")).json() == {"status": "ok"}
        assert (await http.post("/internal/v1/tasks/next", json={"roles": ["worker"], "wait": 0})).status_code == 204
        assert (await http.post("/internal/v1/tasks/collect-9/result", json={"result": {}})).status_code == 404


async def test_queue_runner(monkeypatch, caplog):
    worker = Worker(Settings())
    runner = QueueRunner(worker, {"trivy"}, timeout=0)
    # a role of this process: run here
    assert (await runner.run(ScanVulnerabilitiesTask([]))).vulnerabilities == []
    # not answered in time: given to the next process asking
    waiting = asyncio.create_task(runner.run(CollectTask("a")))
    await asyncio.sleep(0)
    assert runner.waiting() == {"worker": 1}
    assert await runner.next({"trivy"}, 0) is None  # not for this role
    first = await runner.next({"worker"}, 0)
    again = await runner.next({"worker"}, 0)
    assert first["id"] == again["id"] == "collect-1" and first["task"] == {
        "cluster": "a",
        "images": True,
        "charts": True,
        "operator_reports": True,
        "image_name": None,
    }
    assert "task collect-1 not answered within 0s: given to another process" in caplog.text
    assert runner.fail("collect-1", "boom") and not runner.complete("collect-1", {})
    with pytest.raises(TaskFailed, match="task collect-1 failed: boom"):
        await waiting
    # the scan is cancelled: the task is forgotten
    waiting = asyncio.create_task(runner.run(CheckImagesTask([])))
    await asyncio.sleep(0)
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    assert not runner.queue
    # a pull waits for the next task
    pulling = asyncio.create_task(runner.next({"worker"}, 5))
    await asyncio.sleep(0)
    waiting = asyncio.create_task(runner.run(CheckImagesTask([])))
    pulled = await pulling
    assert runner.complete(pulled["id"], {"images": []}) and (await waiting).images == []


async def test_puller_errors(monkeypatch, caplog):
    slept, real_sleep = [], asyncio.sleep

    async def sleep(delay):
        if delay:
            slept.append(delay)
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", sleep)
    runner = QueueRunner(Worker(Settings()), set())
    trivy = _puller(monkeypatch, roles=["trivy"])

    # a task for another role, or that fails: the error goes back to the controller
    async with _client(runner, trivy) as http:
        task = asyncio.create_task(runner.run(CheckImagesTask([])))
        await asyncio.sleep(0)
        runner.queue[0].role = "trivy"  # sent to the wrong process
        assert await trivy.pull(http, wait=0)
        with pytest.raises(TaskFailed, match="ValueError: a worker task was sent to a process with roles trivy"):
            await task

    # the controller cannot be reached: the next tries wait longer
    def unreachable(request):
        raise httpx.ConnectError("connection refused")

    async with httpx.AsyncClient(transport=httpx.MockTransport(unreachable), base_url=trivy.url) as http:
        assert not await trivy.pull(http) and not await trivy.pull(http)
        image = ImageReport(ImageRef("docker.io", "library/nginx", "1.25"))
        sent = {"id": "scan-vulnerabilities-1", "kind": "scan-vulnerabilities", "task": {"images": [encode(image)]}}
        await trivy.answer(http, sent)
    assert slept[:2] == [1, 2] and slept[2:] == list(internal.RETRY)
    assert "cannot reach the controller at http://controller:8081" in caplog.text
    assert "result of task scan-vulnerabilities-1 lost" in caplog.text

    # the result came too late
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)), base_url=trivy.url) as http:
        await trivy.answer(http, {"id": "scan-vulnerabilities-2", "kind": "scan-vulnerabilities", "task": {"images": []}})
    assert "result of task scan-vulnerabilities-2 not needed anymore" in caplog.text


def test_processes_by_role(monkeypatch):
    monkeypatch.setenv("KUBE_TOWER_INTERNAL_TOKEN", TOKEN)
    # worker or trivy alone: no UI, API or metrics, only the probes
    client = TestClient(create_app(_settings(["worker", "trivy"]), background=False))
    assert client.get("/healthz").status_code == client.get("/readyz").status_code == 200
    assert client.get("/").status_code == client.get("/api/snapshot").status_code == 404
    # ui and controller: the other roles get their tasks through the queue
    app = create_app(_settings(["ui", "controller"]), background=False)
    assert isinstance(app.state.scanner.runner, QueueRunner) and app.state.scanner.runner.local_roles == set()
    assert TestClient(app).get("/healthz").status_code == 200


def test_processes_run_their_roles(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="kube_tower")
    monkeypatch.setenv("KUBE_TOWER_INTERNAL_TOKEN", TOKEN)
    ran = []

    async def run_forever(self):
        ran.append(type(self).__name__)

    async def serve(self, sockets=None):
        ran.append("internal API")

    monkeypatch.setattr(Scanner, "run_forever", run_forever)
    monkeypatch.setattr(TaskPuller, "run_forever", run_forever)
    monkeypatch.setattr(uvicorn.Server, "serve", serve)
    settings = _settings(["controller", "worker"])
    settings.internal.port = 0
    with TestClient(create_app(settings)):
        pass
    with TestClient(create_app(_settings(["trivy"]))):
        pass
    assert ran == ["Scanner", "internal API", "TaskPuller"]
    assert "internal API listening on port 0" in caplog.text


async def test_distributed_scan_in_batches(fakes, monkeypatch):  # noqa: F811 - fixture
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
    scanner.runner = runner = QueueRunner(scanner.worker, set())
    runner.loop = asyncio.get_running_loop()
    # two processes share the tasks
    pullers = [_puller(monkeypatch), _puller(monkeypatch)]
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

    task = asyncio.create_task(scanned())
    async with _client(runner, pullers[0]) as http:
        while not task.done():
            await asyncio.gather(*(p.pull(http, wait=0.05) for p in pullers))
        snap = task.result()
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
