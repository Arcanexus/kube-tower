import asyncio
import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient

from kube_tower import administration as administration_module
from kube_tower import internal
from kube_tower import processes as processes_module
from kube_tower import worker as worker_module
from kube_tower.administration import Administration
from kube_tower.backend import UNREACHABLE, LocalBackend, RemoteBackend
from kube_tower.config import Settings
from kube_tower.internal import Reporter, TaskPuller, create_internal_app
from kube_tower.logbuffer import LogBuffer
from kube_tower.main import create_app
from kube_tower.models import ChartReport, ImageRef, ImageReport, Snapshot, Status, Usage, VulnerabilityReport, encode
from kube_tower.processes import Processes
from kube_tower.scanner import Scanner
from kube_tower.tasks import CheckImagesTask, CollectTask, QueueRunner, ScanVulnerabilitiesTask, TaskFailed
from kube_tower.trivy import TrivyStatus, scans_failed
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
    # controller alone: the metrics of the snapshot, no UI
    client = TestClient(create_app(_settings(["controller"]), background=False))
    assert client.get("/metrics").status_code == 200 and client.get("/").status_code == 404
    # ui alone: the pages show what the controller sends, no metrics (they would be duplicated)
    app = create_app(_settings(["ui"]), background=False)
    assert isinstance(app.state.backend, RemoteBackend)
    client = TestClient(app)
    assert client.get("/readyz").status_code == 503  # no snapshot from the controller yet
    assert client.get("/metrics").status_code == 404


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


def _controller(settings=None):
    """A controller process with a snapshot, and its internal API."""
    scanner = Scanner(settings or _settings(["controller", "worker", "trivy"]), TwoClusters())
    image = ImageReport(ImageRef("docker.io", "library/nginx", "1.25"), [Usage("a", "Pod", "default", "web")])
    chart = ChartReport("a", "app", "argocd", "app", "https://charts.example.com", "1.0.0", "helm")
    scanner.snapshot = Snapshot(images=[image], charts=[chart], started_at=datetime.now(UTC), finished_at=datetime.now(UTC))
    backend = LocalBackend(scanner, Administration(scanner))
    return scanner, create_internal_app(QueueRunner(scanner.worker, set()), TOKEN, backend)


async def test_ui_process_reads_the_controller(monkeypatch):
    monkeypatch.setenv("KUBE_TOWER_INTERNAL_TOKEN", TOKEN)
    scanner, app = _controller()
    remote = RemoteBackend(_settings(["ui"]), transport=httpx.ASGITransport(app))
    await remote.refresh()
    assert [str(r.image) for r in remote.snapshot.images] == ["docker.io/library/nginx:1.25"]
    assert remote.state.revision == scanner.revision and not remote.running and not remote.locked
    assert remote.scans_total == {"success": 0, "failure": 0} and remote.activities() == []
    assert remote.trivy_binary == "trivy" and remote.trivy_cached == 0 and remote.admin_running == set()
    assert remote.registry_credentials(Settings()) == ([], {})
    report = remote.snapshot.images[0]
    assert remote.same_name_images(report) == [report] and remote.can_rescan_vulnerabilities(report)
    assert remote.failed_items() == ([], [], [])
    # the snapshot is sent again only when it changed (or while something runs)
    snapshot = remote.snapshot
    await remote.refresh()
    assert remote.snapshot is snapshot
    scanner.snapshot = Snapshot(finished_at=datetime.now(UTC))
    await remote.refresh()
    assert remote.snapshot.images == []

    # the pages of a ui process
    ui = create_app(_settings(["ui"]), background=False)
    ui.state.backend = remote
    scanner.snapshot = Snapshot(images=[report], started_at=datetime.now(UTC), finished_at=datetime.now(UTC))
    await remote.refresh()
    client = TestClient(ui)
    assert client.get("/readyz").status_code == 200
    assert "library/nginx" in client.get("/images").text
    assert client.get("/api/snapshot").json()["images"][0]["image"]["ref"] == "docker.io/library/nginx:1.25"


async def test_ui_process_actions(monkeypatch, fakes):  # noqa: F811 - fixture
    monkeypatch.setenv("KUBE_TOWER_INTERNAL_TOKEN", TOKEN)
    monkeypatch.setattr(Administration, "test_connectivity", lambda self: None)  # no network
    scanner, app = _controller()
    remote = RemoteBackend(_settings(["ui"]), transport=httpx.ASGITransport(app))
    await remote.refresh()
    image, chart = remote.snapshot.images[0], remote.snapshot.charts[0]
    assert await remote.rescan_chart(chart) is None
    assert ("chart", "a", "argocd", "app", "app") in remote.rescanning  # the state is read again at once
    await asyncio.gather(*scanner._rescans)
    assert await remote.rescan_image(image, vulnerabilities=False) is None
    await asyncio.gather(*scanner._rescans)
    assert await remote.retry_failed() == "nothing failed in the last scan"
    assert await remote.clear_trivy_cache() == 0
    assert (await remote.refresh_trivy_status()).message == "trivy binary 'trivy' not found"
    assert "binary 'trivy' is not found" in await remote.update_trivy_db() and await remote.test_connectivity() is None
    assert await remote.trigger() is True
    await scanner._task
    # gone from the controller meanwhile
    gone = ChartReport("b", "app", "argocd", "gone", "https://charts.example.com", "1.0.0", "helm")
    assert "not found in the last scan" in await remote.rescan_chart(gone)
    gone = ImageReport(ImageRef("docker.io", "library/gone", "1"))
    assert "not found in the last scan" in await remote.rescan_image(gone)
    unknown = await remote.http.post("/internal/v1/actions/reboot")
    assert unknown.status_code == 404 and unknown.json() == {"detail": "unknown action 'reboot'"}


async def test_ui_process_without_controller(monkeypatch, caplog):
    monkeypatch.setenv("KUBE_TOWER_INTERNAL_TOKEN", TOKEN)

    def unreachable(request):
        raise httpx.ConnectError("connection refused")

    remote = RemoteBackend(_settings(["ui"]), transport=httpx.MockTransport(unreachable))
    await remote.refresh()
    await remote.refresh()
    assert caplog.text.count("the controller cannot be reached") == 1  # once until it answers again
    assert remote.snapshot.finished_at is None
    assert await remote.trigger() is False and await remote.clear_trivy_cache() == 0
    assert await remote.retry_failed() == UNREACHABLE.format("connection refused")
    assert (await remote.refresh_trivy_status()).message == "the controller cannot be reached"
    _, app = _controller()
    transport = httpx.ASGITransport(app)
    remote.http = httpx.AsyncClient(transport=transport, base_url="http://controller:8081", headers=remote.http.headers)
    await remote.refresh()
    assert "the controller answers again" in caplog.text and remote.snapshot.finished_at is not None


async def test_trivy_administration_in_trivy_processes(monkeypatch, caplog):
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
    scanner.runner = runner = QueueRunner(scanner.worker, {"worker"}, context=lambda: {"trivy": administration.generations})
    runner.loop = asyncio.get_running_loop()
    backend = LocalBackend(scanner, administration)
    assert backend.trivy_remote and backend.trivy_available and backend.trivy_cached == 0  # unknown yet
    trivy = _puller(monkeypatch, roles=["trivy"])
    trivy.worker.trivy.cache["docker.io/library/nginx:1.25"] = VulnerabilityReport("trivy", datetime.now(UTC))
    async with _client(runner, trivy) as http:
        # the status of the trivy process that answered
        status = await _until_done(asyncio.create_task(backend.refresh_trivy_status()), trivy, http)
        assert status.version == "0.60.0" and backend.trivy_status is status and backend.trivy_cached == 1
        # a database update runs in one trivy process, the others refresh theirs before their next task
        assert await backend.update_trivy_db() is None and administration.generations == {"db": 1, "cache": 0}
        await _until_done(next(iter(administration._tasks)), trivy, http)
        assert downloads == [0] and "database refreshed in one trivy process" in backend.trivy_message
        # the cache is forgotten by each trivy process at its next task
        assert await backend.clear_trivy_cache() == -1 and administration.generations == {"db": 1, "cache": 1}
        await _until_done(asyncio.create_task(backend.refresh_trivy_status()), trivy, http)
        assert trivy.worker.trivy.cache == {} and backend.trivy_cached == 0
        assert "Trivy results cache cleared (1 image(s)), as asked on the Administration page" in caplog.text
        administration.generations["db"] += 1
        await _until_done(asyncio.create_task(backend.refresh_trivy_status()), trivy, http)
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
    async with _client(runner, trivy) as http:
        assert await backend.update_trivy_db() is None
        await _until_done(next(iter(administration._tasks)), trivy, http)
    assert backend.trivy_message == "cannot download the Trivy database: 403"


async def test_logs_and_state_of_the_remote_processes(monkeypatch, fakes):  # noqa: F811 - fixture
    monkeypatch.setenv("KUBE_TOWER_INTERNAL_TOKEN", TOKEN)
    monkeypatch.setenv("POD_NAME", "kube-tower-controller-0")
    scanner = Scanner(_settings(["ui", "controller"]), TwoClusters())
    scanner.runner = runner = QueueRunner(scanner.worker, set())
    runner.loop = asyncio.get_running_loop()
    buffer = LogBuffer(source="kube-tower-controller-0", roles=["ui", "controller"])
    buffer.emit(logging.LogRecord("kube_tower.scanner", logging.INFO, "", 0, "scan finished", None, None))
    backend = LocalBackend(scanner, Administration(scanner), buffer, Processes(["ui", "controller"]))
    app = create_internal_app(runner, TOKEN, backend)
    worker = _puller(monkeypatch)
    worker.source = "kube-tower-worker-1"
    seen = []
    original = backend.process_registry.task

    def task(name, kind=""):
        seen.append((name, kind))
        original(name, kind)

    backend.process_registry.task = task
    transport = httpx.ASGITransport(app)
    async with httpx.AsyncClient(transport=transport, base_url=worker.url, headers={"Authorization": f"Bearer {TOKEN}"}) as http:
        await _until_done(asyncio.create_task(scanner.scan()), worker, http)
    # the controller knows which task each process runs
    assert ("kube-tower-worker-1", "collect") in seen and seen[-1] == ("kube-tower-worker-1", "")

    # a worker reports its log lines, kept by the controller with the pod and its roles
    monkeypatch.setenv("POD_NAME", "kube-tower-worker-1")
    worker_buffer = LogBuffer(source="kube-tower-worker-1", roles=["worker"])
    worker_buffer.emit(
        logging.LogRecord("kube_tower.collectors.images", logging.WARNING, "", 0, "[a] cannot list CronJob", None, None)
    )
    reporter = Reporter(_settings(["worker"]), worker_buffer, ["worker"], transport=transport)
    assert await reporter.report()
    remote = buffer.since(1)
    assert [(line.source, line.roles, line.level, line.message) for line in remote] == [
        ("kube-tower-worker-1", ["worker"], "WARNING", "[a] cannot list CronJob")
    ]
    assert await reporter.report() and buffer.since(remote[-1].seq) == []  # only the new lines are sent
    processes = backend.processes()
    assert [(p.name, p.roles, p.state) for p in processes] == [
        ("kube-tower-controller-0", ["ui", "controller"], "active"),
        ("kube-tower-worker-1", ["worker"], "ok"),
    ]
    assert processes[1].version == "dev" and processes[1].task == "" and processes[1].alive

    # a standby controller reports as such; once active it sends nothing (it keeps its own lines)
    monkeypatch.setenv("POD_NAME", "kube-tower-controller-1")
    standby_state = ["standby"]
    standby = Reporter(_settings(["controller"]), LogBuffer(), ["controller"], lambda: standby_state[0], transport=transport)
    assert await standby.report()
    assert backend.processes()[1].state == "standby"
    standby_state[0] = None
    standby.buffer.emit(logging.LogRecord("kube_tower.scanner", logging.INFO, "", 0, "now active", None, None))
    assert not await standby.report() and standby.sent == standby.buffer.seq

    # processes not heard of for a while are lost, then forgotten
    later = datetime.now(UTC) + timedelta(seconds=processes_module.LOST + 1)
    monkeypatch.setattr(processes_module, "_now", lambda: later)
    assert [p.state for p in backend.processes()] == ["active", "lost", "lost"]
    much_later = datetime.now(UTC) + timedelta(seconds=processes_module.FORGET + 1)
    monkeypatch.setattr(processes_module, "_now", lambda: much_later)
    assert [p.name for p in backend.processes()] == ["kube-tower-controller-0"]

    # the ui processes get the processes and the lines of every process
    ui_backend = RemoteBackend(_settings(["ui"]), transport=transport)
    monkeypatch.setattr(processes_module, "_now", lambda: datetime.now(UTC))
    await reporter.report()
    await ui_backend.refresh()
    assert [p.name for p in ui_backend.processes()] == ["kube-tower-controller-0", "kube-tower-worker-1"]
    lines = await ui_backend.log_lines()
    assert [(line.source, line.message) for line in lines] == [
        ("kube-tower-controller-0", "scan finished"),
        ("kube-tower-worker-1", "[a] cannot list CronJob"),
    ]
    assert await ui_backend.log_lines(lines[-1].seq) == []
    ui = create_app(_settings(["ui"]), background=False)
    ui.state.backend = ui_backend
    assert "scan finished" in TestClient(ui).get("/logs").text

    ui_backend.http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503)), base_url="http://c")
    assert await ui_backend.log_lines() == []
    reporter.http = ui_backend.http
    assert not await reporter.report()  # the controller is away: tried again at the next report

    # a process that stops says so: gone at once, not shown as lost
    reporter.http = httpx.AsyncClient(transport=transport, base_url="http://c", headers={"Authorization": f"Bearer {TOKEN}"})
    monkeypatch.setattr(internal, "HEARTBEAT", 0.01)
    running = asyncio.create_task(reporter.run_forever())
    await asyncio.sleep(0.05)
    assert "kube-tower-worker-1" in [p.name for p in backend.processes()]
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert [p.name for p in backend.processes()] == ["kube-tower-controller-0"]


async def test_large_results_and_states_stay_off_the_event_loop(fakes, monkeypatch):  # noqa: F811 - fixture
    import threading

    from kube_tower import tasks as tasks_module

    on_loop = []
    decode_result = tasks_module.decode_result

    def spy(kind, data):
        on_loop.append(threading.current_thread() is threading.main_thread())
        return decode_result(kind, data)

    monkeypatch.setattr(tasks_module, "decode_result", spy)
    settings = _settings(["ui", "controller"])
    scanner = Scanner(settings, TwoClusters())
    scanner.runner = runner = QueueRunner(scanner.worker, set())
    runner.loop = asyncio.get_running_loop()
    backend = LocalBackend(scanner, Administration(scanner))
    puller = _puller(monkeypatch)
    transport = httpx.ASGITransport(create_internal_app(runner, TOKEN, backend))
    async with httpx.AsyncClient(transport=transport, base_url=puller.url, headers={"Authorization": f"Bearer {TOKEN}"}) as http:
        await _until_done(asyncio.create_task(scanner.scan()), puller, http)
        # the results of the worker were decoded in threads, never on the event loop of the internal API
        assert on_loop and not any(on_loop)
        # the snapshot is sent only to the UIs that do not have its revision, even while something runs
        monkeypatch.setattr(LocalBackend, "activities", lambda self: ["a rescan"])
        fresh = await http.post("/internal/v1/state", json={"revision": -1})
        assert fresh.headers["content-type"] == "application/json" and fresh.json()["snapshot"]["images"]
        same = await http.post("/internal/v1/state", json={"revision": scanner.revision})
        assert same.json()["snapshot"] is None
