"""CPU and memory recommendations of krr: what kube-tower gives krr, where it runs, what it answers."""

import asyncio
import base64
import importlib.util
import json
import sys
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
import respx
import yaml
from kubernetes import client

from kube_tower import resources
from kube_tower.clusters import Cluster, api_client_from_argocd_config
from kube_tower.config import PrometheusSettings, ResourcesSettings, Settings
from kube_tower.models import ClusterStatus, Fit, ResourceRecommendation, ResourceScan, ResourceValue, Snapshot
from kube_tower.resources import KrrError, error_message, krr_args, kubeconfig_of, parse_result, recommend
from kube_tower.scanner import Scanner
from kube_tower.scope import scope_snapshot
from kube_tower.tasks import ResourcesResult, ResourcesTask, decode_result, encode_result
from kube_tower.worker import Worker

DATA = Path(__file__).parent / "data"
SERVER = Path(__file__).parents[1] / "charts" / "kube-tower" / "files" / "krr-server.py"
RESULT = json.loads((DATA / "krr-result.json").read_text())


def _server():
    spec = importlib.util.spec_from_file_location("krr_server", SERVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cluster(name="prod", raw=None, tmp_path=None):
    files: list[str] = []
    api = api_client_from_argocd_config("https://prod:6443", raw or {"bearerToken": "tok"}, files)
    return Cluster(name, "https://prod:6443", "secret", api, files)


# What krr answers


def test_parse_result_of_krr():
    recommendations, scan = parse_result("prod", RESULT)
    api, worker = recommendations
    assert api.key == ("prod", "shop", "Deployment", "api", "app")
    assert api.cpu_request == ResourceValue(0.5, 0.05, True, Fit.WARNING)
    assert api.cpu_limit == ResourceValue(None, None, True, Fit.GOOD)  # no CPU limit, none advised
    assert api.memory_limit == ResourceValue(1073741824.0, 209715200.0, True, Fit.CRITICAL)
    assert api.fit == Fit.CRITICAL and api.pods == 1 and not api.hpa and api.info == ""
    assert api.memory_request.change == 209715200.0 - 536870912.0
    # not enough data: no value, unknown
    assert worker.cpu_request == ResourceValue(None, None, False, Fit.UNKNOWN) and worker.cpu_request.change is None
    assert worker.hpa and worker.info == "Not enough data" and worker.fit == Fit.GOOD
    assert scan.cluster == "prod" and scan.strategy == "simple" and scan.score == 50
    assert scan.settings == {"history_duration": "336"} and scan.message is None and scan.scanned_at


def test_parse_result_plain_values_and_empty():
    data = {
        "scans": [{"object": {"name": "a", "allocations": {"requests": {"cpu": 1}}}, "recommended": {"requests": {"cpu": 2}}}]
    }
    (r,), scan = parse_result("c", data)
    assert r.cpu_request == ResourceValue(1.0, 2.0, True, Fit.UNKNOWN) and r.fit == Fit.UNKNOWN
    assert parse_result("c", {})[1].score is None


def test_results_go_through_valkey():
    recommendations, scan = parse_result("prod", RESULT)
    result = ResourcesResult(recommendations, scan)
    assert decode_result("resources", json.loads(json.dumps(encode_result(result)))) == result


# What krr is given


def test_kubeconfig_of_a_cluster_with_token_and_ca(tmp_path):
    ca = base64.b64encode(b"-----BEGIN CERTIFICATE-----\n").decode()
    cluster = _cluster(raw={"bearerToken": "tok", "tlsClientConfig": {"caData": ca, "serverName": "api.prod"}})
    data = yaml.safe_load(kubeconfig_of(cluster))
    assert data["current-context"] == "prod"
    assert data["clusters"][0]["cluster"] == {
        "server": "https://prod:6443",
        "certificate-authority-data": ca,
        "tls-server-name": "api.prod",
    }
    assert data["users"][0]["user"] == {"token": "tok"}
    cluster.close()


def test_kubeconfig_of_a_cluster_with_client_certificate_basic_auth_insecure():
    cert, key = base64.b64encode(b"cert").decode(), base64.b64encode(b"key").decode()
    raw = {"username": "u", "password": "p:w", "tlsClientConfig": {"insecure": True, "certData": cert, "keyData": key}}
    data = yaml.safe_load(kubeconfig_of(_cluster(raw=raw)))
    assert data["clusters"][0]["cluster"] == {"server": "https://prod:6443", "insecure-skip-tls-verify": True}
    assert data["users"][0]["user"] == {
        "client-certificate-data": cert,
        "client-key-data": key,
        "username": "u",
        "password": "p:w",
    }


def test_kubeconfig_refreshes_the_token_first():
    cfg = client.Configuration()
    cfg.host = "https://kubernetes.default.svc"
    cfg.api_key = {"authorization": "old"}
    cfg.api_key_prefix = {"authorization": "Bearer"}
    cfg.refresh_api_key_hook = lambda c: c.api_key.update(authorization="new")
    cluster = Cluster("in-cluster", cfg.host, "in-cluster", client.ApiClient(cfg))
    assert yaml.safe_load(kubeconfig_of(cluster))["users"][0]["user"] == {"token": "new"}


def test_krr_args(tmp_path, monkeypatch):
    monkeypatch.setenv("PROM_AUTH", "Bearer secret")
    header = tmp_path / "header"
    header.write_text("Basic abc\n")
    settings = ResourcesSettings(
        namespaces=["shop", "web"],
        args=["--history_duration", "168"],
        prometheus=[
            PrometheusSettings(
                clusters=["prod-*"], url="http://thanos:9090", cluster_label="cluster", auth_header_env="PROM_AUTH"
            ),
            PrometheusSettings(
                clusters=["edge"],
                url="http://p:9090",
                cluster_label="k8s",
                cluster_value="edge-1",
                headers={"X-Scope-OrgID": "a"},
                auth_header_file=str(header),
            ),
        ],
    )
    assert krr_args(settings, "prod-eu") == [
        "--namespace", "shop", "--namespace", "web",
        "--prometheus-url", "http://thanos:9090",
        "--prometheus-auth-header", "Bearer secret",
        "--prometheus-label", "cluster", "--prometheus-cluster-label", "prod-eu",
        "--history_duration", "168",
    ]  # fmt: skip
    assert krr_args(settings, "edge")[4:] == [
        "--prometheus-url", "http://p:9090",
        "--prometheus-auth-header", "Basic abc",
        "--prometheus-headers", "X-Scope-OrgID: a",
        "--prometheus-label", "k8s", "--prometheus-cluster-label", "edge-1",
        "--history_duration", "168",
    ]  # fmt: skip
    # no entry: krr finds Prometheus in the cluster
    assert krr_args(settings, "staging") == ["--namespace", "shop", "--namespace", "web", "--history_duration", "168"]
    settings.prometheus[1].auth_header_file = str(tmp_path / "missing")
    with pytest.raises(KrrError, match="authHeaderFile"):
        krr_args(settings, "edge")


# Where krr runs


def test_error_message_of_krr():
    message = error_message((DATA / "krr-stderr.txt").read_text())
    assert message.startswith("An unexpected error occurred: urllib3.exceptions.MaxRetryError: HTTPSConnectionPool")
    assert error_message("") == "krr failed" and error_message("some\nlast line") == "last line"
    assert len(error_message("ERROR " + "x" * 900)) == 500
    # krr-server.py gives the same message
    assert _server().error_message((DATA / "krr-stderr.txt").read_text()) == message


FAKE_KRR = """#!{python}
import json, sys
args = sys.argv[1:]
out = args[args.index("--fileoutput") + 1]
assert args[0] == "simple" and "--kubeconfig" in args and args[args.index("--formatter") + 1] == "json"
if "--fail" in args:
    sys.stderr.write("[10:00:00] ERROR    Prometheus not found    runner.py:1\\n")
    sys.exit(1)
if "--sleep" in args:
    import time; time.sleep(5)
json.dump({{"scans": [], "strategy": {{"name": "simple", "settings": {{}}}}, "score": 0, "args": args}}, open(out, "w"))
"""


@pytest.fixture
def fake_krr(tmp_path):
    path = tmp_path / "krr"
    path.write_text(FAKE_KRR.format(python=sys.executable))
    path.chmod(0o755)
    return str(path)


async def test_run_local(fake_krr):
    settings = ResourcesSettings(binary=fake_krr, timeout=2)
    data = await resources.run_local(settings, "kubeconfig", ["--namespace", "x"])
    assert data["args"][-2:] == ["--namespace", "x"] and "--logtostderr" in data["args"]
    with pytest.raises(KrrError, match="Prometheus not found"):
        await resources.run_local(settings, "kubeconfig", ["--fail"])
    with pytest.raises(KrrError, match="within 1s"):
        await resources.run_local(ResourcesSettings(binary=fake_krr, timeout=1), "kubeconfig", ["--sleep"])
    with pytest.raises(KrrError, match="krr.enabled"):
        await resources.run_local(ResourcesSettings(binary="no-such-krr"), "kubeconfig", [])


@respx.mock
async def test_run_remote(monkeypatch, tmp_path):
    token = tmp_path / "token"
    token.write_text("sa-token\n")
    monkeypatch.setattr(resources, "SA_TOKEN", str(token))
    settings = ResourcesSettings(server_url="http://krr:8080/", timeout=60)
    route = respx.post("http://krr:8080/run").mock(return_value=httpx.Response(200, json={"result": RESULT}))
    assert await resources.run_remote(settings, "kc", ["-n", "x"]) == RESULT
    sent = route.calls.last.request
    assert sent.headers["Authorization"] == "Bearer sa-token"
    assert json.loads(sent.content) == {"strategy": "simple", "kubeconfig": "kc", "args": ["-n", "x"], "timeout": 60}
    route.mock(return_value=httpx.Response(502, json={"error": "Prometheus not found"}))
    with pytest.raises(KrrError, match="answered 502: Prometheus not found"):
        await resources.run_remote(settings, "kc", [])
    route.mock(return_value=httpx.Response(503, text="busy"))
    with pytest.raises(KrrError, match="answered 503: busy"):
        await resources.run_remote(settings, "kc", [])
    route.mock(side_effect=httpx.ConnectError("refused"))
    monkeypatch.setattr(resources, "SA_TOKEN", str(tmp_path / "none"))
    with pytest.raises(KrrError, match="unreachable: ConnectError refused"):
        await resources.run_remote(settings, "kc", [])


async def test_recommend(monkeypatch):
    async def answer(settings, kubeconfig, args):
        assert "token: tok" in kubeconfig
        return {**RESULT, "errors": [{"error": "no metrics for job x"}]}

    monkeypatch.setattr(resources, "run_remote", answer)
    settings = ResourcesSettings(server_url="http://krr:8080", prometheus=[PrometheusSettings(url="http://prom:9090")])
    found, scan = await recommend(settings, _cluster())
    assert len(found) == 2 and scan.prometheus == "http://prom:9090" and scan.message == "no metrics for job x"

    async def fail(settings, kubeconfig, args):
        raise KrrError("Prometheus not found")

    monkeypatch.setattr(resources, "run_remote", fail)
    found, scan = await recommend(settings, _cluster())
    assert found == [] and scan.message == "Prometheus not found" and scan.strategy == "simple" and scan.score is None


async def test_worker_runs_the_resources_task(monkeypatch):
    async def answer(settings, cluster):
        return [], ResourceScan(cluster.name, score=100)

    monkeypatch.setattr("kube_tower.worker.recommend", answer)
    worker = Worker(Settings())
    worker.clusters = {"prod": _cluster()}
    assert (await worker.execute(ResourcesTask("prod"))).scan.score == 100
    unknown = await worker.execute(ResourcesTask("gone"))
    assert unknown.recommendations == [] and "unknown cluster" in unknown.scan.message


# The scans


def _recommendation(cluster: str, fit=Fit.WARNING) -> ResourceRecommendation:
    return ResourceRecommendation(cluster, "shop", "Deployment", "api", "app", ResourceValue(0.5, 0.1, True, fit), fit=fit)


class FakeRegistry:
    def __init__(self, names):
        self.clusters = [Cluster(n, f"https://{n}", "secret", None) for n in names]

    def discover(self):
        return self.clusters, [ClusterStatus(c.name, c.server, "secret", True, "v1.30.0") for c in self.clusters]


async def test_scan_asks_krr_and_reuses_fresh_results(monkeypatch):
    asked = []

    async def answer(settings, cluster):
        asked.append(cluster.name)
        await asyncio.sleep(0)
        if cluster.name == "edge":
            return [], ResourceScan("edge", datetime.now(UTC), message="Prometheus not found")
        return [_recommendation(cluster.name)], ResourceScan(cluster.name, datetime.now(UTC), score=70)

    monkeypatch.setattr("kube_tower.worker.recommend", answer)
    monkeypatch.setattr("kube_tower.collectors.images.ImageInventory.collect", lambda self, cluster: [])
    settings = Settings()
    settings.images.enabled = settings.helm.enabled = settings.vulnerabilities.enabled = settings.security.enabled = False
    settings.kubernetes_versions.enabled = False
    settings.resources.enabled = True
    scanner = Scanner(settings, FakeRegistry(["prod", "edge"]))
    monkeypatch.setattr("kube_tower.worker.collect_nodes", lambda cluster, labels: ([], []))
    snap = await scanner.scan()
    assert sorted(asked) == ["edge", "prod"]
    assert [r.cluster for r in snap.resources] == ["prod"]
    assert [(s.cluster, s.score, s.message) for s in snap.resource_scans] == [
        ("edge", None, "Prometheus not found"),
        ("prod", 70, None),
    ]
    # the next scan reuses prod (fresh), asks again for edge (failed)
    asked.clear()
    snap = await scanner.scan()
    assert asked == ["edge"] and [r.cluster for r in snap.resources] == ["prod"]
    # too old: asked again
    for s in snap.resource_scans:
        s.scanned_at -= timedelta(days=2)
    asked.clear()
    await scanner.scan()
    assert sorted(asked) == ["edge", "prod"]
    # off: nothing kept
    settings.resources.enabled = False
    snap = await scanner.scan()
    assert snap.resources == [] and snap.resource_scans == []


async def test_resources_phase_interrupted(monkeypatch):
    scanner = Scanner(Settings(), FakeRegistry([]))

    async def broken(snap, clusters):
        raise RuntimeError("valkey gone")

    monkeypatch.setattr(scanner, "_recommend", broken)
    snap = Snapshot(clusters=[ClusterStatus("prod", "", "secret", True), ClusterStatus("down", "", "secret", False)])
    await scanner._resources_phase(snap)
    assert [(s.cluster, s.message) for s in snap.resource_scans] == [("prod", "interrupted: valkey gone")]
    assert scanner.resources_started_at is None


def test_activity_while_krr_runs():
    scanner = Scanner(Settings(), FakeRegistry([]))
    scanner.resources_started_at = datetime.now(UTC)
    assert [a.name for a in scanner.activities()] == ["Full scan: CPU and memory recommendations (krr)"]


def test_scope_keeps_the_clusters_of_the_role():
    snap = Snapshot(
        clusters=[ClusterStatus("prod", "", "secret", True), ClusterStatus("dev", "", "secret", True)],
        resources=[_recommendation("prod"), _recommendation("dev")],
        resource_scans=[ResourceScan("prod"), ResourceScan("dev")],
    )
    scoped = scope_snapshot(snap, ("prod",))
    assert [r.cluster for r in scoped.resources] == ["prod"] and [s.cluster for s in scoped.resource_scans] == ["prod"]


# The krr server of the chart (files/krr-server.py)


def test_server_authorize(monkeypatch):
    server = _server()
    monkeypatch.setattr(server, "ALLOWED_USERS", {"system:serviceaccount:ns:kube-tower"})
    reviews = []

    def review(token):
        reviews.append(token)
        return {"good": "system:serviceaccount:ns:kube-tower", "other": "system:serviceaccount:ns:other"}.get(token)

    server.authorize("Bearer good", review)
    server.authorize("Bearer good", review)  # trusted for a while: one TokenReview
    assert reviews == ["good"]
    for header, status in [(None, 401), ("Basic x", 401), ("Bearer bad", 401), ("Bearer other", 403)]:
        with pytest.raises(server.Refused) as refused:
            server.authorize(header, review)
        assert refused.value.status == status

    def down(token):
        raise urllib.error.URLError("refused")

    with pytest.raises(server.Refused) as refused:
        server.authorize("Bearer new", down)
    assert refused.value.status == 503
    monkeypatch.setattr(server, "ALLOWED_USERS", set())
    with pytest.raises(server.Refused, match="nobody"):
        server.authorize("Bearer good", review)


def test_server_token_review(monkeypatch, tmp_path):
    server = _server()
    (tmp_path / "token").write_text("own\n")
    monkeypatch.setattr(server, "SA_DIR", str(tmp_path))
    monkeypatch.setattr(server.ssl, "create_default_context", lambda cafile: None)
    sent = {}

    class Answer:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            import io

            return io.BytesIO(json.dumps(self.body).encode())

        def __exit__(self, *exc):
            return False

    def urlopen(request, context, timeout):
        sent.update(auth=request.headers["Authorization"], body=json.loads(request.data))
        token = sent["body"]["spec"]["token"]
        return Answer({"status": {"authenticated": token == "ok", "user": {"username": "sa"}}})

    monkeypatch.setattr(server.urllib.request, "urlopen", urlopen)
    assert server._token_review("ok") == "sa" and sent["auth"] == "Bearer own"
    assert server._token_review("ko") is None


def test_server_command():
    server = _server()
    argv = server.command("simple", ["--namespace", "x"], "/tmp/kc", "/tmp/out.json")
    assert argv[3:] == [
        "simple", "--kubeconfig", "/tmp/kc", "--formatter", "json", "--fileoutput", "/tmp/out.json",
        "--logtostderr", "--width", "4000", "--namespace", "x",
    ]  # fmt: skip
    for strategy, args, message in [
        ("simple; rm", [], "invalid strategy"),
        ("simple", "--namespace", "list of strings"),
        ("simple", ["--kubeconfig=/etc/x"], "not allowed"),
        ("simple", ["--slackoutput", "c"], "not allowed"),
        ("simple", ["-f", "table"], "not allowed"),
    ]:
        with pytest.raises(server.Refused, match=message):
            server.command(strategy, args, "kc", "out")


@pytest.fixture
def krr_server(monkeypatch, fake_krr):
    server = _server()
    monkeypatch.setattr(server, "KRR", [fake_krr])
    monkeypatch.setattr(server, "ALLOWED_USERS", {"sa"})
    monkeypatch.setattr(server, "_token_review", lambda token: "sa" if token == "ok" else None)
    monkeypatch.setattr(server.authorize, "__defaults__", (server._token_review,))
    http = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    yield server, f"http://127.0.0.1:{http.server_address[1]}"
    http.shutdown()


def _post(url, body, token="ok"):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, headers={"Authorization": f"Bearer {token}"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)


def test_server_runs_krr(krr_server):
    server, url = krr_server
    status, body = _post(f"{url}/run", {"kubeconfig": "apiVersion: v1", "args": ["--namespace", "x"], "timeout": 30})
    assert status == 200 and body["result"]["score"] == 0 and "config" not in body["result"]
    assert body["result"]["args"][-2:] == ["--namespace", "x"]
    assert _post(f"{url}/run", {"kubeconfig": "x", "args": ["--fail"]}) == (502, {"error": "Prometheus not found"})
    assert _post(f"{url}/run", {"kubeconfig": "x"}, token="ko")[0] == 401
    assert _post(f"{url}/run", {"args": []})[0] == 400
    assert _post(f"{url}/run", {"kubeconfig": "x", "timeout": -1})[0] == 400
    assert _post(f"{url}/run", b"not json")[0] == 400
    assert _post(f"{url}/run", b"[1]")[0] == 400
    assert _post(f"{url}/other", {})[0] == 404
    with urllib.request.urlopen(f"{url}/healthz", timeout=5) as response:
        assert response.read() == b"ok"
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(f"{url}/nothing", timeout=5)


def test_server_timeout_and_busy(krr_server, monkeypatch):
    server, url = krr_server
    status, body = _post(f"{url}/run", {"kubeconfig": "x", "args": ["--sleep"], "timeout": 1})
    assert status == 504 and "within 1s" in body["error"]
    monkeypatch.setattr(server, "_slots", threading.BoundedSemaphore(1))
    server._slots.acquire()
    assert _post(f"{url}/run", {"kubeconfig": "x", "timeout": 1})[0] == 503
