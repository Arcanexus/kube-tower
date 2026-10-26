import asyncio
import json
import stat
import threading
from datetime import UTC, datetime, timedelta

import pytest
from kubernetes import client

from kube_tower.clusters import Cluster
from kube_tower.collectors import vulnerabilities as operator
from kube_tower.config import TrivySettings
from kube_tower.models import ImageRef, ImageReport, Severity, Vulnerability, VulnerabilityReport
from kube_tower.registry.auth import Credentials
from kube_tower.registry.oci import RegistryError
from kube_tower.trivy import TrivyScanner, _error_message, parse_trivy_output, parse_trivy_version, scan_target

OPERATOR_REPORT = {
    "metadata": {"name": "replicaset-web-nginx", "namespace": "default"},
    "report": {
        "registry": {"server": "index.docker.io"},
        "artifact": {"repository": "library/nginx", "tag": "1.25", "digest": "sha256:run"},
        "os": {"family": "debian", "name": "12.5", "eosl": True},
        "updateTimestamp": "2026-10-20T10:00:00Z",
        "vulnerabilities": [
            {"vulnerabilityID": "CVE-2", "severity": "MEDIUM", "resource": "curl", "installedVersion": "7", "fixedVersion": "8"},
            {
                "vulnerabilityID": "CVE-1",
                "severity": "CRITICAL",
                "resource": "zlib",
                "installedVersion": "1",
                "score": 9.8,
                "title": "overflow",
                "primaryLink": "https://avd.aquasec.com/nvd/cve-1",
            },
            {"vulnerabilityID": "CVE-1", "severity": "CRITICAL", "resource": "zlib", "installedVersion": "1", "score": 9.8},
        ],
    },
}

TRIVY_OUTPUT = {
    "Metadata": {"OS": {"Family": "alpine", "Name": "3.18.12", "EOSL": True}, "RepoDigests": ["alpine@sha256:abc"]},
    "Results": [
        {
            "Target": "alpine:3.18 (alpine 3.18.12)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-9",
                    "PkgName": "musl",
                    "InstalledVersion": "1.2",
                    "FixedVersion": "1.3",
                    "Severity": "HIGH",
                    "Title": "bug",
                    "PrimaryURL": "https://x/cve-9",
                    "CVSS": {"nvd": {"V3Score": 7.5}, "redhat": {"V3Score": 8.1}},
                },
                {"VulnerabilityID": "CVE-8", "PkgName": "busybox", "InstalledVersion": "1.36", "Severity": "WEIRD"},
            ],
        },
        {"Target": "app", "Vulnerabilities": None},
    ],
}


def test_parse_operator_report():
    key, report = operator.parse_operator_report(OPERATOR_REPORT)
    assert key == ImageRef("docker.io", "library/nginx", "1.25")
    assert report.source == "trivy-operator" and report.digest == "sha256:run"
    assert report.os == "debian 12.5" and report.os_eosl
    assert report.scanned_at == datetime(2026, 10, 20, 10, tzinfo=UTC)
    assert [v.id for v in report.vulnerabilities] == ["CVE-1", "CVE-2"]  # deduplicated, most severe first
    assert report.counts()[Severity.CRITICAL] == 1 and report.fixable == 1 and report.worst == Severity.CRITICAL
    assert operator.parse_operator_report({"report": {"artifact": {}}}) is None
    key, report = operator.parse_operator_report({"report": {"artifact": {"repository": "x/y", "digest": "sha256:d"}}})
    assert key == ImageRef("docker.io", "x/y", None, "sha256:d") and report.scanned_at is None


def test_pick_report_prefers_the_running_digest():
    old = VulnerabilityReport("trivy-operator", datetime(2026, 1, 1, tzinfo=UTC), "sha256:run")
    new = VulnerabilityReport("trivy-operator", datetime(2026, 2, 1, tzinfo=UTC), "sha256:other")
    undated = VulnerabilityReport("trivy-operator")
    assert operator.pick_report([old, new, undated], {"sha256:run"}) is old
    assert operator.pick_report([old, new, undated], set()) is new


class FakeCustomObjects:
    pages: list = []
    error: client.ApiException | None = None

    def __init__(self, api_client):
        self.calls = []

    def list_cluster_custom_object(self, group, version, plural, **kwargs):
        assert (group, version, plural) == ("aquasecurity.github.io", "v1alpha1", "vulnerabilityreports")
        if self.error:
            raise self.error
        token = kwargs.get("_continue")
        return self.pages[int(token) if token else 0]


@pytest.fixture
def custom_objects(monkeypatch):
    monkeypatch.setattr(operator.client, "CustomObjectsApi", FakeCustomObjects)
    FakeCustomObjects.error = None
    return FakeCustomObjects


def test_collect_operator_reports_paginates(custom_objects):
    custom_objects.pages = [
        {"items": [OPERATOR_REPORT], "metadata": {"continue": "1"}},
        {"items": [{"report": {}}, OPERATOR_REPORT], "metadata": {}},
    ]
    reports, errors = operator.collect_operator_reports(Cluster("c1", "https://c1", "secret", None))
    assert len(reports) == 2 and errors == []


def test_collect_operator_reports_errors(custom_objects):
    cluster = Cluster("c1", "https://c1", "secret", None)
    custom_objects.error = client.ApiException(status=404, reason="Not Found")
    assert operator.collect_operator_reports(cluster) == ([], [])  # Trivy Operator not installed
    custom_objects.error = client.ApiException(status=403, reason="Forbidden")
    assert operator.collect_operator_reports(cluster) == ([], ["[c1] cannot list VulnerabilityReports: 403 Forbidden"])


def test_parse_trivy_output():
    report = parse_trivy_output(TRIVY_OUTPUT, None)
    assert report.source == "trivy" and report.digest == "sha256:abc"
    assert report.os == "alpine 3.18.12" and report.os_eosl
    high, unknown = report.vulnerabilities
    assert (high.id, high.severity, high.score, high.fixed_version, high.url) == (
        "CVE-9",
        Severity.HIGH,
        8.1,
        "1.3",
        "https://x/cve-9",
    )
    assert unknown.severity == Severity.UNKNOWN and unknown.score is None
    assert parse_trivy_output({}, "sha256:x").digest == "sha256:x"


def test_scan_target():
    image = ImageRef("docker.io", "library/nginx", "1.25")
    assert scan_target(ImageReport(image)) == ("docker.io/library/nginx:1.25", None)
    assert scan_target(ImageReport(image, running_digests={"sha256:a"})) == ("docker.io/library/nginx@sha256:a", "sha256:a")
    assert scan_target(ImageReport(image, running_digests={"sha256:a", "sha256:b"}))[1] is None
    pinned = ImageRef("docker.io", "library/nginx", "1.25", "sha256:p")
    assert scan_target(ImageReport(pinned)) == ("docker.io/library/nginx:1.25@sha256:p", "sha256:p")


def test_error_message():
    stderr = (
        b"2026-10-23T17:41:00Z\tINFO\tDownloading layers\n"
        b"2026-10-23T17:42:14Z\tFATAL\tFatal error\t"
        b'run error: unable to find the specified image in ["remote"]: 1 error occurred:\n'
        b"\t* remote error: DENIED: denied\n"
    )
    assert _error_message(stderr) == "remote error: DENIED: denied"
    assert _error_message(b"") == "trivy failed"
    assert _error_message(b"something odd\n") == "something odd"
    long = _error_message(b"x\tERROR\t" + b"a" * 400 + b" end")
    assert long.startswith("…") and long.endswith(" end") and len(long) == 301


@pytest.fixture
def fake_trivy(tmp_path):
    """A trivy stand-in: logs its arguments and environment, prints TRIVY_OUTPUT or fails on demand."""
    log = tmp_path / "calls.jsonl"
    output = tmp_path / "output.json"
    output.write_text(json.dumps(TRIVY_OUTPUT))
    script = tmp_path / "trivy"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "env = {'user': os.environ.get('TRIVY_USERNAME'), 'ssl': os.environ.get('SSL_CERT_FILE')}\n"
        f"open({str(log)!r}, 'a').write(json.dumps({{'args': sys.argv[1:], **env}}) + '\\n')\n"
        "target = sys.argv[-1]\n"
        "if 'broken' in target or ('--download-db-only' in sys.argv and os.environ.get('FAIL_DB')):\n"
        "    print('2026-10-23T00:00:00Z\\tFATAL\\tFatal error\\tboom', file=sys.stderr); sys.exit(1)\n"
        "if 'garbage' in target:\n"
        "    print('not json'); sys.exit(0)\n"
        f"if '--download' not in ' '.join(sys.argv): print(open({str(output)!r}).read())\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    def calls():
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    return str(script), calls


async def test_trivy_scan_all(fake_trivy):
    binary, calls = fake_trivy
    scanner = TrivyScanner(TrivySettings(binary=binary, cache_dir="/c"), {"docker.io": ("alex", "token")})
    assert scanner.available
    good = ImageReport(ImageRef("docker.io", "library/alpine", "3.18"))
    broken = ImageReport(ImageRef("ghcr.io", "org/broken", "1"))
    garbage = ImageReport(ImageRef("ghcr.io", "org/garbage", "1"))
    errors = await scanner.scan_all([good, broken, garbage])
    assert errors == ["trivy: 2 image scan(s) failed, see the Vulnerabilities page"]
    assert good.vulnerabilities.counts()[Severity.HIGH] == 1
    assert broken.vulnerabilities.message == "boom"
    assert garbage.vulnerabilities.message.startswith("unreadable trivy output")

    db, *scans = calls()
    assert db["args"][:2] == ["image", "--download-db-only"] and "--disable-telemetry" in db["args"]
    alpine = next(c for c in scans if c["args"][-1] == "docker.io/library/alpine:3.18")
    assert alpine["args"][-2] == "--"  # options end before the target
    assert alpine["user"] == "alex"  # credentials of the image registry only
    assert {"--skip-db-update", "--skip-java-db-update", "--skip-files=**/*.jar", "--image-src"} <= set(alpine["args"])
    assert ["--cache-backend", "memory"] == alpine["args"][alpine["args"].index("--cache-backend") :][:2]
    assert next(c for c in scans if "broken" in c["args"][-1])["user"] is None

    # Results are reused until rescanInterval, failed scans are retried
    await scanner.scan_all([good, broken])
    new = calls()[4:]
    assert [c["args"][1] for c in new] == ["--download-db-only", "--format"] and new[-1]["args"][-1] == "ghcr.io/org/broken:1"
    assert set(scanner.cache) == {"docker.io/library/alpine:3.18", "ghcr.io/org/broken:1"}  # garbage forgotten
    scanner.cache["docker.io/library/alpine:3.18"].scanned_at -= timedelta(days=2)
    await scanner.scan_all([good])
    assert calls()[-1]["args"][-1] == "docker.io/library/alpine:3.18"

    # Batches (distributed mode): the databases downloaded less than 10 minutes ago are not refreshed
    count = len(calls())
    await scanner.scan_many([broken])
    assert [c["args"][1] for c in calls()[count:]] == ["--format"]
    await scanner.scan_many([broken], prepared_for=0)
    assert [c["args"][1] for c in calls()[count + 1 :]] == ["--download-db-only", "--format"]


def test_merge_scan_errors():
    from kube_tower.trivy import merge_scan_errors, scans_failed

    db = "cannot download the Trivy database: 403"
    assert merge_scan_errors([scans_failed(2), db, scans_failed(1), db]) == [db, scans_failed(3)]
    assert merge_scan_errors([]) == []


async def test_trivy_all_cached_runs_nothing(fake_trivy):
    binary, calls = fake_trivy
    scanner = TrivyScanner(TrivySettings(binary=binary), {})
    report = ImageReport(ImageRef("docker.io", "library/alpine", "3.18"))
    scanner.cache["docker.io/library/alpine:3.18"] = cached = VulnerabilityReport("trivy", datetime.now(UTC))
    assert await scanner.scan_all([report]) == [] and report.vulnerabilities is cached and calls() == []


async def test_trivy_server_mode_and_options(fake_trivy):
    binary, calls = fake_trivy
    settings = TrivySettings(
        binary=binary, server_url="http://trivy:4954", ignore_unfixed=True, java_db=True, extra_args=["--debug"]
    )
    report = ImageReport(ImageRef("docker.io", "library/alpine", "3.18"))
    assert await TrivyScanner(settings, {}).scan_all([report]) == []
    (scan,) = calls()  # no database download: the server holds it
    assert ["--server", "http://trivy:4954"] == scan["args"][scan["args"].index("--server") :][:2]
    assert "--ignore-unfixed" in scan["args"] and "--debug" in scan["args"]
    assert "--skip-db-update" not in scan["args"] and "--skip-java-db-update" not in scan["args"]
    assert "--cache-backend" not in scan["args"]


async def test_trivy_java_db_download(fake_trivy):
    binary, calls = fake_trivy
    report = ImageReport(ImageRef("docker.io", "library/alpine", "3.18"))
    await TrivyScanner(TrivySettings(binary=binary, java_db=True), {}).scan_all([report])
    assert [c["args"][1] for c in calls()[:2]] == ["--download-db-only", "--download-java-db-only"]


async def test_trivy_database_download_failure(fake_trivy, monkeypatch):
    binary, _ = fake_trivy
    monkeypatch.setenv("FAIL_DB", "1")
    report = ImageReport(ImageRef("docker.io", "library/alpine", "3.18"))
    errors = await TrivyScanner(TrivySettings(binary=binary), {}).scan_all([report])
    assert errors == ["cannot download the Trivy database: boom"]
    assert report.vulnerabilities.message == errors[0]


async def test_trivy_timeout(tmp_path):
    script = tmp_path / "trivy"
    script.write_text("#!/bin/sh\nsleep 5\n")
    script.chmod(0o755)
    scanner = TrivyScanner(TrivySettings(binary=str(script), server_url="http://x", timeout=-59), {})
    result = await scanner.scan(ImageReport(ImageRef("docker.io", "library/alpine", "3.18")))
    assert result.message == "ERROR timeout"


def test_vulnerability_report_counts():
    report = VulnerabilityReport("trivy", vulnerabilities=[Vulnerability("a", Severity.LOW, "p", "1", "2")])
    assert report.counts() == {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 1, Severity.UNKNOWN: 0}
    assert VulnerabilityReport("trivy").worst is None
    assert Severity.parse(None) == Severity.UNKNOWN and Severity.parse("High") == Severity.HIGH


def test_parse_trivy_version():
    status = parse_trivy_version(
        {
            "Version": "0.75.0",
            "VulnerabilityDB": {
                "Version": 2,
                "NextUpdate": "2026-10-24T19:15:43.73441704Z",
                "UpdatedAt": "2026-10-23T19:15:43.7344174Z",
                "DownloadedAt": "2026-10-23T22:22:40.971226632Z",
            },
        }
    )
    assert status.version == "0.75.0" and status.java_db is None and status.message is None
    assert status.db.version == 2 and status.db.downloaded_at == datetime(2026, 10, 23, 22, 22, 40, 971226, tzinfo=UTC)
    assert status.db.next_update.day == 24
    assert parse_trivy_version({"Version": "0.75.0"}).db is None  # never downloaded
    assert parse_trivy_version({"VulnerabilityDB": {"UpdatedAt": "bad"}}).db.updated_at is None


async def test_trivy_status(tmp_path, monkeypatch):
    script = tmp_path / "trivy"
    script.write_text(
        "#!/bin/sh\n"
        'if [ "$FAIL" ]; then printf "x\\tFATAL\\tboom\\n" >&2; exit 1; fi\n'
        'if [ "$GARBAGE" ]; then echo "nope"; exit 0; fi\n'
        """echo '{"Version":"0.75.0","JavaDB":{"Version":1}}'\n"""
    )
    script.chmod(0o755)
    scanner = TrivyScanner(TrivySettings(binary=str(script)), {})
    status = await scanner.status()
    assert status.version == "0.75.0" and status.java_db.version == 1
    monkeypatch.setenv("GARBAGE", "1")
    assert (await scanner.status()).message.startswith("unreadable trivy version output")
    monkeypatch.setenv("FAIL", "1")
    assert (await scanner.status()).message == "trivy version failed: boom"
    missing = await TrivyScanner(TrivySettings(binary=str(tmp_path / "none")), {}).status()
    assert missing.message.endswith("not found")


def test_trivy_database_downloaded_once_at_a_time(monkeypatch):
    """The Trivy phase of a scan and the rescans prepare the database from different threads."""
    active, overlaps = [], []

    async def download(self):
        active.append(1)
        overlaps.append(len(active))
        await asyncio.sleep(0.05)
        active.pop()

    monkeypatch.setattr(TrivyScanner, "_download_db", download)
    scanner = TrivyScanner(TrivySettings(), {})
    threads = [threading.Thread(target=lambda: asyncio.run(scanner.prepare())) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert overlaps == [1, 1, 1]


async def test_trivy_refuses_option_like_target(fake_trivy, monkeypatch):
    binary, calls = fake_trivy
    scanner = TrivyScanner(TrivySettings(binary=binary, cache_dir="/c"), {})
    monkeypatch.setattr("kube_tower.trivy.scan_target", lambda r: ("--output=/tmp/x", None))
    result = await scanner.scan(ImageReport(ImageRef("docker.io", "x", "1")))
    assert result.message == "invalid image reference '--output=/tmp/x'" and calls() == []


async def test_trivy_insecure_ca_and_cloud_credentials(fake_trivy):
    binary, calls = fake_trivy

    class Failing:
        name = "aws"

        async def fetch(self, registry):
            raise RegistryError("no AWS identity for provider aws")

    ecr = "123456789012.dkr.ecr.eu-west-1.amazonaws.com"
    scanner = TrivyScanner(TrivySettings(binary=binary, server_url="http://trivy:4954"), Credentials(providers={ecr: Failing()}))
    scanner.insecure = ["registry.local*"]
    scanner.ca_bundle = "/tmp/bundle.pem"
    local = ImageReport(ImageRef("registry.local:5000", "app", "1"))
    public = ImageReport(ImageRef("docker.io", "library/alpine", "3.18"))
    private = ImageReport(ImageRef(ecr, "team/app", "1"))
    await scanner.scan_all([local, public, private])
    by_target = {c["args"][-1]: c for c in calls()}
    assert "--insecure" in by_target["registry.local:5000/app:1"]["args"]
    assert "--insecure" not in by_target["docker.io/library/alpine:3.18"]["args"]
    assert by_target["docker.io/library/alpine:3.18"]["ssl"] == "/tmp/bundle.pem"
    assert f"{ecr}/team/app:1" not in by_target  # not scanned: no token
    assert private.vulnerabilities.message == "no AWS identity for provider aws"
