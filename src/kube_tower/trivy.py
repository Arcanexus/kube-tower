"""Vulnerability scans with the Trivy CLI, for the images without a Trivy Operator report.

Standalone mode downloads the vulnerability database in `cacheDir` once per scan round;
client/server mode (`serverUrl`) leaves the database to a Trivy server. Images are pulled
from their registry by Trivy itself (no container runtime needed), with the registry
credentials of kube-tower. Results are kept in memory and reused until `rescanInterval`.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import os
import re
import shutil
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from kube_tower.collectors.vulnerabilities import dedupe_vulnerabilities
from kube_tower.config import TrivySettings
from kube_tower.models import ImageReport, Severity, Vulnerability, VulnerabilityReport
from kube_tower.registry.auth import Credentials
from kube_tower.registry.oci import RegistryError

log = logging.getLogger(__name__)

# The databases downloaded for a batch of scans serve the next batches for this long (seconds).
PREPARED_FOR = 600
SCANS_FAILED = re.compile(r"trivy: (\d+) image scan\(s\) failed")
# Errors of a scan that may pass when tried again: a download cut short, a network or registry hiccup.
TRANSIENT = re.compile(
    r"unexpected EOF|connection reset|broken pipe|i/o timeout|TLS handshake timeout|connection refused"
    r"|TOOMANYREQUESTS|too many requests|\b(429|500|502|503|504)\b|bad gateway|service unavailable|gateway timeout",
    re.IGNORECASE,
)
RETRY_DELAYS = (10, 30)  # seconds before each new attempt of a scan that failed on a transient error


def scans_failed(count: int) -> str:
    return f"trivy: {count} image scan(s) failed, see the Vulnerabilities page"


def merge_scan_errors(errors: list[str]) -> list[str]:
    """The errors of several batches of scans: each error once, the failed scans counted together."""
    failed = sum(int(m.group(1)) for e in errors if (m := SCANS_FAILED.match(e)))
    return [e for e in dict.fromkeys(errors) if not SCANS_FAILED.match(e)] + ([scans_failed(failed)] if failed else [])


MESSAGE_LIMIT = 300
# No progress bars, no usage data sent to Aqua, no update notices in the logs
QUIET_ARGS = ["--quiet", "--disable-telemetry", "--skip-version-check"]
JAVA_ARCHIVES = ("jar", "war", "ear", "par")


def scan_target(report: ImageReport) -> tuple[str, str | None]:
    """(reference given to Trivy, digest) for an image: the running digest when there is a single one."""
    image = report.image
    if image.digest:
        return str(image), image.digest
    if len(report.running_digests) == 1:
        digest = next(iter(report.running_digests))
        return f"{image.name}@{digest}", digest
    return str(image), None


def _score(cvss: dict | None) -> float | None:
    scores = [v.get("V3Score") or v.get("V2Score") for v in (cvss or {}).values()]
    scores = [s for s in scores if s]
    return max(scores) if scores else None


def parse_trivy_output(data: dict, digest: str | None) -> VulnerabilityReport:
    """VulnerabilityReport from the JSON of `trivy image --format json`."""
    metadata = data.get("Metadata") or {}
    os_info = metadata.get("OS") or {}
    vulnerabilities = [
        Vulnerability(
            id=v.get("VulnerabilityID", ""),
            severity=Severity.parse(v.get("Severity")),
            package=v.get("PkgName", ""),
            installed_version=v.get("InstalledVersion", ""),
            fixed_version=v.get("FixedVersion", "") or "",
            title=v.get("Title", "") or "",
            url=v.get("PrimaryURL", "") or "",
            score=_score(v.get("CVSS")),
        )
        for result in data.get("Results") or []
        for v in result.get("Vulnerabilities") or []
    ]
    repo_digests = metadata.get("RepoDigests") or []
    return VulnerabilityReport(
        source="trivy",
        scanned_at=datetime.now(UTC),
        digest=digest or (repo_digests[0].split("@", 1)[1] if repo_digests and "@" in repo_digests[0] else None),
        os=" ".join(filter(None, [os_info.get("Family"), os_info.get("Name")])),
        os_eosl=bool(os_info.get("EOSL")),
        vulnerabilities=dedupe_vulnerabilities(vulnerabilities),
    )


def _error_message(stderr: bytes) -> str:
    """The error of a failed trivy run: its last FATAL/ERROR log line and the detail lines after it."""
    lines = [line.strip() for line in stderr.decode(errors="replace").splitlines() if line.strip()]
    start = max((i for i, line in enumerate(lines) if "FATAL" in line or "ERROR" in line), default=None)
    if start is None:
        return (lines[-1] if lines else "trivy failed")[-MESSAGE_LIMIT:]
    # e.g. "2026-10-23T17:42:14Z\tFATAL\tFatal error\trun error: ..." -> "run error: ..."
    message = " ".join([lines[start].split("\t")[-1], *(line.lstrip("* ") for line in lines[start + 1 :])])
    message = message.removesuffix(":").replace("1 error occurred: ", "")
    # Image pull errors: only the registry answer matters, not the chain of wrappers before it.
    message = message.split('in ["remote"]: ', 1)[-1]
    # The end is the most specific part (the chain of errors starts with generic wrappers).
    return message if len(message) <= MESSAGE_LIMIT else "…" + message[-MESSAGE_LIMIT:]


@dataclass
class TrivyDatabase:
    """A Trivy database, as `trivy version` describes it."""

    version: int | None = None
    updated_at: datetime | None = None  # built by Aqua
    next_update: datetime | None = None  # a newer one is published after this date
    downloaded_at: datetime | None = None


@dataclass
class TrivyStatus:
    """The Trivy CLI and its local databases (none in client/server mode: the server holds them)."""

    checked_at: datetime
    version: str = ""
    db: TrivyDatabase | None = None
    java_db: TrivyDatabase | None = None
    message: str | None = None  # why the status could not be read


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_trivy_version(data: dict) -> TrivyStatus:
    """TrivyStatus from the JSON of `trivy version --format json` (databases absent when never downloaded)."""

    def database(key: str) -> TrivyDatabase | None:
        db = data.get(key)
        if not db:
            return None
        return TrivyDatabase(
            db.get("Version"), _date(db.get("UpdatedAt")), _date(db.get("NextUpdate")), _date(db.get("DownloadedAt"))
        )

    return TrivyStatus(datetime.now(UTC), data.get("Version", ""), database("VulnerabilityDB"), database("JavaDB"))


class TrivyScanner:
    def __init__(self, settings: TrivySettings, credentials: Credentials | dict[str, tuple[str, str]]):
        self.settings = settings
        self.credentials = credentials if isinstance(credentials, Credentials) else Credentials(credentials)
        # Set by the scanner from the registries settings: hosts whose TLS is not verified, and a CA bundle
        # holding the public CAs plus registries.caFile.
        self.insecure: list[str] = []
        self.ca_bundle = ""
        self.cache: dict[str, VulnerabilityReport] = {}  # by scan target, kept between scans
        self._prepared_at: float | None = None  # last database download (time.monotonic())
        # The Trivy phase of a scan and the rescans run at the same time, in different threads:
        # one database download at a time.
        self._prepare_lock = threading.Lock()

    @property
    def available(self) -> bool:
        return shutil.which(self.settings.binary) is not None

    def _common_args(self) -> list[str]:
        args = [*QUIET_ARGS, "--cache-dir", self.settings.cache_dir, "--timeout", f"{self.settings.timeout}s"]
        if self.settings.server_url:
            args += ["--server", self.settings.server_url]
        else:
            # The database is downloaded once per round by prepare(). Layers are cached in memory:
            # concurrent scans sharing the cacheDir layer cache fail with "cache may be in use".
            args += ["--skip-db-update", "--cache-backend", "memory"]
        if not self.settings.java_db:
            # Without the Java DB Trivy fails on images holding Java archives: skip them.
            args += ["--skip-java-db-update", *(f"--skip-files=**/*.{ext}" for ext in JAVA_ARCHIVES)]
        return args

    async def _run(self, args: list[str], env: dict[str, str] | None = None) -> tuple[int, bytes, bytes]:
        proc = await asyncio.create_subprocess_exec(
            self.settings.binary,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={
                **os.environ,
                "TRIVY_NO_PROGRESS": "true",
                # Go programs read the CAs to trust from SSL_CERT_FILE (registries.caFile).
                **({"SSL_CERT_FILE": self.ca_bundle} if self.ca_bundle else {}),
                **(env or {}),
            },
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), self.settings.timeout + 60)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return -1, b"", b"ERROR timeout"
        return proc.returncode or 0, stdout, stderr

    async def prepare(self, max_age: float = 0) -> str | None:
        """Download (or refresh) the databases once before the scans, unless done less than `max_age`
        seconds ago (the batches of one scan). Returns an error message."""
        if self.settings.server_url:
            return None
        while not self._prepare_lock.acquire(blocking=False):  # polled: cancelling the wait leaves the lock free
            await asyncio.sleep(0.5)
        try:
            if self._prepared_at is not None and time.monotonic() - self._prepared_at < max_age:
                return None
            error = await self._download_db()
            self._prepared_at = None if error else time.monotonic()
            return error
        finally:
            self._prepare_lock.release()

    async def _download_db(self) -> str | None:
        args = [*QUIET_ARGS, "--cache-dir", self.settings.cache_dir]
        code, _, stderr = await self._run(["image", "--download-db-only", *args])
        if code == 0 and self.settings.java_db:
            code, _, stderr = await self._run(["image", "--download-java-db-only", *args])
        if code != 0:
            return f"cannot download the Trivy database: {_error_message(stderr)}"
        return None

    async def status(self) -> TrivyStatus:
        """Version of Trivy and of its databases."""
        if not self.available:
            return TrivyStatus(datetime.now(UTC), message=f"trivy binary {self.settings.binary!r} not found")
        code, stdout, stderr = await self._run(["version", "--format", "json", "--cache-dir", self.settings.cache_dir])
        if code != 0:
            return TrivyStatus(datetime.now(UTC), message=f"trivy version failed: {_error_message(stderr)}")
        try:
            return parse_trivy_version(json.loads(stdout or b"{}"))
        except (ValueError, AttributeError) as exc:
            return TrivyStatus(datetime.now(UTC), message=f"unreadable trivy version output: {exc}")

    async def _env(self, registry: str) -> dict[str, str]:
        """The credentials of the image registry only (Trivy sends TRIVY_USERNAME/PASSWORD to the registry it pulls from)."""
        if pair := await self.credentials.get(registry):
            return {"TRIVY_USERNAME": pair[0], "TRIVY_PASSWORD": pair[1]}
        return {}

    async def scan(self, report: ImageReport) -> VulnerabilityReport:
        target, digest = scan_target(report)
        args = ["image", "--format", "json", "--scanners", "vuln", "--image-src", "remote", *self._common_args()]
        if self.settings.ignore_unfixed:
            args.append("--ignore-unfixed")
        if any(fnmatch.fnmatch(report.image.registry, pattern) for pattern in self.insecure):
            args.append("--insecure")
        if target.startswith("-"):  # an image name read from the clusters must never be taken as an option
            return VulnerabilityReport("trivy", datetime.now(UTC), digest, message=f"invalid image reference {target!r}")
        # `--` ends the options: the target is always read as an image reference.
        try:
            env = await self._env(report.image.registry)
        except RegistryError as exc:
            log.warning("trivy scan of %s skipped: %s", target, exc)
            return VulnerabilityReport("trivy", datetime.now(UTC), digest, message=str(exc))
        for attempt, delay in enumerate((*RETRY_DELAYS, None), start=1):
            code, stdout, stderr = await self._run([*args, *self.settings.extra_args, "--", target], env)
            if code == 0:
                break
            message = _error_message(stderr)
            if delay is None or not TRANSIENT.search(message):
                log.warning("trivy scan of %s failed: %s", target, message)
                return VulnerabilityReport("trivy", datetime.now(UTC), digest, message=message)
            log.info(
                "trivy scan of %s failed on a transient error (attempt %d of %d), trying again in %ss: %s",
                target,
                attempt,
                len(RETRY_DELAYS) + 1,
                delay,
                message,
            )
            await asyncio.sleep(delay)
        try:
            return parse_trivy_output(json.loads(stdout or b"{}"), digest)
        except (ValueError, AttributeError) as exc:
            return VulnerabilityReport("trivy", datetime.now(UTC), digest, message=f"unreadable trivy output: {exc}")

    def _cached(self, target: str) -> VulnerabilityReport | None:
        cached = self.cache.get(target)
        if cached is None or cached.message or cached.scanned_at is None:
            return None
        age = (datetime.now(UTC) - cached.scanned_at).total_seconds()
        return cached if age < self.settings.rescan_interval else None

    def expire_databases(self) -> None:
        """The next scans refresh the databases first."""
        self._prepared_at = None

    async def scan_all(self, reports: list[ImageReport]) -> list[str]:
        """Scan the images of a full scan: the cache forgets the images gone. Returns error messages."""
        targets = {scan_target(r)[0] for r in reports}
        self.cache = {t: v for t, v in self.cache.items() if t in targets}  # forget images gone
        return await self.scan_many(reports, prepared_for=0)

    async def scan_many(self, reports: list[ImageReport], prepared_for: float = PREPARED_FOR) -> list[str]:
        """Scan the images not cached (setting report.vulnerabilities as each scan ends). Returns error messages.
        The databases are refreshed first, unless they were less than `prepared_for` seconds ago."""
        # Results too old to be used are forgotten (the batches of the distributed mode never forget the others).
        self.cache = {t: v for t, v in self.cache.items() if self._cached(t)}
        todo = []
        for r in reports:
            if cached := self._cached(scan_target(r)[0]):
                r.vulnerabilities = cached
            else:
                todo.append(r)
        if not todo:
            return []
        if error := await self.prepare(prepared_for):
            log.error(error)
            for r in todo:
                r.vulnerabilities = VulnerabilityReport("trivy", datetime.now(UTC), message=error)
            return [error]
        log.info("trivy: scanning %d images (%d cached)", len(todo), len(reports) - len(todo))
        semaphore = asyncio.Semaphore(max(1, self.settings.concurrency))

        async def one(r: ImageReport) -> None:
            async with semaphore:
                result = await self.scan(r)
            self.cache[scan_target(r)[0]] = result
            r.vulnerabilities = result

        await asyncio.gather(*(one(r) for r in todo))
        failed = sum(1 for r in todo if r.vulnerabilities and r.vulnerabilities.message)
        return [scans_failed(failed)] if failed else []
