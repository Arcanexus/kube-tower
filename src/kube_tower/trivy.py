"""Vulnerability scans with the Trivy CLI, for the images without a Trivy Operator report.

Standalone mode downloads the vulnerability database in `cacheDir` once per scan round;
client/server mode (`serverUrl`) leaves the database to a Trivy server. Images are pulled
from their registry by Trivy itself (no container runtime needed), with the registry
credentials of kube-tower. Results are kept in memory and reused until `rescanInterval`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from datetime import UTC, datetime

from kube_tower.collectors.vulnerabilities import dedupe_vulnerabilities
from kube_tower.config import TrivySettings
from kube_tower.models import ImageReport, Severity, Vulnerability, VulnerabilityReport

log = logging.getLogger(__name__)

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


class TrivyScanner:
    def __init__(self, settings: TrivySettings, credentials: dict[str, tuple[str, str]]):
        self.settings = settings
        self.credentials = credentials
        self.cache: dict[str, VulnerabilityReport] = {}  # by scan target, kept between scans

    @property
    def available(self) -> bool:
        return shutil.which(self.settings.binary) is not None

    def _common_args(self) -> list[str]:
        args = [*QUIET_ARGS, "--cache-dir", self.settings.cache_dir, "--timeout", f"{self.settings.timeout}s"]
        if self.settings.server_url:
            args += ["--server", self.settings.server_url]
        else:
            args += ["--skip-db-update"]  # downloaded once per round by prepare()
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
            env={**os.environ, "TRIVY_NO_PROGRESS": "true", **(env or {})},
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), self.settings.timeout + 60)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return -1, b"", b"ERROR timeout"
        return proc.returncode or 0, stdout, stderr

    async def prepare(self) -> str | None:
        """Download (or refresh) the databases once before the scans. Returns an error message."""
        if self.settings.server_url:
            return None
        args = [*QUIET_ARGS, "--cache-dir", self.settings.cache_dir]
        code, _, stderr = await self._run(["image", "--download-db-only", *args])
        if code == 0 and self.settings.java_db:
            code, _, stderr = await self._run(["image", "--download-java-db-only", *args])
        if code != 0:
            return f"cannot download the Trivy database: {_error_message(stderr)}"
        return None

    def _env(self, registry: str) -> dict[str, str]:
        if pair := self.credentials.get(registry):
            return {"TRIVY_USERNAME": pair[0], "TRIVY_PASSWORD": pair[1]}
        return {}

    async def scan(self, report: ImageReport) -> VulnerabilityReport:
        target, digest = scan_target(report)
        args = ["image", "--format", "json", "--scanners", "vuln", "--image-src", "remote", *self._common_args()]
        if self.settings.ignore_unfixed:
            args.append("--ignore-unfixed")
        code, stdout, stderr = await self._run([*args, *self.settings.extra_args, target], self._env(report.image.registry))
        if code != 0:
            message = _error_message(stderr)
            log.warning("trivy scan of %s failed: %s", target, message)
            return VulnerabilityReport("trivy", datetime.now(UTC), digest, message=message)
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

    async def scan_all(self, reports: list[ImageReport]) -> list[str]:
        """Scan the images (setting report.vulnerabilities as each scan ends). Returns error messages."""
        targets = {scan_target(r)[0] for r in reports}
        self.cache = {t: v for t, v in self.cache.items() if t in targets}  # forget images gone
        todo = []
        for r in reports:
            if cached := self._cached(scan_target(r)[0]):
                r.vulnerabilities = cached
            else:
                todo.append(r)
        if not todo:
            return []
        if error := await self.prepare():
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
        return [f"trivy: {failed} image scan(s) failed, see the Vulnerabilities page"] if failed else []
