"""HTTP front of krr (https://github.com/robusta-dev/krr) for kube-tower, run in the official krr image.

kube-tower sends the kubeconfig of a cluster and the krr options; this server runs krr against that
cluster and answers its JSON result. Only the ServiceAccounts in KRR_ALLOWED_USERS may call it: the
caller sends its ServiceAccount token, checked with a TokenReview of the Kubernetes API of this pod.

Python standard library only (the krr image has no other package that kube-tower would need).

    POST /run      {"strategy": "simple", "kubeconfig": "<yaml>", "args": ["--namespace", "x"], "timeout": 900}
                   -> 200 {"result": {<krr JSON>}} | 4xx/5xx {"error": "..."}
    GET  /healthz  -> 200 ok
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("krr-server")

# krr without its greeting, which also asks api.robusta.dev for news and a newer version (krr.py of the image
# otherwise): its --quiet option would hide the errors too.
LAUNCHER = """
import os, sys
sys.path.insert(0, os.environ.get("KRR_APP_DIR", "/app"))
sys.argv[0] = "krr"
from robusta_krr.common.ssl_utils import add_custom_certificate
add_custom_certificate(os.environ.get("CERTIFICATE", ""))
from robusta_krr.core import runner
async def _no_greeting(self):
    return None
runner.Runner._greet = _no_greeting
from robusta_krr import run
run()
"""
KRR = os.environ["KRR_COMMAND"].split() if os.environ.get("KRR_COMMAND") else [sys.executable, "-c", LAUNCHER]
PORT = int(os.environ.get("KRR_PORT", "8080"))
ALLOWED_USERS = {u.strip() for u in os.environ.get("KRR_ALLOWED_USERS", "").split(",") if u.strip()}
# krr runs at the same time: each one reads Prometheus and the Kubernetes API of a cluster
CONCURRENCY = int(os.environ.get("KRR_CONCURRENCY", "2"))
MAX_TIMEOUT = int(os.environ.get("KRR_MAX_TIMEOUT", "3600"))
MAX_BODY = 1024 * 1024
SA_DIR = os.environ.get("KRR_SA_DIR", "/var/run/secrets/kubernetes.io/serviceaccount")
API_SERVER = os.environ.get("KRR_API_SERVER", "https://kubernetes.default.svc")
REVIEW_TTL = 300  # seconds a token accepted by the TokenReview is trusted again without asking
STRATEGY = re.compile(r"^[a-z][a-z0-9_-]{0,40}$")
# Options kube-tower may not pass: kube-tower chooses the cluster and the output, nothing is sent elsewhere.
FORBIDDEN = re.compile(
    r"^--?(kubeconfig|context|cluster|all-clusters|formatter|f|fileoutput|fileoutput-dynamic|slackoutput|slacktitle"
    r"|azurebloboutput|teams-webhook|publish_scan_url|named_sinks|as|as-group)(=|$)"
)
MESSAGE_LIMIT = 500

_slots = threading.BoundedSemaphore(CONCURRENCY)
_reviewed: dict[str, float] = {}
_reviewed_lock = threading.Lock()


class Refused(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _token_review(token: str) -> str | None:
    """The username of the token according to the Kubernetes API of this pod, None if not authenticated."""
    with open(os.path.join(SA_DIR, "token")) as fh:
        own_token = fh.read().strip()
    body = json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {"token": token}})
    request = urllib.request.Request(
        f"{API_SERVER}/apis/authentication.k8s.io/v1/tokenreviews",
        data=body.encode(),
        headers={"Authorization": f"Bearer {own_token}", "Content-Type": "application/json"},
        method="POST",
    )
    context = ssl.create_default_context(cafile=os.path.join(SA_DIR, "ca.crt"))
    with urllib.request.urlopen(request, context=context, timeout=10) as response:
        status = json.load(response).get("status") or {}
    return (status.get("user") or {}).get("username") if status.get("authenticated") else None


def authorize(header: str | None, review=_token_review) -> None:
    """Accept the request of a ServiceAccount of KRR_ALLOWED_USERS, else raise Refused."""
    if not ALLOWED_USERS:
        raise Refused(403, "KRR_ALLOWED_USERS is empty: nobody may run krr")
    if not header or not header.startswith("Bearer "):
        raise Refused(401, "a ServiceAccount token is required (Authorization: Bearer)")
    token = header.removeprefix("Bearer ").strip()
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = time.monotonic()
    with _reviewed_lock:
        if _reviewed.get(digest, 0) > now:
            return
    try:
        user = review(token)
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise Refused(503, f"cannot check the token with the Kubernetes API: {exc}") from exc
    if user is None:
        raise Refused(401, "the token is not valid")
    if user not in ALLOWED_USERS:
        raise Refused(403, f"{user} may not run krr")
    with _reviewed_lock:
        for key in [k for k, until in _reviewed.items() if until <= now]:
            del _reviewed[key]
        _reviewed[digest] = now + REVIEW_TTL


def command(strategy: str, args: list, kubeconfig: str, output: str) -> list[str]:
    """The krr command line, after checking what kube-tower asked."""
    if not isinstance(strategy, str) or not STRATEGY.match(strategy):
        raise Refused(400, f"invalid strategy {strategy!r}")
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise Refused(400, "args must be a list of strings")
    if bad := [a for a in args if FORBIDDEN.match(a)]:
        raise Refused(400, f"option(s) not allowed: {', '.join(bad)}")
    return [
        *KRR,
        strategy,
        "--kubeconfig",
        kubeconfig,
        "--formatter",
        "json",
        "--fileoutput",
        output,
        "--logtostderr",
        "--width",
        "4000",  # one log line per message
        *args,
    ]


LOG_LINE = re.compile(r"^(?:\[[\d:]+\]\s*)?(DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+(.*?)(?:\s+[\w.]+\.py:\d+)?$")
EXCEPTION = re.compile(r"^[A-Za-z_][\w.]*(Error|Exception|Exceeded|Timeout)\w*: \S")


def error_message(stderr: str) -> str:
    """Why krr failed: its last error log line, with the exception that ended it (the last line of the traceback)."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    logged = [(i, m[2]) for i, line in enumerate(lines) if (m := LOG_LINE.match(line)) and m[1] in ("ERROR", "CRITICAL")]
    start, message = logged[-1] if logged else (0, "")
    exceptions = [line for line in lines[start:] if EXCEPTION.match(line)]
    message = ": ".join(filter(None, [message, exceptions[-1] if exceptions else ""])) or (lines[-1] if lines else "krr failed")
    return message if len(message) <= MESSAGE_LIMIT else message[: MESSAGE_LIMIT - 1] + "…"


def run(payload: dict) -> dict:
    """Run krr for the request and return its result."""
    kubeconfig = payload.get("kubeconfig")
    if not isinstance(kubeconfig, str) or not kubeconfig.strip():
        raise Refused(400, "kubeconfig is required")
    timeout = payload.get("timeout") or 900
    if not isinstance(timeout, int) or timeout <= 0:
        raise Refused(400, "timeout must be a positive number of seconds")
    timeout = min(timeout, MAX_TIMEOUT)
    workdir = tempfile.mkdtemp(prefix="krr-")
    try:
        config = os.path.join(workdir, "kubeconfig")
        with open(os.open(config, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fh:
            fh.write(kubeconfig)
        output = os.path.join(workdir, "result.json")
        argv = command(payload.get("strategy", "simple"), payload.get("args") or [], config, output)
        if not _slots.acquire(timeout=timeout):
            raise Refused(503, f"{CONCURRENCY} krr run(s) already in progress, try again later")
        try:
            started = time.monotonic()
            done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=workdir, check=False)
        except subprocess.TimeoutExpired as exc:
            raise Refused(504, f"krr did not finish within {timeout}s") from exc
        finally:
            _slots.release()
        if done.returncode != 0 or not os.path.exists(output):
            raise Refused(502, error_message(done.stderr))
        with open(output) as fh:
            result = json.load(fh)
        result.pop("config", None)  # the settings of the run, with the Prometheus credentials
        log.info("krr %s done in %.0fs: %d scan(s)", argv[len(KRR)], time.monotonic() - started, len(result.get("scans") or []))
        return {"result": result}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "kube-tower-krr"

    def _answer(self, status: int, body: dict | str) -> None:
        data = (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain" if isinstance(body, str) else "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path == "/healthz":
            self._answer(200, "ok")
        else:
            self._answer(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        if self.path != "/run":
            self._answer(404, {"error": "not found"})
            return
        try:
            authorize(self.headers.get("Authorization"))
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= MAX_BODY:
                raise Refused(400, "a JSON body of at most 1 MiB is required")
            try:
                payload = json.loads(self.rfile.read(length))
            except ValueError as exc:
                raise Refused(400, f"invalid JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise Refused(400, "the body must be a JSON object")
            self._answer(200, run(payload))
        except Refused as exc:
            log.warning("request refused or failed (%d): %s", exc.status, exc)
            self._answer(exc.status, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - always answer
            log.exception("krr run failed")
            self._answer(500, {"error": f"krr run failed: {exc}"[:MESSAGE_LIMIT]})

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - http.server API
        log.debug("%s %s", self.address_string(), format % args)


def main() -> None:
    logging.basicConfig(level=os.environ.get("KRR_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)  # noqa: S104 - reached through its Service
    log.info(
        "listening on :%d, %d krr run(s) at a time, callers: %s", PORT, CONCURRENCY, ", ".join(sorted(ALLOWED_USERS)) or "none"
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
