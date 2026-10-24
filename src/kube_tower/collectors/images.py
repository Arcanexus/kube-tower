"""Inventory of container images: workloads (running or not) and images cached on nodes."""

from __future__ import annotations

import base64
import dataclasses
import fnmatch
import json
import logging
import threading
import time
from collections.abc import Iterable

from kubernetes import client

from kube_tower.clusters import Cluster
from kube_tower.config import ImagesSettings
from kube_tower.errors import kubernetes_hint
from kube_tower.models import ImageRef, ImageReport, Usage
from kube_tower.registry.oci import parse_docker_config, parse_image_ref

log = logging.getLogger(__name__)

PAGE_SIZE = 250


def _pod_spec_images(spec: client.V1PodSpec | None) -> Iterable[tuple[str, str]]:
    if spec is None:
        return
    for container in [*(spec.init_containers or []), *(spec.containers or []), *(spec.ephemeral_containers or [])]:
        if container.image:
            yield container.name, container.image


def _digest_from_image_id(image_id: str | None) -> str | None:
    # e.g. docker.io/library/nginx@sha256:abc... or docker-pullable://nginx@sha256:...
    if image_id and "@sha256:" in image_id:
        return image_id.split("@", 1)[1]
    return None


PULL_SECRET_KEYS = {"kubernetes.io/dockerconfigjson": ".dockerconfigjson", "kubernetes.io/dockercfg": ".dockercfg"}


def _pull_secret_names(spec: client.V1PodSpec | None) -> Iterable[str]:
    for ref in (spec.image_pull_secrets or []) if spec else []:
        if ref.name:
            yield ref.name


class ImageInventory:
    """Accumulates image usages, deduplicated by image reference (without digest)."""

    def __init__(self, settings: ImagesSettings, pull_secrets: bool = False):
        self.settings = settings
        # Read the image pull secrets of the pods and workloads (registries.useImagePullSecrets).
        self.read_pull_secrets = pull_secrets
        # Their credentials by registry host: the first Secret found for a host wins.
        self.pull_secrets: dict[str, tuple[str, str]] = {}
        self.reports: dict[str, ImageReport] = {}
        # Usages already recorded, per image: a set lookup, not a scan of report.usages (an image used by
        # thousands of pods or present on hundreds of nodes made each add slower than the previous one).
        self._seen: dict[str, set[tuple]] = {}
        self._lock = threading.Lock()  # clusters are collected in parallel threads

    def ignored(self, ref: ImageRef) -> bool:
        return any(fnmatch.fnmatch(ref.name, pattern) or fnmatch.fnmatch(str(ref), pattern) for pattern in self.settings.ignore)

    def add(self, image: str, usage: Usage, running_digest: str | None = None) -> None:
        ref = parse_image_ref(image)
        if self.ignored(ref):
            return
        key_ref = ImageRef(ref.registry, ref.repository, ref.tag, None if ref.tag else ref.digest)
        key = str(key_ref)
        with self._lock:
            report = self.reports.setdefault(key, ImageReport(image=key_ref))
            seen = self._seen.setdefault(key, set())
            if (identity := dataclasses.astuple(usage)) not in seen:
                seen.add(identity)
                report.usages.append(usage)
            if running_digest:
                report.running_digests.add(running_digest)
            elif ref.digest:
                report.running_digests.add(ref.digest)

    def collect(self, cluster: Cluster) -> list[str]:
        """Read every image of a cluster. Returns non fatal error messages."""
        errors: list[str] = []
        core = client.CoreV1Api(cluster.api_client)
        apps = client.AppsV1Api(cluster.api_client)
        batch = client.BatchV1Api(cluster.api_client)
        counts: dict[str, int] = {}
        start = time.monotonic()

        def safe(what: str, fn):
            # Paginated lists: a single huge response holds the GIL while it is parsed and
            # starves the event loop (/healthz times out and the liveness probe kills the pod).
            items, token = [], None
            try:
                while True:
                    page = fn(limit=PAGE_SIZE, _continue=token) if token else fn(limit=PAGE_SIZE)
                    items += page.items
                    token = page.metadata._continue if page.metadata else None
                    if not token:
                        log.debug("[%s] %d %s listed", cluster.name, len(items), what)
                        counts[what] = len(items)
                        return items
            except client.ApiException as exc:
                message = f"[{cluster.name}] cannot list {what}: {exc.status} {exc.reason}"
                if hint := kubernetes_hint(exc.status, what):
                    message += f" - {hint}"
                errors.append(message)
                log.warning("%s", message)
                return items

        secret_refs: set[tuple[str, str]] = set()  # (namespace, name) of the image pull secrets
        for pod in safe("pods", core.list_pod_for_all_namespaces):
            secret_refs |= {(pod.metadata.namespace, name) for name in _pull_secret_names(pod.spec)}
            digests = {
                cs.name: _digest_from_image_id(cs.image_id)
                for cs in [*(pod.status.init_container_statuses or []), *(pod.status.container_statuses or [])]
            }
            for name, image in _pod_spec_images(pod.spec):
                usage = Usage(cluster.name, "Pod", pod.metadata.namespace, pod.metadata.name, name)
                self.add(image, usage, digests.get(name))

        workloads = [
            ("Deployment", apps.list_deployment_for_all_namespaces),
            ("StatefulSet", apps.list_stateful_set_for_all_namespaces),
            ("DaemonSet", apps.list_daemon_set_for_all_namespaces),
        ]
        for kind, fn in workloads:
            for obj in safe(kind, fn):
                secret_refs |= {(obj.metadata.namespace, name) for name in _pull_secret_names(obj.spec.template.spec)}
                for name, image in _pod_spec_images(obj.spec.template.spec):
                    self.add(image, Usage(cluster.name, kind, obj.metadata.namespace, obj.metadata.name, name))

        for cron in safe("CronJob", batch.list_cron_job_for_all_namespaces):
            spec = cron.spec.job_template.spec.template.spec
            secret_refs |= {(cron.metadata.namespace, name) for name in _pull_secret_names(spec)}
            for name, image in _pod_spec_images(cron.spec.job_template.spec.template.spec):
                self.add(image, Usage(cluster.name, "CronJob", cron.metadata.namespace, cron.metadata.name, name))

        if self.settings.include_node_images:
            for node in safe("nodes", core.list_node):
                for node_image in node.status.images or []:
                    names = node_image.names or []
                    digest = next((_digest_from_image_id(n) for n in names if "@sha256:" in n), None)
                    for image in names:
                        if "@sha256:" in image:
                            continue
                        self.add(image, Usage(cluster.name, "Node", None, node.metadata.name), digest)
        if self.read_pull_secrets:
            errors += self._read_pull_secrets(cluster, core, secret_refs)
        log.info(
            "[%s] images collected in %.1fs: %s",
            cluster.name,
            time.monotonic() - start,
            ", ".join(f"{n} {what}" for what, n in counts.items()) or "nothing listed",
        )
        return errors

    def _read_pull_secrets(self, cluster: Cluster, core: client.CoreV1Api, refs: set[tuple[str, str]]) -> list[str]:
        """Read the image pull secrets used on a cluster and keep their registry credentials."""
        found: dict[str, tuple[str, str]] = {}
        denied: list[str] = []
        for namespace, name in sorted(refs):
            try:
                secret = core.read_namespaced_secret(name, namespace)
            except client.ApiException as exc:
                if exc.status in (401, 403):
                    denied.append(f"{namespace}/{name}")
                else:  # e.g. a pull secret referenced but never created
                    log.debug(
                        "[%s] image pull secret %s/%s not read: %s %s", cluster.name, namespace, name, exc.status, exc.reason
                    )
                continue
            key = PULL_SECRET_KEYS.get(secret.type or "")
            raw = (secret.data or {}).get(key or "")
            if not raw:
                continue
            try:
                creds = parse_docker_config(json.loads(base64.b64decode(raw)))
            except (ValueError, AttributeError) as exc:
                log.warning("[%s] image pull secret %s/%s ignored: unreadable %s (%s)", cluster.name, namespace, name, key, exc)
                continue
            for host, pair in creds.items():
                found.setdefault(host, pair)
        with self._lock:
            for host, pair in found.items():
                self.pull_secrets.setdefault(host, pair)
        log.info(
            "[%s] %d image pull secret(s) read: credentials for %s",
            cluster.name,
            len(refs) - len(denied),
            ", ".join(sorted(found)) or "no registry",
        )
        if denied:
            return [
                f"[{cluster.name}] cannot read {len(denied)} image pull secret(s) (e.g. {denied[0]}): 403 Forbidden - "
                "registries.useImagePullSecrets needs `get` on secrets in every namespace (Helm chart: "
                "config.registries.useImagePullSecrets=true adds it for the local cluster, see deploy/remote-cluster-rbac.yaml "
                "for remote ones)"
            ]
        return []
