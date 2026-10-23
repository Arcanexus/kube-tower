"""Inventory of container images: workloads (running or not) and images cached on nodes."""

from __future__ import annotations

import fnmatch
import logging
from collections.abc import Iterable

from kubernetes import client

from kube_tower.clusters import Cluster
from kube_tower.config import ImagesSettings
from kube_tower.models import ImageRef, ImageReport, Usage
from kube_tower.registry.oci import parse_image_ref

log = logging.getLogger(__name__)


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


class ImageInventory:
    """Accumulates image usages, deduplicated by image reference (without digest)."""

    def __init__(self, settings: ImagesSettings):
        self.settings = settings
        self.reports: dict[str, ImageReport] = {}

    def ignored(self, ref: ImageRef) -> bool:
        return any(fnmatch.fnmatch(ref.name, pattern) or fnmatch.fnmatch(str(ref), pattern) for pattern in self.settings.ignore)

    def add(self, image: str, usage: Usage, running_digest: str | None = None) -> None:
        ref = parse_image_ref(image)
        if self.ignored(ref):
            return
        key_ref = ImageRef(ref.registry, ref.repository, ref.tag, None if ref.tag else ref.digest)
        report = self.reports.setdefault(str(key_ref), ImageReport(image=key_ref))
        if usage not in report.usages:
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

        def safe(what: str, fn):
            try:
                return fn().items
            except client.ApiException as exc:
                errors.append(f"[{cluster.name}] cannot list {what}: {exc.status} {exc.reason}")
                return []

        for pod in safe("pods", core.list_pod_for_all_namespaces):
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
                for name, image in _pod_spec_images(obj.spec.template.spec):
                    self.add(image, Usage(cluster.name, kind, obj.metadata.namespace, obj.metadata.name, name))

        for cron in safe("CronJob", batch.list_cron_job_for_all_namespaces):
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
        return errors
