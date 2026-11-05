"""Nodes of a cluster for the Clusters page: role, node group, versions and state.

The image inventory reads the nodes anyway (the images they cache, their sizes): it builds the NodeInfo
from the same list. collect_nodes() reads them alone when the images are not collected.
"""

from __future__ import annotations

import logging
from datetime import datetime

from kubernetes import client

from kube_tower.clusters import Cluster
from kube_tower.errors import kubernetes_hint
from kube_tower.models import NodeInfo

log = logging.getLogger(__name__)

ROLE_PREFIX = "node-role.kubernetes.io/"
CONTROL_PLANE_ROLES = {"control-plane", "master"}
ZONE_LABEL = "topology.kubernetes.io/zone"
INSTANCE_TYPE_LABEL = "node.kubernetes.io/instance-type"


def _map(value) -> dict:
    """A free-form map of a node (labels, capacity) as a dict, read from a client model or raw JSON."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    return getattr(value, "_data", None) or {}


def _time(value) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


_UNITS = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "K": 10**3, "M": 10**6, "G": 10**9, "T": 10**12}


def memory_size(quantity: str) -> str:
    """16303540Ki -> 15.5 GiB: the memory capacity of a node, as people read it."""
    quantity = str(quantity or "").strip()
    unit = next((u for u in sorted(_UNITS, key=len, reverse=True) if quantity.endswith(u)), "")
    try:
        size = float(quantity.removesuffix(unit) or "x") * _UNITS.get(unit, 1)
    except ValueError:
        return quantity
    return f"{size / 2**30:.1f} GiB"


def node_role(labels: dict) -> str:
    """control-plane for the control plane nodes, else the first other node-role label, else worker."""
    roles = sorted(key.removeprefix(ROLE_PREFIX) for key in labels if key.startswith(ROLE_PREFIX))
    roles = [r for r in roles if r]
    if CONTROL_PLANE_ROLES & set(roles):
        return "control-plane"
    return roles[0] if roles else "worker"


def node_info(cluster: str, node, pool_labels: list[str]) -> NodeInfo:
    """The NodeInfo of a V1Node (or of the same node read as raw JSON). Missing fields are left empty."""
    labels = _map(getattr(node.metadata, "labels", None))
    status = getattr(node, "status", None)
    info = getattr(status, "node_info", None)
    capacity = _map(getattr(status, "capacity", None))
    conditions = getattr(status, "conditions", None) or []
    ready = next((c.status == "True" for c in conditions if c.type == "Ready"), False)
    problems = sorted(c.type for c in conditions if c.type != "Ready" and c.status == "True")
    try:
        max_pods = int(capacity.get("pods", 0))
    except (TypeError, ValueError):
        max_pods = 0
    return NodeInfo(
        cluster=cluster,
        name=node.metadata.name,
        role=node_role(labels),
        pool=next((labels[k] for k in pool_labels if labels.get(k)), ""),
        kubelet_version=getattr(info, "kubelet_version", None) or "",
        kube_proxy_version=getattr(info, "kube_proxy_version", None) or "",
        os_image=getattr(info, "os_image", None) or "",
        kernel_version=getattr(info, "kernel_version", None) or "",
        container_runtime=getattr(info, "container_runtime_version", None) or "",
        architecture=getattr(info, "architecture", None) or "",
        operating_system=getattr(info, "operating_system", None) or "",
        ready=ready,
        unschedulable=bool(getattr(getattr(node, "spec", None), "unschedulable", None)),
        problems=problems,
        cpu=str(capacity.get("cpu", "")),
        memory=memory_size(capacity.get("memory", "")),
        max_pods=max_pods,
        zone=labels.get(ZONE_LABEL, ""),
        instance_type=labels.get(INSTANCE_TYPE_LABEL, ""),
        created_at=_time(getattr(node.metadata, "creation_timestamp", None)),
    )


def collect_nodes(cluster: Cluster, pool_labels: list[str]) -> tuple[list[NodeInfo], list[str]]:
    """The nodes of a cluster, and the error when they cannot be listed."""
    try:
        nodes = client.CoreV1Api(cluster.api_client).list_node().items
    except client.ApiException as exc:
        message = f"[{cluster.name}] cannot list nodes: {exc.status} {exc.reason}"
        if hint := kubernetes_hint(exc.status, "nodes"):
            message += f" - {hint}"
        log.warning("%s", message)
        return [], [message]
    return [node_info(cluster.name, n, pool_labels) for n in nodes], []
