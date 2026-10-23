"""Inventory of Helm charts deployed by ArgoCD Applications."""

from __future__ import annotations

import logging

from kubernetes import client

from kube_tower.clusters import Cluster
from kube_tower.config import HelmSettings
from kube_tower.models import ChartReport

log = logging.getLogger(__name__)

ARGO_GROUP, ARGO_VERSION, ARGO_PLURAL = "argoproj.io", "v1alpha1", "applications"


def _sources(app: dict) -> list[tuple[dict, str | None]]:
    """Return (source, sourceType) pairs for single and multi-source Applications."""
    spec, status = app.get("spec", {}), app.get("status", {})
    if spec.get("sources"):
        types = status.get("sourceTypes") or []
        return [(src, types[i] if i < len(types) else None) for i, src in enumerate(spec["sources"])]
    if spec.get("source"):
        return [(spec["source"], status.get("sourceType"))]
    return []


def charts_from_application(cluster: str, app: dict) -> list[ChartReport]:
    meta = app.get("metadata", {})
    destination = app.get("spec", {}).get("destination", {})
    reports = []
    for source, source_type in _sources(app):
        repo = source.get("repoURL", "")
        base = dict(
            cluster=cluster,
            application=meta.get("name", ""),
            app_namespace=meta.get("namespace", ""),
            repository=repo,
            version=source.get("targetRevision") or "",
            destination_namespace=destination.get("namespace"),
        )
        if source.get("chart"):
            kind = "oci" if repo.startswith("oci://") or "://" not in repo else "helm"
            reports.append(ChartReport(chart=source["chart"], source_type=kind, **base))
        elif source.get("path") is not None and source_type in (None, "Helm"):
            # Git path: the chart version is read from Chart.yaml by the checker. A None
            # sourceType (app never synced) is kept and reported as an error without Chart.yaml.
            base["version"] = ""
            git_ref = source.get("targetRevision") or "HEAD"
            reports.append(ChartReport(chart=source["path"] or ".", source_type="git", git_ref=git_ref, **base))
    return reports


def collect_charts(cluster: Cluster, settings: HelmSettings) -> tuple[list[ChartReport], list[str]]:
    api = client.CustomObjectsApi(cluster.api_client)
    apps: list[dict] = []
    errors: list[str] = []
    try:
        if settings.application_namespaces:
            for ns in settings.application_namespaces:
                apps += api.list_namespaced_custom_object(ARGO_GROUP, ARGO_VERSION, ns, ARGO_PLURAL)["items"]
        else:
            apps = api.list_cluster_custom_object(ARGO_GROUP, ARGO_VERSION, ARGO_PLURAL)["items"]
    except client.ApiException as exc:
        if exc.status == 404:
            log.info("ArgoCD Application CRD not found on cluster %s", cluster.name)
        else:
            errors.append(f"[{cluster.name}] cannot list ArgoCD Applications: {exc.status} {exc.reason}")
        return [], errors
    reports = [r for app in apps for r in charts_from_application(cluster.name, app)]
    return reports, errors
