"""What a user whose roles are limited to some clusters sees (auth.roles.<role>.clusters).

The snapshot is cut down to those clusters: their images (with only their usages), charts, statuses,
Trivy Operator reports, CPU and memory recommendations and the scan errors that name no other cluster.
Built for each request from the snapshot of the backend, which is never changed.
"""

from __future__ import annotations

import dataclasses
import re
from fnmatch import fnmatchcase

from kube_tower.models import Snapshot


def cluster_matcher(patterns: tuple[str, ...] | None):
    """A test of a cluster name against fnmatch patterns, None when every cluster is visible."""
    if patterns is None:
        return None
    return lambda name: any(fnmatchcase(name, p) for p in patterns)


def scope_snapshot(snapshot: Snapshot, patterns: tuple[str, ...] | None) -> Snapshot:
    """The part of the snapshot in the clusters matching the patterns (the snapshot itself for None)."""
    visible = cluster_matcher(patterns)
    if visible is None:
        return snapshot
    hidden = [c.name for c in snapshot.clusters if not visible(c.name)]
    images = []
    for report in snapshot.images:
        usages = [u for u in report.usages if visible(u.cluster)]
        if usages:
            images.append(report if len(usages) == len(report.usages) else dataclasses.replace(report, usages=usages))
    # A scan error naming a hidden cluster ("[prod] ...", "cluster prod: ...") is left out.
    names = re.compile(r"(?<![\w.-])(" + "|".join(map(re.escape, hidden)) + r")(?![\w.-])") if hidden else None
    return dataclasses.replace(
        snapshot,
        images=images,
        charts=[c for c in snapshot.charts if visible(c.cluster)],
        clusters=[c for c in snapshot.clusters if visible(c.name)],
        errors=[e for e in snapshot.errors if names is None or not names.search(e)],
        security=[r for r in snapshot.security if visible(r.cluster)],
        compliance=[r for r in snapshot.compliance if visible(r.cluster)],
        trivy_operator=[c for c in snapshot.trivy_operator if visible(c)],
        nodes=[n for n in snapshot.nodes if visible(n.cluster)],
        resources=[r for r in snapshot.resources if visible(r.cluster)],
        resource_scans=[s for s in snapshot.resource_scans if visible(s.cluster)],
    )
