"""Versions of an image or a chart shown apart: current, latest minor or patch release, latest major release,
and the age of their release dates (images.releaseAgeDays). Shared by the pages, the Overview and the metrics.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from kube_tower.models import ChartReport, ImageReport, Status
from kube_tower.versions import update_kind


def image_versions(r: ImageReport) -> tuple[tuple[str, str], tuple[str, str]]:
    """((current tag, current digest), (latest tag, latest digest)) of an image, to show both side by side.
    The current digest is the pinned one, else the running one, else the one published for the tag.
    The latest is unknown ("") when the registry could not tell.
    """
    tag = r.image.tag or ""
    running = sorted(r.running_digests)
    current = (tag, r.image.digest or (running[0] if running else "") or r.tag_digest or "")
    if r.latest_tag:
        latest = (r.latest_tag, r.latest_digest or "")
    elif r.status == Status.OUTDATED and r.latest_digest:  # same tag pushed again (latest, 1.25...)
        latest = (tag, r.latest_digest)
    elif r.status == Status.UP_TO_DATE:
        latest = (tag, r.tag_digest or current[1])
    else:
        latest = ("", "")
    return current, latest


# A release older than each of these ages (images.releaseAgeDays) turns yellow, orange, then red.
RELEASE_AGES = ("recent", "aging", "old", "stale")
RELEASE_AGE_TEXT = {
    "recent": "recent",
    "aging": "aging",
    "old": "old",
    "stale": "very old: check that it is still maintained",
}


def release_age(when: datetime | None, days: Sequence[int] = (180, 365, 730), now: datetime | None = None) -> str:
    """The age class of a release date (RELEASE_AGES), empty when unknown. `days`: images.releaseAgeDays."""
    if when is None:
        return ""
    elapsed = ((now or datetime.now(UTC)) - when).days
    return RELEASE_AGES[sum(1 for d in days if elapsed >= d)]


def image_updates(r: ImageReport) -> tuple[tuple[str, str, datetime | None], tuple[str, str, datetime | None]]:
    """((tag, digest, release date) of the latest minor or patch release, same of the latest major release) of
    an image, for their own columns. The first one is the latest of the same major version, the current tag
    when there is none (or the latest of all for versions without major numbers: calendar, date...); the
    second one is empty ("") unless a newer major version is published.
    """
    current, latest = image_versions(r)
    if r.latest_tag and update_kind(r.image.tag, r.latest_tag) == "major":
        major = (r.latest_tag, r.latest_digest or "", r.latest_released)
        if r.minor_tag and r.minor_tag != r.image.tag:
            return (r.minor_tag, "", r.minor_released), major
        return (current[0], r.tag_digest or current[1], r.current_released), major
    released = r.latest_released if latest[0] and latest[0] == r.latest_tag else None
    return (latest[0], latest[1], released), ("", "", None)


def chart_updates(c: ChartReport) -> tuple[tuple[str, datetime | None], tuple[str, datetime | None]]:
    """((version, release date) of the latest minor or patch release, same of the latest major release) of a
    chart, as image_updates. Empty ("") when the repository could not tell (or a chart deployed from git).
    """
    if not c.latest_version:
        return ("", None), ("", None)
    if update_kind(c.version, c.latest_version) == "major":
        major = (c.latest_version, c.latest_released)
        if c.minor_version and c.minor_version != c.version and c.minor_version != c.latest_version:
            return (c.minor_version, c.minor_released), major
        return (c.version, c.current_released), major
    return (c.latest_version, c.latest_released), ("", None)


# Updates told apart by the filters of the Images and Helm charts pages, the Overview and the metrics.
AVAILABLE = {"minor": "minor/patch", "major": "major"}


def available(item: ImageReport | ChartReport) -> set[str]:
    """The kinds of update (AVAILABLE) of an image or a chart: `minor` when a newer release of the same major
    version is published (a new minor or patch version, or a newer calendar or build version), `major` when a
    newer major version is. Both at once when the current version is behind in its own major version too. A
    tag pushed again (new digest) is neither. The subcharts of a chart are not counted.
    """
    if isinstance(item, ImageReport):
        current = item.image.tag
        (minor, *_), (major, *_) = image_updates(item)
        if item.status != Status.OUTDATED:
            return set()
    else:
        current = item.version
        (minor, _), (major, _) = chart_updates(item)
    kinds = {"major"} if major else set()
    if minor and update_kind(current, minor) in ("minor", "patch", "newer"):
        kinds.add("minor")
    return kinds
