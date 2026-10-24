"""Version parsing and comparison helpers shared by image and chart checkers.

Tags are compared only with tags of the same "shape": same `v` prefix, same
number of numeric components and same suffix (e.g. `-alpine`), and of the same
versioning scheme (semver, calendar, date, build number). This avoids proposing
`2.0` for `1.25.3-alpine`, a `-rc1` for a stable release, `2024.10` for `1.2` or
a build number `4521` for `redis:7`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

_TAG_RE = re.compile(r"^(?P<prefix>v?)(?P<numbers>\d+(?:\.\d+){0,3})(?P<suffix>.*)$")
_PRERELEASE_RE = re.compile(r"(alpha|beta|rc|dev|pre|snapshot|nightly|canary)", re.IGNORECASE)


@dataclass(frozen=True, order=True)
class Version:
    numbers: tuple[int, ...]
    prefix: str
    suffix: str
    raw: str

    @property
    def shape(self) -> tuple[str, int, str]:
        return (self.prefix, len(self.numbers), self.suffix)

    @property
    def is_prerelease(self) -> bool:
        return bool(_PRERELEASE_RE.search(self.suffix))


class Scheme(StrEnum):
    """How a repository numbers its versions, told from one tag."""

    SEMVER = "semver"  # 1.25.3, v2.1, 7 (major only)
    CALVER = "calver"  # 2024.10.1, 2024.10 (the year first)
    DATE = "date"  # 20241024, 20241024.1, 202410241530 (a date first)
    BUILD = "build"  # 4521 (a build or pipeline number)


def _is_date(number: int) -> bool:
    digits = str(number)
    if len(digits) not in (8, 10, 12, 14):  # YYYYMMDD, then hours, minutes, seconds
        return False
    try:
        return 1990 <= datetime.strptime(digits[:8], "%Y%m%d").year <= 2100
    except ValueError:
        return False


def scheme(version: Version) -> Scheme:
    first = version.numbers[0]
    if _is_date(first):
        return Scheme.DATE
    if 1990 <= first <= 2100 and len(version.numbers) > 1:
        return Scheme.CALVER
    if len(version.numbers) == 1 and first >= 1000:
        return Scheme.BUILD
    return Scheme.SEMVER


def versioning(tag: str | None) -> str:
    """The versioning scheme of a tag (see Scheme), empty for a tag without version (`latest`)."""
    version = parse(tag) if tag else None
    return scheme(version).value if version else ""


def parse(tag: str) -> Version | None:
    """Parse a tag like `v1.2.3-alpine`; return None for non versioned tags (`latest`)."""
    match = _TAG_RE.match(tag)
    if not match or match["suffix"].startswith((".", "*")):
        # "1.x", "1.2.*": version constraints, not versions
        return None
    numbers = tuple(int(n) for n in match["numbers"].split("."))
    return Version(numbers=numbers, prefix=match["prefix"], suffix=match["suffix"], raw=tag)


_IDENTIFIER_RE = re.compile(r"\d+|[^\d.\-+]+")


def _semver_suffix_key(suffix: str) -> tuple:
    """Order pre-releases like semver: identifiers compared one by one, numbers as numbers (`rc.9` <
    `rc.10`, also `rc9` < `rc10`), numbers before words, fewer identifiers first. Build metadata (`+...`)
    is ignored. A release (no suffix) sorts after any pre-release of the same numbers.
    """
    suffix = suffix.partition("+")[0]
    if not suffix:
        return (1, ())
    return (0, tuple((0, int(i), "") if i.isdigit() else (1, 0, i) for i in _IDENTIFIER_RE.findall(suffix)))


def latest_matching(current: str, candidates: list[str], include_prerelease: bool = False) -> str | None:
    """Return the highest candidate sharing the shape of `current`, or None if `current` is not versioned."""
    cur = parse(current)
    if cur is None:
        return None
    best = cur
    for tag in candidates:
        ver = parse(tag)
        if ver is None or ver.shape != cur.shape or scheme(ver) != scheme(cur):
            continue
        if ver.is_prerelease and not include_prerelease:
            continue
        if ver.numbers > best.numbers:
            best = ver
    return best.raw


def latest_semver(candidates: list[str], include_prerelease: bool = False) -> str | None:
    """Return the highest semver-like version, ignoring shape (used for Helm charts)."""
    best: Version | None = None
    for tag in candidates:
        ver = parse(tag)
        if ver is None:
            continue
        if ver.is_prerelease and not include_prerelease:
            continue
        if best is None or (ver.numbers, _semver_suffix_key(ver.suffix)) > (
            best.numbers,
            _semver_suffix_key(best.suffix),
        ):
            best = ver
    return best.raw if best else None


def is_newer(candidate: str | None, current: str) -> bool:
    if candidate is None:
        return False
    a, b = parse(candidate), parse(current)
    if a is None or b is None:
        return False
    return (a.numbers, _semver_suffix_key(a.suffix)) > (b.numbers, _semver_suffix_key(b.suffix))


def update_kind(current: str | None, latest: str | None) -> str:
    """Classify an update as `major`, `minor` or `patch`, or `newer` for versions that are not semver
    (calendar, date, build number); empty when there is none.
    """
    if not current or not latest or not is_newer(latest, current):
        return ""
    a, b = parse(latest), parse(current)
    if scheme(b) != Scheme.SEMVER:  # a newer calendar version, date or build number: no major/minor/patch
        return "newer"
    for kind, i in (("major", 0), ("minor", 1)):
        if a.numbers[i : i + 1] != b.numbers[i : i + 1]:
            return kind
    return "patch"
