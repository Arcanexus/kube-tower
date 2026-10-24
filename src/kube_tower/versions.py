"""Version parsing and comparison helpers shared by image and chart checkers.

Tags are compared only with tags of the same "shape": same `v` prefix, same
number of numeric components and same suffix (e.g. `-alpine`). This avoids
proposing `2.0` for `1.25.3-alpine` or a `-rc1` for a stable release.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

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
        if ver is None or ver.shape != cur.shape:
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
    """Classify an update as `major`, `minor` or `patch` (empty when there is none or it cannot be told)."""
    if not current or not latest or not is_newer(latest, current):
        return ""
    a, b = parse(latest), parse(current)
    for kind, i in (("major", 0), ("minor", 1)):
        if a.numbers[i : i + 1] != b.numbers[i : i + 1]:
            return kind
    return "patch"
