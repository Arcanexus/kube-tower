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


def _semver_suffix_key(suffix: str) -> tuple[int, str]:
    # A release (no suffix) sorts after any pre-release of the same numbers.
    return (1, "") if not suffix else (0, suffix)


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
