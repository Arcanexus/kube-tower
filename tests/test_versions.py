import pytest

from kube_tower.versions import is_newer, latest_matching, latest_semver, parse, update_kind, versioning


def test_parse():
    v = parse("v1.2.3-alpine")
    assert v.numbers == (1, 2, 3) and v.prefix == "v" and v.suffix == "-alpine"
    assert parse("latest") is None


@pytest.mark.parametrize(
    "current,candidates,expected",
    [
        ("1.25.3", ["1.25.4", "1.26.0", "latest", "1.27", "2.0.0-rc1"], "1.26.0"),
        ("1.25.3-alpine", ["1.26.0", "1.26.1-alpine", "1.27.0-alpine3.20"], "1.26.1-alpine"),
        ("v2.1", ["v2.2", "2.3", "v3.0.0"], "v2.2"),
        ("1.0.0", ["0.9.0"], "1.0.0"),
        ("latest", ["1.0.0"], None),
    ],
)
def test_latest_matching(current, candidates, expected):
    assert latest_matching(current, candidates) == expected


def test_latest_matching_prerelease():
    assert latest_matching("1.0.0-rc1", ["1.1.0-rc1"], include_prerelease=True) == "1.1.0-rc1"
    assert latest_matching("1.0.0-rc1", ["1.1.0-rc1"]) == "1.0.0-rc1"
    assert parse("1.x") is None


def test_latest_semver():
    assert latest_semver(["1.2.0", "1.10.0", "1.9.9", "2.0.0-beta.1"]) == "1.10.0"
    assert latest_semver(["2.0.0-beta.1"], include_prerelease=True) == "2.0.0-beta.1"
    assert latest_semver(["abc"]) is None


def test_is_newer():
    assert is_newer("1.2.4", "1.2.3")
    assert is_newer("1.0.0", "1.0.0-rc1")
    assert not is_newer("1.2.3", "1.2.3")
    assert not is_newer(None, "1.2.3")


@pytest.mark.parametrize(
    ("current", "latest", "expected"),
    [
        ("1.2.3", "2.0.0", "major"),
        ("v1.2.3", "v1.3.0", "minor"),
        ("1.25", "1.27", "minor"),
        ("1.2.3", "1.2.4", "patch"),
        ("1.0.0-rc1", "1.0.0", "patch"),
        ("1.2.3", "1.2.3", ""),
        ("latest", "1.0", ""),
        (None, "1.0", ""),
        ("1.0", None, ""),
    ],
)
def test_update_kind(current, latest, expected):
    assert update_kind(current, latest) == expected


def test_prerelease_identifiers_compared_as_numbers():
    tags = ["1.0.0-rc.9", "1.0.0-rc.10", "1.0.0-rc.2"]
    assert latest_semver(tags, include_prerelease=True) == "1.0.0-rc.10"
    assert latest_semver(["2.0.0-rc9", "2.0.0-rc10"], include_prerelease=True) == "2.0.0-rc10"
    assert latest_semver(["1.0.0-beta.11", "1.0.0-rc.1"], include_prerelease=True) == "1.0.0-rc.1"
    assert latest_semver(["1.0.0-alpha", "1.0.0-alpha.1"], include_prerelease=True) == "1.0.0-alpha.1"
    assert latest_semver(["1.0.0-rc.1", "1.0.0"], include_prerelease=True) == "1.0.0"
    assert is_newer("1.0.0-rc.10", "1.0.0-rc.9") and not is_newer("1.0.0-rc.9", "1.0.0-rc.10")
    assert not is_newer("1.0.0+build.2", "1.0.0+build.1")  # build metadata does not order versions


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("1.25.3", "semver"),
        ("v2.1-alpine", "semver"),
        ("7", "semver"),
        ("999", "semver"),
        ("2024.10.1", "calver"),
        ("v2024.10", "calver"),
        ("20241024", "date"),
        ("20241024.1", "date"),
        ("202410241530", "date"),
        ("20241399", "build"),  # not a date
        ("4521", "build"),
        ("2024", "build"),  # a year alone is no calendar version
        ("latest", ""),
        (None, ""),
    ],
)
def test_versioning(tag, expected):
    assert versioning(tag) == expected


@pytest.mark.parametrize(
    ("current", "candidates", "expected"),
    [
        ("7", ["4521", "8", "20241024"], "8"),
        ("4521", ["7", "4600"], "4600"),
        ("1.2", ["2024.10", "1.3"], "1.3"),
        ("2024.10", ["1.3", "2024.11"], "2024.11"),
        ("20241024", ["99999999", "4521", "20241101"], "20241101"),
    ],
)
def test_latest_matching_same_scheme(current, candidates, expected):
    assert latest_matching(current, candidates) == expected


@pytest.mark.parametrize(
    ("current", "latest"),
    [("2024.10.1", "2025.1.0"), ("20241024", "20241101"), ("4521", "4600"), ("2024.10", "2024.11")],
)
def test_update_kind_not_semver(current, latest):
    assert update_kind(current, latest) == "newer"
