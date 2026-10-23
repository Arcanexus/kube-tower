import pytest

from kube_tower.versions import is_newer, latest_matching, latest_semver, parse


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
