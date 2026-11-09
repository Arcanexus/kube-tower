"""Tests of .github/scripts/release.py, which checks a release tag and writes the notes of its GitHub Release."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SPEC = importlib.util.spec_from_file_location("release", ROOT / ".github" / "scripts" / "release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)

CHANGELOG = """# Changelog

## [Unreleased]

### Added

- Next thing, see [usage](docs/usage.md#x).

## [1.2.0] - 2026-11-06

### Fixed

- A fix ([wiki](https://example.org/wiki)).

## [1.1.0] - 2026-11-04

- Older.
"""


def repo(tmp_path: Path, version: str = "1.2.0", app_version: str | None = None, changelog: str = CHANGELOG) -> Path:
    (tmp_path / "charts" / "kube-tower").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(f'[project]\nname = "kube-tower"\nversion = "{version}"\n')
    (tmp_path / "charts" / "kube-tower" / "Chart.yaml").write_text(
        f'apiVersion: v2\nname: kube-tower\nversion: {version}\nappVersion: "{app_version or version}"\n'
    )
    (tmp_path / "CHANGELOG.md").write_text(changelog)
    return tmp_path


def test_repository_versions_match():
    """pyproject.toml and Chart.yaml carry the same version, the one being prepared."""
    versions = set(release.project_versions(ROOT).values())
    assert len(versions) == 1, versions
    assert release.TAG.fullmatch("v" + versions.pop())


@pytest.mark.parametrize(
    ("tag", "expected"),
    [("v1.3.0", ("1.3.0", False)), ("v1.3.0-rc.2", ("1.3.0", True)), ("v10.0.12", ("10.0.12", False))],
)
def test_parse_tag(tag, expected):
    assert release.parse_tag(tag) == expected


@pytest.mark.parametrize("tag", ["1.3.0", "v1.3", "v1.3.0-beta.1", "v1.3.0-rc", "main"])
def test_parse_tag_rejects(tag):
    with pytest.raises(ValueError, match="vX.Y.Z"):
        release.parse_tag(tag)


def test_final_tag_notes(tmp_path):
    problems, notes = release.check("v1.2.0", repo(tmp_path))
    assert problems == []
    assert notes.startswith("### Fixed\n\n- A fix ([wiki](https://example.org/wiki)).\n\n## Install")
    assert "Older" not in notes
    assert "`ghcr.io/arcanexus/kube-tower:1.2.0`" in notes
    assert "oci://ghcr.io/arcanexus/charts/kube-tower --version 1.2.0`" in notes


def test_release_candidate_uses_unreleased(tmp_path):
    problems, notes = release.check("v1.3.0-rc.1", repo(tmp_path, "1.3.0"))
    assert problems == []
    assert notes.startswith("### Added\n\n- Next thing, see [usage]")
    # Relative links point to the files of the tag
    assert "(https://github.com/Arcanexus/kube-tower/blob/v1.3.0-rc.1/docs/usage.md#x)" in notes
    assert ":1.3.0-rc.1`" in notes


def test_release_candidate_uses_its_section(tmp_path):
    problems, notes = release.check("v1.2.0-rc.3", repo(tmp_path))
    assert problems == []
    assert notes.startswith("### Fixed")


def test_final_tag_needs_its_section(tmp_path):
    problems, _ = release.check("v1.3.0", repo(tmp_path, "1.3.0"))
    assert problems == ["CHANGELOG.md has no '## [1.3.0] - <date>' section: rename [Unreleased] before the tag"]


def test_versions_must_match_the_tag(tmp_path):
    problems, _ = release.check("v1.2.0", repo(tmp_path, "1.3.0", app_version="1.2.0"))
    assert problems == [
        "pyproject.toml version is 1.3.0, the tag v1.2.0 needs 1.2.0",
        "Chart.yaml version is 1.3.0, the tag v1.2.0 needs 1.2.0",
    ]


def test_bad_tag(tmp_path):
    assert release.check("latest", repo(tmp_path)) == (["latest: a release tag is vX.Y.Z or vX.Y.Z-rc.N"], "")


def test_empty_changelog(tmp_path):
    problems, notes = release.check("v1.2.0-rc.1", repo(tmp_path, changelog="# Changelog\n"))
    assert problems == []
    assert notes.startswith("See the [changelog](https://github.com/Arcanexus/kube-tower/blob/v1.2.0-rc.1/CHANGELOG.md).")


def test_main(tmp_path, capsys):
    root = repo(tmp_path)
    out = tmp_path / "notes.md"
    assert release.main(["v1.2.0", "--root", str(root), "--notes", str(out)]) == 0
    assert out.read_text().startswith("### Fixed")
    assert release.main(["v1.2.0", "--root", str(root)]) == 0
    assert capsys.readouterr().out.startswith("### Fixed")
    assert release.main(["v1.1.1", "--root", str(root)]) == 1
    assert "error: pyproject.toml version is 1.2.0, the tag v1.1.1 needs 1.1.1" in capsys.readouterr().err
