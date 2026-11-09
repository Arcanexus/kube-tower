"""Checks a release tag and writes the notes of its GitHub Release (run by .github/workflows/release.yml).

The version being prepared is written in pyproject.toml and in charts/kube-tower/Chart.yaml (version and
appVersion). A tag must match it: v1.3.0, or a release candidate v1.3.0-rc.1. A final tag also needs its
`## [1.3.0] - <date>` section in CHANGELOG.md; the notes of a release candidate come from that section when
it exists, else from `## [Unreleased]`.

Usage: python .github/scripts/release.py <tag> [--root DIR] [--notes FILE]
Prints the problems and exits with 1 when the tag does not match, else writes the notes to FILE (or stdout).
"""

import argparse
import re
import sys
import tomllib
from pathlib import Path

REPO = "Arcanexus/kube-tower"
TAG = re.compile(r"v(?P<version>\d+\.\d+\.\d+)(?P<pre>-rc\.\d+)?")


def parse_tag(tag: str) -> tuple[str, bool]:
    """The version of a tag (v1.3.0-rc.1 -> 1.3.0) and whether it is a release candidate."""
    match = TAG.fullmatch(tag)
    if not match:
        raise ValueError(f"{tag}: a release tag is vX.Y.Z or vX.Y.Z-rc.N")
    return match["version"], match["pre"] is not None


def project_versions(root: Path) -> dict[str, str]:
    """The versions written in the repository, by file."""
    pyproject = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    chart = (root / "charts" / "kube-tower" / "Chart.yaml").read_text()

    def field(name: str) -> str:
        match = re.search(rf"^{name}:\s*[\"']?([^\"'\s]+)", chart, re.M)
        return match[1] if match else ""

    return {
        "pyproject.toml version": pyproject,
        "Chart.yaml version": field("version"),
        "Chart.yaml appVersion": field("appVersion"),
    }


def changelog_section(changelog: str, title: str) -> str | None:
    """The body of the `## [title]` section, without its heading, or None."""
    match = re.search(rf"^## \[{re.escape(title)}\][^\n]*\n(.*?)(?=^## \[|\Z)", changelog, re.M | re.S)
    if not match:
        return None
    # Reference links at the end of the file belong to no section
    body = re.sub(r"^\[[^\]]+\]: \S+\s*$", "", match[1], flags=re.M)
    return body.strip()


def check(tag: str, root: Path) -> tuple[list[str], str]:
    """The problems of a tag, and the notes of its release."""
    try:
        version, candidate = parse_tag(tag)
    except ValueError as exc:
        return [str(exc)], ""
    problems = [
        f"{name} is {found or 'missing'}, the tag {tag} needs {version}"
        for name, found in project_versions(root).items()
        if found != version
    ]
    changelog = (root / "CHANGELOG.md").read_text()
    section = changelog_section(changelog, version)
    if section is None and not candidate:
        problems.append(f"CHANGELOG.md has no '## [{version}] - <date>' section: rename [Unreleased] before the tag")
    if section is None:
        section = changelog_section(changelog, "Unreleased") or ""
    return problems, notes(tag, section)


def absolute_links(text: str, tag: str) -> str:
    """Relative links of the CHANGELOG (docs/x.md#y) point to the files of the tag: a release page has no base."""
    return re.sub(r"\]\((?!https?:|#|mailto:)([^)\s]+)\)", rf"](https://github.com/{REPO}/blob/{tag}/\1)", text)


def notes(tag: str, section: str) -> str:
    version = tag.removeprefix("v")
    owner = REPO.split("/")[0].lower()
    section = absolute_links(section, tag)
    return (
        f"{section or f'See the [changelog](https://github.com/{REPO}/blob/{tag}/CHANGELOG.md).'}\n\n"
        "## Install\n\n"
        f"- Image: `ghcr.io/{REPO.lower()}:{version}`\n"
        f"- Chart: `helm install kube-tower oci://ghcr.io/{owner}/charts/kube-tower --version {version}`\n\n"
        f"Read the [upgrade notes](https://github.com/{REPO}/wiki/Upgrading) before upgrading.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tag")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--notes", type=Path, help="file to write the release notes to")
    args = parser.parse_args(argv)
    problems, text = check(args.tag, args.root)
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    if args.notes:
        args.notes.write_text(text)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
