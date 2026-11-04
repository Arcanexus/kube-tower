"""Builds the GitHub wiki of kube-tower from docs/.

docs/ stays the only source of the documentation: it is versioned and reviewed with the code. This
script turns it into wiki pages (run by .github/workflows/wiki.yml on every push to main):

- docs/README.md becomes Home, every other page gets the name given in PAGES,
- links between pages become wiki links (`installation.md#x` -> `Installation#x`), links to other
  files of the repository become links to GitHub (`../deploy/x.yaml` -> .../blob/main/deploy/x.yaml),
- docs/images/ is copied into the wiki, image links keep working,
- _Sidebar.md lists the pages, each page ends with a link to its source.

Usage: python .github/scripts/docs_to_wiki.py <docs dir> <wiki dir> [--repo-url URL] [--ref main]
The wiki directory is emptied first (its .git is kept).
"""

import argparse
import posixpath
import re
import shutil
import sys
from pathlib import Path

REPO_URL = "https://github.com/Arcanexus/kube-tower"

# Sidebar sections: (title, [(file in docs/, wiki page name), ...]), sorted by what the reader wants to do.
# A page of docs/ missing here is an error, so that a new page is never left out of the wiki. Keep the page
# names: the website, the README and the UI link to them.
PAGES: list[tuple[str, list[tuple[str, str]]]] = [
    ("Getting started", [
        ("quick-start.md", "Quick-start"),
        ("prerequisites.md", "Prerequisites"),
        ("installation.md", "Installation"),
        ("upgrading.md", "Upgrading"),
        ("comparison.md", "Comparison"),
    ]),
    ("Configure", [
        ("clusters.md", "Clusters"),
        ("registries.md", "Registries"),
        ("authentication.md", "Authentication"),
        ("vulnerabilities.md", "Vulnerabilities"),
        ("security.md", "Security"),
        ("scaling.md", "Scaling"),
        ("metrics.md", "Metrics-and-Grafana"),
    ]),
    ("Use the UI", [
        ("usage.md", "Usage"),
        ("statuses.md", "Statuses-and-versions"),
    ]),
    ("Reference", [
        ("configuration.md", "Configuration"),
        ("chart-values.md", "Chart-values"),
        ("api.md", "API"),
        ("permissions.md", "Permissions"),
        ("network.md", "Network-and-ports"),
    ]),
    ("Help", [
        ("troubleshooting.md", "Troubleshooting"),
    ]),
    ("Inside kube-tower", [
        ("architecture.md", "Architecture"),
        ("development.md", "Development"),
    ]),
]  # fmt: skip
HOME = ("README.md", "Home")

FENCE = re.compile(r"^\s*(```|~~~)")
# Markdown links and images: [text](target) or ![alt](target "title")
MD_LINK = re.compile(r"(!?\[[^\]]*\])\(\s*([^)\s]+)((?:\s+\"[^\"]*\")?)\s*\)")
HTML_SRC = re.compile(r"""(<(?:img|a)\b[^>]*?\b(?:src|href)=)(["'])([^"']+)\2""")
H1 = re.compile(r"^#\s+(.+?)\s*$")


class DocsError(Exception):
    pass


def page_map(docs: Path) -> dict[str, str]:
    """docs-relative path (posix) -> wiki page name, for every page of docs/."""
    pages = {HOME[0]: HOME[1]}
    for _, entries in PAGES:
        pages.update(entries)
    found = {p.relative_to(docs).as_posix() for p in docs.rglob("*.md")}
    if missing := sorted(found - pages.keys()):
        raise DocsError(f"pages of docs/ not in the wiki sidebar, add them to PAGES in {Path(__file__).name}: {missing}")
    if absent := sorted(set(pages) - found):
        raise DocsError(f"pages listed in PAGES but missing from docs/: {absent}")
    return pages


def rewrite_target(target: str, source: str, pages: dict[str, str], repo_url: str, ref: str) -> str:
    """New target of a link found in docs/<source>."""
    if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I) or target.startswith(("#", "//")):
        return target  # absolute URL, mailto: or anchor in the same page
    path, _, anchor = target.partition("#")
    if path.startswith("/"):
        resolved = path.lstrip("/")
        in_docs = None
    else:
        resolved = posixpath.normpath(posixpath.join("docs", posixpath.dirname(source), path))
        in_docs = resolved[len("docs/") :] if resolved.startswith("docs/") else None
    suffix = f"#{anchor}" if anchor else ""
    if in_docs in pages:
        return pages[in_docs] + suffix
    if in_docs is not None and in_docs.startswith("images/"):
        return in_docs + suffix  # copied into the wiki
    kind = "tree" if path.endswith("/") else "blob"  # GitHub redirects blob/ of a directory to tree/
    return f"{repo_url}/{kind}/{ref}/{resolved}{suffix}"


def convert(text: str, source: str, pages: dict[str, str], repo_url: str, ref: str) -> str:
    """Wiki version of the page docs/<source>: links rewritten (not in code blocks), title removed."""
    out, in_code, title_done = [], False, False
    for line in text.splitlines():
        if FENCE.match(line):
            in_code = not in_code
        elif not in_code:
            if not title_done and H1.match(line):
                title_done = True  # the wiki shows the page name as title
                continue
            line = MD_LINK.sub(
                lambda m: f"{m.group(1)}({rewrite_target(m.group(2), source, pages, repo_url, ref)}{m.group(3)})", line
            )
            line = HTML_SRC.sub(
                lambda m: f"{m.group(1)}{m.group(2)}{rewrite_target(m.group(3), source, pages, repo_url, ref)}{m.group(2)}",
                line,
            )
        out.append(line)
    body = "\n".join(out).strip("\n")
    source_url = f"{repo_url}/blob/{ref}/docs/{source}"
    return f"{body}\n\n---\n\n_This page is generated from [docs/{source}]({source_url}): edit it there._\n"


def sidebar() -> str:
    lines = [f"**[Home]({HOME[1]})**", ""]
    sections = [(title, [(name, name.replace("-", " ")) for _, name in entries]) for title, entries in PAGES]
    for title, entries in sections:
        lines += [f"**{title}**", ""]
        lines += [f"- [{label}]({name})" for name, label in entries]
        lines.append("")
    return "\n".join(lines)


def build(docs: Path, wiki: Path, repo_url: str = REPO_URL, ref: str = "main") -> list[str]:
    """Writes the wiki into `wiki` (emptied first, .git kept). Returns the written page names."""
    pages = page_map(docs)
    wiki.mkdir(parents=True, exist_ok=True)
    for entry in wiki.iterdir():
        if entry.name == ".git":
            continue
        shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
    for source, name in pages.items():
        text = (docs / source).read_text(encoding="utf-8")
        (wiki / f"{name}.md").write_text(convert(text, source, pages, repo_url, ref), encoding="utf-8")
    (wiki / "_Sidebar.md").write_text(sidebar(), encoding="utf-8")
    if (docs / "images").is_dir():
        shutil.copytree(docs / "images", wiki / "images")
    return sorted(pages.values())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("docs", type=Path)
    parser.add_argument("wiki", type=Path)
    parser.add_argument("--repo-url", default=REPO_URL)
    parser.add_argument("--ref", default="main")
    args = parser.parse_args(argv)
    try:
        names = build(args.docs, args.wiki, args.repo_url.rstrip("/"), args.ref)
    except DocsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"{len(names)} wiki pages written to {args.wiki}: {', '.join(names)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
