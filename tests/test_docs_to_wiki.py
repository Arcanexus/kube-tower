"""Tests of .github/scripts/docs_to_wiki.py, which publishes docs/ to the GitHub wiki."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SPEC = importlib.util.spec_from_file_location("docs_to_wiki", ROOT / ".github" / "scripts" / "docs_to_wiki.py")
wiki = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wiki)

REPO = "https://github.com/Arcanexus/kube-tower"
PAGES = {"README.md": "Home", "usage.md": "Usage", "adr/0001-architecture.md": "ADR-0001-kube-tower-architecture"}


def rewrite(target: str, source: str = "usage.md") -> str:
    return wiki.rewrite_target(target, source, PAGES, REPO, "main")


@pytest.mark.parametrize(
    ("target", "source", "expected"),
    [
        ("usage.md", "README.md", "Usage"),
        ("usage.md#images", "README.md", "Usage#images"),
        ("../usage.md#x", "adr/0001-architecture.md", "Usage#x"),
        ("adr/0001-architecture.md", "usage.md", "ADR-0001-kube-tower-architecture"),
        ("images/a.png", "usage.md", "images/a.png"),
        ("../images/a.png", "adr/0001-architecture.md", "images/a.png"),
        ("../deploy/rbac.yaml", "usage.md", f"{REPO}/blob/main/deploy/rbac.yaml"),
        ("../CHANGELOG.md", "usage.md", f"{REPO}/blob/main/CHANGELOG.md"),
        ("../README.md#quick-start", "usage.md", f"{REPO}/blob/main/README.md#quick-start"),
        ("../charts/kube-tower/", "usage.md", f"{REPO}/tree/main/charts/kube-tower"),
        ("/LICENSE", "usage.md", f"{REPO}/blob/main/LICENSE"),
        ("#anchor", "usage.md", "#anchor"),
        ("https://example.com/a.md", "usage.md", "https://example.com/a.md"),
        ("mailto:a@b.c", "usage.md", "mailto:a@b.c"),
    ],
)
def test_rewrite_target(target, source, expected):
    assert rewrite(target, source) == expected


def test_convert_rewrites_links_but_not_code_and_drops_the_title():
    text = "\n".join(
        [
            "# Usage",
            "",
            'See [home](README.md "Home page") and ![img](images/a.png).',
            '<img src="images/b.png" width="10"> <a href="../deploy/x.yaml">x</a>',
            "```md",
            "[kept](README.md)",
            "# not a title",
            "```",
            "# Second H1 kept",
        ]
    )
    out = wiki.convert(text, "usage.md", PAGES, REPO, "main")
    assert "# Usage" not in out
    assert '[home](Home "Home page")' in out
    assert "![img](images/a.png)" in out
    assert '<img src="images/b.png" width="10">' in out
    assert f'<a href="{REPO}/blob/main/deploy/x.yaml">' in out
    assert "[kept](README.md)" in out and "# not a title" in out
    assert "# Second H1 kept" in out
    assert out.endswith(f"_This page is generated from [docs/usage.md]({REPO}/blob/main/docs/usage.md): edit it there._\n")


def test_wiki_name():
    assert wiki.wiki_name("ADR 0002: horizontal scaling (roles)") == "ADR-0002-horizontal-scaling-roles"


def make_docs(tmp_path: Path, extra: str | None = None) -> Path:
    docs = tmp_path / "docs"
    (docs / "adr").mkdir(parents=True)
    (docs / "images").mkdir()
    (docs / "images" / "a.png").write_bytes(b"png")
    (docs / "README.md").write_text("# Docs\n\n[Usage](usage.md)\n")
    for _, entries in wiki.PAGES:
        for source, _ in entries:
            (docs / source).write_text(f"# {source}\n\n![a](images/a.png)\n")
    (docs / "adr" / "0001-x.md").write_text("# ADR 0001: the first choice\n\n[back](../README.md)\n")
    if extra:
        (docs / extra).write_text("# Extra\n")
    return docs


def test_build_writes_pages_sidebar_and_images(tmp_path):
    docs = make_docs(tmp_path)
    out = tmp_path / "wiki"
    (out / ".git").mkdir(parents=True)
    (out / "Old-page.md").write_text("removed from docs/")
    (out / "old-dir").mkdir()
    names = wiki.build(docs, out, REPO, "main")
    assert "Home" in names and "ADR-0001-the-first-choice" in names
    assert (out / ".git").is_dir()
    assert not (out / "Old-page.md").exists() and not (out / "old-dir").exists()
    assert (out / "images" / "a.png").read_bytes() == b"png"
    assert "[Usage](Usage)" in (out / "Home.md").read_text()
    assert "[back](Home)" in (out / "ADR-0001-the-first-choice.md").read_text()
    side = (out / "_Sidebar.md").read_text()
    assert "**[Home](Home)**" in side
    assert "- [Metrics and Grafana](Metrics-and-Grafana)" in side
    assert "- [ADR 0001: the first choice](ADR-0001-the-first-choice)" in side


def test_a_page_missing_from_the_sidebar_is_an_error(tmp_path, capsys):
    docs = make_docs(tmp_path, extra="new-page.md")
    assert wiki.main([str(docs), str(tmp_path / "wiki")]) == 1
    assert "new-page.md" in capsys.readouterr().err


def test_a_listed_page_missing_from_docs_is_an_error(tmp_path):
    docs = make_docs(tmp_path)
    (docs / "usage.md").unlink()
    with pytest.raises(wiki.DocsError, match="usage.md"):
        wiki.page_map(docs)


def test_the_real_docs_build(tmp_path, capsys):
    """Every page of docs/ is in the sidebar and every link to another page or image of docs/ resolves."""
    out = tmp_path / "wiki"
    assert wiki.main([str(ROOT / "docs"), str(out)]) == 0
    assert "wiki pages written" in capsys.readouterr().out
    names = {p.stem for p in out.glob("*.md")}
    for page in out.glob("*.md"):
        for target in wiki.MD_LINK.findall(page.read_text()):
            link = target[1].partition("#")[0]
            if not link or "://" in link:
                continue
            assert link in names or (out / link).is_file(), f"{page.name}: broken link {target[1]}"
