"""Link rewriting and offline validation for generated documentation."""

from __future__ import annotations

import posixpath
import re
from html.parser import HTMLParser
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

SITE_URL = "https://containers.strukturpiloten.de/"
REPOSITORY_URL = "https://github.com/Strukturpiloten/containers"
LINK_RE = re.compile(r"(?<!!)\[([^\]\n]+)\]\(([^\s)]+)(?:\s+\"[^\"]*\")?\)")


def page_url(path: str) -> str:
    """Return the canonical directory URL of a generated Markdown page."""
    if path == "index.md":
        return SITE_URL
    stem = path.removesuffix(".md").removesuffix("/index")
    return f"{SITE_URL}{stem}/"


def rewrite_links(text: str, source: Path, *, root: Path, pages: Mapping[Path, str]) -> str:
    """Preserve repository links and map known source documents to public pages."""

    def replace(match: re.Match[str]) -> str:
        label, target = match.groups()
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            return match.group(0)
        destination = (source.parent / unquote(parsed.path)).resolve()
        if not destination.is_relative_to(root):
            msg = f"Documentation link escapes repository: {source}: {target}"
            raise ValueError(msg)
        if not destination.exists():
            msg = f"Broken repository documentation link: {source}: {target}"
            raise ValueError(msg)
        if destination in pages:
            rewritten = page_url(pages[destination])
        else:
            kind = "tree" if destination.is_dir() else "blob"
            rewritten = f"{REPOSITORY_URL}/{kind}/main/{destination.relative_to(root).as_posix()}"
        if parsed.fragment:
            rewritten += f"#{parsed.fragment}"
        return f"[{label}]({rewritten})"

    # Code examples often contain shell Markdown-like syntax; leave fenced code intact.
    chunks = re.split(r"(^```[^\n]*\n.*?^```\s*$)", text, flags=re.MULTILINE | re.DOTALL)
    return "".join(chunk if index % 2 else LINK_RE.sub(replace, chunk) for index, chunk in enumerate(chunks))


class PageLinks(HTMLParser):
    """Collect rendered anchors, local assets, and search metadata."""

    def __init__(self) -> None:
        """Initialize one rendered page inspection."""
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.ids: set[str] = set()
        self.canonical: list[str] = []
        self.descriptions: list[str] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Read attributes relevant to offline correctness."""
        attributes = dict(attrs)
        if identifier := attributes.get("id"):
            self.ids.add(identifier)
        self._in_title = self._in_title or tag == "title"
        if tag == "link" and attributes.get("rel") == "canonical":
            self.canonical.append(attributes.get("href") or "")
        elif tag in {"a", "link"} and attributes.get("href"):
            self.links.append(str(attributes["href"]))
        elif tag in {"script", "img"} and attributes.get("src"):
            self.links.append(str(attributes["src"]))
        if tag == "meta" and attributes.get("name") == "description":
            self.descriptions.append(attributes.get("content") or "")

    def handle_endtag(self, tag: str) -> None:
        """Track text belonging to the title element."""
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        """Save the rendered title for uniqueness checks."""
        if self._in_title:
            self.title += data


def _local_destination(href: str, source: Path, output: Path) -> tuple[Path, str] | None:
    parsed = urlsplit(href)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return None
    if parsed.netloc and parsed.netloc != urlsplit(SITE_URL).netloc:
        return None
    path = unquote(parsed.path)
    if not path:
        destination = source
    elif path.startswith("/") or parsed.netloc:
        destination = output / path.lstrip("/")
    else:
        destination = source.parent / path
    destination = destination.resolve()
    if destination.is_dir():
        destination /= "index.html"
    return destination, unquote(parsed.fragment)


def validate_site(output: Path) -> int:  # noqa: C901
    """Require valid HTML navigation, anchors, metadata and canonical URLs."""
    output = output.resolve()
    pages: dict[Path, PageLinks] = {}
    for path in sorted(output.rglob("*.html")):
        if path.name == "404.html":
            continue
        document = PageLinks()
        document.feed(path.read_text(encoding="utf-8"))
        pages[path] = document
    errors: list[str] = []
    titles: set[str] = set()
    for path, document in pages.items():
        relative = path.relative_to(output).as_posix()
        route = relative.removesuffix("index.html")
        expected = SITE_URL + route
        if document.canonical != [expected]:
            errors.append(f"{relative}: canonical must be {expected}")
        if not document.title.strip() or document.title in titles:
            errors.append(f"{relative}: missing or duplicate page title")
        titles.add(document.title)
        if len(document.descriptions) != 1 or not document.descriptions[0].strip():
            errors.append(f"{relative}: missing or duplicate description")
        for href in document.links:
            resolved = _local_destination(href, path, output)
            if resolved is None:
                continue
            target, fragment = resolved
            if not target.is_relative_to(output) or not target.is_file():
                errors.append(f"{relative}: missing local target {href}")
            elif fragment and target in pages and fragment not in pages[target].ids:
                errors.append(f"{relative}: missing anchor {href}")
    if errors:
        raise ValueError("Documentation validation failed:\n" + "\n".join(errors[:50]))
    return len(pages)


def relative_markdown_link(source: str, destination: str) -> str:
    """Return the path between virtual Markdown source files."""
    return posixpath.relpath(destination, posixpath.dirname(source))
