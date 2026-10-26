"""Link rewriting and offline validation for generated documentation."""

from __future__ import annotations

import posixpath
import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

SITE_URL = "https://containers.strukturpiloten.de/"
REPOSITORY_URL = "https://github.com/Strukturpiloten/containers"
LINK_RE = re.compile(r"(?<!!)\[([^\]\n]+)\]\(([^\s)]+)(?:\s+\"[^\"]*\")?\)")
LEGAL_PAGE_LANGUAGES = {
    "legal-notice.md": ("en", "impressum.md", "de", "Deutsch"),
    "impressum.md": ("de", "legal-notice.md", "en", "English"),
    "privacy-policy.md": ("en", "datenschutz.md", "de", "Deutsch"),
    "datenschutz.md": ("de", "privacy-policy.md", "en", "English"),
}


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
        self.language = ""
        self.alternates: dict[str, str] = {}
        self.footer_links: list[str] = []
        self._in_footer = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Read attributes relevant to offline correctness."""
        attributes = dict(attrs)
        if tag == "html":
            self.language = attributes.get("lang") or ""
        if tag == "link" and attributes.get("rel") == "alternate":
            self.alternates[attributes.get("hreflang") or ""] = attributes.get("href") or ""
        if tag == "footer":
            self._in_footer = True
        if self._in_footer and tag == "a" and attributes.get("href"):
            self.footer_links.append(str(attributes["href"]))
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
        if tag == "footer":
            self._in_footer = False

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


def _legal_sitemap_errors(output: Path) -> list[str]:
    """Require the generated sitemap to expose every public legal route."""
    try:
        # The sitemap is generated locally by the documentation builder, not fetched.
        sitemap = ET.parse(output / "sitemap.xml")  # noqa: S314
    except OSError, ET.ParseError:
        return ["Missing or invalid sitemap for legal pages"]
    urls = {entry.text for entry in sitemap.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")}
    return [
        f"Missing legal sitemap entry: {filename}"
        for filename in LEGAL_PAGE_LANGUAGES
        if page_url(filename) not in urls
    ]


def _legal_page_errors(output: Path, pages: Mapping[Path, PageLinks]) -> list[str]:
    """Enforce public legal routes, translations, exports, and footer discovery."""
    errors: list[str] = []
    required_pages = {output / filename.removesuffix(".md") / "index.html" for filename in LEGAL_PAGE_LANGUAGES}
    for filename, (language, alternate, alternate_language, _label) in LEGAL_PAGE_LANGUAGES.items():
        path = output / filename.removesuffix(".md") / "index.html"
        document = pages.get(path)
        if document is None:
            errors.append(f"Missing legal page: {filename}")
        else:
            if document.language != language:
                errors.append(f"{filename}: incorrect HTML language")
            if document.alternates != {language: page_url(filename), alternate_language: page_url(alternate)}:
                errors.append(f"{filename}: incorrect language alternatives")
        if not (output / "markdown" / filename).is_file():
            errors.append(f"Missing legal Markdown export: {filename}")
    errors.extend(_legal_sitemap_errors(output))
    for path, document in pages.items():
        targets = {
            destination[0]
            for href in document.footer_links
            if (destination := _local_destination(href, path, output)) is not None
        }
        relative = path.relative_to(output).as_posix()
        if not required_pages.issubset(targets):
            errors.append(f"{relative}: missing legal footer links")
        if "https://www.strukturpiloten.de/kontakt" not in document.footer_links:
            errors.append(f"{relative}: missing company contact footer link")
    return errors


def validate_site(output: Path, *, require_legal: bool = False) -> int:  # noqa: C901
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
    if require_legal:
        errors.extend(_legal_page_errors(output, pages))
    if errors:
        raise ValueError("Documentation validation failed:\n" + "\n".join(errors[:50]))
    return len(pages)


def relative_markdown_link(source: str, destination: str) -> str:
    """Return the path between virtual Markdown source files."""
    return posixpath.relpath(destination, posixpath.dirname(source))
