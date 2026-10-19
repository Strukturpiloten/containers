"""Check static-site navigation boundaries and safe generated output handling."""

from __future__ import annotations

import tempfile
import unittest
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin

from scripts.docs_site import SITE_URL, page_url, rewrite_links, validate_site
from scripts.documentation import ROOT, build


class LegalNavigation(HTMLParser):
    """Inspect language alternatives and links in the shared rendered footer."""

    def __init__(self) -> None:
        """Initialize one rendered page inspection."""
        super().__init__()
        self.language = ""
        self.alternates: dict[str, str] = {}
        self.footer_links: set[str] = set()
        self.in_footer = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "html":
            self.language = values.get("lang") or ""
        if tag == "link" and values.get("rel") == "alternate":
            self.alternates[values.get("hreflang") or ""] = values.get("href") or ""
        if tag == "footer":
            self.in_footer = True
        if self.in_footer and tag == "a" and values.get("href"):
            self.footer_links.add(str(values["href"]))

    def handle_endtag(self, tag: str) -> None:
        if tag == "footer":
            self.in_footer = False


def html(title: str, route: str, content: str) -> str:
    """Make a minimal rendered document with required search metadata."""
    return (
        f'<html><head><title>{title}</title><link rel="canonical" href="{SITE_URL}{route}">'
        '<meta name="description" content="Useful image reference"></head>'
        f"<body>{content}</body></html>"
    )


class DocumentationSiteTests(unittest.TestCase):
    def test_repository_links_map_to_pages_and_keep_code_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "README.md"
            other = root / "guide.md"
            other.write_text("# Guide", encoding="utf-8")
            source.write_text("# Readme", encoding="utf-8")
            text = "[Guide](guide.md#usage)\n\n```md\n[example](missing.md)\n```\n"
            result = rewrite_links(text, source, root=root, pages={other: "guides/example.md"})
            self.assertIn(f"[Guide]({SITE_URL}guides/example/#usage)", result)
            self.assertIn("[example](missing.md)", result)
            with self.assertRaisesRegex(ValueError, "Broken repository"):
                rewrite_links("[Missing](missing.md)", source, root=root, pages={})

    def test_rendered_links_require_existing_pages_and_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            target = output / "images/example"
            target.mkdir(parents=True)
            (output / "index.html").write_text(
                html("Catalogue", "", '<a href="images/example/#usage">Example</a>'),
                encoding="utf-8",
            )
            (target / "index.html").write_text(
                html("Example", "images/example/", '<h1 id="usage">Use this image</h1>'),
                encoding="utf-8",
            )
            self.assertEqual(validate_site(output), 2)
            (target / "index.html").write_text(html("Example", "images/example/", "No anchor"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing anchor"):
                validate_site(output)

    def test_rendered_external_links_are_not_fetched(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "index.html").write_text(
                html("Catalogue", "", '<a href="https://example.org/no-network#unknown">External</a>'),
                encoding="utf-8",
            )
            self.assertEqual(validate_site(output), 1)

    def test_wrong_canonical_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "index.html").write_text(html("Catalogue", "wrong/", ""), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "canonical must be"):
                validate_site(output)

    def test_output_cannot_clean_source_or_unowned_directory(self) -> None:
        with self.assertRaisesRegex(ValueError, "source directory"):
            build(ROOT / "docs/generated")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            valuable = output / "preserve.txt"
            valuable.write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Refusing to clean"):
                build(output)
            self.assertEqual(valuable.read_text(encoding="utf-8"), "preserve")

    def test_directory_page_urls_are_canonical(self) -> None:
        self.assertEqual(page_url("index.md"), SITE_URL)
        self.assertEqual(page_url("guides/index.md"), SITE_URL + "guides/")
        self.assertEqual(page_url("images/example.md"), SITE_URL + "images/example/")

    def test_bilingual_legal_pages_are_discoverable_from_every_rendered_page(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "site"
            build(output)
            alternatives = {
                "legal-notice": ("en", "impressum", "de"),
                "impressum": ("de", "legal-notice", "en"),
                "privacy-policy": ("en", "datenschutz", "de"),
                "datenschutz": ("de", "privacy-policy", "en"),
            }
            sitemap = ET.parse(output / "sitemap.xml")  # noqa: S314 - generated by this test's offline build.
            sitemap_urls = {
                element.text for element in sitemap.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")
            }
            for route, (language, alternate, alternate_language) in alternatives.items():
                with self.subTest(route=route):
                    page = output / route / "index.html"
                    document = LegalNavigation()
                    document.feed(page.read_text(encoding="utf-8"))
                    self.assertEqual(document.language, language)
                    self.assertEqual(
                        document.alternates,
                        {language: f"{SITE_URL}{route}/", alternate_language: f"{SITE_URL}{alternate}/"},
                    )
                    self.assertIn(f"{SITE_URL}{route}/", sitemap_urls)
                    self.assertTrue((output / "markdown" / f"{route}.md").is_file())
            for page in output.rglob("*.html"):
                with self.subTest(page=page.relative_to(output)):
                    document = LegalNavigation()
                    document.feed(page.read_text(encoding="utf-8"))
                    current_url = SITE_URL + page.relative_to(output).as_posix()
                    footer_urls = {urljoin(current_url, href) for href in document.footer_links}
                    for route in alternatives:
                        self.assertIn(f"{SITE_URL}{route}/", footer_urls)
                    self.assertIn("https://www.strukturpiloten.de/kontakt", document.footer_links)


if __name__ == "__main__":
    unittest.main()
