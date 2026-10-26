"""Check static-site navigation boundaries and safe generated output handling."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.docs_site import SITE_URL, page_url, rewrite_links, validate_site
from scripts.documentation import ROOT, build


def html(title: str, route: str, content: str) -> str:
    """Make a minimal rendered document with required search metadata."""
    return (
        f'<html><head><title>{title}</title><link rel="canonical" href="{SITE_URL}{route}">'
        '<meta name="description" content="Useful image reference"></head>'
        f"<body>{content}</body></html>"
    )


def legal_site(output: Path) -> None:
    """Write small rendered fixtures without the optional MkDocs dependency."""
    routes = {
        "legal-notice": ("en", "impressum", "de"),
        "impressum": ("de", "legal-notice", "en"),
        "privacy-policy": ("en", "datenschutz", "de"),
        "datenschutz": ("de", "privacy-policy", "en"),
    }
    footer = "<footer>" + "".join(f'<a href="{SITE_URL}{route}/">{route}</a>' for route in routes)
    footer += '<a href="https://www.strukturpiloten.de/kontakt">Contact</a></footer>'
    (output / "index.html").write_text(html("Catalogue", "", footer), encoding="utf-8")
    for route, (language, alternate, alternate_language) in routes.items():
        target = output / route
        target.mkdir(exist_ok=True)
        text = html(route, route + "/", footer).replace("<html>", f'<html lang="{language}">')
        alternatives = (
            f'<link rel="alternate" hreflang="{language}" href="{SITE_URL}{route}/">'
            f'<link rel="alternate" hreflang="{alternate_language}" href="{SITE_URL}{alternate}/">'
        )
        (target / "index.html").write_text(text.replace("</head>", alternatives + "</head>"), encoding="utf-8")
        export = output / "markdown" / f"{route}.md"
        export.parent.mkdir(exist_ok=True)
        export.write_text(f"# {route}\n", encoding="utf-8")
    sitemap = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    sitemap += "".join(f"<url><loc>{SITE_URL}{route}/</loc></url>" for route in routes)
    (output / "sitemap.xml").write_text(sitemap + "</urlset>", encoding="utf-8")


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
            output = Path(directory)
            legal_site(output)
            self.assertEqual(validate_site(output, require_legal=True), 5)
            home = output / "index.html"
            text = home.read_text(encoding="utf-8")
            home.write_text(text.replace("<footer>", "<nav>").replace("</footer>", "</nav>"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "index.html: missing legal footer links"):
                validate_site(output, require_legal=True)

    def test_legal_language_metadata_must_identify_both_translations(self) -> None:
        for original, replacement, error in (
            ('lang="de"', 'lang="en"', "incorrect HTML language"),
            ('hreflang="en"', 'hreflang="fr"', "incorrect language alternatives"),
        ):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                legal_site(output)
                page = output / "datenschutz/index.html"
                text = page.read_text(encoding="utf-8")
                page.write_text(text.replace(original, replacement), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, error):
                    validate_site(output, require_legal=True)

    def test_missing_legal_route_export_or_sitemap_entry_fails_the_build(self) -> None:
        for relative, error in (
            ("datenschutz/index.html", "Missing legal page"),
            ("markdown/privacy-policy.md", "Missing legal Markdown export"),
            ("sitemap.xml", "Missing or invalid sitemap"),
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                legal_site(output)
                (output / relative).unlink()
                with self.assertRaisesRegex(ValueError, error):
                    validate_site(output, require_legal=True)


if __name__ == "__main__":
    unittest.main()
