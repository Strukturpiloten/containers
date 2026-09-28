"""Build the public documentation website and versioned data exports offline."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from scripts import container_engine, docs_catalogue
from scripts.docs_site import REPOSITORY_URL, SITE_URL, page_url, rewrite_links, validate_site

ROOT = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(ROOT), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return result.stdout.strip()


@lru_cache(maxsize=512)
def _source_time(path: str) -> str:
    """Read actual source modification time instead of assigning build time."""
    return _git("log", "-1", "--format=%cI", "--", path) or _git("show", "-s", "--format=%cI", "HEAD")


def _source_pages() -> dict[Path, str]:
    result = {path.resolve(): f"guides/{path.stem}.md" for path in (ROOT / "docs").glob("*.md")}
    result[(ROOT / "docs/index.md").resolve()] = "guides/index.md"
    for name in ("CONTRIBUTING", "SECURITY"):
        result[(ROOT / f"{name}.md").resolve()] = f"guides/{name.lower()}.md"
    result[(ROOT / "README.md").resolve()] = "guides/repository.md"
    for path in (ROOT / "images").rglob("README.md"):
        relative = path.relative_to(ROOT)
        if len(relative.parts) == 3:  # noqa: PLR2004
            destination = f"families/{relative.parts[1]}.md"
        else:
            destination = f"guides/{'-'.join(relative.parts[2:-1])}.md"
        result[path.resolve()] = destination
    result[(ROOT / "shared/container-utilities/README.md").resolve()] = "guides/container-utilities.md"
    return result


def _page(  # noqa: PLR0913
    content: str,
    *,
    title: str,
    description: str,
    virtual: str,
    source: str,
    updated: str,
    catalogue: bool = False,
) -> str:
    frontmatter = {
        "title": title,
        "description": description,
        "source_url": f"{REPOSITORY_URL}/blob/main/{source}",
        "updated": updated,
        "markdown_url": SITE_URL + "markdown/" + virtual,
        "catalogue": catalogue,
    }
    return "---\n" + yaml.safe_dump(frontmatter, sort_keys=False) + "---\n\n" + content


def _guide_summary(content: str, title: str) -> str:
    for paragraph in content.split("\n\n"):
        if paragraph.strip() and not paragraph.lstrip().startswith(("#", "|", "```", "-", ">")):
            # Description is plain text; strip Markdown destinations and formatting.
            import re  # noqa: PLC0415

            text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", paragraph)
            text = " ".join(text.replace("`", "").replace("**", "").split())
            return text[:200].rsplit(" ", 1)[0] if len(text) > 200 else text  # noqa: PLR2004
    return f"{title}: reference and operational guidance for Strukturpiloten container images."


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def _json(path: Path, value: object) -> None:
    _write(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _render_sources(source: Path, images: list[dict[str, Any]], report: dict[str, Any]) -> dict[str, str]:
    pages = _source_pages()
    modified: dict[str, str] = {}
    for path, virtual in pages.items():
        content = rewrite_links(path.read_text(encoding="utf-8"), path, root=ROOT, pages=pages)
        title = next((line.removeprefix("# ") for line in content.splitlines() if line.startswith("# ")), path.stem)
        updated = _source_time(path.relative_to(ROOT).as_posix())
        modified[virtual] = updated
        _write(
            source / virtual,
            _page(
                content,
                title=title,
                description=_guide_summary(content, title),
                virtual=virtual,
                source=path.relative_to(ROOT).as_posix(),
                updated=updated,
            ),
        )
    metadata_times = {str(image["name"]): _source_time(str(image["metadataFile"])) for image in images}
    catalogue_time = max(metadata_times.values())
    if report.get("generatedAt"):
        catalogue_time = max(catalogue_time, str(report["generatedAt"]))
    _write(
        source / "index.md",
        _page(
            docs_catalogue.index_markdown(report),
            title="Container image catalogue",
            description=(
                "Browse every Strukturpiloten Docker, Podman, Nextcloud, and TYPO3 image. "
                "Compare versions, architectures, support, and observed registry tags."
            ),
            virtual="index.md",
            source="README.md",
            updated=catalogue_time,
            catalogue=True,
        ),
    )
    modified["index.md"] = catalogue_time
    for row in report["images"]:
        virtual = f"images/{row['name']}.md"
        updated = metadata_times[row["name"]]
        observation = row.get("observation")
        if observation and observation.get("observedAt"):
            updated = max(updated, observation["observedAt"])
        metadata = next(image for image in images if image["name"] == row["name"])
        _write(
            source / virtual,
            _page(
                docs_catalogue.image_markdown(row),
                title=str(row["name"]),
                description=(
                    f"{row['name']}: {row['description']}. Versions, pull references, architectures, "
                    "runtime requirements, and registry evidence."
                ),
                virtual=virtual,
                source=str(metadata["metadataFile"]),
                updated=updated,
            ),
        )
        modified[virtual] = updated
    for family in ("nextcloud", "typo3"):
        virtual = f"families/{family}.md"
        family_rows = [row for row in report["images"] if row["family"] == family]
        label = "Nextcloud" if family == "nextcloud" else "TYPO3"
        content = (
            f"# {label} images\n\nApplication runtime images maintained by Strukturpiloten. "
            "Image versions describe the container contract, not the installed application release.\n\n"
        )
        content += "\n".join(f"- [{row['name']}]({row['docsUrl']}): {row['description']}" for row in family_rows)
        content += (
            f"\n\nSee the [getting started guide]({SITE_URL}guides/getting-started/) "
            "for image selection and configuration.\n"
        )
        _write(
            source / virtual,
            _page(
                content,
                title=f"{label} images",
                description=(
                    f"Choose a {label} application runtime image and review its configuration, "
                    "version policy, and support scope."
                ),
                virtual=virtual,
                source="README.md",
                updated=catalogue_time,
            ),
        )
        modified[virtual] = catalogue_time
    return modified


def _sitemap(output: Path, modified: dict[str, str]) -> None:
    ET.register_namespace("", "http://www.sitemaps.org/schemas/sitemap/0.9")
    namespace = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    sitemap = ET.Element(namespace + "urlset")
    for virtual, updated in sorted(modified.items()):
        entry = ET.SubElement(sitemap, namespace + "url")
        ET.SubElement(entry, namespace + "loc").text = page_url(virtual)
        ET.SubElement(entry, namespace + "lastmod").text = updated
    ET.indent(sitemap)
    ET.ElementTree(sitemap).write(output / "sitemap.xml", encoding="utf-8", xml_declaration=True)
    # The standard generator's compressed sitemap used build dates; omit that variant.
    (output / "sitemap.xml.gz").unlink(missing_ok=True)


def _load_snapshot(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    snapshot = json.loads(path.read_text(encoding="utf-8"))
    from scripts.docs_observations import validate  # noqa: PLC0415

    validate(snapshot)
    return snapshot


def build(output: Path, *, snapshot_path: Path | None = None) -> int:
    """Build static HTML, exports and sitemap, then validate all local navigation."""
    output = output.resolve()
    # MkDocs cleans its output: require a dedicated generated directory.
    protected = ("docs", "images", "documentation", "scripts", "tests", ".git", ".github", "shared")
    if output == ROOT or ROOT.is_relative_to(output) or any(output.is_relative_to(ROOT / name) for name in protected):
        msg = "Choose a dedicated generated site output directory, never a source directory."
        raise ValueError(msg)
    if output.exists() and any(output.iterdir()) and not (output / ".containers-documentation-site").is_file():
        msg = "Refusing to clean an existing directory that is not a generated documentation site."
        raise ValueError(msg)
    snapshot = _load_snapshot(snapshot_path)
    images = container_engine._load_images()  # noqa: SLF001
    revision = _git("rev-parse", "HEAD")
    report = docs_catalogue.catalogue(images, snapshot, source_revision=revision)
    jsonschema.validate(report, json.loads((ROOT / "docs/catalogue.schema.json").read_text(encoding="utf-8")))
    with tempfile.TemporaryDirectory(prefix="containers-docs-") as temporary:
        workspace = Path(temporary)
        source = workspace / "source"
        source.mkdir()
        modified = _render_sources(source, images, report)
        shutil.copytree(ROOT / "documentation/assets", source / "assets")
        _json(source / "data/catalogue.json", report)
        _json(
            source / "data/declarations.json",
            json.loads((ROOT / "docs/image-catalogue.json").read_text(encoding="utf-8")),
        )
        for filename in ("catalogue.schema.json", "registry-snapshot.schema.json"):
            shutil.copyfile(ROOT / "docs" / filename, source / "data" / filename)
        if snapshot is not None:
            _json(source / "data/registry-snapshot.json", snapshot)
        _write(source / "CNAME", "containers.strukturpiloten.de")
        _write(
            source / "robots.txt", f"User-agent: *\nAllow: /\nDisallow: /markdown/\n\nSitemap: {SITE_URL}sitemap.xml"
        )
        llms = (
            "# Strukturpiloten Containers\n\n> Public OCI image catalogue and documentation. "
            "This optional navigation file is not a search ranking guarantee.\n\n"
            f"- [Image catalogue]({SITE_URL})\n- [Documentation]({SITE_URL}guides/)\n"
            f"- [Version and tag policy]({SITE_URL}guides/tags-and-versions/)\n"
            f"- [Security and support]({SITE_URL}guides/security-and-support/)\n"
            f"- [Machine-readable catalogue]({SITE_URL}data/catalogue.json)\n"
            f"- [Export contract]({SITE_URL}guides/data-and-discovery/)\n"
        )
        _write(source / "llms.txt", llms)
        config = yaml.safe_load((ROOT / "documentation/mkdocs.yml").read_text(encoding="utf-8"))
        config.update({"docs_dir": str(source), "site_dir": str(output)})
        config["theme"]["custom_dir"] = str(ROOT / "documentation/theme")
        config_path = workspace / "mkdocs.yml"
        _write(config_path, yaml.safe_dump(config, sort_keys=False))
        subprocess.run(  # noqa: S603
            [sys.executable, "-m", "mkdocs", "build", "--strict", "--config-file", str(config_path)],
            check=True,
            timeout=180,
        )
        for virtual in modified:
            raw = (source / virtual).read_text(encoding="utf-8")
            # Exports keep titles and canonical provenance but omit generator frontmatter.
            content = raw.split("---\n", 2)[-1].lstrip()
            export = f"Canonical page: {page_url(virtual)}\n\n{content}"
            _write(output / "markdown" / virtual, export)
        _sitemap(output, modified)
        _write(output / ".nojekyll", "")
        _write(output / ".containers-documentation-site", "Generated by scripts.documentation")
    return validate_site(output)


def main() -> None:
    """Parse the offline site builder CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path)
    args = parser.parse_args()
    count = build(args.output, snapshot_path=args.snapshot)
    print(f"Validated {count} documentation pages in {args.output}.")  # noqa: T201


if __name__ == "__main__":
    main()
