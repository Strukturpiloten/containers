"""Render declared image metadata and separately observed registry state."""

from __future__ import annotations

import datetime as dt
import html
import json
from collections import defaultdict
from typing import Any

from scripts.maintenance import lifecycle_for
from scripts.policy import semver_tags

CANONICAL_URL = "https://containers.strukturpiloten.de"
SOURCE_URL = "https://github.com/Strukturpiloten/containers"
FAMILIES = ("docker", "podman", "nextcloud", "typo3")
FAMILY_LABELS = {
    "docker": "Docker Engine",
    "podman": "Podman",
    "nextcloud": "Nextcloud",
    "typo3": "TYPO3",
}
GUIDES = {
    "docker": "/families/docker/",
    "podman": "/families/podman/",
    "nextcloud-phpfpm": "/guides/nextcloud-phpfpm/",
    "nextcloud-notifypush": "/guides/nextcloud-notifypush/",
    "typo3-phpfpm": "/guides/typo3-phpfpm/",
}


def _family(name: str) -> str:
    family = name.split("-", 1)[0]
    if family not in FAMILIES:
        msg = f"Unknown image family for {name}."
        raise ValueError(msg)
    return family


def _root_mode(name: str) -> str:
    if name.endswith("-rootful"):
        return "rootful"
    if name.endswith("-rootless"):
        return "rootless"
    return "not-applicable"


def _build_arg(metadata: dict[str, Any], key: str) -> str | None:
    args = metadata.get("build", {}).get("args", {})
    value = args.get(key)
    if isinstance(value, dict):
        value = value.get("value")
    return value if isinstance(value, str) else None


def _base_image(metadata: dict[str, Any]) -> str | None:
    key = metadata.get("build", {}).get("runtimeBaseArg")
    return _build_arg(metadata, key) if isinstance(key, str) else None


def _distribution(name: str, family: str) -> str | None:
    if family not in {"docker", "podman"}:
        return None
    body = name.removeprefix(f"{family}-").removesuffix("-rootful").removesuffix("-rootless")
    if body and body[0].isdigit():
        return None
    return body or None


def _software_version(metadata: dict[str, Any], family: str, distribution: str | None) -> str | None:
    if family in {"docker", "podman"} and distribution is None:
        return str(metadata["version"]).removeprefix("v")
    if metadata["name"] == "nextcloud-notifypush":
        return _build_arg(metadata, "NOTIFYPUSH_VERSION")
    # Distro package revisions are selected at build time. PHP-FPM images do
    # not bundle Nextcloud or TYPO3, so the image version is not an app version.
    return None


def _php_base_version(metadata: dict[str, Any]) -> str | None:
    if metadata["name"] not in {"nextcloud-phpfpm", "typo3-phpfpm"}:
        return None
    base = _base_image(metadata)
    if not base or ":" not in base:
        return None
    return base.split("@", 1)[0].rsplit(":", 1)[-1]


def catalogue(  # noqa: C901 - each declaration and observation needs its own identity check.
    images: list[dict[str, Any]], snapshot: dict[str, Any] | None, *, source_revision: str
) -> dict[str, Any]:
    """Combine metadata and optional observations without inventing proof."""
    observations: dict[str, dict[str, Any]] = {}
    if snapshot is not None:
        if snapshot.get("schemaVersion") != 1 or not isinstance(snapshot.get("images"), list):
            msg = "Registry snapshot has an unsupported shape."
            raise ValueError(msg)
        for observed in snapshot["images"]:
            if not isinstance(observed, dict) or not isinstance(observed.get("name"), str):
                msg = "Registry snapshot contains an invalid image observation."
                raise TypeError(msg)
            if observed["name"] in observations:
                msg = f"Duplicate registry observation for {observed['name']}."
                raise ValueError(msg)
            observations[observed["name"]] = observed

    rows = []
    seen: set[str] = set()
    for metadata in sorted(images, key=lambda item: item["name"]):
        name = metadata["name"]
        if name in seen:
            msg = f"Duplicate image declaration for {name}."
            raise ValueError(msg)
        seen.add(name)
        family = _family(name)
        image = metadata["image"]
        observed = observations.get(name)
        if observed is not None and observed.get("image") != image:
            msg = f"Registry observation for {name} names a different image."
            raise ValueError(msg)
        distribution = _distribution(name, family)
        metadata_path = metadata.get("metadataFile", f"images/{family}/{name}/container.yaml")
        if not isinstance(metadata_path, str) or not metadata_path.startswith("images/"):
            msg = f"Invalid metadata path for {name}."
            raise ValueError(msg)
        rows.append(
            {
                "name": name,
                "image": image,
                "description": metadata["description"],
                "title": metadata["title"],
                "family": family,
                "imageVersion": metadata["version"],
                "softwareVersion": _software_version(metadata, family, distribution),
                "phpBaseTag": _php_base_version(metadata),
                "rootMode": _root_mode(name),
                "architectures": list(metadata["build"]["architectures"]),
                "distribution": distribution,
                "baseImage": _base_image(metadata),
                "lifecycle": lifecycle_for(metadata),
                "declaredTags": [*semver_tags(metadata["version"]), "main", "latest"],
                "runtimeTests": metadata.get("tests", {}),
                "docsUrl": f"{CANONICAL_URL}/images/{name}/",
                "guideUrl": f"{CANONICAL_URL}{GUIDES.get(name, f'/families/{family}/')}",
                "sourceUrl": f"{SOURCE_URL}/blob/{source_revision}/{metadata_path}",
                "packageUrl": f"https://github.com/orgs/Strukturpiloten/packages/container/package/{name}",
                "metadataPath": metadata_path,
                "observation": observed,
            }
        )

    unknown = set(observations) - seen
    if unknown:
        msg = f"Registry snapshot contains undeclared images: {', '.join(sorted(unknown))}."
        raise ValueError(msg)
    return {
        "schemaVersion": 1,
        "sourceRevision": source_revision,
        "generatedAt": snapshot.get("generatedAt") if snapshot else None,
        "canonicalUrl": CANONICAL_URL,
        "images": rows,
    }


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _status(row: dict[str, Any]) -> str:
    observation = row.get("observation")
    return str(observation.get("status", "unavailable")) if isinstance(observation, dict) else "unknown"


def _observed_at(row: dict[str, Any]) -> str:
    observation = row.get("observation")
    if isinstance(observation, dict) and observation.get("observedAt"):
        return dt.datetime.fromisoformat(observation["observedAt"]).astimezone(dt.UTC).strftime("%Y-%m-%d %H:%M UTC")
    return "unknown"


def index_markdown(report: dict[str, Any]) -> str:
    """Render a complete static catalogue with progressive search controls."""
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in report["images"]:
        by_family[row["family"]].append(row)
    lines = [
        '<div class="hero">',
        '<div><p class="eyebrow">Public OCI image catalogue</p>',
        "<h1>Find the right image.<br>Know what you run.</h1>",
        (
            "<p>Docker and Podman compatibility fixtures. Nextcloud and TYPO3 runtimes. "
            "Compare versions, check support, and find your pull reference.</p></div>"
        ),
        '<div class="hero-panel">',
        '<p class="eyebrow">One registry. Clear references.</p>',
        "<code>ghcr.io/strukturpiloten/&lt;image&gt;:&lt;tag&gt;</code>",
        (
            "<p>Use a digest to pin an exact build. "
            '<a href="https://containers.strukturpiloten.de/guides/getting-started/">Get started →</a></p>'
        ),
        "</div></div>",
        "",
        '<div class="family-cards">',
    ]
    for family in FAMILIES:
        count = len(by_family[family])
        lines.append(
            f'<a class="family-card" href="#{family}-images"><strong>{FAMILY_LABELS[family]}</strong>'
            f"<span>{count} declared images</span></a>"
        )
    lines += [
        "</div>",
        "",
        '<div class="catalogue-controls">',
        '<label for="image-search">Search images',
        '<input id="image-search" type="search" placeholder="Name, purpose, or distribution"></label>',
        '<label for="family-filter">Family',
        '<select id="family-filter"><option value="">All families</option>',
    ]
    for family in FAMILIES:
        lines.append(f'<option value="{family}">{FAMILY_LABELS[family]}</option>')
    lines += [
        "</select></label>",
        '<label for="mode-filter">Mode',
        (
            '<select id="mode-filter"><option value="">All modes</option>'
            '<option value="rootful">Rootful</option><option value="rootless">Rootless</option>'
            '<option value="not-applicable">Application</option></select></label>'
        ),
        "</div>",
        '<p id="result-count" aria-live="polite"></p>',
        (
            '<p class="subtle">Registry status shows when a digest was last checked in GHCR. '
            '<a href="https://containers.strukturpiloten.de/guides/data-and-discovery/">Understand the data →</a></p>'
        ),
        '<p id="no-results" hidden>No images match those filters.</p>',
        "",
    ]
    for family in FAMILIES:
        lines += [
            f'<section class="image-group" id="{family}-images">',
            f'<h2>{FAMILY_LABELS[family]}<a href="{CANONICAL_URL}/families/{family}/">Family guide →</a></h2>',
            '<table class="image-table">',
            (
                "<thead><tr><th>Image and purpose</th><th>Image / software version</th>"
                "<th>Architectures / mode</th><th>Lifecycle</th><th>Registry / observed</th></tr></thead>"
            ),
            "<tbody>",
        ]
        for row in by_family[family]:
            software = row["softwareVersion"] or (
                "not bundled" if row["name"] in {"nextcloud-phpfpm", "typo3-phpfpm"} else "unknown"
            )
            status = _status(row)
            observed = _observed_at(row)
            search = _escape(f"{row['name']} {row['description']} {row['distribution'] or ''}").lower()
            lines.append(
                f'<tr data-family="{family}" data-mode="{row["rootMode"]}" data-search="{search}">'
                f'<td><a class="image-name" href="{_escape(row["docsUrl"])}">{_escape(row["name"])}</a>'
                f'<span class="image-detail">{_escape(row["description"])}</span></td>'
                f"<td><code>{_escape(row['imageVersion'])}</code>"
                f'<span class="image-detail">Software: {_escape(software)}</span></td>'
                f"<td>{_escape(', '.join(row['architectures']))}"
                f'<span class="image-detail">{_escape(row["rootMode"])}</span></td>'
                f'<td><span class="badge badge-{_escape(row["lifecycle"]["state"])}">'
                f"{_escape(row['lifecycle']['state'])}</span>"
                f'<span class="image-detail">{_escape(row["lifecycle"]["admission"])}</span></td>'
                f'<td><span class="badge badge-{_escape(status)}">{_escape(status)}</span>'
                f'<span class="image-detail">{_escape(observed)}</span></td></tr>'
            )
        lines += ["</tbody></table></section>", ""]
    lines += [
        (
            "A declaration does not prove a package is public. Verify a digest, architecture, and matching "
            "[maintenance evidence](https://containers.strukturpiloten.de/guides/maintenance-evidence/) before use."
        ),
        "",
    ]
    return "\n".join(lines)


def _markdown(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")


def image_markdown(row: dict[str, Any]) -> str:  # noqa: C901, PLR0912, PLR0915 - ordered page sections.
    """Render a single image, preserving observation and evidence limits."""
    name, image = row["name"], row["image"]
    observation = row.get("observation")
    status = _status(row)
    lines = [
        f"# {row['title']}",
        "",
        row["description"],
        "",
        f"**Image:** `{image}`  ",
        f"**Declared image version:** `{row['imageVersion']}`  ",
        f"**Family:** {FAMILY_LABELS[row['family']]}  ",
        f"**Architecture:** {', '.join(row['architectures'])}  ",
        f"**Inner mode:** {row['rootMode']}",
        "",
        f"**Declared runtime base:** {row['baseImage'] or 'unknown'}",
        "",
        (
            f"[Image source and metadata]({row['sourceUrl']}) · [GHCR package]({row['packageUrl']})"
            f" · [Detailed guide]({row['guideUrl']})"
        ),
        "",
        "## Choose and inspect",
        "",
    ]
    if row["softwareVersion"]:
        lines += [f"**Declared upstream software:** `{row['softwareVersion']}`", ""]
    elif row["distribution"]:
        lines += [
            (
                "The distribution selects the installed engine package at build time. "
                "Inspect the published image's component manifest or SBOM for its exact revision."
            ),
            "",
        ]
    elif row["phpBaseTag"]:
        lines += [
            (
                f"**Declared PHP base tag:** `{row['phpBaseTag']}`. "
                "This runtime does not bundle Nextcloud or TYPO3 application code."
            ),
            "",
        ]
    lines += [
        (
            f"Declared tags: {', '.join(f'`{tag}`' for tag in row['declaredTags'])}. "
            "These are publication policy aliases, not proof that any tag exists in GHCR. "
            "Even the exact SemVer tag can move after a reviewed rebuild."
        ),
        "",
    ]
    latest = observation.get("latest") if isinstance(observation, dict) else None
    if isinstance(latest, dict):
        lines += [
            f"Registry status: **{status}**; checked at **{observation.get('observedAt') or 'unknown'}**."
            + (" This is retained stale data from a failed refresh." if observation.get("stale") else ""),
            "",
            f"Observed `latest` index digest: `{latest['digest']}`.",
            "",
            "Pull the observed immutable artifact:",
            "",
            "```sh",
            f"podman pull {latest['reference']}",
            "```",
            "",
        ]
    else:
        lines += [
            (
                f"Registry status: **{status}**. No verified current digest is available from this snapshot. "
                "Check the GHCR package before pulling a declared tag."
            ),
            "",
        ]
        if isinstance(observation, dict) and observation.get("refreshError"):
            lines += [f"Refresh error: {_markdown(observation['refreshError'])}", ""]
    if row["family"] == "docker":
        ref = latest["reference"] if isinstance(latest, dict) else f"{image}:{row['imageVersion']}"
        oom = " --oom-score-adj=0" if name == "docker-debian-11-rootless" else ""
        lines += [
            (
                "For an isolated Linux nested-Docker test, the outer Podman boundary runs rootfully and privileged. "
                "Use a trusted runner and keep its image store separate from other tests:"
            ),
            "",
            "```sh",
            (
                f"sudo podman run --rm --detach --name nested-docker --privileged --device /dev/fuse"
                f" --security-opt label=disable{oom} {ref}"
            ),
            "sudo podman exec nested-docker docker info",
            "sudo podman stop nested-docker",
            "```",
            "",
            "This fixture does not use the host Docker socket. Read the detailed guide for nested workloads.",
            "",
        ]
    elif row["family"] == "podman":
        lines += [
            "A CLI check can run without a nested workload:",
            "",
            "```sh",
            f"podman run --rm {image}:{row['imageVersion']} podman --version",
            "```",
            "",
            (
                "Nested workloads require the profile-specific outer privilege and device setup in the detailed guide. "
                "Some rootless distro profiles intentionally omit nested workload checks."
            ),
            "",
        ]
    else:
        lines += [
            (
                "Read the detailed guide for application mounts, service ports, and stack dependencies. "
                "PHP-FPM runtime images need application code supplied by the consuming stack."
            ),
            "",
        ]
    lines += [
        "## Support and runtime contract",
        "",
        (
            f"Lifecycle: **{row['lifecycle']['state']}**; admission: **{row['lifecycle']['admission']}**; "
            f"review after: **{row['lifecycle']['reviewAfter']}**."
        ),
        "",
        _markdown(row["lifecycle"]["supportBoundary"]),
        "",
        (
            f"Declared runtime profiles: {', '.join(row['lifecycle']['requiredRuntimeProfiles'])}. "
            "Declared test settings are in the metadata source. Admission is policy, not evidence of a passed test."
        ),
        "",
        "Declared runtime test contract:",
        "",
        "```json",
        json.dumps(row["runtimeTests"], indent=2, sort_keys=True),
        "```",
        "",
        "## Registry aliases and history",
        "",
    ]
    tags = observation.get("tags") if isinstance(observation, dict) else None
    if isinstance(tags, dict) and isinstance(latest, dict):
        aliases = tags.get("currentAliases", [])
        lines += [
            f"Aliases resolved to the observed current digest: {', '.join(f'`{tag}`' for tag in aliases) or 'none'}.",
            "",
        ]
        history = tags.get("history", [])
        if history:
            lines += ["Other resolved aliases at observation time:", "", "| Digest | Aliases |", "| --- | --- |"]
            lines += [f"| `{item['digest']}` | {_markdown(', '.join(item['tags']))} |" for item in history]
            lines.append("")
        unresolved = tags.get("unresolved", [])
        if unresolved:
            lines += [
                f"Listed without digest resolution: {', '.join(f'`{tag}`' for tag in unresolved)}.",
                "",
            ]
    else:
        lines += ["No registry tag history was supplied.", ""]
    lines += ["## Evidence and timestamps", ""]
    if isinstance(latest, dict):
        evidence = latest.get("evidence", {})
        built_at = evidence.get("buildSucceededAt") if evidence.get("status") == "verified" else "unknown"
        lines += [
            "| Field | Observed value |",
            "| --- | --- |",
            f"| Source revision | {_markdown(latest.get('sourceRevision') or 'unknown')} |",
            f"| Build succeeded | {_markdown(built_at)} |",
            f"| Published | {_markdown(latest.get('publishedAt') or 'unknown')} |",
            f"| Registry checked | {_markdown(observation.get('observedAt') or 'unknown')} |",
            f"| Evidence | {_markdown(evidence.get('status', 'unknown'))} |",
            "",
        ]
        if evidence.get("status") == "verified":
            lines += [
                (
                    "Matching release asset verified the build record and per-architecture runtime and scan evidence. "
                    "Signature and provenance remain unverified in this snapshot."
                ),
                "",
            ]
            evidence_links = []
            if evidence.get("releaseUrl"):
                evidence_links.append(f"[Maintenance release]({evidence['releaseUrl']})")
            if evidence.get("assetUrl"):
                evidence_links.append(f"[Evidence asset]({evidence['assetUrl']})")
            if evidence_links:
                lines += [" · ".join(evidence_links), ""]
        else:
            lines += [
                f"Evidence reason: {_markdown(evidence.get('reason', 'No matching verified record.'))}",
                "",
            ]
        if observation.get("refreshError"):
            lines += [f"Refresh error: {_markdown(observation['refreshError'])}", ""]
        for platform in latest.get("platforms", []):
            architecture = _escape(platform["architecture"])
            labels = platform.get("labels", {})
            lines += [
                "<details>",
                f"<summary>{architecture} OCI config and labels</summary>",
                "",
                (
                    f"<p>Manifest: <code>{_escape(platform['manifestDigest'])}</code><br>"
                    f"Config: <code>{_escape(platform['configDigest'])}</code><br>"
                    f"Config created: {_escape(platform.get('configCreatedAt') or 'unknown')}</p>"
                ),
                "<table><thead><tr><th>Label</th><th>Value</th></tr></thead><tbody>",
            ]
            lines += [
                f"<tr><td>{_escape(key)}</td><td>{_escape(value)}</td></tr>" for key, value in sorted(labels.items())
            ]
            lines += ["</tbody></table>", "</details>", ""]
    else:
        lines += ["No build, publication, architecture, or registry observation time was supplied.", ""]
    lines += [
        (
            "GitHub package activity can include signatures and attestations; it does not identify "
            "when the current runnable image was published. "
            "A registry observation is a point-in-time check; mutable tags may move afterward. "
            "Use the immutable digest and [maintenance evidence]"
            "(https://containers.strukturpiloten.de/guides/maintenance-evidence/) for an audit."
        ),
        "",
    ]
    return "\n".join(lines)
