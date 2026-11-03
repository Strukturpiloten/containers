# Strukturbo Nautobot

The same image repository now has a v0.2.0 candidate for authenticated hardware observations and native review. Its private source manifest explicitly selects appVersion0.2.0 and commit3996b2828d008eba295e00611e27750b3ec0a5d5, including both exact known-target v1 and generic v2 release contracts. v0.1.0 tags/digests and its exact historical recipe revision remain immutable. This change does not alter bootstrap's0.1 rollout/recovery policy.

Source staging selects the supported0.1 or0.2 receipt/file contract explicitly. The0.2 wheel must include its JSON schemas and fixtures, and installed qualification compares image provenance, versions and package-file hashes against the staged private source. Source-mounted checks do not replace the final installed-image, existing-data migration/restore, fresh enrollment epoch and reachable guest HTTPS gates. Local candidate builds are not publication or live selection.

The [image guide](../images/strukturbo/README.md) documents the private commit-pinned source, installed package provenance, configuration and disposable runtime checks for `strukturbo-nautobot`.

Image recipes, builds, Renovate inputs and publication belong to this repository. Registry development, existing-data migration/recovery rehearsals and guarded deployment belong to `Strukturpiloten/strukturbo-bootstrap`. Use a tested immutable image digest and its retained software archive for deployment/recovery; a local build or source-only qualification is not live installation acceptance.
