# Documentation site operations

The intended public URL is **https://containers.strukturpiloten.de/**. The site is generated from the repository's declarations and an optional, timestamped registry observation. The registry snapshot is published at `/data/registry-snapshot.json`; an observation should only be described as verified when its status and source say so. The live domain and Pages deployment must be checked after setup; the URL in this file is the intended address, not proof of a live site.

## One-time GitHub Pages and DNS setup

An owner with repository administration access must open **Settings → Pages** for `Strukturpiloten/containers`, select **GitHub Actions** as the build and deployment source, and set **Custom domain** to `containers.strukturpiloten.de`. The workflow deploys to the `github-pages` environment. If GitHub asks to create or approve that environment, allow deployments from `main` for the trusted documentation workflow.

In the DNS zone for `strukturpiloten.de`, create this record:

| Type | Name / host | Target / value |
| --- | --- | --- |
| CNAME | `containers` | `strukturpiloten.github.io` |

Do not add a URL, path, port, or IP address as the CNAME target. If another record already uses the `containers` name, replace that conflicting record. Wait for DNS propagation and GitHub's certificate issuance, then enable **Enforce HTTPS** in Pages settings. Verify the CNAME with `dig +short CNAME containers.strukturpiloten.de` and the site with `curl -I https://containers.strukturpiloten.de/`. The response should be successful and use HTTPS. Check `https://containers.strukturpiloten.de/data/registry-snapshot.json` separately after the first successful refresh.

The repository **About** website URL should be `https://containers.strukturpiloten.de/` once Pages serves the site. Repository description and topics are maintained in GitHub repository settings; they are separate from DNS and Pages.

## Build and refresh

The repository administrator owns Pages configuration and deployment access. The DNS-zone administrator owns the `containers` CNAME and any verification records. An organization owner can additionally verify the domain in the organization's Pages settings: use the exact TXT name and challenge value GitHub supplies and retain that record after verification. Do not invent a challenge value or replace the website CNAME with the TXT record.

After launch, optionally verify `containers.strukturpiloten.de` in Google Search Console using the account that will maintain the site. A domain property requires the TXT record supplied by Search Console; a URL-prefix property offers other verification methods. Submit `https://containers.strukturpiloten.de/sitemap.xml` and inspect a catalogue and image URL. Indexing and inclusion in AI search results are controlled by the search provider and are not guaranteed. Important content is static HTML; JSON and Markdown exports are additional representations.

Pull requests run the documentation generator in the existing `Validate containers` CI workflow. That build uses checked-in declarations only and validates the site without registry network access or deployment credentials:

```sh
uv run --frozen --group docs python -m scripts.documentation --output _site
```

`Documentation site` deploys from trusted `main` after `Publish images` completes, including runs with a failed image job. It also refreshes independently every day at 07:23 UTC, after documentation-only pushes to `main`, and via **Actions → Documentation site → Run workflow** on `main`. A mixed documentation and image-input push waits for the publish workflow completion before refreshing the site. The independent schedule keeps catalogue observations visible even when image publication is disabled. Publication failures can leave individual observations incomplete while other image entries refresh. Review each observation's source, status, and timestamp rather than interpreting a workflow completion as proof that every registry tag was published.

The refresh downloads the prior published snapshot when it is reachable and passes it to the observation script. A missing site or failed fetch is reported in the workflow summary. It does not invent prior observations. The build job reads public registry and release data; the deploy job alone receives `pages: write` and `id-token: write`. No pull-request artifact or pull-request code is executed in the deployment workflow.

To build the observed site locally, first install `skopeo`, then run:

```sh
uv run --frozen python -m scripts.docs_observations --repository Strukturpiloten/containers --output /tmp/registry-snapshot.json
uv run --frozen --group docs python -m scripts.documentation --output _site --snapshot /tmp/registry-snapshot.json
```

## Recovery

For a temporary registry or GitHub API failure, inspect the `Documentation site` build log and its published snapshot statuses, then dispatch the workflow again on `main`. The observer uses bounded network attempts and records incomplete results; a failed site build or deployment leaves the previous successful Pages deployment in place. If a publish workflow is still retrying failed image jobs, wait for its retry to finish and then dispatch one more documentation refresh to pick up final tags.

For a source or rendering regression, revert the offending commit through the normal repository workflow and dispatch `Documentation site` on `main`. For a bad registry observation, correct the observation source or script, then refresh; compare the new `/data/registry-snapshot.json` against the previous successful run's artifact or downloaded snapshot before considering the incident closed. GitHub Pages deployment history in **Actions** identifies the last successful build, but rerunning an old workflow executes the current trusted `main` checkout and performs a fresh registry observation. A historical workflow rerun alone is not a data rollback.
