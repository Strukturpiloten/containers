# Security reporting

Report potential vulnerabilities privately through [GitHub’s vulnerability reporting form](https://github.com/Strukturpiloten/containers/security/advisories/new), also available as **Report a vulnerability** on the repository’s Security tab. Reports are shared privately with the maintainers. Do not post exploit details, credentials, or other sensitive information in public issues.

For non-sensitive bugs, outdated dependencies, documentation errors, or compatibility gaps, use [GitHub Issues](https://github.com/Strukturpiloten/containers/issues). Include the affected image name, architecture, exact tag and digest, observed behavior, and relevant logs with secrets removed. Refer to the [security and support guide](docs/security-and-support.md) for scope and evidence.

Container images include upstream software under its own maintenance and licensing terms. Historical Docker and Podman compatibility fixtures intentionally retain old engine or operating-system behavior and are not production container hosts. The repository's vulnerability admission checks, SBOMs, signatures, and runtime evidence reduce uncertainty but do not guarantee that an image is free of vulnerabilities or suitable for a particular deployment. Verify the image digest and its [maintenance evidence](docs/maintenance-evidence.md) before use.
