# Security Policy

## Reporting

Do not disclose exploitable security issues, access tokens, private subscription URLs, UUIDs, or active configurations in a public issue.

Contact the maintainer privately through the GitHub profile until a dedicated security-contact channel is published. Provide the affected version, minimal reproduction, impact, and a redacted log.

## Token handling

The application reads `GITHUB_TOKEN` only from the environment and sends it only to GitHub-owned hostnames used for source retrieval. Real tokens must never be committed.
