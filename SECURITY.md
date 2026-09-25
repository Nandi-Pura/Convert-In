# Security Policy

## Supported versions

Security fixes currently target the latest code on `main` and the latest published alpha release. Older alpha builds are unsupported.

## Reporting a vulnerability

Use GitHub's **Security → Report a vulnerability** private reporting flow for this repository. Do not open a public issue containing exploit details, firewall configurations, credentials, certificates, tokens, customer identifiers, or other sensitive data. If private reporting is unavailable, contact the repository owner through their GitHub profile without sending configuration data; request a private channel first.

Include a minimal sanitized reproducer, affected version, impact, and suggested mitigation where possible. No private security email is currently published.

## Configuration confidentiality

ConfigMorph is local-only by design: no cloud API, telemetry, analytics, external AI, or configuration upload. Source configurations and generated workspaces remain sensitive plaintext on the local filesystem. Users must control host access, backups, filesystem permissions, and retention. Do not expose the service beyond its default `127.0.0.1` bind without adding appropriate authentication and TLS.