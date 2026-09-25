# Optional corporate CA

ConfigMorph uses normal public CA verification by default. If a corporate TLS-interception CA is required for a local Docker build, keep its PEM bundle outside this repository and set `CORPORATE_CA_FILE` to that absolute local path before `docker compose build --no-cache`.

The Compose build passes the file as a BuildKit secret. Never copy a real root/intermediate certificate into this directory or commit it. Never disable TLS verification. `empty.crt` is an intentionally empty default placeholder.