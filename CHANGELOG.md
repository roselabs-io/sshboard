# Changelog

All notable changes to `sshboard` will be documented in this file.

Format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/) once we reach v1.0; until then, breaking changes can land in minor releases — see "Stability promises" in [README.md](README.md).

## [Unreleased]

### Planned for v0.1

- Real cert table: parses sshca's JSONL audit log, renders sortable rows (KEY_ID, principals, valid-from, valid-until, status), click-to-revoke action shelling out to `sshca cert revoke`.
- Real endpoint table: parses bastionhub's `endpoints.yaml`, queries live tunnel state via `bastionhub status`, renders rows with UP/DOWN/UPTIME.
- Configurable paths via `--ca-dir` and `--config` flags (in addition to `$SSHCA_CA_DIR` / `$BASTIONHUB_CONFIG`).

## [0.0.1-dev] — 2026-05-29

Initial scaffold. Not a release; the placeholder before v0.1 ships real functionality.

### Added

- HTTP server on `127.0.0.1:7890` by default (`--bind` to override, with a loud warning for non-localhost binds).
- Random startup token gates all routes under `/t/<token>/` — Jupyter-style. Defends against drive-by from other localhost services.
- CLI detection at startup: `sshca` and `bastionhub` on PATH light up the corresponding tabs; missing CLIs gray them out with install hints.
- Three view stubs: Home (welcome + detection status), Certs (placeholder), Endpoints (placeholder).
- Embedded HTMX 1.9.12, Pico.css 2.0.6, custom `app.css`. Single binary; no JS build pipeline.
- Cross-platform: builds clean for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`.
- GitHub Actions CI: build + vet matrix on every push/PR across all six platforms.
