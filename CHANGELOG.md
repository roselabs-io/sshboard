# Changelog

All notable changes to `sshboard` will be documented in this file.

Format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/) once we reach v1.0; until then, breaking changes can land in minor releases — see "Stability promises" in [README.md](README.md).

## [Unreleased]

### Added (toward v0.1)

- **Certs view wires real data.** Parses sshca's JSONL audit log at `$SSHCA_CA_DIR/issuance-log.jsonl` (or `--ca-dir <path>`), computes expiry via the same `+8h`/`+52w`/`from:to` parsing sshca uses internally, classifies each cert as ACTIVE / EXPIRING (within 24h) / EXPIRED / NEVER, sorts by expiry ascending. Renders as a Pico-styled table with status badges.
- **Click-to-revoke via HTMX.** Each non-revoked row carries a Revoke button that POSTs to `/t/<token>/api/cert/revoke`; server shells out to `sshca cert revoke --ca <ca> --key-id <id>`. Browser `hx-confirm` prompts before sending. Server responds with the row's HTML re-rendered with status REVOKED; HTMX swaps it in place. No page reload.
- **Optional KRL ship.** New `--krl-ship user@host:/etc/ssh/revoked_keys.krl` flag at startup; when set, every revoke also runs `sshca cert revoke --ship <target>` so the bastion's KRL stays in sync. Default (unset) is local-only revoke; UI shows a hint about manual shipping in that mode.
- `--ca-dir` startup flag (overrides `$SSHCA_CA_DIR`, which overrides default `./ca`).

### Planned (remaining for v0.1)

- Real endpoint table: parses bastionhub's `endpoints.yaml`, queries live tunnel state via `bastionhub status`, renders rows with UP/DOWN/UPTIME and a click-to-copy SSH command.
- `--config` flag for endpoints.yaml path.

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
