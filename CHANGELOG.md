# Changelog

All notable changes to `sshboard` will be documented in this file.

Format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/) once we reach v1.0; until then, breaking changes can land in minor releases — see "Stability promises" in [README.md](README.md).

## [0.1.0] — 2026-05-29

Initial release. Both views render live data. Certificate revocation is delegated to sshca; endpoint SSH commands are copied to the clipboard.

### Added — Certs view

- Parses sshca's JSONL audit log at `$SSHCA_CA_DIR/issuance-log.jsonl` (or `--ca-dir <path>`), computes expiry via the same `+8h`/`+52w`/`from:to` parsing sshca uses internally, classifies each cert as ACTIVE / EXPIRING (within 24h) / EXPIRED / NEVER, sorts by expiry ascending. Renders as a Pico-styled table with status badges.
- **Click-to-revoke via HTMX.** Each non-revoked row carries a Revoke button that POSTs to `/t/<token>/api/cert/revoke`; server shells out to `sshca cert revoke --ca <ca> --key-id <id>`. Browser `hx-confirm` prompts before sending. Server responds with the row's HTML re-rendered with status REVOKED; HTMX swaps it in place. No page reload.
- **Optional KRL ship.** `--krl-ship user@host:/etc/ssh/revoked_keys.krl` flag; when set, every revoke also runs `sshca cert revoke --ship <target>` so the bastion's KRL stays in sync. Default is local-only.

### Added — Endpoints view

- Parses bastionhub's `endpoints.yaml` at `$BASTIONHUB_CONFIG` (or `--config <path>`, defaults to `~/.config/bastionhub/endpoints.yaml`).
- Shells out to `bastionhub status` for live tunnel state; parses the tabular output per bastionhub's documented contract; merges with the YAML config.
- Renders as table: STATUS (UP/DOWN/UNKNOWN), NAME, PORT, USER, UPTIME, DESCRIPTION. UP-first sort with name tiebreak.
- **Click-to-copy SSH command** copies `bastionhub ssh <name>` to clipboard via `navigator.clipboard.writeText`; button text confirms `✓ Copied` for 1.2s then resets.

### Added — Flags

- `--ca-dir` (overrides `$SSHCA_CA_DIR`, defaults to `./ca`)
- `--config` (overrides `$BASTIONHUB_CONFIG`, defaults to `~/.config/bastionhub/endpoints.yaml`)
- `--krl-ship <scp-target>` (described above)

### Added — CD release pipeline

- `.github/workflows/release.yml` on `v*` tag push builds the 6-platform matrix with ldflags injection, packages as `.tar.gz` / `.zip`, generates SHA-256 checksums, attaches to a GitHub Release.

### Added — Tests

- 5 tests covering `parseSSHKeygenDuration` (units + edge cases), `parseExpiry` (relative / absolute / `always`), `formatTimeLeft`, `parseBastionhubStatus` (happy path + empty + no-header defensive).

### Dependencies

- New runtime dep: `gopkg.in/yaml.v3` (for endpoints.yaml parsing).

## [0.0.1-dev] — 2026-05-29

Initial scaffold. Not a release; the placeholder before v0.1 ships real functionality.

### Added

- HTTP server on `127.0.0.1:7890` by default (`--bind` to override, with a loud warning for non-localhost binds).
- A random startup token gates all routes under `/t/<token>/`, so other processes on the same host cannot reach them by guessing the port.
- CLI detection at startup: each view is enabled if its binary is on `PATH`, and disabled with an install hint otherwise.
- Three view stubs: Home (welcome + detection status), Certs (placeholder), Endpoints (placeholder).
- Embedded HTMX 1.9.12, Pico.css 2.0.6, custom `app.css`. Single binary; no JS build pipeline.
- Cross-platform: builds clean for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`.
- GitHub Actions CI: build + vet matrix on every push/PR across all six platforms.
