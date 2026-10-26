# Changelog

All notable changes to `sshboard` will be documented in this file.

Format roughly follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning is [SemVer](https://semver.org/) once we reach v1.0; until then, breaking changes can land in minor releases — see "Stability promises" in [README.md](README.md).

## [Unreleased]

### Added — Health and metrics

- **`/health` and `/t/<token>/health`** (new routes): `GET` and `HEAD` answer `200` with `{"status": "ok"}`; `/health` needs no token. See README, "Health and metrics".
- **`/t/<token>/metrics`** (new route): `GET` and `HEAD` answer the counter `sshboard_http_requests_total` by `route` and `code` in the Prometheus text format. `/metrics` without the token is not served. See README, "Health and metrics".

### Added — Log view

- **Issuance log tab.** `/t/<token>/log` (new route) lists the issuance log entry by entry, oldest first, filtered by the query parameters `principal` (exact match), `ca` (`ALL`, `user`, `host`) and `from` / `to` (inclusive UTC dates, `YYYY-MM-DD`); an invalid `ca` or date returns 400. Read-only. See README, "Issuance log".

### Added — Certs view

- **Filtering.** A search field filters rows by `key_id` substring (ignoring case) and status buttons by ACTIVE, EXPIRING, EXPIRED or ALL. Both are query parameters of `/t/<token>/certs`: `q` and `status` (default `ALL`; another value returns 400). See README, "Filtering certificates".
- **Click-to-renew.** Each row with an expiry carries a Renew action that POSTs to `/t/<token>/api/cert/renew`; the server runs `sshca cert renew --ca <ca> --pubkey-file <pubkey> --dir <ca-dir>`, with `--ship <target>` when the confirmation prompt is answered with a target. The pubkey file is the entry's `pubkey` field in the issuance log. Rows whose pubkey file is not on the host show no Renew action. See README, "Renewing a certificate".
- **Inspect dialog.** Each row carries an Inspect action that GETs `/t/<token>/api/cert/inspect`; the server runs `sshca cert inspect <cert>`, where `<cert>` is the entry's `cert` field in the issuance log, and returns a dialog holding the output. See README, "Inspecting a certificate".
- **CI deploy group.** Certificates with a `deploy-*` principal are listed in a "CI deploy" table, with the repository taken from the key ID (`<repo>@github-actions`). See README, "CI deploy certificates".
- **`--deploy-expiring-within`** (default `14d`): deploy certificates that expire within this duration are marked EXPIRING. Other certificates keep the 24h window.

### Added — Endpoints view

- **Enroll form.** An "Enroll an endpoint" form POSTs to `/t/<token>/api/endpoint/enroll`; the server runs `bastionhub endpoint enroll --ca-dir=<ca-dir> [--<flag>=<value> ...] <name>` with `BASTIONHUB_CONFIG` set to the endpoints.yaml the view reads. See README, "Enrolling an endpoint".
- **Unregister.** Each row carries an Unregister action, behind a confirmation, that POSTs to `/t/<token>/api/endpoint/unregister`; the server runs `bastionhub endpoint unregister <name>`. The endpoint's certificate is not revoked. See README, "Unregistering an endpoint".
- **Bastion switch.** `--config` can be repeated, one endpoints.yaml per bastion. With more than one, the Endpoints view shows a button per file and reads the one named by the new query parameter `config` of `/t/<token>/endpoints` (default: the first `--config`; another value returns 400). Enroll, Unregister and `bastionhub status` run with `BASTIONHUB_CONFIG` set to the selected file, and Copy SSH prefixes `BASTIONHUB_CONFIG='<config>'`. See README, "Switching between bastions".

### Changed — Release

- A merge into `main` that adds a version heading to this file creates the tag `vX.Y.Z` and the GitHub Release from CI. See README, "Releases".
- The release sends a `formula-update` event to `roselabs-io/homebrew-tools`, the type its workflow listens for; it sent `release`, so `Formula/sshboard.rb` was not updated.

### Changed — Endpoints view

- `bastionhub status` runs with `BASTIONHUB_CONFIG` set to the endpoints.yaml the view reads; it inherited sshboard's environment, so with `--config` set it reported on `$BASTIONHUB_CONFIG` or the default file.

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
