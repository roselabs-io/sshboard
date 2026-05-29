# sshboard

Operator console for [sshca](https://github.com/roselabs-io/sshca) and [bastionhub](https://github.com/roselabs-io/bastionhub). HTMX + Go.

**v0.0.1-dev** — scaffold stage. HTTP server + token gate + CLI detection + view skeleton in place. Real data parsing + actions land in v0.1.

## What it is

A small web UI that sits above the two SSH-substrate CLIs and answers the relational questions that don't fit in `--principal X` filters:

- *Who has what active cert right now?* (sshca's audit log, rendered as a sortable table)
- *Which endpoints are UP, which are DOWN, what's the uptime?* (bastionhub's status, refreshed)
- *What's expiring in the next 24h?* (cross-cut view)
- One-click revoke / renew / SSH actions, shelling out to the CLIs.

Substrate-narrow scope: sshboard never holds CA keys, never opens its own SSH connections, never bundles its own auth. It's a render layer + action proxy over the CLIs.

## Install

### Homebrew (macOS + Linuxbrew)

```sh
brew tap roselabs-io/tools
brew install sshboard
# requires sshca and/or bastionhub also installed:
brew install sshca bastionhub
```

### From source

```sh
git clone https://github.com/roselabs-io/sshboard.git
cd sshboard
go build -o sshboard .
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/roselabs-io/sshboard/releases) — `.tar.gz` for Unix, `.zip` for Windows, six platforms (linux/darwin/windows × amd64/arm64), SHA-256 checksums attached.

## Quick start

```sh
sshboard
```

Output:

```
sshboard version 0.0.1
Detected: sshca at /opt/homebrew/bin/sshca
Detected: bastionhub at /opt/homebrew/bin/bastionhub

Listening on: http://127.0.0.1:7890/t/a1b2c3d4e5f6.../

Open this URL in your browser. The token defends against drive-by access
from other localhost services. Don't share it.
```

Open the URL → operator console.

If only one of sshca / bastionhub is on PATH, the relevant tab is grayed out with an install hint; the other tab works as expected.

## Deployment patterns

### 1. Solo operator on a laptop (default)

`sshboard` binds `127.0.0.1:7890`. No auth needed — you're already on the box, the OS is the trust boundary.

The random startup token in the URL path defends against drive-by access from other localhost services (a malicious dev tool on your laptop hitting the unprotected port). Same pattern Jupyter uses.

### 2. Dogfood — run on your bastion, access via SSH LocalForward

This is the recommended pattern for team use. sshboard runs on the bastion VPS; engineers SSH to the bastion (cert-auth via bastionhub) with `LocalForward` set; they open `http://localhost:7890` locally.

The substrate IS the auth layer. SSH + cert is the security boundary. sshboard never listens on the network.

```
~/.ssh/config (on each engineer's laptop):

Host bastion
    HostName <bastion-ip>
    User gw-user
    LocalForward 7890 127.0.0.1:7890
```

Then `ssh bastion` opens the forward + the session. Open browser → `http://localhost:7890`.

Revoke an engineer's `gw-user` cert → access gone (sshd re-reads KRL every connection).

### 3. Behind a reverse proxy (advanced)

If you must expose sshboard to the network directly, put it behind nginx / Caddy / Traefik with TLS + your existing SSO. sshboard does NOT include its own auth.

```sh
sshboard --bind 127.0.0.1:7890   # still localhost-bound; proxy in front
```

sshboard will print a startup warning if you `--bind` to anything other than localhost.

## How it works

- Reads sshca's JSONL audit log (`<ca-dir>/issuance-log.jsonl`) directly. Schema is sshca's contract surface.
- Reads bastionhub's `endpoints.yaml` (`~/.config/bastionhub/endpoints.yaml` or `$BASTIONHUB_CONFIG`) directly. Schema is bastionhub's contract surface.
- Shells out to `sshca cert revoke / renew / inspect` for cert-side actions.
- Shells out to `bastionhub status / ssh` for endpoint-side actions.

Auto-discovery, in order:

1. `$SSHCA_CA_DIR` env var (matches sshca's convention)
2. `$BASTIONHUB_CONFIG` env var
3. `--ca-dir` and `--config` flags (override env) — *coming v0.1*
4. Sensible defaults

## Stability promises

Pre-1.0: minor releases may break things. Breaking changes will be called out in [CHANGELOG.md](CHANGELOG.md) with the rationale.

Post-1.0: [SemVer](https://semver.org/). The versioned surfaces will be:

- **CLI flags** of the `sshboard` binary
- **URL routes** the UI serves (relevant if you script against it)

The interpretation of sshca's and bastionhub's data is delegated to those tools' own contract surfaces; if their schemas change in a breaking way, sshboard adjusts in a coordinated release.

## Roadmap

- **v0.1** — Real cert table (parse JSONL, render sortable, click-to-revoke). Real endpoint table (parse YAML, query live state, click-to-SSH-via-copy-to-clipboard).
- **v0.2** — Cross-cut "expiring in 24h" dashboard. Audit log browse with filters. Sshd auth log integration when running on a bastion.
- **v0.3** — Bastion-deployment polish: documented systemd / launchd units, dogfood-pattern recipes, audit-log-sync mechanism so cert view lights up even when sshboard runs on the bastion (not the laptop).
- **Later** — `roles.yaml` policy view if a roles file is detected. Multi-tenant view when there's a real product context.

## License

MIT. See [LICENSE](LICENSE).
