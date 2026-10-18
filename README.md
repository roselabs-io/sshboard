# sshboard

A web interface over [sshca](https://github.com/roselabs-io/sshca) and
[bastionhub](https://github.com/roselabs-io/bastionhub). Go and HTMX, single
binary.

## Overview

`sshboard` renders two views and proxies actions to the two CLIs:

- **Certificates** — sshca's issuance log as a table, with expiry state,
  filtered by `key_id` substring and by status.
- **Endpoints** — bastionhub's registry with live tunnel state and uptime.

Actions run the CLIs: `sshca cert revoke`, `sshca cert renew`, `sshca cert
inspect`, `bastionhub status`, `bastionhub ssh`.

It holds no CA keys, opens no SSH connections of its own, and ships no
authentication. It reads two files and executes two binaries.

## Install

### Homebrew (macOS + Linuxbrew)

```sh
brew tap roselabs-io/tools
brew trust roselabs-io/tools   # recent Homebrew refuses third-party taps otherwise
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

The token in the path prevents other processes on this host from
reaching the port. It is not authentication; do not share the URL.
```

If only one of `sshca` or `bastionhub` is on `PATH`, the corresponding view is
disabled and the other remains available.

## Deployment patterns

### 1. Local (default)

`sshboard` binds `127.0.0.1:7890`. The operating system's user boundary is the
access control.

The random token in the URL path prevents other processes on the same host from
reaching the port. It is not a substitute for authentication.

### 2. On the bastion, reached over an SSH local forward

`sshboard` runs on the bastion and stays bound to loopback. Operators connect
with `LocalForward` configured and open the port locally. Access is therefore
governed by the same certificate that grants SSH access; revoking it removes
access, since sshd re-reads the KRL on every connection.

```
~/.ssh/config (on each engineer's laptop):

Host bastion
    HostName <bastion-ip>
    User gw-user
    LocalForward 7890 127.0.0.1:7890
```

`ssh bastion` opens the forward; the interface is then at
`http://localhost:7890`.

In this arrangement the certificates view is empty: `sshboard` reads sshca's
issuance log from the local filesystem, and that log is on the machine holding
the CA, not on the bastion. The endpoints view is unaffected.

### 3. Behind a reverse proxy

To expose `sshboard` on a network, place it behind a proxy providing TLS and
authentication. `sshboard` has none of its own.

```sh
sshboard --bind 127.0.0.1:7890   # still localhost-bound; proxy in front
```

`--bind` to a non-loopback address prints a warning at startup.

## How it works

- Reads sshca's JSONL audit log (`<ca-dir>/issuance-log.jsonl`) directly. Schema is sshca's contract surface.
- Reads bastionhub's `endpoints.yaml` (`~/.config/bastionhub/endpoints.yaml` or `$BASTIONHUB_CONFIG`) directly. Schema is bastionhub's contract surface.
- Shells out to `sshca cert revoke / renew / inspect` for cert-side actions.
- Shells out to `bastionhub status / ssh` for endpoint-side actions.

Auto-discovery, in order:

1. `$SSHCA_CA_DIR` env var (matches sshca's convention)
2. `$BASTIONHUB_CONFIG` env var
3. `--ca-dir` and `--config` flags, which override the environment
4. The default paths above

### Filtering certificates

The Certs view has a search field and four status buttons above the table. Both
filters are query parameters of `/t/<token>/certs`:

| Parameter | Values | Default |
|---|---|---|
| `q` | substring of `key_id`, matched ignoring case | empty: every `key_id` |
| `status` | `ALL`, `ACTIVE`, `EXPIRING`, `EXPIRED` | `ALL` |

- `ALL` includes certificates without expiry (`NEVER`); no other button shows
  them.
- Any other `status` value returns `400 Bad Request`.
- The search field applies on Enter and keeps the selected status; a status
  button keeps the search text.
- The filter is not stored; it lives only in the URL. A row swapped in by
  Revoke or Renew stays on the page until it is reloaded, whether or not it
  matches the filter.

### Renewing a certificate

Each certificate row with an expiry has a Renew action next to Revoke. It runs:

```sh
sshca cert renew --ca <ca> --pubkey-file <pubkey> --dir <ca-dir> [--ship <target>]
```

- `<pubkey>` is the `pubkey` field of the row's issuance-log entry: the path
  passed to sshca when the certificate was signed. A relative path resolves
  against sshboard's working directory.
- The confirmation prompt asks for an optional scp target; an empty answer runs
  without `--ship`, Cancel runs nothing. A target starting with `-` is rejected.
- Principals and validity are sshca's defaults for `cert renew`: principals read
  from the existing `<pubkey>-cert.pub`, validity `+8h`.
- On success the row is replaced by the new certificate's row followed by the
  renewed one. The renewed certificate is not revoked.
- A row whose pubkey file does not exist on the sshboard host shows
  "Renew: pubkey file not found" instead of the action. This is the case when
  the certificate was signed on another machine or from another working
  directory.

## Stability promises

Pre-1.0: minor releases may break things. Breaking changes will be called out in [CHANGELOG.md](CHANGELOG.md) with the rationale.

Post-1.0: [SemVer](https://semver.org/). The versioned surfaces will be:

- **CLI flags** of the `sshboard` binary
- **URL routes** the UI serves (relevant if you script against it)

The formats `sshboard` reads are sshca's and bastionhub's contract surfaces, not
its own.

## License

MIT. See [LICENSE](LICENSE).
