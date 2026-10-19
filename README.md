# sshboard

A web interface over [sshca](https://github.com/roselabs-io/sshca) and
[bastionhub](https://github.com/roselabs-io/bastionhub). Go and HTMX, single
binary.

## Overview

`sshboard` renders three views and proxies actions to the two CLIs:

- **Certificates** — sshca's issuance log as a table, with expiry state,
  filtered by `key_id` substring and by status.
- **Log** — sshca's issuance log entry by entry, in order of time, filtered by
  principal, CA and date range.
- **Endpoints** — bastionhub's registry with live tunnel state and uptime, for
  one bastion at a time when several `--config` files are given.

Actions run the CLIs: `sshca cert revoke`, `sshca cert renew`, `sshca cert
inspect`, `bastionhub status`, `bastionhub ssh`, `bastionhub endpoint enroll`,
`bastionhub endpoint unregister`.

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
- Shells out to `bastionhub status / ssh / endpoint enroll / endpoint unregister` for endpoint-side actions.

Auto-discovery, in order:

1. `$SSHCA_CA_DIR` env var (matches sshca's convention)
2. `$BASTIONHUB_CONFIG` env var
3. `--ca-dir` and `--config` flags, which override the environment; `--config`
   can be repeated, one endpoints.yaml per bastion
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

### Issuance log

The Log view lists every entry of `<ca-dir>/issuance-log.jsonl`, oldest first
by `ts`, with the columns `ts`, `ca`, `key_id`, `principals`, `valid` and
`cert`. Entries with the same `ts` keep their file order. It requires `sshca`
on `PATH`, as the Certs view does, and does not write to the log.

The filters are query parameters of `/t/<token>/log`, set by the form above the
table:

| Parameter | Values | Default |
|---|---|---|
| `principal` | one principal; matches entries that list it among their `principals` | empty: every principal |
| `ca` | `ALL`, `user`, `host` | `ALL` |
| `from` | date `YYYY-MM-DD`, inclusive | empty: no lower bound |
| `to` | date `YYYY-MM-DD`, inclusive | empty: no upper bound |

- Dates compare against the UTC date of `ts`.
- An invalid `ca`, `from` or `to` returns `400 Bad Request`.
- The principal list offers the principals present in the log. The match is
  exact, not a substring.
- An entry whose `ts` does not parse as RFC 3339 is listed first and is
  excluded when `from` or `to` is set.

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

### Inspecting a certificate

Each certificate row has an Inspect action. It runs:

```sh
sshca cert inspect <cert>
```

- `<cert>` is the `cert` field of the row's issuance-log entry. A relative path
  resolves against sshboard's working directory.
- The output (`ssh-keygen -L`) is shown in a dialog over the Certs view; Close
  dismisses it. When sshca exits non-zero, the dialog shows "Inspect failed"
  and sshca's output, for example when the cert file is not on the sshboard
  host.
- The dialog is read-only.

### Switching between bastions

`--config` can be given more than once, one bastionhub endpoints.yaml per
bastion:

```sh
sshboard --config ~/.config/bastionhub/endpoints.yaml --config /srv/bastion-eu/endpoints.yaml
```

- With more than one file, the Endpoints view shows one button per file, by
  path, above the table. The first `--config` is selected by default.
- The selection is the query parameter `config` of `/t/<token>/endpoints`,
  whose value is one of the `--config` paths. Any other value returns
  `400 Bad Request`.
- The table, `bastionhub status`, Enroll and Unregister use the selected file:
  each runs bastionhub with `BASTIONHUB_CONFIG` set to it. The forms submit the
  path as a `config` field; an unknown path returns `400 Bad Request` without
  running bastionhub.
- With more than one file, Copy SSH copies
  `BASTIONHUB_CONFIG='<config>' bastionhub ssh <name>`.
- The Certs and Log views are unchanged: there is one `--ca-dir`.
- When `--config` is given, `$BASTIONHUB_CONFIG` is not read.

### Enrolling an endpoint

The Endpoints view has an "Enroll an endpoint" form. It runs:

```sh
BASTIONHUB_CONFIG=<config> bastionhub endpoint enroll --ca-dir=<ca-dir> [--<flag>=<value> ...] <name>
```

- `<config>` is the endpoints.yaml the view reads (the selected `--config`,
  `$BASTIONHUB_CONFIG`, or the default path), and `<ca-dir>` is sshboard's CA
  dir, so the new endpoint and its tunnel certificate appear in the Endpoints
  and Certs views.
- The fields are the command's inputs: name and pubkey file (required), user,
  port, identity, validity, principal, description. An empty field omits its
  flag and takes bastionhub's default (user `root`, the next free port in
  12001-12099, validity `+52w`, principal `gw-tunnel`).
- The pubkey file is a path on the sshboard host; a relative path resolves
  against sshboard's working directory.
- A name starting with `-` is rejected without running bastionhub.
- The result, including bastionhub's next steps for shipping the certificate
  to the endpoint, is shown above the re-read table. On failure the form keeps
  the submitted values.
- Enrollment through `bastionhub invite` is not available here.

### Unregistering an endpoint

Each endpoint row has an Unregister action. After a confirmation it runs:

```sh
BASTIONHUB_CONFIG=<config> bastionhub endpoint unregister <name>
```

This removes the endpoint from endpoints.yaml. It does not revoke the
endpoint's tunnel certificate; that certificate stays valid until it expires or
is revoked from the Certs view.

## Stability promises

Pre-1.0: minor releases may break things. Breaking changes will be called out in [CHANGELOG.md](CHANGELOG.md) with the rationale.

Post-1.0: [SemVer](https://semver.org/). The versioned surfaces will be:

- **CLI flags** of the `sshboard` binary
- **URL routes** the UI serves (relevant if you script against it)

The formats `sshboard` reads are sshca's and bastionhub's contract surfaces, not
its own.

## License

MIT. See [LICENSE](LICENSE).
