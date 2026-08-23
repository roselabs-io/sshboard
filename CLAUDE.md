# sshboard — contributor notes

A web interface over [sshca](https://github.com/roselabs-io/sshca) and
[bastionhub](https://github.com/roselabs-io/bastionhub). Go and HTMX, single
binary. Server-rendered from embedded templates and vendored static assets;
there is no JavaScript build step.

It reads two files and runs two binaries. It holds no CA keys, opens no SSH
connections, and has no authentication.

## Scope

Out of scope, deliberately:

- **Certificate authority.** Reads sshca's issuance log; calls
  `sshca cert revoke` and `sshca cert renew` for actions.
- **SSH.** Calls `bastionhub ssh` and `bastionhub status`.
- **Authentication.** The random startup token only prevents other processes on
  the same host from reaching the port. Network exposure requires an SSH local
  forward or a reverse proxy in front.
- **A JavaScript build.** HTMX and Pico are vendored.
- **Bundling the CLIs.** They are called as subprocesses and detected at
  startup, which keeps their versions independent of this one.

## Contract surface

Two versioned surfaces, from v1.0:

- **CLI flags** — `--bind`, `--ca-dir`, `--config`.
- **URL routes** — `/`, `/t/<token>/`, `/t/<token>/certs`,
  `/t/<token>/endpoints`, relevant if scripted against.

The formats it reads are sshca's and bastionhub's contract surfaces, not its
own; a breaking change there is handled in a coordinated release.

## Constraints worth knowing

- **The default bind is `127.0.0.1:7890`.** The warning printed on a
  non-loopback bind is intentional.
- **Each view requires its binary on `PATH`.** With neither present the process
  exits.
- **State is read from files; actions shell out.** The issuance log and
  `endpoints.yaml` are read directly. Mutations and live queries go through the
  CLIs.
- **`version` in `main.go` is a `var`, not a `const`**, so release builds can
  inject the tag with `-ldflags "-X main.version=<tag>"`.

## Conventions

- Filenames: kebab-case.
- Dates: ISO `YYYY-MM-DD`.
- No YAML frontmatter in Markdown.
