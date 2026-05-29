# sshboard — contributor / agent context

Operator console for [sshca](https://github.com/roselabs-io/sshca) and [bastionhub](https://github.com/roselabs-io/bastionhub). HTMX + Go. Single binary; serves a server-rendered web UI from embedded templates + vendored static assets. No JS build pipeline.

## Read order

1. This file
2. [README.md](README.md) — install + Quick start + Deployment patterns
3. [CHANGELOG.md](CHANGELOG.md) — per-release changes
4. [main.go](main.go) — http server, template loading, detection logic, token gate
5. [templates/](templates/) + [static/](static/) — the UI

## Project shape

**What this is:** a thin operator UI over the SSH-substrate CLIs. Renders relational views the CLI handles awkwardly (who-has-what-on-what); shells out to the CLIs for actions (revoke, renew, ssh). Substrate-adjacent — not part of either CLI, not the gateway product.

**What this isn't:**

- A CA. Never touches CA private keys. Reads sshca's audit log + shells out to `sshca cert revoke / renew`.
- A bastion. Never opens SSH connections itself. Shells out to `bastionhub ssh / status`.
- An auth system. Bundles a random startup token (Jupyter-style) as a drive-by defense. For network exposure, expects SSH-LocalForward dogfood or a reverse proxy.

## Key principles

1. **Single binary, no JS build.** Go server + embedded templates + vendored HTMX + Pico. `go build` produces the entire app. Matches the substrate aesthetic.
2. **Substrate is the auth layer.** SSH cert auth (via bastionhub) is how operators reach sshboard in the dogfood pattern. sshboard itself binds localhost + a startup token.
3. **Graceful degradation.** sshca on PATH → Certs view lights up. bastionhub on PATH → Endpoints view lights up. Both → integrated views. Neither → useless, exits.
4. **Shell out for actions; read files for state.** Reads sshca's JSONL log + bastionhub's `endpoints.yaml` directly (their documented contract surfaces). Calls `sshca cert revoke ...` / `bastionhub status` for mutations and live queries.
5. **Server-rendered + HTMX for interactivity.** No SPA. Each action is `<form hx-post="/api/cert/revoke">` swapping a DOM fragment on response.

## Contract surface (semver-disciplined)

Two versioned surfaces, both post-v1.0:

- **CLI flags** of the `sshboard` binary (`--bind`, future `--ca-dir`, `--config`)
- **URL routes** the UI serves (`/`, `/t/<token>/`, `/t/<token>/certs`, `/t/<token>/endpoints`, future `/api/...`) — relevant if you script against it

sshboard's reading of sshca's JSONL + bastionhub's YAML is delegated to those tools' own contract surfaces; coordinated major bumps if their schemas change in a breaking way.

## Don't re-walk these

- **Don't add auth code to sshboard.** SSH-LocalForward dogfood + reverse proxy handle it. Bundling auth would mean OAuth flows, password DB, session management — sshboard stays small by delegating. The startup token is a drive-by defense, not auth.
- **Don't bind to a non-localhost address by default.** `--bind 127.0.0.1:7890` is the default for a reason. The warning on non-localhost bind is intentional and shouldn't be suppressed.
- **Don't add a JS build step.** Vendored HTMX + Pico keep the single-binary aesthetic. If you want React, fork into a separate UI repo; don't bloat sshboard.
- **Don't bundle sshca or bastionhub.** Calls them as subprocess. Loose coupling means version-independent. Detection at startup is the contract.

## File structure

```
sshboard/
├── README.md           # public face: install, deployment patterns
├── CHANGELOG.md        # per-release
├── CLAUDE.md           # this file
├── LICENSE             # MIT
├── main.go             # http server + detection + template render + token gate
├── go.mod / go.sum
├── templates/          # *.html.tmpl, embedded via go:embed
│   ├── layout.html.tmpl
│   ├── index.html.tmpl
│   ├── certs.html.tmpl
│   └── endpoints.html.tmpl
├── static/             # embedded via go:embed
│   ├── htmx.min.js     # vendored htmx 1.9.x
│   ├── pico.min.css    # vendored pico 2.0.x
│   └── app.css         # custom layout overrides
└── .github/workflows/  # CI + release (matches sshca + bastionhub pattern)
```

## Conventions

- **Filenames:** kebab-case for docs, `.html.tmpl` for templates, `.css` / `.js` for static
- **Dates:** ISO `YYYY-MM-DD`
- **No YAML frontmatter** on Markdown docs
- **Version variable** in `main.go` is `var` not `const` so release builds inject the tag via `-ldflags "-X main.version=<tag>"`
- **Template inheritance** via Go's `{{block}}` directive. `layout.html.tmpl` defines `{{block "content" .}}{{end}}`; each view template defines `{{define "content"}}...{{end}}`. Each view is loaded as `[layout, view]` and rendered as the `"layout"` template.

## See also

- [sshca](https://github.com/roselabs-io/sshca) — cert tool sshboard reads + shells out to
- [bastionhub](https://github.com/roselabs-io/bastionhub) — bastion tool sshboard reads + shells out to
- Internal design notes, roadmap, current operational state live in a private workspace (not public).
