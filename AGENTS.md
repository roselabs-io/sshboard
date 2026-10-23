# AGENTS.md

Instructions for agent sessions working in this repository. `pipeline.yaml` names this file for
`docs.agents`, `docs.contract`, `docs.review_posture` and `docs.operating_model`.

[`CLAUDE.md`](CLAUDE.md) holds the scope, the contract surface (CLI flags, URL routes), the
constraints and the conventions. This file does not repeat them.

## Repository

A Go web server built as one binary (`go.mod`: `go 1.25.5`, one dependency, `gopkg.in/yaml.v3`).
Templates and static assets are embedded with `go:embed`; there is no JavaScript build step.

| Path | Content |
|---|---|
| `main.go` | the whole implementation; `version` is a `var` set with `-ldflags "-X main.version=<tag>"` at release |
| `main_test.go` | the tests (`go test ./...`) |
| `tests/browser/`, `playwright.config.js`, `package.json`, `package-lock.json` | the Chromium test and its pinned Playwright runner; no application JavaScript build |
| `templates/*.html.tmpl` | the server-rendered views, embedded |
| `static/` | `app.css` and the vendored `htmx.min.js` and `pico.min.css`, embedded |
| `README.md`, `CHANGELOG.md`, `CLAUDE.md` | usage, release notes, contributor notes |
| `.github/workflows/ci.yml` | `go vet` and `go build` for six targets, `go test` on linux/amd64 |
| `.github/workflows/release.yml` | on a `v*` tag: builds six targets, archives, `checksums.txt`, a GitHub Release, then notifies `roselabs-io/homebrew-tools` |
| `.github/workflows/sshboard-ci.yml` | `validate` (PR metadata) and `gate` (`just gate`) |
| `.github/workflows/sshboard-pm.yml` | the issue and board sync of Governor |
| `.github/workflows/audit.yml` | `just audit` on a change to `go.mod` or `go.sum`, and weekly on `main` |
| `.secrets.baseline` | the detect-secrets findings that are not secrets, read by `just scan` |
| `pipeline.yaml` | the Governor dispatcher's config for this repository |
| Governor's package preflight (`tools/local_preflight.py` of the Governor package, run by the dispatcher; this repository keeps no copy) | the local check the dispatcher runs: `just check`, then `just gate` |

No key or token is tracked. A merge into `main` deploys nothing; a `v*` tag creates a GitHub
Release; for a tag without `-`, the `homebrew` job of `release.yml` then sends a `release`
`repository_dispatch` event (`tool`, `tag`) to `roselabs-io/homebrew-tools`, authenticated with the
secret `HOMEBREW_TAP_TOKEN`, for a workflow there to update `Formula/sshboard.rb`. The
binary also runs as `sshboard.service` on the box; how it is installed and updated there is not
recorded in this repository.

## Commands

| Recipe | Runs |
|---|---|
| `just check` | `go vet ./...`; fails when `gofmt -l .` lists a file |
| `just test` | `go test ./...` |
| `just browser-test` | Playwright Chromium flow in `tests/browser/`; requires Node.js 24, `npm ci` and `npx playwright install chromium` (`--with-deps` on Linux) |
| `just build` | `go build` with `CGO_ENABLED=0` for linux, darwin and windows on amd64 and arm64, into a temporary directory |
| `just scan` | `detect-secrets scan --no-verify` (detect-secrets 1.5.0, through `uvx`) of the tracked files; fails on a finding not in `.secrets.baseline` |
| `just audit` | `govulncheck ./...` (govulncheck v1.9.0, through `go run`); needs the network and is not part of the gate |
| `just gate` | `check`, `scan`, `test`, `build`; the deterministic gate CI runs |
| `just fix` | `gofmt -w .` |
| `just ff` | switches to `main` and fast-forwards it from `origin`; refuses local changes or a diverged `main` |

`up`, `down` and `logs` are not applicable (`checks.recipes.not_applicable` of `pipeline.yaml`):
there is no local stack. `just`, Go and uv (for `uvx`) are required. `uvx` downloads detect-secrets
and `go run` downloads govulncheck on their first run.

### Browser test

`just browser-test` builds sshboard in a temporary directory and starts it on loopback with a
synthetic issuance log and an `sshca` stub. Chromium loads the embedded assets and exercises Inspect
through HTMX, verifies the selected certificate output, closes the dialog and reopens it. The test
stops its server and removes its temporary files before returning. It needs no installed sshca,
bastionhub, CA keys or external service. It currently runs on macOS and Linux.

The `browser` job of `sshboard-ci.yml` prepares Node.js, the locked npm dependencies and Chromium,
then runs the same recipe as a separate blocking job. Browser tests run outside `just gate`.

### Secret scan

`just scan` runs `detect-secrets scan` over the files `git ls-files` lists (tracked and staged),
except `.secrets.baseline`. `--no-verify` disables the plugins' network verification. A finding is
its file, detector type and hash; the recipe exits 1 and prints each finding of the scan that
`.secrets.baseline` does not list. Line numbers are not compared, so moving a baselined line does not
fail the scan. `.secrets.baseline` currently lists no finding.

After confirming that a new finding is not a secret, regenerate the baseline:

```sh
uvx --from detect-secrets==1.5.0 detect-secrets scan --no-verify --exclude-files '^\.secrets\.baseline$' > .secrets.baseline
```

Limitations:

- Untracked files and Git history are not scanned.
- detect-secrets matches patterns, keywords and string entropy. A secret of a format it has no
  detector for, with entropy under the Base64 (4.5) and hex (3.0) limits, and not assigned to a
  keyword, is not found.

### Dependency audit

`just audit` runs govulncheck over `./...`: it reports the advisories of the Go vulnerability
database (vuln.go.dev) whose vulnerable symbols the code reaches, in the required modules and in the
standard library of the Go toolchain that runs it, and exits non-zero when it finds one. Locally that
toolchain is the installed `go`; in `audit.yml` it is the version of `go.mod`. A finding is triaged
like a review finding: a fix, or a recorded disposition with its follow-up issue.

## CI

All workflows run on GitHub-hosted `ubuntu-latest`. The repository is public; the organization's
self-hosted runners do not serve it. `validate` and `sshboard-pm.yml` check out the private
`roselabs-io/governor` with the organization secret `GOVERNOR_PM_TOKEN`, which a workflow run from a
fork does not receive.

## Pull requests

A PR from a branch `agent/<N>-…` carries exactly one `Sshboard-Issue: #N` line; a dispatched run
also requires a `Sshboard-Agent` line naming a configured lane. `validate` of `sshboard-ci.yml`
checks both. `sshboard-pm.yml` moves issue N on the board from that line. `autonomy: tiered`: an
approved PR merges through the merge queue, except the PR of a complex or exceptional ticket, whose
merge is left to a person.

A change to the CLI flags or the URL routes is a contract change (`CLAUDE.md`, Contract surface)
and is recorded in `CHANGELOG.md`.

## Finding triage

`docs.operating_model` in `pipeline.yaml` names this file. Each independent-review finding is
triaged before a correction is requested. The dispatcher runs this as a read-only triage session
(Governor `governor/docs/service/finishing.md`, Review triage); an operator correcting by hand
applies the same rules:

Only a CRITICAL finding requests changes; a review with WARNING and INFO findings only approves, and
its WARNINGs are triaged before the merge queue (Governor `governor/docs/postures/pr-review-posture.md`).

1. Open the cited code and confirm the finding against it. A finding that does not hold is answered
   on the PR with the evidence, and no correction is requested for it.
2. Request a correction for every confirmed CRITICAL and for every confirmed WARNING that is a
   boundary finding: security (including the unauthenticated listener, the bind address, the
   subprocess calls to `sshca` and `bastionhub`, and what the dispatcher pushes, merges or
   deletes), data loss, or the issue's contract or scope.
3. Each other confirmed WARNING is either corrected or dispositioned: a PR comment names the
   follow-up issue and why deferral is safe, and the follow-up issue is opened.

Every later review of the PR receives the dispositions and does not reopen one without new evidence.
