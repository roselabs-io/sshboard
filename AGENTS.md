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
| `templates/*.html.tmpl` | the server-rendered views, embedded |
| `static/` | `app.css` and the vendored `htmx.min.js` and `pico.min.css`, embedded |
| `README.md`, `CHANGELOG.md`, `CLAUDE.md` | usage, release notes, contributor notes |
| `.github/workflows/ci.yml` | `go vet` and `go build` for six targets, `go test` on linux/amd64 |
| `.github/workflows/release.yml` | on a `v*` tag, or called by `release-on-merge.yml` with a tag: builds six targets, archives, `checksums.txt`, a GitHub Release, then notifies `roselabs-io/homebrew-tools` |
| `.github/workflows/release-on-merge.yml` | after `sshboard CI` succeeds on a push to `main`: tags the newest version heading of `CHANGELOG.md` when its tag does not exist, and calls `release.yml` |
| `.github/workflows/sshboard-ci.yml` | `validate` (PR metadata) and `gate` (`just gate`) |
| `.github/workflows/sshboard-pm.yml` | the issue and board sync of Governor |
| `.github/workflows/audit.yml` | `just audit` on a change to `go.mod` or `go.sum`, and weekly on `main` |
| `.secrets.baseline` | the detect-secrets findings that are not secrets, read by `just scan` |
| `pipeline.yaml` | the Governor dispatcher's config for this repository |
| Governor's package preflight (`tools/local_preflight.py` of the Governor package, run by the dispatcher; this repository keeps no copy) | the local check the dispatcher runs: `just check`, then `just gate` |

No key or token is tracked. The binary also runs as `sshboard.service` on the box; how it is
installed and updated there is not recorded in this repository.

## Releases

A release is made by a merge into `main` that adds a version heading to `CHANGELOG.md`: the PR
renames `## [Unreleased]` to `## [X.Y.Z] — YYYY-MM-DD` (or adds that heading) and starts a new
empty `## [Unreleased]` above it. A merge that adds no version heading releases nothing.

1. `sshboard CI` runs on the push to `main`. When its run succeeds, `release-on-merge.yml` starts
   (`workflow_run`); a failed or cancelled run, and a dispatched exact-head run, start no release.
2. Its `tag` job reads the first heading of the form `## [X.Y.Z]` at the pushed commit;
   `[Unreleased]` and headings with a prerelease suffix (`[0.0.1-dev]`) do not match. When the tag
   `vX.Y.Z` does not exist on `origin`, it creates the tag on the pushed commit and pushes it with
   `GITHUB_TOKEN`.
3. Its `release` job calls `release.yml` (`workflow_call`) with the tag. A tag pushed with
   `GITHUB_TOKEN` starts no workflow, so the `push: tags` trigger of `release.yml` does not also run.
4. `release.yml` builds the six targets at the tag and creates the GitHub Release. For a tag without
   `-`, its `homebrew` job sends a `formula-update` `repository_dispatch` event (`tool`, `tag`) to
   `roselabs-io/homebrew-tools`, authenticated with the organization secret `HOMEBREW_TAP_TOKEN`.
   The workflow there opens a PR that updates `Formula/sshboard.rb`.

Pushing a `v*` tag by hand still runs `release.yml` directly; CI creates no prerelease tag. When a
CI run of the merge is cancelled or fails, the next push to `main` whose run succeeds finds the tag
missing and releases from its own commit. A bad release is not deleted: revert on `main` and merge a
new patch heading.

## Commands

| Recipe | Runs |
|---|---|
| `just check` | `go vet ./...`; fails when `gofmt -l .` lists a file |
| `just test` | `go test ./...` |
| `just browser` | `go test -tags browser -run TestBrowser ./...`: browser tests (chromedp) in headless Chrome or Chromium; a test skips when neither is installed |
| `just build` | `go build` with `CGO_ENABLED=0` for linux, darwin and windows on amd64 and arm64, into a temporary directory |
| `just scan` | `detect-secrets scan --no-verify` (detect-secrets 1.5.0, through `uvx`) of the tracked files; fails on a finding not in `.secrets.baseline` |
| `just audit` | `govulncheck ./...` (govulncheck v1.7.0, the last release that builds with Go 1.25, through `go run`); needs the network and is not part of the gate |
| `just gate` | `check`, `scan`, `test`, `browser`, `build`; the deterministic gate CI runs |
| `just fix` | `gofmt -w .` |
| `just ff` | switches to `main` and fast-forwards it from `origin`; refuses local changes or a diverged `main` |

`up`, `down` and `logs` are not applicable (`checks.recipes.not_applicable` of `pipeline.yaml`):
there is no local stack. `just`, Go and uv (for `uvx`) are required. `uvx` downloads detect-secrets
and `go run` downloads govulncheck on their first run.

### Secret scan

`just scan` runs `detect-secrets scan` over the files `git ls-files` lists (tracked and staged),
except `.secrets.baseline`. `--no-verify` disables the plugins' network verification. A finding is
its file, detector type and hash; the recipe exits 1 and prints each finding of the scan that
`.secrets.baseline` does not list. Line numbers are not compared, so moving a baselined line does not
fail the scan. `.secrets.baseline` lists one finding, a Secret Keyword match on the line
`secrets: inherit` of `release-on-merge.yml`.

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
