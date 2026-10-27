# Go CLI recipes of the command contract. `check` and `gate` are what the local preflight runs.

# Static checks: vet and formatting.
check:
    go vet ./...
    test -z "$(gofmt -l .)"

# The test suite.
test:
    go test ./...

# The browser tier: tests with the `browser` build tag drive the views in headless Chrome or Chromium through
# chromedp, one of them against the built binary. A test skips when no Chrome or Chromium executable is found; `ubuntu-latest` runners have Chrome.
browser:
    go test -tags browser -run TestBrowser ./...

# `go build` with CGO_ENABLED=0 for the six release targets of `release.yml` (the build matrix of `ci.yml`).
# The binaries are written to a temporary directory and removed.
build:
    #!/usr/bin/env sh
    set -eu
    out="$(mktemp -d)"
    trap 'rm -rf "$out"' EXIT
    for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
        echo "go build $target"
        CGO_ENABLED=0 GOOS="${target%/*}" GOARCH="${target#*/}" go build -o "$out/sshboard-${target%/*}-${target#*/}" .
    done

# Secret scan of the tracked files with detect-secrets 1.5.0, pinned through uvx; `--no-verify` makes no network
# call. Fails on a finding whose file, type and hash are not in `.secrets.baseline`; line numbers are not compared.
scan:
    #!/usr/bin/env -S uvx --from detect-secrets==1.5.0 python
    import json, subprocess, sys
    def findings(report):
        return {(f["filename"], f["type"], f["hashed_secret"]) for found in report["results"].values() for f in found}
    scan = subprocess.run([sys.executable, "-m", "detect_secrets", "scan", "--no-verify", "--exclude-files", r"^\.secrets\.baseline$"], check=True, capture_output=True, text=True).stdout
    new = sorted(findings(json.loads(scan)) - findings(json.load(open(".secrets.baseline", encoding="utf-8"))))
    for filename, kind, digest in new:
        print(f"{filename}: {kind} {digest} is not in .secrets.baseline", file=sys.stderr)
    sys.exit(1 if new else 0)

# Dependency advisory check. Needs the network; CI runs it outside the gate in `audit.yml`. govulncheck is pinned
# outside go.mod; v1.7.0 is the last release that builds with the Go version of `go.mod` (1.25); v1.8.0 and later
# require Go 1.26.
audit:
    go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

# The deterministic gate CI runs.
gate: check scan test browser build

# Apply the formatter.
fix:
    gofmt -w .

# Switch to main and fast-forward it from origin; refuses local changes or a diverged main.
ff:
    #!/usr/bin/env sh
    set -eu
    if [ -n "$(git status --porcelain)" ]; then echo "ff: the working tree has changes" >&2; exit 1; fi
    git switch main
    git fetch origin main
    git merge --ff-only origin/main
