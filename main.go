// sshboard — operator console for sshca + bastionhub.
//
// Single Go binary serving an HTMX-driven web UI. Reads sshca's JSONL audit
// log and bastionhub's endpoints.yaml; shells out to both for actions.
//
// Defaults to localhost:7890 + a random startup token in the URL path
// (Jupyter-style) to defend against drive-by from other localhost services.
// No bundled auth. For network exposure, see README "Deployment patterns".
package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// version is the sshboard tool version. Defaults to "0.0.1-dev" during local
// development; release builds override via:
//
//	go build -ldflags "-X main.version=<tag>"
var version = "0.0.1-dev"

//go:embed templates/*.html.tmpl
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// -----------------------------------------------------------------------------
// Detected substrate CLIs
// -----------------------------------------------------------------------------

type detected struct {
	Sshca      string // path or empty
	Bastionhub string // path or empty
}

func detectCLIs() detected {
	d := detected{}
	if p, err := exec.LookPath("sshca"); err == nil {
		d.Sshca = p
	}
	if p, err := exec.LookPath("bastionhub"); err == nil {
		d.Bastionhub = p
	}
	return d
}

// -----------------------------------------------------------------------------
// JSONL audit log parsing
//
// Mirrors sshca's documented schema. Field names + types are sshca's contract
// surface (see CLAUDE.md in the sshca repo).
// -----------------------------------------------------------------------------

type logEntry struct {
	TS         string `json:"ts"`
	CA         string `json:"ca"`
	KeyID      string `json:"key_id"`
	Principals string `json:"principals"`
	Valid      string `json:"valid"`
	Pubkey     string `json:"pubkey"`
	Cert       string `json:"cert"`
}

// CertView is a logEntry enriched with computed display fields for the table.
// Token is the URL token (so the per-row template can build hx-post URLs).
type CertView struct {
	logEntry
	ExpiresAt      time.Time
	HasExpiry      bool
	TimeLeft       string // human-readable, e.g. "3h53m0s" or "-14h0m0s"
	Status         string // ACTIVE | EXPIRING | EXPIRED | NEVER | REVOKED
	StatusClass    string // pico-friendly CSS class
	PrincipalsList []string
	Token          string // URL token for hx-post action endpoints
}

// parseSSHKeygenDuration parses ssh-keygen -V style durations. Mirrors the same
// helper in sshca (sshca extends time.ParseDuration with d and w units).
func parseSSHKeygenDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	last := s[len(s)-1:]
	if last == "w" || last == "d" {
		n, err := strconv.ParseInt(strings.TrimSuffix(s, last), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parsing %s: %w", s, err)
		}
		mul := 24 * time.Hour
		if last == "w" {
			mul = 7 * 24 * time.Hour
		}
		return time.Duration(n) * mul, nil
	}
	return time.ParseDuration(s)
}

// parseExpiry computes when a cert with the given validity string expires,
// given the timestamp at which it was issued. Mirrors sshca's parseExpiry.
func parseExpiry(validStr, tsStr string) (time.Time, bool, error) {
	ts, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("parsing ts: %w", err)
	}
	if validStr == "always" {
		return time.Time{}, false, nil
	}
	if strings.HasPrefix(validStr, "+") {
		d, err := parseSSHKeygenDuration(strings.TrimPrefix(validStr, "+"))
		if err != nil {
			return time.Time{}, false, err
		}
		return ts.Add(d), true, nil
	}
	if strings.Contains(validStr, ":") {
		parts := strings.SplitN(validStr, ":", 2)
		upper := parts[1]
		if upper == "always" {
			return time.Time{}, false, nil
		}
		if strings.HasPrefix(upper, "+") {
			d, err := parseSSHKeygenDuration(strings.TrimPrefix(upper, "+"))
			if err != nil {
				return time.Time{}, false, err
			}
			return ts.Add(d), true, nil
		}
		if len(upper) == 8 {
			t, err := time.Parse("20060102", upper)
			return t, err == nil, err
		}
		if len(upper) == 14 {
			t, err := time.Parse("20060102150405", upper)
			return t, err == nil, err
		}
		return time.Time{}, false, fmt.Errorf("unparseable upper bound %q", upper)
	}
	return time.Time{}, false, fmt.Errorf("unparseable validity %q", validStr)
}

func formatTimeLeft(d time.Duration) string {
	sign := ""
	if d < 0 {
		sign = "-"
		d = -d
	}
	return sign + d.Truncate(time.Minute).String()
}

// readCerts parses the JSONL audit log at caDir/issuance-log.jsonl, computes
// expiry for each entry, and returns the enriched list. Sorted by expiry
// ascending (most-urgent first); never-expiring entries go last.
func readCerts(caDir string, expiringWindow time.Duration) ([]CertView, error) {
	path := filepath.Join(caDir, "issuance-log.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()

	var views []CertView
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var entry logEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		v := CertView{logEntry: entry}
		v.PrincipalsList = strings.Split(entry.Principals, ",")
		exp, has, _ := parseExpiry(entry.Valid, entry.TS)
		v.ExpiresAt = exp
		v.HasExpiry = has
		switch {
		case !has:
			v.Status = "NEVER"
			v.StatusClass = "muted"
			v.TimeLeft = "—"
		case !exp.After(now):
			v.Status = "EXPIRED"
			v.StatusClass = "status-expired"
			v.TimeLeft = formatTimeLeft(exp.Sub(now))
		case exp.Before(now.Add(expiringWindow)):
			v.Status = "EXPIRING"
			v.StatusClass = "status-expiring"
			v.TimeLeft = formatTimeLeft(exp.Sub(now))
		default:
			v.Status = "ACTIVE"
			v.StatusClass = "status-active"
			v.TimeLeft = formatTimeLeft(exp.Sub(now))
		}
		views = append(views, v)
	}

	// Sort: by ExpiresAt ascending; never-expiring entries last.
	sort.Slice(views, func(i, j int) bool {
		if !views[i].HasExpiry {
			return false
		}
		if !views[j].HasExpiry {
			return true
		}
		return views[i].ExpiresAt.Before(views[j].ExpiresAt)
	})

	return views, nil
}

// -----------------------------------------------------------------------------
// App
// -----------------------------------------------------------------------------

type app struct {
	detected   detected
	tmpl       *template.Template
	token      string
	caDir      string
	shipTarget string // optional --krl-ship target; empty = local-only revoke
}

func (a *app) viewData(view string, extra map[string]any) map[string]any {
	data := map[string]any{
		"Title":    "sshboard",
		"Version":  version,
		"Detected": a.detected,
		"Token":    a.token,
		"View":     view,
		"CADir":    a.caDir,
		"ShipTarget": a.shipTarget,
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

func (a *app) render(w http.ResponseWriter, view string, extra map[string]any) {
	if err := a.tmpl.ExecuteTemplate(w, "layout", a.viewData(view, extra)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *app) index(w http.ResponseWriter, _ *http.Request) {
	a.render(w, "index", nil)
}

func (a *app) certs(w http.ResponseWriter, _ *http.Request) {
	extra := map[string]any{}
	if a.detected.Sshca == "" {
		extra["Error"] = "sshca not detected on PATH."
		a.render(w, "certs", extra)
		return
	}
	views, err := readCerts(a.caDir, 24*time.Hour)
	if err != nil {
		extra["Error"] = fmt.Sprintf("Reading audit log at %s/issuance-log.jsonl: %v", a.caDir, err)
		a.render(w, "certs", extra)
		return
	}
	for i := range views {
		views[i].Token = a.token
	}
	extra["Certs"] = views
	a.render(w, "certs", extra)
}

func (a *app) endpoints(w http.ResponseWriter, _ *http.Request) {
	a.render(w, "endpoints", nil)
}

// revokeCert handles POST /t/<token>/api/cert/revoke
// Form: key_id, ca
// Returns: HTML fragment for the row (HTMX swaps it in)
func (a *app) revokeCert(w http.ResponseWriter, r *http.Request) {
	if a.detected.Sshca == "" {
		http.Error(w, "sshca not detected", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	keyID := r.FormValue("key_id")
	ca := r.FormValue("ca")
	if keyID == "" || (ca != "user" && ca != "host") {
		http.Error(w, "missing or invalid key_id / ca", http.StatusBadRequest)
		return
	}

	args := []string{"cert", "revoke", "--ca", ca, "--key-id", keyID, "--dir", a.caDir}
	if a.shipTarget != "" {
		args = append(args, "--ship", a.shipTarget)
	}
	out, err := exec.Command(a.detected.Sshca, args...).CombinedOutput()
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `<tr><td colspan="6"><article class="error"><strong>Revoke failed for %s:</strong><pre>%s</pre></article></td></tr>`,
			template.HTMLEscapeString(keyID),
			template.HTMLEscapeString(string(out)),
		)
		return
	}

	// Render the row with REVOKED status. We rebuild a CertView with the
	// status forced; pulling the original entry data isn't needed since
	// HTMX only needs to know what to swap in.
	v := CertView{
		logEntry:    logEntry{KeyID: keyID, CA: ca, Principals: r.FormValue("principals")},
		Status:      "REVOKED",
		StatusClass: "status-revoked",
		TimeLeft:    "—",
		Token:       a.token,
	}
	v.PrincipalsList = strings.Split(v.Principals, ",")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.tmpl.ExecuteTemplate(w, "cert-row", v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// -----------------------------------------------------------------------------
// CA dir discovery
// -----------------------------------------------------------------------------

func resolveCaDir(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv("SSHCA_CA_DIR"); env != "" {
		return env
	}
	return "./ca"
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------

func generateToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Fatal("token generation: ", err)
	}
	return hex.EncodeToString(b[:])
}

func main() {
	bind := flag.String("bind", "127.0.0.1:7890", "address to bind (default: 127.0.0.1:7890 — localhost only)")
	caDirFlag := flag.String("ca-dir", "", "sshca CA directory (default: $SSHCA_CA_DIR, then ./ca)")
	shipTarget := flag.String("krl-ship", "", "optional scp target for cert revoke (e.g. root@bastion:/etc/ssh/revoked_keys.krl). If unset, revoke updates local KRL only.")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("sshboard version", version)
		return
	}

	// Parse all templates as a single template tree. Each view's content
	// template has a distinct name (index-content, certs-content,
	// endpoints-content); the layout's switch dispatches on .View.
	// Partials like cert-row are also defined in their own files and
	// available globally for the API handlers.
	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl"))

	a := &app{
		detected:   detectCLIs(),
		tmpl:       tmpl,
		token:      generateToken(),
		caDir:      resolveCaDir(*caDirFlag),
		shipTarget: *shipTarget,
	}

	// Startup banner
	fmt.Println("sshboard version", version)
	if a.detected.Sshca != "" {
		fmt.Println("Detected: sshca at", a.detected.Sshca)
	} else {
		fmt.Println("sshca: not found on PATH — Certs view will be grayed out.")
		fmt.Println("  Install: brew install roselabs-io/tools/sshca")
	}
	if a.detected.Bastionhub != "" {
		fmt.Println("Detected: bastionhub at", a.detected.Bastionhub)
	} else {
		fmt.Println("bastionhub: not found on PATH — Endpoints view will be grayed out.")
		fmt.Println("  Install: brew install roselabs-io/tools/bastionhub")
	}
	if a.detected.Sshca == "" && a.detected.Bastionhub == "" {
		log.Fatal("Neither sshca nor bastionhub found on PATH — sshboard has nothing to show.")
	}
	fmt.Println("CA dir:", a.caDir)
	if a.shipTarget != "" {
		fmt.Println("KRL ship target:", a.shipTarget)
	}

	// Warn loudly on non-localhost bind
	if !isLocalhost(*bind) {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "WARNING: --bind", *bind, "exposes sshboard to the network.")
		fmt.Fprintln(os.Stderr, "sshboard does NOT include its own auth. Put it behind a reverse proxy")
		fmt.Fprintln(os.Stderr, `with TLS + auth (nginx, Caddy) or use the recommended SSH-LocalForward`)
		fmt.Fprintln(os.Stderr, `pattern instead. See README.md "Deployment patterns".`)
		fmt.Fprintln(os.Stderr, "")
	}

	prefix := "/t/" + a.token
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/", a.index)
	mux.HandleFunc(prefix+"/certs", a.certs)
	mux.HandleFunc(prefix+"/endpoints", a.endpoints)
	mux.HandleFunc(prefix+"/api/cert/revoke", a.revokeCert)

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal("static fs sub: ", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, prefix+"/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	fmt.Println()
	fmt.Printf("Listening on: http://%s%s/\n", *bind, prefix)
	fmt.Println()
	fmt.Println("Open this URL in your browser. The token defends against drive-by access")
	fmt.Println("from other localhost services. Don't share it.")
	fmt.Println()

	if err := http.ListenAndServe(*bind, mux); err != nil {
		log.Fatal(err)
	}
}

func isLocalhost(addr string) bool {
	for _, prefix := range []string{"127.0.0.1:", "localhost:", "[::1]:"} {
		if strings.HasPrefix(addr, prefix) {
			return true
		}
	}
	return false
}
