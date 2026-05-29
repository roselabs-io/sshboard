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
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
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

// detected captures which substrate CLIs are on PATH at startup.
// Views light up or stay grayed-out based on what's available.
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

func generateToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Fatal("token generation: ", err)
	}
	return hex.EncodeToString(b[:])
}

type app struct {
	detected detected
	tmpls    map[string]*template.Template
	token    string
}

func newApp() *app {
	tmpls := map[string]*template.Template{}
	for _, view := range []string{"index", "certs", "endpoints"} {
		t := template.Must(template.ParseFS(templatesFS,
			"templates/layout.html.tmpl",
			"templates/"+view+".html.tmpl",
		))
		tmpls[view] = t
	}
	return &app{
		detected: detectCLIs(),
		tmpls:    tmpls,
		token:    generateToken(),
	}
}

func (a *app) viewData(view string) map[string]any {
	return map[string]any{
		"Title":    "sshboard",
		"Version":  version,
		"Detected": a.detected,
		"Token":    a.token,
		"View":     view,
	}
}

func (a *app) render(w http.ResponseWriter, view string) {
	if err := a.tmpls[view].ExecuteTemplate(w, "layout", a.viewData(view)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *app) index(w http.ResponseWriter, _ *http.Request)     { a.render(w, "index") }
func (a *app) certs(w http.ResponseWriter, _ *http.Request)     { a.render(w, "certs") }
func (a *app) endpoints(w http.ResponseWriter, _ *http.Request) { a.render(w, "endpoints") }

func main() {
	bind := flag.String("bind", "127.0.0.1:7890", "address to bind (default: 127.0.0.1:7890 — localhost only)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("sshboard version", version)
		return
	}

	a := newApp()

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
		log.Fatal("Neither sshca nor bastionhub found on PATH — sshboard has nothing to show. Install at least one and re-run.")
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

	// Routes are gated behind /t/<token>/ to defend against drive-by from other
	// localhost services. Same pattern as Jupyter.
	prefix := "/t/" + a.token
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/", a.index)
	mux.HandleFunc(prefix+"/certs", a.certs)
	mux.HandleFunc(prefix+"/endpoints", a.endpoints)

	// Static assets — no token gate (they're public assets).
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatal("static fs sub: ", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Root → tokened root
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
