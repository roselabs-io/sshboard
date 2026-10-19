// sshboard — operator console for sshca + bastionhub.
//
// Single Go binary serving an HTMX-driven web UI. Reads sshca's JSONL audit
// log and bastionhub's endpoints.yaml; shells out to both for actions.
//
// Defaults to localhost:7890 + a random startup token in the URL path
// so that other processes on the same host cannot reach the port by guessing it.
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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// version is the sshboard tool version. Defaults to "0.0.1-dev" during local
// development; release builds override via:
//
//	go build -ldflags "-X main.version=<tag>"
var version = "0.1.0-dev"

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
	ExpiresAt       time.Time
	HasExpiry       bool
	TimeLeft        string // human-readable, e.g. "3h53m0s" or "-14h0m0s"
	Status          string // ACTIVE | EXPIRING | EXPIRED | NEVER | REVOKED
	StatusClass     string // pico-friendly CSS class
	PrincipalsList  []string
	PubkeyAvailable bool   // the entry's pubkey file exists here; Renew needs it
	Token           string // URL token for hx-post action endpoints
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

// readLog parses the JSONL audit log at caDir/issuance-log.jsonl and returns
// its entries in file order. Lines that are not valid JSON are skipped.
func readLog(caDir string) ([]logEntry, error) {
	data, err := os.ReadFile(filepath.Join(caDir, "issuance-log.jsonl"))
	if err != nil {
		return nil, err
	}
	var entries []logEntry
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var entry logEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// newCertView computes the display fields of one log entry at time now.
// PubkeyAvailable is true when the entry's pubkey path names a regular file on
// this host; a relative path resolves against sshboard's working directory.
func newCertView(entry logEntry, now time.Time, expiringWindow time.Duration) CertView {
	v := CertView{logEntry: entry}
	v.PrincipalsList = strings.Split(entry.Principals, ",")
	if fi, err := os.Stat(entry.Pubkey); err == nil && fi.Mode().IsRegular() {
		v.PubkeyAvailable = true
	}
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
	return v
}

// readCerts reads the audit log, computes expiry for each entry, and returns
// the enriched list. Sorted by expiry ascending (most-urgent first);
// never-expiring entries go last.
func readCerts(caDir string, expiringWindow time.Duration) ([]CertView, error) {
	entries, err := readLog(caDir)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()

	var views []CertView
	for _, entry := range entries {
		views = append(views, newCertView(entry, now, expiringWindow))
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
// Endpoints — read bastionhub's endpoints.yaml + merge with live status
//
// Schema mirrors bastionhub's documented contract. Reads YAML directly for
// the static config; shells out to `bastionhub status` for the live tunnel
// state and parses the documented tabular output.
// -----------------------------------------------------------------------------

type Endpoint struct {
	Port        int    `yaml:"port"`
	User        string `yaml:"user"`
	Identity    string `yaml:"identity,omitempty"`
	Description string `yaml:"description,omitempty"`
}

type endpointsConfig struct {
	BastionAlias string              `yaml:"bastion_alias"`
	AdminAlias   string              `yaml:"admin_alias"`
	Endpoints    map[string]Endpoint `yaml:"endpoints"`
}

// EndpointView is an Endpoint enriched with live status + Token (for the
// per-row template's hx-on/copy actions).
type EndpointView struct {
	Name        string
	Port        int
	User        string
	Identity    string
	Description string
	Status      string // UP | DOWN | UNKNOWN
	StatusClass string
	Uptime      string
	Token       string
	SSHCommand  string // the command the Copy SSH button copies
}

// configFlags collects the values of the repeatable --config flag.
type configFlags []string

func (c *configFlags) String() string { return strings.Join(*c, ",") }

func (c *configFlags) Set(v string) error {
	*c = append(*c, v)
	return nil
}

// resolveBastionhubConfigs returns the endpoints.yaml files, one per bastion:
// the --config values in flag order, else $BASTIONHUB_CONFIG, else the default path.
func resolveBastionhubConfigs(flagVals []string) []string {
	if len(flagVals) > 0 {
		return flagVals
	}
	if env := os.Getenv("BASTIONHUB_CONFIG"); env != "" {
		return []string{env}
	}
	home, _ := os.UserHomeDir()
	return []string{filepath.Join(home, ".config", "bastionhub", "endpoints.yaml")}
}

// parseBastionhubStatus parses the tabular output of `bastionhub status`.
// Returns a map of endpoint name → (status, uptime). Skips header lines.
// Tabular format per bastionhub's documented contract:
//
//	NAME                 PORT    STATUS UPTIME       DESCRIPTION
//	customer-002         12002   DOWN   —            ...
func parseBastionhubStatus(out string) map[string][2]string {
	result := map[string][2]string{}
	seenHeader := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !seenHeader {
			if strings.HasPrefix(trimmed, "NAME") {
				seenHeader = true
			}
			continue
		}
		// Data row. First 4 tokens are NAME PORT STATUS UPTIME; rest is DESCRIPTION.
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		name := parts[0]
		status := parts[2]
		uptime := parts[3]
		result[name] = [2]string{status, uptime}
	}
	return result
}

func readEndpoints(configPath, bastionhubPath string) ([]EndpointView, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	cfg := &endpointsConfig{Endpoints: map[string]Endpoint{}}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", configPath, err)
	}
	if cfg.Endpoints == nil {
		cfg.Endpoints = map[string]Endpoint{}
	}

	// Try to fetch live status — failure is non-fatal; views fall back to "?"
	liveStatus := map[string][2]string{}
	if bastionhubPath != "" {
		cmd := exec.Command(bastionhubPath, "status")
		cmd.Env = append(os.Environ(), "BASTIONHUB_CONFIG="+configPath)
		out, err := cmd.CombinedOutput()
		if err == nil {
			liveStatus = parseBastionhubStatus(string(out))
		}
	}

	var views []EndpointView
	for name, ep := range cfg.Endpoints {
		v := EndpointView{
			Name:        name,
			Port:        ep.Port,
			User:        ep.User,
			Identity:    ep.Identity,
			Description: ep.Description,
			Status:      "UNKNOWN",
			StatusClass: "status-unknown",
			Uptime:      "—",
		}
		if s, ok := liveStatus[name]; ok {
			v.Status = s[0]
			v.Uptime = s[1]
			switch s[0] {
			case "UP":
				v.StatusClass = "status-up"
			case "DOWN":
				v.StatusClass = "status-down"
			}
		}
		views = append(views, v)
	}
	// Sort: UP first, then DOWN, then UNKNOWN; tie-break by name.
	sort.Slice(views, func(i, j int) bool {
		ord := func(s string) int {
			switch s {
			case "UP":
				return 0
			case "DOWN":
				return 1
			default:
				return 2
			}
		}
		if a, b := ord(views[i].Status), ord(views[j].Status); a != b {
			return a < b
		}
		return views[i].Name < views[j].Name
	})
	return views, nil
}

// -----------------------------------------------------------------------------
// App
// -----------------------------------------------------------------------------

type app struct {
	detected          detected
	tmpl              *template.Template
	token             string
	caDir             string
	bastionhubConfigs []string // one endpoints.yaml per bastion; the first is the default
	shipTarget        string   // optional --krl-ship target; empty = local-only revoke
}

func (a *app) viewData(view string, extra map[string]any) map[string]any {
	data := map[string]any{
		"Title":             "sshboard",
		"Version":           version,
		"Detected":          a.detected,
		"Token":             a.token,
		"View":              view,
		"CADir":             a.caDir,
		"BastionhubConfigs": a.bastionhubConfigs,
		"ShipTarget":        a.shipTarget,
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

// certFilterStatuses are the values of the Certs view's status filter.
var certFilterStatuses = []string{"ALL", "ACTIVE", "EXPIRING", "EXPIRED"}

// filterCerts keeps the views whose key_id contains q, ignoring case, and
// whose status is status; "ALL" keeps every status, including NEVER.
func filterCerts(views []CertView, q, status string) []CertView {
	q = strings.ToLower(q)
	var kept []CertView
	for _, v := range views {
		if (status == "ALL" || v.Status == status) && strings.Contains(strings.ToLower(v.KeyID), q) {
			kept = append(kept, v)
		}
	}
	return kept
}

// certs handles GET /t/<token>/certs?q=<key_id substring>&status=<status>.
// An empty or absent status is ALL.
func (a *app) certs(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "ALL"
	}
	if !slices.Contains(certFilterStatuses, status) {
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}
	extra := map[string]any{"Query": q, "StatusFilter": status, "FilterStatuses": certFilterStatuses}
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
	extra["Total"] = len(views)
	extra["Certs"] = filterCerts(views, q, status)
	a.render(w, "certs", extra)
}

// logFilterCAs are the values of the Log view's CA filter.
var logFilterCAs = []string{"ALL", "user", "host"}

// LogFilter selects issuance-log entries. Empty Principal keeps every
// principal; a zero From or To leaves that end of the date range open.
type LogFilter struct {
	Principal string
	CA        string // one of logFilterCAs
	From, To  time.Time
}

// filterLog keeps the entries that list f.Principal among their principals,
// were issued by f.CA ("ALL" keeps both) and whose ts falls, as a UTC date,
// between f.From and f.To inclusive. An entry whose ts does not parse is kept
// only when no date bound is set.
func filterLog(entries []logEntry, f LogFilter) []logEntry {
	var kept []logEntry
	for _, e := range entries {
		if f.CA != "ALL" && e.CA != f.CA {
			continue
		}
		if f.Principal != "" && !slices.Contains(strings.Split(e.Principals, ","), f.Principal) {
			continue
		}
		if !f.From.IsZero() || !f.To.IsZero() {
			ts, err := time.Parse(time.RFC3339, e.TS)
			if err != nil {
				continue
			}
			day := ts.UTC().Truncate(24 * time.Hour)
			if (!f.From.IsZero() && day.Before(f.From)) || (!f.To.IsZero() && day.After(f.To)) {
				continue
			}
		}
		kept = append(kept, e)
	}
	return kept
}

// sortLogByTime orders entries by ts ascending, keeping file order between
// equal timestamps.
func sortLogByTime(entries []logEntry) {
	slices.SortStableFunc(entries, func(x, y logEntry) int {
		tx, _ := time.Parse(time.RFC3339, x.TS)
		ty, _ := time.Parse(time.RFC3339, y.TS)
		return tx.Compare(ty)
	})
}

// logPrincipals returns the distinct principals of entries, sorted.
func logPrincipals(entries []logEntry) []string {
	var ps []string
	for _, e := range entries {
		for _, p := range strings.Split(e.Principals, ",") {
			if p != "" && !slices.Contains(ps, p) {
				ps = append(ps, p)
			}
		}
	}
	slices.Sort(ps)
	return ps
}

// issuanceLog handles GET /t/<token>/log?principal=<p>&ca=<ca>&from=<date>&to=<date>.
// Dates are YYYY-MM-DD in UTC; an empty or absent ca is ALL.
func (a *app) issuanceLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := LogFilter{Principal: q.Get("principal"), CA: q.Get("ca")}
	if f.CA == "" {
		f.CA = "ALL"
	}
	if !slices.Contains(logFilterCAs, f.CA) {
		http.Error(w, "invalid ca", http.StatusBadRequest)
		return
	}
	for _, bound := range []struct {
		name string
		dst  *time.Time
	}{{"from", &f.From}, {"to", &f.To}} {
		if v := q.Get(bound.name); v != "" {
			d, err := time.Parse(time.DateOnly, v)
			if err != nil {
				http.Error(w, "invalid "+bound.name+" date", http.StatusBadRequest)
				return
			}
			*bound.dst = d
		}
	}
	extra := map[string]any{
		"Filter":    f,
		"FilterCAs": logFilterCAs,
		"FromValue": q.Get("from"),
		"ToValue":   q.Get("to"),
	}
	if a.detected.Sshca == "" {
		extra["Error"] = "sshca not detected on PATH."
		a.render(w, "log", extra)
		return
	}
	entries, err := readLog(a.caDir)
	if err != nil {
		extra["Error"] = fmt.Sprintf("Reading audit log at %s/issuance-log.jsonl: %v", a.caDir, err)
		a.render(w, "log", extra)
		return
	}
	sortLogByTime(entries)
	extra["Total"] = len(entries)
	extra["Principals"] = logPrincipals(entries)
	extra["Entries"] = filterLog(entries, f)
	a.render(w, "log", extra)
}

// selectConfig returns the endpoints.yaml named by the request's "config"
// value, which must be one of the --config files; an empty value selects the first.
func (a *app) selectConfig(value string) (string, bool) {
	if value == "" {
		return a.bastionhubConfigs[0], true
	}
	return value, slices.Contains(a.bastionhubConfigs, value)
}

// endpointsExtra returns the Endpoints view's data for the bastion whose
// endpoints.yaml is config: the endpoints, or an Error, and the values to
// prefill the enroll form with (none).
func (a *app) endpointsExtra(config string) map[string]any {
	extra := map[string]any{"EnrollForm": url.Values{}, "BastionhubConfig": config}
	if a.detected.Bastionhub == "" {
		extra["Error"] = "bastionhub not detected on PATH."
		return extra
	}
	views, err := readEndpoints(config, a.detected.Bastionhub)
	if err != nil {
		extra["Error"] = fmt.Sprintf("Reading %s: %v", config, err)
		return extra
	}
	// With more than one bastion, the copied command names the selected
	// endpoints.yaml, since the operator's shell resolves only one.
	prefix := ""
	if len(a.bastionhubConfigs) > 1 {
		prefix = "BASTIONHUB_CONFIG='" + strings.ReplaceAll(config, "'", `'\''`) + "' "
	}
	for i := range views {
		views[i].Token = a.token
		views[i].SSHCommand = prefix + "bastionhub ssh " + views[i].Name
	}
	extra["Endpoints"] = views
	return extra
}

// endpoints handles GET /t/<token>/endpoints?config=<endpoints.yaml>.
// An absent config is the first --config file; a path that is not one of them returns 400.
func (a *app) endpoints(w http.ResponseWriter, r *http.Request) {
	config, ok := a.selectConfig(r.URL.Query().Get("config"))
	if !ok {
		http.Error(w, "unknown config", http.StatusBadRequest)
		return
	}
	a.render(w, "endpoints", a.endpointsExtra(config))
}

// endpointResult is the outcome of an endpoint action, shown above the table.
type endpointResult struct {
	Title  string
	Output string
	Failed bool
}

// runBastionhub runs bastionhub with BASTIONHUB_CONFIG set to the selected
// bastion's endpoints.yaml; bastionhub has no flag for the config path.
func (a *app) runBastionhub(config string, args ...string) ([]byte, error) {
	cmd := exec.Command(a.detected.Bastionhub, args...)
	cmd.Env = append(os.Environ(), "BASTIONHUB_CONFIG="+config)
	return cmd.CombinedOutput()
}

// renderEndpointsResult writes the #endpoints-view element, the target the
// action forms swap with outerHTML, re-read after the action, with the action's result above the table and the enroll
// form prefilled with form. Status is 200 also on failure, so that HTMX swaps.
func (a *app) renderEndpointsResult(w http.ResponseWriter, config string, res endpointResult, form url.Values) {
	extra := a.endpointsExtra(config)
	extra["Result"] = res
	if form != nil {
		extra["EnrollForm"] = form
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.tmpl.ExecuteTemplate(w, "endpoints-view", a.viewData("endpoints", extra)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// enrollFlags are the optional `bastionhub endpoint enroll` flags the enroll
// form submits, each under the flag's name; an empty field omits the flag.
var enrollFlags = []string{"pubkey-file", "user", "port", "identity", "description", "valid", "principal"}

// enrollEndpoint handles POST /t/<token>/api/endpoint/enroll
// Form: config (as for the Endpoints view), name and the fields of enrollFlags. Runs `bastionhub endpoint enroll`
// with --ca-dir set to sshboard's CA dir. Flags are passed as --flag=value so
// that a value starting with "-" is not parsed as a flag.
// Returns: the Endpoints view's content fragment with bastionhub's output; on
// failure the form keeps the submitted values.
func (a *app) enrollEndpoint(w http.ResponseWriter, r *http.Request) {
	if a.detected.Bastionhub == "" {
		http.Error(w, "bastionhub not detected", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	config, ok := a.selectConfig(r.PostFormValue("config"))
	if !ok {
		http.Error(w, "unknown config", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || strings.HasPrefix(name, "-") {
		a.renderEndpointsResult(w, config, endpointResult{Title: "Enroll failed", Output: `The name is required and must not start with "-".`, Failed: true}, r.PostForm)
		return
	}
	args := []string{"endpoint", "enroll", "--ca-dir=" + a.caDir}
	for _, f := range enrollFlags {
		if v := strings.TrimSpace(r.PostFormValue(f)); v != "" {
			args = append(args, "--"+f+"="+v)
		}
	}
	args = append(args, name)
	out, err := a.runBastionhub(config, args...)
	if err != nil {
		a.renderEndpointsResult(w, config, endpointResult{Title: "Enroll failed for " + name, Output: string(out), Failed: true}, r.PostForm)
		return
	}
	a.renderEndpointsResult(w, config, endpointResult{Title: "Enrolled " + name, Output: string(out)}, nil)
}

// unregisterEndpoint handles POST /t/<token>/api/endpoint/unregister
// Form: config (as for the Endpoints view) and name. Runs `bastionhub endpoint unregister <name>`, which removes the
// endpoint from endpoints.yaml and does not revoke its certificate.
// Returns: the Endpoints view's content fragment with bastionhub's output.
func (a *app) unregisterEndpoint(w http.ResponseWriter, r *http.Request) {
	if a.detected.Bastionhub == "" {
		http.Error(w, "bastionhub not detected", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	config, ok := a.selectConfig(r.PostFormValue("config"))
	if !ok {
		http.Error(w, "unknown config", http.StatusBadRequest)
		return
	}
	name := r.PostFormValue("name")
	if name == "" || strings.HasPrefix(name, "-") {
		http.Error(w, "missing or invalid name", http.StatusBadRequest)
		return
	}
	out, err := a.runBastionhub(config, "endpoint", "unregister", name)
	res := endpointResult{Title: "Unregistered " + name, Output: string(out)}
	if err != nil {
		res = endpointResult{Title: "Unregister failed for " + name, Output: string(out), Failed: true}
	}
	a.renderEndpointsResult(w, config, res, nil)
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

// renewCert handles POST /t/<token>/api/cert/renew
// Form: key_id, ca. Header HX-Prompt: optional scp target for the new cert.
// The pubkey file is the one the issuance log records for the entry, never a
// path from the request.
// Returns: HTML fragment of the new cert's row followed by the renewed row.
func (a *app) renewCert(w http.ResponseWriter, r *http.Request) {
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
	ship := strings.TrimSpace(r.Header.Get("HX-Prompt"))
	// scp parses a destination starting with "-" as an option.
	if strings.HasPrefix(ship, "-") {
		http.Error(w, "invalid ship target", http.StatusBadRequest)
		return
	}

	before, err := readLog(a.caDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var entry *logEntry
	for i := range before {
		if before[i].KeyID == keyID && before[i].CA == ca {
			entry = &before[i]
		}
	}
	if entry == nil {
		http.Error(w, "no issuance log entry for key_id", http.StatusNotFound)
		return
	}

	args := []string{"cert", "renew", "--ca", ca, "--pubkey-file", entry.Pubkey, "--dir", a.caDir}
	if ship != "" {
		args = append(args, "--ship", ship)
	}
	out, err := exec.Command(a.detected.Sshca, args...).CombinedOutput()
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, `<tr><td colspan="7"><article class="error"><strong>Renew failed for %s:</strong><pre>%s</pre></article></td></tr>`,
			template.HTMLEscapeString(keyID),
			template.HTMLEscapeString(string(out)),
		)
		return
	}

	after, err := readLog(a.caDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	var rows []CertView
	// sshca appends the new entry with the pubkey path it was given.
	for i := len(after) - 1; i >= len(before); i-- {
		if after[i].Pubkey == entry.Pubkey {
			rows = append(rows, newCertView(after[i], now, 24*time.Hour))
			break
		}
	}
	rows = append(rows, newCertView(*entry, now, 24*time.Hour))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	for _, v := range rows {
		v.Token = a.token
		if err := a.tmpl.ExecuteTemplate(w, "cert-row", v); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

// inspectCert handles GET /t/<token>/api/cert/inspect
// Query: key_id, ca, cert. The entry is the issuance-log entry matching all
// three, so rows sharing key_id and ca stay distinct; the path passed to sshca
// is the one the log records, and a cert value not in the log is a 404.
// Returns: HTML fragment of a dialog holding the output of `sshca cert inspect`,
// with status 200 also when sshca fails, so that HTMX swaps the dialog in.
func (a *app) inspectCert(w http.ResponseWriter, r *http.Request) {
	if a.detected.Sshca == "" {
		http.Error(w, "sshca not detected", http.StatusServiceUnavailable)
		return
	}
	keyID := r.FormValue("key_id")
	ca := r.FormValue("ca")
	cert := r.FormValue("cert")
	if keyID == "" || cert == "" || (ca != "user" && ca != "host") {
		http.Error(w, "missing or invalid key_id / ca / cert", http.StatusBadRequest)
		return
	}

	entries, err := readLog(a.caDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var entry *logEntry
	for i := range entries {
		if entries[i].KeyID == keyID && entries[i].CA == ca && entries[i].Cert == cert {
			entry = &entries[i]
		}
	}
	if entry == nil {
		http.Error(w, "no issuance log entry for key_id and cert", http.StatusNotFound)
		return
	}

	out, err := exec.Command(a.detected.Sshca, "cert", "inspect", entry.Cert).CombinedOutput()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]any{
		"KeyID":  keyID,
		"Cert":   entry.Cert,
		"Output": string(out),
		"Failed": err != nil,
	}
	if err := a.tmpl.ExecuteTemplate(w, "cert-inspect", data); err != nil {
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
	var configFlag configFlags
	flag.Var(&configFlag, "config", "bastionhub endpoints.yaml path, one per bastion; repeat to switch between bastions in the Endpoints view (default: $BASTIONHUB_CONFIG, then ~/.config/bastionhub/endpoints.yaml)")
	shipTarget := flag.String("krl-ship", "", "optional scp target for cert revoke (e.g. root@bastion:/etc/ssh/revoked_keys.krl). If unset, revoke updates local KRL only.")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("sshboard version", version)
		return
	}

	// Parse all templates as a single template tree. Each view's content
	// template has a distinct name (index-content, certs-content,
	// log-content, endpoints-content); the layout's switch dispatches on .View.
	// Partials like cert-row are also defined in their own files and
	// available globally for the API handlers.
	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl"))

	a := &app{
		detected:          detectCLIs(),
		tmpl:              tmpl,
		token:             generateToken(),
		caDir:             resolveCaDir(*caDirFlag),
		bastionhubConfigs: resolveBastionhubConfigs(configFlag),
		shipTarget:        *shipTarget,
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
	for _, config := range a.bastionhubConfigs {
		fmt.Println("Bastionhub config:", config)
	}
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
	mux.HandleFunc(prefix+"/log", a.issuanceLog)
	mux.HandleFunc(prefix+"/endpoints", a.endpoints)
	mux.HandleFunc(prefix+"/api/cert/revoke", a.revokeCert)
	mux.HandleFunc(prefix+"/api/cert/renew", a.renewCert)
	mux.HandleFunc(prefix+"/api/cert/inspect", a.inspectCert)
	mux.HandleFunc(prefix+"/api/endpoint/enroll", a.enrollEndpoint)
	mux.HandleFunc(prefix+"/api/endpoint/unregister", a.unregisterEndpoint)

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
	fmt.Println("The token in the path prevents other processes on this host from")
	fmt.Println("reaching the port. It is not authentication; do not share the URL.")
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
