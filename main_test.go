package main

import (
	"fmt"
	"html"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseSSHKeygenDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{"8h", 8 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"300s", 300 * time.Second, false},
		{"1d", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"1w", 7 * 24 * time.Hour, false},
		{"52w", 52 * 7 * 24 * time.Hour, false},
		{"", 0, true},
		{"xyz", 0, true},
		{"d", 0, true},
	}
	for _, c := range cases {
		got, err := parseSSHKeygenDuration(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseSSHKeygenDuration(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSSHKeygenDuration(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseSSHKeygenDuration(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseExpiry(t *testing.T) {
	const ts = "2026-05-29T15:00:00Z"
	cases := []struct {
		validity string
		wantExp  string
		wantHas  bool
		err      bool
	}{
		{"+8h", "2026-05-29T23:00:00Z", true, false},
		{"+52w", "2027-05-28T15:00:00Z", true, false},
		{"always", "", false, false},
		{"always:always", "", false, false},
		{"20260601:20260701", "2026-07-01T00:00:00Z", true, false},
		{"invalid", "", false, true},
	}
	for _, c := range cases {
		got, has, err := parseExpiry(c.validity, ts)
		if c.err {
			if err == nil {
				t.Errorf("parseExpiry(%q) = (%v, %v, nil), want error", c.validity, got, has)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseExpiry(%q) error: %v", c.validity, err)
			continue
		}
		if has != c.wantHas {
			t.Errorf("parseExpiry(%q) hasExpiry = %v, want %v", c.validity, has, c.wantHas)
			continue
		}
		if c.wantExp != "" {
			want, _ := time.Parse(time.RFC3339, c.wantExp)
			if !got.Equal(want) {
				t.Errorf("parseExpiry(%q) = %v, want %v", c.validity, got, want)
			}
		}
	}
}

func TestFormatTimeLeft(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{3*time.Hour + 53*time.Minute, "3h53m0s"},
		{-14 * time.Hour, "-14h0m0s"},
		{0, "0s"},
	}
	for _, c := range cases {
		got := formatTimeLeft(c.d)
		if got != c.want {
			t.Errorf("formatTimeLeft(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestParseBastionhubStatus(t *testing.T) {
	// Sample output mirroring bastionhub's tabular contract:
	//   NAME                 PORT    STATUS UPTIME       DESCRIPTION
	// First two lines are header noise + blank; data rows follow.
	input := `Querying bastion-root — 3 configured endpoint(s), 2 live listener(s)

NAME                 PORT    STATUS UPTIME       DESCRIPTION
customer-002         12002   DOWN   —            Future client site (placeholder, not yet deployed)
perso-mbp            12001   UP     04:53:24     Patrick's personal laptop
work-laptop          12003   UP     01:36:32     Patrick's work laptop
`
	got := parseBastionhubStatus(input)

	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	for _, c := range []struct {
		name   string
		status string
		uptime string
	}{
		{"customer-002", "DOWN", "—"},
		{"perso-mbp", "UP", "04:53:24"},
		{"work-laptop", "UP", "01:36:32"},
	} {
		v, ok := got[c.name]
		if !ok {
			t.Errorf("missing entry %q", c.name)
			continue
		}
		if v[0] != c.status {
			t.Errorf("%s status = %q, want %q", c.name, v[0], c.status)
		}
		if v[1] != c.uptime {
			t.Errorf("%s uptime = %q, want %q", c.name, v[1], c.uptime)
		}
	}
}

func TestParseBastionhubStatus_Empty(t *testing.T) {
	// Header but no data rows = empty map, no error
	input := "NAME                 PORT    STATUS UPTIME       DESCRIPTION\n"
	got := parseBastionhubStatus(input)
	if len(got) != 0 {
		t.Errorf("got %d entries, want 0", len(got))
	}
}

func TestParseBastionhubStatus_NoHeader(t *testing.T) {
	// No header = nothing parsed (defensive)
	input := "perso-mbp 12001 UP 1h Patrick's laptop\n"
	got := parseBastionhubStatus(input)
	if len(got) != 0 {
		t.Errorf("got %d entries (no header), want 0", len(got))
	}
	// silence unused import vars if test changes
	_ = strings.Contains
}

// TestCertsGroupsDeployCerts drives the certs handler over a synthetic issuance
// log and checks the CI deploy group, the repository column and both expiry windows.
func TestCertsGroupsDeployCerts(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	ts := func(ago time.Duration) string { return now.Add(-ago).Format(time.RFC3339) }
	log := strings.Join([]string{
		// Issued 51w ago with +52w: expires in about 7 days.
		`{"ts":"` + ts(51*7*24*time.Hour) + `","ca":"user","key_id":"roselabs-io/site@github-actions","principals":"deploy-site","valid":"+52w"}`,
		`{"ts":"` + ts(0) + `","ca":"user","key_id":"roselabs-io/api@github-actions","principals":"deploy-api","valid":"+52w"}`,
		// A 7-day user cert stays ACTIVE: the 14-day window applies to deploy certs only.
		`{"ts":"` + ts(0) + `","ca":"user","key_id":"alice-laptop","principals":"gw-user","valid":"+7d"}`,
		`{"ts":"` + ts(0) + `","ca":"user","key_id":"bob-laptop","principals":"gw-user","valid":"+8h"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "issuance-log.jsonl"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &app{
		detected:         detected{Sshca: "/usr/bin/sshca"},
		tmpl:             template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl")),
		token:            "tok",
		caDir:            dir,
		deployWindow:     14 * 24 * time.Hour,
		deployWindowFlag: "14d",
	}
	rec := httptest.NewRecorder()
	a.certs(rec, httptest.NewRequest(http.MethodGet, "/t/tok/certs", nil))
	body := rec.Body.String()

	deployStart := strings.Index(body, `id="certs-deploy"`)
	otherStart := strings.Index(body, `id="certs-other"`)
	if deployStart < 0 || otherStart < deployStart {
		t.Fatalf("want a CI deploy section before the other certs section:\n%s", body)
	}
	deploy, other := body[deployStart:otherStart], body[otherStart:]
	if !strings.Contains(deploy, "<h2>CI deploy</h2>") {
		t.Errorf("deploy section has no CI deploy heading")
	}

	row := func(section, keyID string) string {
		start := strings.Index(section, `<tr id="cert-row-`+keyID+`">`)
		if start < 0 {
			t.Fatalf("row %s not in its section", keyID)
		}
		end := strings.Index(section[start:], "</tr>")
		return section[start : start+end]
	}
	for _, c := range []struct {
		section, keyID, repo, status string
	}{
		{deploy, "roselabs-io/site@github-actions", "roselabs-io/site", "EXPIRING"},
		{deploy, "roselabs-io/api@github-actions", "roselabs-io/api", "ACTIVE"},
		{other, "alice-laptop", "", "ACTIVE"},
		{other, "bob-laptop", "", "EXPIRING"},
	} {
		r := row(c.section, c.keyID)
		if !strings.Contains(r, ">"+c.status+"<") {
			t.Errorf("%s: want status %s in row:\n%s", c.keyID, c.status, r)
		}
		if c.repo != "" && !strings.Contains(r, "<td><code>"+c.repo+"</code></td>") {
			t.Errorf("%s: want repository %s in row:\n%s", c.keyID, c.repo, r)
		}
		// A key ID such as "<repo>@github-actions" is not a valid CSS id
		// selector, so the row actions must not target the row by its key ID.
		if !strings.Contains(r, `hx-target="closest tr"`) || strings.Contains(r, `hx-target="#cert-row-`) {
			t.Errorf("%s: row actions must target the row with closest tr:\n%s", c.keyID, r)
		}
	}
}

// renewFixture writes a CA dir whose log holds one +8h entry for a pubkey that
// exists and one for a pubkey that does not, and a fake sshca that records its
// arguments and appends a renewed entry the way `sshca cert renew` does.
func renewFixture(t *testing.T) (*app, string) {
	t.Helper()
	dir := t.TempDir()
	pub := filepath.Join(dir, "alice.pub")
	if err := os.WriteFile(pub, []byte("ssh-ed25519 AAAA alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	log := fmt.Sprintf(`{"ts":%q,"ca":"user","key_id":"alice-old","principals":"alice","valid":"+8h","pubkey":%q,"cert":"x"}
{"ts":%q,"ca":"user","key_id":"bob-old","principals":"bob","valid":"+8h","pubkey":%q,"cert":"y"}
`, ts, pub, ts, filepath.Join(dir, "missing.pub"))
	if err := os.WriteFile(filepath.Join(dir, "issuance-log.jsonl"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	sshca := filepath.Join(dir, "sshca")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$@" > %q
printf '{"ts":"%%s","ca":"user","key_id":"alice-new","principals":"alice","valid":"+8h","pubkey":%q,"cert":"x"}\n' "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" >> %q
echo "cert renewed"
`, filepath.Join(dir, "args"), pub, filepath.Join(dir, "issuance-log.jsonl"))
	if err := os.WriteFile(sshca, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl"))
	return &app{detected: detected{Sshca: sshca}, tmpl: tmpl, token: "tok", caDir: dir}, dir
}

func TestCertsRenderRenewOnlyWithPubkeyFile(t *testing.T) {
	a, _ := renewFixture(t)
	rec := httptest.NewRecorder()
	a.certs(rec, httptest.NewRequest("GET", "/t/tok/certs", nil))
	body := rec.Body.String()
	alice := body[strings.Index(body, `id="cert-row-alice-old"`):strings.Index(body, `id="cert-row-bob-old"`)]
	bob := body[strings.Index(body, `id="cert-row-bob-old"`):]
	if !strings.Contains(alice, `name="cert" value="x"`) || !strings.Contains(bob, `name="cert" value="y"`) {
		t.Errorf("every row's Inspect action should submit its entry's cert:\n%s", body)
	}
	if !strings.Contains(alice, "/api/cert/renew") {
		t.Errorf("alice row has no Renew action:\n%s", alice)
	}
	if strings.Contains(bob, "/api/cert/renew") || !strings.Contains(bob, "pubkey file not found") {
		t.Errorf("bob row (missing pubkey) should show no Renew action:\n%s", bob)
	}
}

func TestRenewCert(t *testing.T) {
	cases := []struct {
		name     string
		keyID    string
		ship     string
		wantCode int
		wantArgs string // "" = sshca must not run
	}{
		{"local", "alice-old", "", 200, "cert renew --ca user --pubkey-file PUB --dir DIR"},
		{"ship", "alice-old", "alice@laptop:/home/alice/.ssh/", 200, "cert renew --ca user --pubkey-file PUB --dir DIR --ship alice@laptop:/home/alice/.ssh/"},
		{"ship option rejected", "alice-old", "-oProxyCommand=x", 400, ""},
		{"unknown key_id", "nobody", "", 404, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, dir := renewFixture(t)
			req := httptest.NewRequest("POST", "/t/tok/api/cert/renew", strings.NewReader("key_id="+c.keyID+"&ca=user"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("HX-Prompt", c.ship)
			rec := httptest.NewRecorder()
			a.renewCert(rec, req)
			if rec.Code != c.wantCode {
				t.Fatalf("status = %d, want %d: %s", rec.Code, c.wantCode, rec.Body)
			}
			args, err := os.ReadFile(filepath.Join(dir, "args"))
			if c.wantArgs == "" {
				if err == nil {
					t.Fatalf("sshca ran with %q", args)
				}
				return
			}
			want := strings.NewReplacer("PUB", filepath.Join(dir, "alice.pub"), "DIR", dir).Replace(c.wantArgs)
			if got := strings.Join(strings.Fields(string(args)), " "); got != want {
				t.Errorf("sshca args = %q, want %q", got, want)
			}
			body := rec.Body.String()
			newRow, oldRow := strings.Index(body, `id="cert-row-alice-new"`), strings.Index(body, `id="cert-row-alice-old"`)
			if newRow < 0 || oldRow < newRow {
				t.Errorf("want the new row, then the renewed row:\n%s", body)
			}
		})
	}
}

// The fixture includes a NEVER certificate, which is visible under ALL.
func TestCertsFilter(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	entry := func(keyID string, issued time.Duration, valid string) string {
		return fmt.Sprintf(`{"ts":%q,"ca":"user","key_id":%q,"principals":"p","valid":%q,"pubkey":"x.pub","cert":"x"}`+"\n",
			now.Add(issued).Format(time.RFC3339), keyID, valid)
	}
	log := entry("alice-active", -time.Hour, "+52w") +
		entry("Alice-expiring", -time.Hour, "+8h") +
		entry("bob-expired", -48*time.Hour, "+8h") +
		entry("bob-never", -time.Hour, "always")
	if err := os.WriteFile(filepath.Join(dir, "issuance-log.jsonl"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl"))
	a := &app{detected: detected{Sshca: "sshca"}, tmpl: tmpl, token: "tok", caDir: dir}

	all := []string{"alice-active", "Alice-expiring", "bob-expired", "bob-never"}
	cases := []struct {
		query    string
		wantCode int
		want     []string
	}{
		{"", 200, all},
		{"?status=ALL", 200, all},
		{"?status=ACTIVE", 200, []string{"alice-active"}},
		{"?status=EXPIRING", 200, []string{"Alice-expiring"}},
		{"?status=EXPIRED", 200, []string{"bob-expired"}},
		{"?q=alice", 200, []string{"alice-active", "Alice-expiring"}},
		{"?q=BOB&status=EXPIRED", 200, []string{"bob-expired"}},
		{"?q=bob&status=ACTIVE", 200, nil},
		{"?q=" + url.QueryEscape(`a & "b"+c`) + "&status=EXPIRING", 200, nil},
		{"?status=NEVER", 400, nil},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			rec := httptest.NewRecorder()
			a.certs(rec, httptest.NewRequest("GET", "/t/tok/certs"+c.query, nil))
			if rec.Code != c.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, c.wantCode)
			}
			if c.wantCode != 200 {
				return
			}
			body := rec.Body.String()
			for _, k := range all {
				if got, want := strings.Contains(body, `id="cert-row-`+k+`"`), slices.Contains(c.want, k); got != want {
					t.Errorf("row %s shown = %v, want %v", k, got, want)
				}
			}
			if wantCount := fmt.Sprintf("%d of 4 cert(s)", len(c.want)); !strings.Contains(body, wantCount) {
				t.Errorf("body lacks %q", wantCount)
			}
			params, err := url.ParseQuery(strings.TrimPrefix(c.query, "?"))
			if err != nil {
				t.Fatal(err)
			}
			q, status := params.Get("q"), params.Get("status")
			if status == "" {
				status = "ALL"
			}
			_, form, found := strings.Cut(body, `<form method="get" action="/t/tok/certs"`)
			if !found {
				t.Fatal("missing search form")
			}
			form, _, found = strings.Cut(form, "</form>")
			if !found {
				t.Fatal("missing search form closing tag")
			}
			for _, input := range []string{
				`<input type="search" name="q" value="` + q + `"`,
				`<input type="hidden" name="status" value="` + status + `"`,
			} {
				if !strings.Contains(html.UnescapeString(form), input) {
					t.Errorf("search form lacks %q", input)
				}
			}
			buttons := regexp.MustCompile(`<a role="button" href="([^"]*)"([^>]*)>(ALL|ACTIVE|EXPIRING|EXPIRED)</a>`).FindAllStringSubmatch(body, -1)
			if len(buttons) != 4 {
				t.Fatalf("status buttons = %d, want 4", len(buttons))
			}
			for i, target := range []string{"ALL", "ACTIVE", "EXPIRING", "EXPIRED"} {
				button := buttons[i]
				link, err := url.Parse(html.UnescapeString(button[1]))
				if err != nil {
					t.Fatal(err)
				}
				if button[3] != target || link.Path != "/t/tok/certs" || link.Query().Get("status") != target || link.Query().Get("q") != q {
					t.Errorf("%s status button = %q, want certs link preserving q=%q", target, button[0], q)
				}
				if current := strings.Contains(button[2], `aria-current="true"`); current != (target == status) {
					t.Errorf("%s aria-current = %v, selected status = %s", target, current, status)
				}
			}
		})
	}
}

// TestInspectCert covers the dialog fragment of GET /api/cert/inspect: sshca
// runs on the cert path of the issuance-log entry the request selects, also
// when two entries share key_id and ca, its output fills the dialog, and a
// failing sshca still returns the dialog, marked as failed.
func TestInspectCert(t *testing.T) {
	cases := []struct {
		name       string
		keyID      string
		cert       string // file name in the CA dir
		exit       int
		wantCode   int
		wantFailed bool
	}{
		{"first of two entries", "alice", "alice-1-cert.pub", 0, 200, false},
		{"second of two entries", "alice", "alice-2-cert.pub", 0, 200, false},
		{"sshca fails", "alice", "alice-1-cert.pub", 1, 200, true},
		{"unknown key_id", "nobody", "alice-1-cert.pub", 0, 404, false},
		{"cert not in log", "alice", "other-cert.pub", 0, 404, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			cert := filepath.Join(dir, c.cert)
			var log string
			for _, name := range []string{"alice-1-cert.pub", "alice-2-cert.pub"} {
				log += fmt.Sprintf(`{"ts":"2026-05-29T15:00:00Z","ca":"user","key_id":"alice","principals":"alice","valid":"+8h","pubkey":"alice.pub","cert":%q}`+"\n", filepath.Join(dir, name))
			}
			if err := os.WriteFile(filepath.Join(dir, "issuance-log.jsonl"), []byte(log), 0o600); err != nil {
				t.Fatal(err)
			}
			sshca := filepath.Join(dir, "sshca")
			script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %q\necho '<Type: ssh-ed25519-cert-v01@openssh.com user certificate>'\nexit %d\n", filepath.Join(dir, "args"), c.exit)
			if err := os.WriteFile(sshca, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl"))
			a := &app{detected: detected{Sshca: sshca}, tmpl: tmpl, token: "tok", caDir: dir}

			rec := httptest.NewRecorder()
			q := url.Values{"key_id": {c.keyID}, "ca": {"user"}, "cert": {cert}}
			a.inspectCert(rec, httptest.NewRequest("GET", "/t/tok/api/cert/inspect?"+q.Encode(), nil))
			if rec.Code != c.wantCode {
				t.Fatalf("status = %d, want %d: %s", rec.Code, c.wantCode, rec.Body)
			}
			args, err := os.ReadFile(filepath.Join(dir, "args"))
			if c.wantCode != 200 {
				if err == nil {
					t.Fatalf("sshca ran with %q", args)
				}
				return
			}
			if got, want := strings.Join(strings.Fields(string(args)), " "), "cert inspect "+cert; got != want {
				t.Errorf("sshca args = %q, want %q", got, want)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "<dialog open>") || !strings.Contains(body, "&lt;Type: ssh-ed25519-cert-v01@openssh.com user certificate&gt;") {
				t.Errorf("want a dialog holding the escaped sshca output:\n%s", body)
			}
			if got := strings.Contains(body, "Inspect failed"); got != c.wantFailed {
				t.Errorf("failed marker = %v, want %v:\n%s", got, c.wantFailed, body)
			}
		})
	}
}

// TestEndpointActions covers POST /api/endpoint/enroll and /unregister through
// a fake bastionhub that records its arguments and, on success, rewrites the
// file named by BASTIONHUB_CONFIG to hold one endpoint "new-ep". The response
// is the #endpoints-view element re-read from that file, with bastionhub's output.
func TestEndpointActions(t *testing.T) {
	cases := []struct {
		name       string
		action     string
		form       url.Values
		exit       int
		wantCode   int
		wantArgs   string // "" = bastionhub must not run the action
		wantFailed bool
	}{
		{"enroll, all fields", "enroll", url.Values{"name": {"web-01"}, "pubkey-file": {"/k/web.pub"}, "user": {"ops"}, "port": {"12005"}, "identity": {"~/.ssh/id"}, "description": {"web server"}, "valid": {"+4w"}, "principal": {"tun"}}, 0, 200,
			"endpoint enroll --ca-dir=DIR --pubkey-file=/k/web.pub --user=ops --port=12005 --identity=~/.ssh/id --description=web server --valid=+4w --principal=tun web-01", false},
		{"enroll, empty fields omitted", "enroll", url.Values{"name": {"web-01"}, "pubkey-file": {"/k/web.pub"}, "user": {""}}, 0, 200,
			"endpoint enroll --ca-dir=DIR --pubkey-file=/k/web.pub web-01", false},
		{"enroll, bastionhub fails", "enroll", url.Values{"name": {"web-01"}, "pubkey-file": {"/k/web.pub"}}, 1, 200,
			"endpoint enroll --ca-dir=DIR --pubkey-file=/k/web.pub web-01", true},
		{"enroll, name starting with -", "enroll", url.Values{"name": {"--help"}, "pubkey-file": {"/k/web.pub"}}, 0, 200, "", true},
		{"unregister", "unregister", url.Values{"name": {"old-ep"}}, 0, 200, "endpoint unregister old-ep", false},
		{"unregister, bastionhub fails", "unregister", url.Values{"name": {"old-ep"}}, 1, 200, "endpoint unregister old-ep", true},
		{"unregister, name starting with -", "unregister", url.Values{"name": {"-x"}}, 0, 400, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			config := filepath.Join(dir, "endpoints.yaml")
			if err := os.WriteFile(config, []byte("endpoints:\n  old-ep: {port: 12001, user: root}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			bastionhub := filepath.Join(dir, "bastionhub")
			script := fmt.Sprintf(`#!/bin/sh
[ "$1" = status ] && exit 0
printf '%%s\n' "$@" > %q
echo 'bastionhub <output>'
[ %d -ne 0 ] && exit %d
printf 'endpoints:\n  new-ep: {port: 12002, user: root}\n' > "$BASTIONHUB_CONFIG"
`, filepath.Join(dir, "args"), c.exit, c.exit)
			if err := os.WriteFile(bastionhub, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl"))
			a := &app{detected: detected{Bastionhub: bastionhub}, tmpl: tmpl, token: "tok", caDir: dir, bastionhubConfigs: []string{config}}

			req := httptest.NewRequest("POST", "/t/tok/api/endpoint/"+c.action, strings.NewReader(c.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			if c.action == "enroll" {
				a.enrollEndpoint(rec, req)
			} else {
				a.unregisterEndpoint(rec, req)
			}
			if rec.Code != c.wantCode {
				t.Fatalf("status = %d, want %d: %s", rec.Code, c.wantCode, rec.Body)
			}
			body := rec.Body.String()
			args, err := os.ReadFile(filepath.Join(dir, "args"))
			if c.wantArgs == "" {
				if err == nil {
					t.Fatalf("bastionhub ran with %q", args)
				}
			} else {
				want := strings.ReplaceAll(c.wantArgs, "DIR", dir)
				if got := strings.Join(strings.Split(strings.TrimSpace(string(args)), "\n"), " "); got != want {
					t.Errorf("bastionhub args = %q, want %q", got, want)
				}
				if !strings.Contains(body, "bastionhub &lt;output&gt;") {
					t.Errorf("want the escaped bastionhub output:\n%s", body)
				}
			}
			if c.wantCode != 200 {
				return
			}
			if !strings.HasPrefix(strings.TrimSpace(body), `<div id="endpoints-view">`) || strings.Contains(body, "<hgroup>") || strings.Contains(body, "<script>") {
				t.Errorf("want only the #endpoints-view element, which the forms swap with outerHTML:\n%s", body)
			}
			if got := strings.Contains(body, `<article class="error">`); got != c.wantFailed {
				t.Errorf("failed result = %v, want %v:\n%s", got, c.wantFailed, body)
			}
			changed := c.wantArgs != "" && !c.wantFailed
			if strings.Contains(body, `id="endpoint-row-new-ep"`) != changed || strings.Contains(body, `id="endpoint-row-old-ep"`) == changed {
				t.Errorf("want the view re-read from BASTIONHUB_CONFIG (changed = %v):\n%s", changed, body)
			}
			if c.action == "enroll" && c.wantFailed && !strings.Contains(body, fmt.Sprintf(`name="name" required value="%s"`, c.form.Get("name"))) {
				t.Errorf("a failed enroll should keep the submitted values:\n%s", body)
			}
		})
	}
}

func TestEndpointsRenderUnregisterPerRow(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "endpoints.yaml")
	if err := os.WriteFile(config, []byte("endpoints:\n  a: {port: 12001, user: root}\n  b: {port: 12002, user: root}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl"))
	a := &app{detected: detected{Bastionhub: "/bin/false"}, tmpl: tmpl, token: "tok", bastionhubConfigs: []string{config}}
	rec := httptest.NewRecorder()
	a.endpoints(rec, httptest.NewRequest("GET", "/t/tok/endpoints", nil))
	body := rec.Body.String()
	for _, name := range []string{"a", "b"} {
		row := body[strings.Index(body, `id="endpoint-row-`+name+`"`):]
		row = row[:strings.Index(row, "</tr>")]
		if !strings.Contains(row, "/api/endpoint/unregister") || !strings.Contains(row, `name="name" value="`+name+`"`) || !strings.Contains(row, "hx-confirm=") {
			t.Errorf("row %s has no confirmed Unregister action:\n%s", name, row)
		}
	}
	if !strings.Contains(body, `hx-post="/t/tok/api/endpoint/enroll"`) {
		t.Errorf("the view has no enroll form:\n%s", body)
	}
}

// TestEndpointsSwitchBastion covers the Endpoints view with two --config
// files: the config query parameter selects the endpoints.yaml that is read,
// that `bastionhub status` and the actions run against, and that the copied
// SSH command names. The fake bastionhub reports "UP" for every endpoint of
// the file named by BASTIONHUB_CONFIG and records that file for actions.
func TestEndpointsSwitchBastion(t *testing.T) {
	dir := t.TempDir()
	configA := filepath.Join(dir, "a.yaml")
	configB := filepath.Join(dir, "it's b.yaml")
	if err := os.WriteFile(configA, []byte("endpoints:\n  ep-a: {port: 12001, user: root}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configB, []byte("endpoints:\n  ep-b: {port: 12001, user: root}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bastionhub := filepath.Join(dir, "bastionhub")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = status ]; then
	echo 'NAME PORT STATUS UPTIME DESCRIPTION'
	sed -n 's/^  \([a-z-]*\):.*/\1 12001 UP 01:00:00/p' "$BASTIONHUB_CONFIG"
	exit 0
fi
printf '%%s' "$BASTIONHUB_CONFIG" > %q
`, filepath.Join(dir, "used-config"))
	if err := os.WriteFile(bastionhub, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl"))
	a := &app{detected: detected{Bastionhub: bastionhub}, tmpl: tmpl, token: "tok", bastionhubConfigs: []string{configA, configB}}

	for _, c := range []struct {
		query, wantEP, wantConfig string
	}{
		{"", "ep-a", configA},
		{"?config=" + url.QueryEscape(configB), "ep-b", configB},
	} {
		rec := httptest.NewRecorder()
		a.endpoints(rec, httptest.NewRequest("GET", "/t/tok/endpoints"+c.query, nil))
		body := rec.Body.String()
		other := map[string]string{"ep-a": "ep-b", "ep-b": "ep-a"}[c.wantEP]
		if !strings.Contains(body, `id="endpoint-row-`+c.wantEP+`"`) || strings.Contains(body, `id="endpoint-row-`+other+`"`) {
			t.Errorf("%q: want only %s's rows:\n%s", c.query, c.wantEP, body)
		}
		if !strings.Contains(body, `status-up`) {
			t.Errorf("%q: bastionhub status did not run against %s:\n%s", c.query, c.wantConfig, body)
		}
		escaped := template.HTMLEscapeString(c.wantConfig)
		if strings.Count(body, `name="config" value="`+escaped+`"`) != 2 {
			t.Errorf("%q: the unregister and enroll forms should carry config %s:\n%s", c.query, c.wantConfig, body)
		}
		if !strings.Contains(body, `aria-current="true">`+escaped+`</a>`) || strings.Count(body, `href="/t/tok/endpoints?config=`) != 2 {
			t.Errorf("%q: want a switch with both configs, %s selected:\n%s", c.query, c.wantConfig, body)
		}
	}

	rec := httptest.NewRecorder()
	a.endpoints(rec, httptest.NewRequest("GET", "/t/tok/endpoints?config=%2Fetc%2Fother.yaml", nil))
	if rec.Code != 400 {
		t.Errorf("unknown config: status = %d, want 400", rec.Code)
	}

	rec = httptest.NewRecorder()
	a.endpoints(rec, httptest.NewRequest("GET", "/t/tok/endpoints?config="+url.QueryEscape(configB), nil))
	if want := template.HTMLEscapeString(`BASTIONHUB_CONFIG='` + filepath.Join(dir, `it'\''s b.yaml`) + `' bastionhub ssh ep-b`); !strings.Contains(rec.Body.String(), `data-copy="`+want+`"`) {
		t.Errorf("want the copied command to name config B, %s:\n%s", want, rec.Body)
	}

	for _, c := range []struct {
		config   string
		wantCode int
	}{
		{configB, 200},
		{"/etc/other.yaml", 400},
	} {
		os.Remove(filepath.Join(dir, "used-config"))
		form := url.Values{"config": {c.config}, "name": {"ep-b"}}
		req := httptest.NewRequest("POST", "/t/tok/api/endpoint/unregister", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		a.unregisterEndpoint(rec, req)
		if rec.Code != c.wantCode {
			t.Fatalf("unregister with config %s: status = %d, want %d", c.config, rec.Code, c.wantCode)
		}
		used, err := os.ReadFile(filepath.Join(dir, "used-config"))
		if c.wantCode != 200 {
			if err == nil {
				t.Errorf("bastionhub ran for unknown config %s", c.config)
			}
			continue
		}
		if string(used) != configB {
			t.Errorf("BASTIONHUB_CONFIG = %q, want %q", used, configB)
		}
		if !strings.Contains(rec.Body.String(), `id="endpoint-row-ep-b"`) {
			t.Errorf("want the view re-read from config B:\n%s", rec.Body)
		}
	}
}

// TestIssuanceLog covers GET /log: entries in ts order regardless of file
// order, and the principal, CA and inclusive UTC date-range filters.
func TestIssuanceLog(t *testing.T) {
	dir := t.TempDir()
	entry := func(keyID, ts, ca, principals string) string {
		return fmt.Sprintf(`{"ts":%q,"ca":%q,"key_id":%q,"principals":%q,"valid":"+8h","pubkey":"x.pub","cert":"x"}`+"\n",
			ts, ca, keyID, principals)
	}
	log := entry("c-host", "2026-05-03T09:00:00Z", "host", "bastion.example") +
		entry("a-alice", "2026-05-01T23:30:00Z", "user", "alice,root") +
		entry("b-bob", "2026-05-02T00:30:00+02:00", "user", "bob") +
		entry("d-alice", "2026-05-04T12:00:00Z", "user", "alice")
	if err := os.WriteFile(filepath.Join(dir, "issuance-log.jsonl"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl"))
	a := &app{detected: detected{Sshca: "sshca"}, tmpl: tmpl, token: "tok", caDir: dir}

	cases := []struct {
		query    string
		wantCode int
		want     []string // key_ids, in rendered order
	}{
		// b-bob is 2026-05-01T22:30Z, before a-alice.
		{"", 200, []string{"b-bob", "a-alice", "c-host", "d-alice"}},
		{"?principal=alice", 200, []string{"a-alice", "d-alice"}},
		{"?principal=root", 200, []string{"a-alice"}},
		{"?principal=ali", 200, nil},
		{"?ca=host", 200, []string{"c-host"}},
		{"?ca=user&principal=bob", 200, []string{"b-bob"}},
		{"?from=2026-05-02", 200, []string{"c-host", "d-alice"}},
		{"?to=2026-05-01", 200, []string{"b-bob", "a-alice"}},
		{"?from=2026-05-03&to=2026-05-03", 200, []string{"c-host"}},
		{"?from=2026-05-01&to=2026-05-04&ca=user&principal=alice", 200, []string{"a-alice", "d-alice"}},
		{"?ca=root", 400, nil},
		{"?from=05/01/2026", 400, nil},
		{"?to=2026-13-01", 400, nil},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			rec := httptest.NewRecorder()
			a.issuanceLog(rec, httptest.NewRequest("GET", "/t/tok/log"+c.query, nil))
			if rec.Code != c.wantCode {
				t.Fatalf("status = %d, want %d: %s", rec.Code, c.wantCode, rec.Body)
			}
			if c.wantCode != 200 {
				return
			}
			var got []string
			for _, row := range strings.Split(rec.Body.String(), `<tr class="log-row">`)[1:] {
				for _, k := range []string{"a-alice", "b-bob", "c-host", "d-alice"} {
					if strings.Contains(row, "<code>"+k+"</code>") {
						got = append(got, k)
					}
				}
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("rows = %v, want %v", got, c.want)
			}
			if wantCount := fmt.Sprintf("%d of 4 entries", len(c.want)); !strings.Contains(rec.Body.String(), wantCount) {
				t.Errorf("body lacks %q", wantCount)
			}
		})
	}
}
