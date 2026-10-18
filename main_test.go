package main

import (
	"fmt"
	"html/template"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
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
