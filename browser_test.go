//go:build browser

package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// browserBinary returns the first Chrome or Chromium executable found, or "".
func browserBinary() string {
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	const macChrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	if _, err := os.Stat(macChrome); err == nil {
		return macChrome
	}
	return ""
}

// TestBrowserCertsInspectDialog drives the Certs view in Chrome: Inspect swaps the
// dialog with the output of `sshca cert inspect` into the page, and Close dismisses it.
func TestBrowserCertsInspectDialog(t *testing.T) {
	chrome := browserBinary()
	if chrome == "" {
		t.Skip("no Chrome or Chromium executable found")
	}

	dir := t.TempDir()
	cert := filepath.Join(dir, "alice-cert.pub")
	ts := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	log := fmt.Sprintf(`{"ts":%q,"ca":"user","key_id":"alice","principals":"alice","valid":"+8h","pubkey":"alice.pub","cert":%q}`+"\n", ts, cert)
	if err := os.WriteFile(filepath.Join(dir, "issuance-log.jsonl"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	sshca := filepath.Join(dir, "sshca")
	script := "#!/bin/sh\necho 'Type: ssh-ed25519-cert-v01@openssh.com user certificate'\n"
	if err := os.WriteFile(sshca, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl"))
	a := &app{detected: detected{Sshca: sshca}, tmpl: tmpl, token: "tok", caDir: dir}
	srv := httptest.NewServer(a.handler())
	defer srv.Close()

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(),
		append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chrome), chromedp.NoSandbox,
			chromedp.Flag("disable-background-networking", true), chromedp.Flag("disable-component-update", true))...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	// The first Run starts the browser; the deadline applies to the steps after it.
	if _, err := chromedp.Run(ctx, chromedp.Navigate(srv.URL+"/t/tok/certs")); err != nil {
		t.Fatal(err)
	}
	ctx, cancelTimeout := context.WithTimeout(ctx, 60*time.Second)
	defer cancelTimeout()

	const dialog = "#cert-dialog dialog[open]"
	run := func(a chromedp.Action[chromedp.Void]) {
		t.Helper()
		if _, err := chromedp.Run(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	run(chromedp.WaitVisible("#cert-row-alice"))
	run(chromedp.Click("#cert-row-alice form[hx-get] button"))
	run(chromedp.WaitVisible(dialog))
	text, err := chromedp.Run(ctx, chromedp.Text(dialog))
	if err != nil {
		t.Fatal(err)
	}
	run(chromedp.Click(dialog + " button"))
	run(chromedp.WaitNotPresent(dialog))
	for _, want := range []string{"alice", "ssh-ed25519-cert-v01@openssh.com user certificate"} {
		if !strings.Contains(text, want) {
			t.Errorf("dialog text %q lacks %q", text, want)
		}
	}
}
