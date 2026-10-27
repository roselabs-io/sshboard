//go:build browser

package main

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
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

// browserContext starts Chrome and returns a context whose deadline is 60 seconds after the browser is up.
func browserContext(t *testing.T, chrome, url string) context.Context {
	t.Helper()
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(),
		append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chrome), chromedp.NoSandbox,
			chromedp.Flag("disable-background-networking", true), chromedp.Flag("disable-component-update", true))...)
	t.Cleanup(cancelAlloc)
	ctx, cancel := chromedp.NewContext(allocCtx)
	t.Cleanup(cancel)
	// The first Run starts the browser; the deadline applies to the steps after it.
	if _, err := chromedp.Run(ctx, chromedp.Navigate(url)); err != nil {
		t.Fatal(err)
	}
	ctx, cancelTimeout := context.WithTimeout(ctx, 60*time.Second)
	t.Cleanup(cancelTimeout)
	return ctx
}

const inspectDialog = "#cert-dialog dialog[open]"

// inspectAndClose clicks Inspect in the row, returns the dialog text and closes the dialog.
func inspectAndClose(t *testing.T, ctx context.Context, row string) string {
	t.Helper()
	run := func(a chromedp.Action[chromedp.Void]) {
		t.Helper()
		if _, err := chromedp.Run(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	run(chromedp.WaitVisible(row))
	run(chromedp.Click(row + " form[hx-get] button"))
	run(chromedp.WaitVisible(inspectDialog))
	text, err := chromedp.Run(ctx, chromedp.Text(inspectDialog))
	if err != nil {
		t.Fatal(err)
	}
	run(chromedp.Click(inspectDialog + " button"))
	run(chromedp.WaitNotPresent(inspectDialog))
	return text
}

func writeIssuanceLog(t *testing.T, dir, cert string) {
	t.Helper()
	ts := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	log := fmt.Sprintf(`{"ts":%q,"ca":"user","key_id":"alice","principals":"alice","valid":"+8h","pubkey":"alice.pub","cert":%q}`+"\n", ts, cert)
	if err := os.WriteFile(filepath.Join(dir, "issuance-log.jsonl"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
}

const sshcaStub = "#!/bin/sh\necho 'Type: ssh-ed25519-cert-v01@openssh.com user certificate'\n"

func checkInspectText(t *testing.T, text string) {
	t.Helper()
	for _, want := range []string{"alice", "ssh-ed25519-cert-v01@openssh.com user certificate"} {
		if !strings.Contains(text, want) {
			t.Errorf("dialog text %q lacks %q", text, want)
		}
	}
}

// TestBrowserCertsInspectDialog drives the Certs view in Chrome: Inspect swaps the
// dialog with the output of `sshca cert inspect` into the page, Close dismisses it,
// and Inspect opens it again.
func TestBrowserCertsInspectDialog(t *testing.T) {
	chrome := browserBinary()
	if chrome == "" {
		t.Skip("no Chrome or Chromium executable found")
	}

	dir := t.TempDir()
	writeIssuanceLog(t, dir, filepath.Join(dir, "alice-cert.pub"))
	sshca := filepath.Join(dir, "sshca")
	if err := os.WriteFile(sshca, []byte(sshcaStub), 0o700); err != nil {
		t.Fatal(err)
	}
	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html.tmpl"))
	a := &app{detected: detected{Sshca: sshca}, tmpl: tmpl, token: "tok", caDir: dir}
	srv := httptest.NewServer(a.handler())
	defer srv.Close()

	ctx := browserContext(t, chrome, srv.URL+"/t/tok/certs")
	for range 2 {
		checkInspectText(t, inspectAndClose(t, ctx, "#cert-row-alice"))
	}
}

// TestBrowserBuiltBinary builds sshboard, runs it on a loopback port with an `sshca` stub as the only
// executable on PATH, and opens the Inspect dialog from the home page through the Certs link.
func TestBrowserBuiltBinary(t *testing.T) {
	chrome := browserBinary()
	if chrome == "" {
		t.Skip("no Chrome or Chromium executable found")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	sshboard := filepath.Join(bin, "sshboard")
	if out, err := exec.Command("go", "build", "-o", sshboard, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(bin, "sshca"), []byte(sshcaStub), 0o700); err != nil {
		t.Fatal(err)
	}
	writeIssuanceLog(t, dir, filepath.Join(dir, "alice-cert.pub"))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	server := exec.Command(sshboard, "--bind", addr, "--ca-dir", dir, "--config", filepath.Join(dir, "endpoints.yaml"))
	server.Env = []string{"PATH=" + bin, "HOME=" + dir}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server.Process.Kill()
		server.Wait()
	})
	origin := "http://" + addr
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(origin)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("sshboard did not answer 200 on %s: %v", origin, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	ctx := browserContext(t, chrome, origin)
	if _, err := chromedp.Run(ctx, chromedp.Click(`nav a[href$="/certs"]`)); err != nil {
		t.Fatal(err)
	}
	checkInspectText(t, inspectAndClose(t, ctx, "#cert-row-alice"))
}
