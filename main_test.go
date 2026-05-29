package main

import (
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
