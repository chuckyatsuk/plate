package main

import (
	"testing"
	"time"
)

// parseTTL extends time.ParseDuration with a days suffix; these are the cases
// operators actually type, plus the ones that must be rejected.
func TestParseTTL(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"90d", 90 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"0.5d", 12 * time.Hour, false},
		{"720h", 720 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{" 90d ", 90 * 24 * time.Hour, false}, // trimmed
		{"", 0, true},
		{"d", 0, true},      // no number
		{"90x", 0, true},    // bad unit
		{"abc", 0, true},    // garbage
		{"90days", 0, true}, // only a bare `d` suffix is special
	}
	for _, c := range cases {
		got, err := parseTTL(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseTTL(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTTL(%q) errored: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseTTL(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSplitCSV(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"assets:read,assets:write", []string{"assets:read", "assets:write"}},
		{" assets:read , assets:write ", []string{"assets:read", "assets:write"}}, // trimmed
		{"assets:read,,assets:write", []string{"assets:read", "assets:write"}},    // empties dropped
		{"", nil},
		{" , ", nil},
	}
	for _, c := range cases {
		got := splitCSV(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitCSV(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitCSV(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// Every scope the command accepts must be one the token model knows; a typo must
// not silently mint a credential that grants nothing.
func TestKnownScopes(t *testing.T) {
	for _, s := range []string{"assets:read", "assets:write", "renditions:generate", "grants:manage", "assets:export", "accounts:provision"} {
		if !knownScopes[s] {
			t.Errorf("known scope %q missing from knownScopes", s)
		}
	}
	for _, s := range []string{"assets:bogus", "assets:admin", "read", ""} {
		if knownScopes[s] {
			t.Errorf("unknown scope %q unexpectedly accepted", s)
		}
	}
}

func TestValidKidArg(t *testing.T) {
	for _, ok := range []string{"files", "ops-2", "a_b", "A9"} {
		if !validKidArg(ok) {
			t.Errorf("validKidArg(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "has space", "kid=1", "läder", "x,y"} {
		if validKidArg(bad) {
			t.Errorf("validKidArg(%q) = true, want false", bad)
		}
	}
}
