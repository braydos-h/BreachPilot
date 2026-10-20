package allowlist_test

import "testing"

import "github.com/braydos-h/BreachPilot/internal/allowlist"

func TestCheckVectors(t *testing.T) {
	cases := []struct {
		target  string
		entries []string
		req     bool
		want    bool
	}{
		{"10.0.0.5", []string{"10.0.0.5"}, true, true},
		{"10.0.0.6", []string{"10.0.0.5"}, true, false},
		{"10.0.0.99", []string{"10.0.0.0/24"}, true, true},
		{"10.0.1.1", []string{"10.0.0.0/24"}, true, false},
		{"evil.com", []string{"10.0.0.0/8"}, true, false}, // no implicit DNS grant
		{"a.example.com", []string{"*.example.com"}, true, true},
		{"example.com", []string{"*.example.com"}, true, false},
		{"notevil.com", []string{"*.evil.com"}, true, false},
		{"10.0.0.1", nil, true, false}, // empty fails closed
		{"10.0.0.1", nil, false, true}, // permissive when not required
		{"Example.COM", []string{"example.com"}, true, true},
	}
	for _, c := range cases {
		if got := allowlist.Check(c.target, c.entries, c.req); got != c.want {
			t.Errorf("Check(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

func TestSubdomain(t *testing.T) {
	if !allowlist.IsSubdomain("a.example.com", "example.com") {
		t.Error("expected subdomain")
	}
	if allowlist.IsSubdomain("notexample.com", "example.com") {
		t.Error("endswith collision must not match")
	}
}

func TestApprovalEntriesExcludeSelfAuth(t *testing.T) {
	// The run's own target env must NEVER authorize it: only config plus the
	// explicit EXPLOIT_ALLOWED_TARGETS/ALLOWED_TARGETS grants count.
	env := map[string]string{
		"EXPLOIT_TARGET":             "10.9.9.9",
		"EXPLOIT_TARGET_IP":          "10.9.9.9",
		"EXPLOIT_TARGET_DOMAIN":      "victim.example.com",
		"EXPLOIT_DISCOVERED_TARGETS": "10.9.9.9",
		"EXPLOIT_ALLOWED_TARGETS":    "10.0.0.0/24",
		"ALLOWED_TARGETS":            "",
	}
	lookup := func(k string) string { return env[k] }
	entries := allowlist.ApprovalEntries(nil, lookup)
	if allowlist.Check("10.9.9.9", entries, true) {
		t.Fatal("EXPLOIT_TARGET must not self-authorize")
	}
	if allowlist.Check("victim.example.com", entries, true) {
		t.Fatal("EXPLOIT_TARGET_DOMAIN must not self-authorize")
	}
	if !allowlist.Check("10.0.0.7", entries, true) {
		t.Fatal("explicit EXPLOIT_ALLOWED_TARGETS grant must authorize")
	}
	if got := allowlist.ApprovalEntries([]string{"10.1.0.0/16"}, lookup); !allowlist.Check("10.1.2.3", got, true) {
		t.Fatal("config entries must authorize")
	}
}
