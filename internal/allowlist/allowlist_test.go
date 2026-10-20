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
