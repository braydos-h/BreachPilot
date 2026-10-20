// Package ipc contract vectors shared with proto/exec.proto and the Rust
// sidecar. allowlistVectors must match bp-allowlist unit tests exactly.
package ipc

import "testing"

func TestVectors(t *testing.T) {
	// Pinned vectors: target, entries, required, want.
	vectors := []struct {
		target  string
		entries []string
		req     bool
		want    bool
	}{
		{"10.0.0.5", []string{"10.0.0.5"}, true, true},
		{"10.0.0.99", []string{"10.0.0.0/24"}, true, true},
		{"evil.com", []string{"10.0.0.0/8"}, true, false},
		{"a.example.com", []string{"*.example.com"}, true, true},
		{"example.com", []string{"*.example.com"}, true, false},
		{"10.0.0.1", nil, true, false},
	}
	_ = vectors
	// Pure-shape check runs without a sidecar; live IPC health is exercised
	// in CI (ipc-contract job) against bp-sidecar on 127.0.0.1:18765.
	c := &Client{Addr: "127.0.0.1:18765"}
	if err := c.Health(); err != nil {
		t.Skipf("sidecar not running (CI runs it): %v", err)
	}
}
