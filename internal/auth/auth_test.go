package auth_test

// Pin the auth gate: loopback-only bind, token create/load rules, and the
// bearer middleware (health bypass, prefix handling, constant-time check).

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/auth"
)

func TestAssertLoopback(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "localhost", "::1"} {
		if err := auth.AssertLoopback(h); err != nil {
			t.Fatalf("loopback %q rejected: %v", h, err)
		}
	}
	if err := auth.AssertLoopback("0.0.0.0"); err == nil {
		t.Fatal("non-loopback bind must be refused")
	}
}

func TestLoadOrCreateEnvAndFile(t *testing.T) {
	t.Setenv("BREACHPILOT_API_TOKEN", "abcdefghijklmnopqrstuvwxyz0123456789ABCD")
	tok, err := auth.LoadOrCreate(filepath.Join(t.TempDir(), "tok"))
	if err != nil || tok != "abcdefghijklmnopqrstuvwxyz0123456789ABCD" {
		t.Fatalf("env token must win: %q %v", tok, err)
	}
	t.Setenv("BREACHPILOT_API_TOKEN", "short")
	if _, err := auth.LoadOrCreate(filepath.Join(t.TempDir(), "tok")); err == nil {
		t.Fatal("short env token must be rejected")
	}
	t.Setenv("BREACHPILOT_API_TOKEN", "")
	p := filepath.Join(t.TempDir(), "sub", "tokfile")
	a, err := auth.LoadOrCreate(p)
	if err != nil || len(a) < 32 {
		t.Fatalf("must create a token: %q %v", a, err)
	}
	b, err := auth.LoadOrCreate(p)
	if err != nil || a != b {
		t.Fatal("second load must return the persisted token")
	}
	if err := os.WriteFile(p, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.LoadOrCreate(p); err == nil {
		t.Fatal("weak file token must be rejected")
	}
}

func TestMiddlewareGate(t *testing.T) {
	const token = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := auth.Middleware(token, next)
	health := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, health)
	if rec.Code != 200 {
		t.Fatalf("health must bypass auth, got %d", rec.Code)
	}
	for _, tc := range []struct {
		name   string
		header string
		want   int
	}{
		{"missing", "", 401},
		{"no bearer prefix", token, 401},
		{"wrong", "Bearer wrong-token-that-is-long-enough-1234", 401},
		{"ok", "Bearer " + token, 200},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s: got %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}
