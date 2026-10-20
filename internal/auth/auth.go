// Package auth implements v1 bearer auth: loopback bind gate, token load or
// create (env wins, else 0o600 file, 256-bit), constant-time compare, and the
// WebSocket first-message handshake. Mirrors tools/api/auth.py.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

var loopbacks = map[string]bool{"127.0.0.1": true, "localhost": true, "::1": true}

// AssertLoopback refuses any non-loopback bind. v1 has no public override.
func AssertLoopback(host string) error {
	if !loopbacks[host] {
		return fmt.Errorf("API host must be loopback (127.0.0.1/localhost/::1); got %q", host)
	}
	return nil
}

const minTokenLen = 32

func validShape(tok string) bool {
	if len(tok) < minTokenLen {
		return false
	}
	for _, r := range tok {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

// LoadOrCreate returns BREACHPILOT_API_TOKEN when set and well-formed,
// otherwise loads tokenFile or atomically creates a 256-bit token with 0o600.
func LoadOrCreate(tokenFile string) (string, error) {
	if env := strings.TrimSpace(os.Getenv("BREACHPILOT_API_TOKEN")); env != "" {
		if !validShape(env) {
			return "", errors.New("BREACHPILOT_API_TOKEN must be at least 32 printable characters (no whitespace)")
		}
		return env, nil
	}
	path := filepath.Clean(tokenFile)
	raw, err := os.ReadFile(path)
	if err == nil {
		tok := strings.TrimSpace(string(raw))
		if tok == "" {
			return "", fmt.Errorf("API token file %s is empty; delete it to generate a fresh token", path)
		}
		if !validShape(tok) {
			return "", fmt.Errorf("API token file %s holds a weak token; delete it to regenerate", path)
		}
		return tok, nil
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("API token file %s unreadable: %w", path, err)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	_ = tmp.Chmod(0o600)
	if _, err := tmp.WriteString(tok + "\n"); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", err
	}
	// Atomic publish: link wins the race, loser adopts winner's token.
	if err := os.Link(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		raw, err2 := os.ReadFile(path)
		if err2 != nil {
			return "", fmt.Errorf("token race: %w", err)
		}
		tok = strings.TrimSpace(string(raw))
		if !validShape(tok) {
			return "", fmt.Errorf("API token file %s holds a weak token after race", path)
		}
		return tok, nil
	}
	_ = os.Remove(tmpName)
	return tok, nil
}

// Middleware enforces Bearer on every route except GET /api/v1/health.
func Middleware(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" && r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if r.Header.Get("Authorization") == "" || got == r.Header.Get("Authorization") {
			writeErr(w, 401, "unauthorized", "Missing or invalid Authorization header")
			return
		}
		if !hmac.Equal([]byte(strings.TrimSpace(got)), []byte(token)) {
			writeErr(w, 401, "unauthorized", "Invalid bearer token.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", "go-native")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"code":%q,"message":%q,"details":{},"request_id":"go-native"}}`, code, msg)
}
