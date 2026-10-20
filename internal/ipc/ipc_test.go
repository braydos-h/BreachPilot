// Cross-language contract tests: Go client <-> Rust bp-sidecar over the v1
// JSON IPC envelope (proto/exec.proto is the IDL source of truth).
// All tests skip when the sidecar is absent; the ci-native ipc-contract job
// runs the sidecar and executes them live.
package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"
)

const sidecarAddr = "127.0.0.1:18765"

func liveClient(t *testing.T) *Client {
	t.Helper()
	c := &Client{Addr: sidecarAddr, Timeout: 10 * time.Second}
	if err := c.Health(); err != nil {
		t.Skipf("sidecar not running (CI ipc-contract job runs it): %v", err)
	}
	return c
}

// rawRoundTrip sends one JSON line and decodes one JSON line, exercising the
// envelope shape directly (version negotiation, unknown ops).
func rawRoundTrip(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	conn, err := net.DialTimeout("tcp", sidecarAddr, 5*time.Second)
	if err != nil {
		t.Skipf("sidecar not running: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	raw, _ := json.Marshal(payload)
	if _, err := fmt.Fprintf(conn, "%s\n", raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func TestLiveHealth(t *testing.T) {
	c := liveClient(t)
	resp, err := c.Call("health", map[string]any{})
	if err != nil {
		t.Fatalf("health call: %v", err)
	}
	if !resp.OK || resp.Version != "v1" {
		t.Fatalf("health response: %+v", resp)
	}
}

func TestLiveScopeDenied(t *testing.T) {
	c := liveClient(t)
	// Deterministic: gate denies before any process spawns, on any platform.
	resp, err := c.Call("exec", map[string]any{
		"argv":              []string{"echo", "hi"},
		"targets":           []string{"192.168.99.9"},
		"allowed_targets":   []string{"10.0.0.0/24"},
		"require_allowlist": true,
		"timeout_seconds":   10,
		"max_output_bytes":  65536,
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if resp.OK {
		t.Fatal("out-of-scope exec must fail")
	}
	if resp.Error == nil || resp.Error.Code != "SANDBOX_SCOPE_DENIED" {
		t.Fatalf("expected SANDBOX_SCOPE_DENIED, got %+v", resp.Error)
	}
}

func TestLiveSpawnFailed(t *testing.T) {
	c := liveClient(t)
	// In-scope target, nonexistent binary: deterministic SPAWN_FAILED.
	resp, err := c.Call("exec", map[string]any{
		"argv":              []string{"definitely-not-a-binary-xyz"},
		"targets":           []string{},
		"allowed_targets":   []string{},
		"require_allowlist": false,
		"timeout_seconds":   10,
		"max_output_bytes":  65536,
	})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if resp.OK {
		t.Fatal("nonexistent binary must fail")
	}
	if resp.Error == nil || resp.Error.Code != "SANDBOX_SPAWN_FAILED" {
		t.Fatalf("expected SANDBOX_SPAWN_FAILED, got %+v", resp.Error)
	}
}

func TestLiveVersionMismatch(t *testing.T) {
	liveClient(t)
	resp := rawRoundTrip(t, map[string]any{"version": "v0", "id": "1", "op": "health"})
	if resp["ok"] == true {
		t.Fatal("version mismatch must fail")
	}
	errBody, _ := resp["error"].(map[string]any)
	if errBody["code"] != "SANDBOX_INVALID" {
		t.Fatalf("expected SANDBOX_INVALID, got %v", resp)
	}
}

func TestLiveUnknownOp(t *testing.T) {
	liveClient(t)
	resp := rawRoundTrip(t, map[string]any{"version": "v1", "id": "1", "op": "nope"})
	if resp["ok"] == true {
		t.Fatal("unknown op must fail")
	}
	errBody, _ := resp["error"].(map[string]any)
	if errBody["code"] != "SANDBOX_INVALID" {
		t.Fatalf("expected SANDBOX_INVALID, got %v", resp)
	}
}
