package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/audit"
	"github.com/braydos-h/BreachPilot/internal/intel"
	"github.com/braydos-h/BreachPilot/internal/mcp"
	"github.com/braydos-h/BreachPilot/internal/skills"
	"github.com/braydos-h/BreachPilot/internal/store"
)

func TestIsInDefensiveScopeCIDRSubset(t *testing.T) {
	allow := []string{"10.0.0.0/16", "*.example.com"}
	if !mcp.IsInDefensiveScope("10.0.1.5", allow) {
		t.Fatal("expected single IP inside /16 to pass")
	}
	if !mcp.IsInDefensiveScope("10.0.2.0/24", allow) {
		t.Fatal("expected /24 subnet inside /16 to pass")
	}
	if mcp.IsInDefensiveScope("10.1.0.0/24", allow) {
		t.Fatal("expected /24 outside /16 to fail")
	}
	if mcp.IsInDefensiveScope("10.0.0.0/8", allow) {
		t.Fatal("expected broader /8 supernet to fail against /16 allowlist")
	}
}

func TestValidateBindHostTwoPersonRule(t *testing.T) {
	if err := mcp.ValidateBindHost("127.0.0.1", false); err != nil {
		t.Fatalf("loopback must pass: %v", err)
	}
	if err := mcp.ValidateBindHost("0.0.0.0", false); err == nil {
		t.Fatal("public bind without flag must fail")
	}
	if err := mcp.ValidateBindHost("0.0.0.0", true); err == nil {
		t.Fatal("public bind without env + token must fail")
	}
	t.Setenv("MCP_ALLOW_PUBLIC_BIND", "1")
	if err := mcp.ValidateBindHost("0.0.0.0", true); err == nil {
		t.Fatal("public bind without MCP_HTTP_TOKEN must fail")
	}
	t.Setenv("MCP_HTTP_TOKEN", "secret-token")
	if err := mcp.ValidateBindHost("0.0.0.0", true); err != nil {
		t.Fatalf("public bind with flag + env + token must pass: %v", err)
	}
}

func TestEngineServerStdioAndTools(t *testing.T) {
	tmp := t.TempDir()
	db, err := store.Open(filepath.Join(tmp, "test.db"), filepath.Join(tmp, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.CreateRun("run-101", "completed", "127.0.0.1", "recon", "service_mapping", `{"target":"127.0.0.1"}`)

	skDir := filepath.Join(tmp, "skills")
	if err := os.MkdirAll(skDir, 0o755); err != nil {
		t.Fatal(err)
	}
	skStore := skills.NewStore([]string{skDir})
	_, err = skStore.Create("web-recon", "---\nname: web-recon\ndescription: Web reconnaissance guide\ntags:\n  - web\n---\n# Overview\n Enumerate endpoints.")
	if err != nil {
		t.Fatal(err)
	}

	nvdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","published":"2024-01-01","descriptions":[{"lang":"en","value":"Test vuln"}]}}]}`))
	}))
	defer nvdSrv.Close()
	s := intel.DefaultSettings()
	s.NVDBaseURL = nvdSrv.URL
	nvd := intel.NewNVDClient(s)

	srv := mcp.NewEngineServer(db, skStore, nvd)

	// Exercise JSON-RPC over stdio
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_skills","arguments":{"query":"web"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_run","arguments":{"run_id":"run-101"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"cve_lookup","arguments":{"query":"nginx 1.18"}}}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := srv.ServeStdio(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 5 { // notification produces no response
		t.Fatalf("expected 5 JSON-RPC responses, got %d:\n%s", len(lines), out.String())
	}
	if !strings.Contains(lines[2], "web-recon") {
		t.Fatalf("expected search_skills to find web-recon: %s", lines[2])
	}
	if !strings.Contains(lines[3], "run-101") {
		t.Fatalf("expected get_run to return run-101: %s", lines[3])
	}
	if !strings.Contains(lines[4], "CVE-2024-0001") {
		t.Fatalf("expected cve_lookup to return CVE-2024-0001: %s", lines[4])
	}
}

func TestDefensiveServerScopeAndLimitedTerminal(t *testing.T) {
	srv := mcp.NewDefensiveServer([]string{"127.0.0.1", "10.0.0.0/16"}, nil, nil)
	ctx := context.Background()

	// Out-of-scope scan is rejected
	out, err := srv.Call(ctx, "run_nmap_ping_sweep", map[string]any{"subnet": "192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["ok"] != false || !strings.Contains(m["error"].(string), "not in scope") {
		t.Fatalf("expected scope rejection, got %+v", m)
	}

	// Shell metacharacters in run_limited_terminal are rejected
	out2, _ := srv.Call(ctx, "run_limited_terminal", map[string]any{"command": "nmap 127.0.0.1; id"})
	if out2.(map[string]any)["ok"] != false {
		t.Fatalf("expected metacharacter rejection, got %+v", out2)
	}

	// Non-nmap command in run_limited_terminal is rejected
	out3, _ := srv.Call(ctx, "run_limited_terminal", map[string]any{"command": "curl 127.0.0.1"})
	if out3.(map[string]any)["ok"] != false {
		t.Fatalf("expected non-nmap rejection, got %+v", out3)
	}

	// Valid in-scope nmap command runs and records unprivileged flag downgrade
	out4, err := srv.Call(ctx, "run_limited_terminal", map[string]any{"command": "nmap -sS -O 127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	m4 := out4.(map[string]any)
	if m4["ok"] != true || m4["downgrade_note"] == nil {
		t.Fatalf("expected ok + downgrade_note, got %+v", m4)
	}
}

func TestAssessmentServerAllowlistAuditAndFailClosedSandbox(t *testing.T) {
	ws := t.TempDir()
	srv := mcp.NewAssessmentServer(mcp.AssessmentConfig{
		RunID:            "run-assess-1",
		WorkspaceDir:     ws,
		AllowedTargets:   []string{"127.0.0.1"},
		RequireAllowlist: true,
		SandboxEnabled:   true,
		Sidecar:          nil, // Sidecar absent -> must fail closed with SANDBOX_UNAVAILABLE
	})
	ctx := context.Background()

	// 1. Workspace write/read works inside workspace, blocks traversal outside
	_, err := srv.Call(ctx, "write_workspace_file", map[string]any{
		"filename": "notes/scan.txt",
		"content":  "port 80 open",
	})
	if err != nil {
		t.Fatalf("write_workspace_file failed: %v", err)
	}
	readOut, err := srv.Call(ctx, "read_workspace_file", map[string]any{"filename": "notes/scan.txt"})
	if err != nil || readOut.(map[string]any)["content"] != "port 80 open" {
		t.Fatalf("read_workspace_file mismatch: %v %v", readOut, err)
	}
	if _, err := srv.Call(ctx, "read_workspace_file", map[string]any{"filename": "../escape.txt"}); err == nil || !strings.Contains(err.Error(), "SANDBOX_WORKSPACE_FAILED") {
		t.Fatalf("expected SANDBOX_WORKSPACE_FAILED on traversal, got %v", err)
	}

	// 2. Out-of-scope target is blocked with SANDBOX_SCOPE_DENIED
	if _, err := srv.Call(ctx, "check_os", map[string]any{"target_ip": "192.168.99.9"}); err == nil || !strings.Contains(err.Error(), "SANDBOX_SCOPE_DENIED") {
		t.Fatalf("expected SANDBOX_SCOPE_DENIED, got %v", err)
	}

	// 3. In-scope run_sandbox_command without sidecar/Docker fails closed with SANDBOX_UNAVAILABLE (never host exec)
	if _, err := srv.Call(ctx, "run_sandbox_command", map[string]any{
		"argv":      []string{"echo", "hi"},
		"target_ip": "127.0.0.1",
	}); err == nil || !strings.Contains(err.Error(), "SANDBOX_UNAVAILABLE") {
		t.Fatalf("expected SANDBOX_UNAVAILABLE fail-closed error, got %v", err)
	}

	// 4. Verify hash-chained audit trail in workspace
	valid, reason, count := audit.Verify(ws)
	if !valid || count == 0 {
		t.Fatalf("audit chain invalid: valid=%v reason=%q count=%d", valid, reason, count)
	}

	// 5. Verify HTTP handler serves tool catalog
	httpSrv := httptest.NewServer(srv.HTTPHandler())
	defer httpSrv.Close()
	resp, err := http.Get(httpSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var cat map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&cat)
	if cat["name"] != "AI Exploitation Tools" {
		t.Fatalf("unexpected catalog: %+v", cat)
	}
}
