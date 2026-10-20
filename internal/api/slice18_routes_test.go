package api_test

// Slice 18 RED: full parity for /system/sandbox (+ /fix/plan, /fix),
// /system/memory, /system/reset, and per-run subroutes (/artifacts/{name},
// /swarm, /campaign, /logs/{name}, /workspace, /workspace/{path}, /sandbox,
// /loot, /credentials, /errors, /witness).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/memory"
)

func TestSystemSandboxAndFixPlan(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "GET", "/api/v1/system/sandbox", token, "")
	if rec.Code != 200 {
		t.Fatalf("system/sandbox = %d: %s", rec.Code, rec.Body.String())
	}
	v := decode(t, rec)
	mode, _ := v["mode"].(string)
	if mode != "contained" && mode != "blocked" && mode != "disabled" && mode != "native_fallback" {
		t.Fatalf("sandbox response missing valid mode: %v", v)
	}
	netCfg, _ := v["network"].(map[string]any)
	resCfg, _ := v["resources"].(map[string]any)
	cleanCfg, _ := v["cleanup"].(map[string]any)
	if netCfg["enforce"] == nil || resCfg["memory_mb"] == nil || cleanCfg["remove_on_exit"] == nil {
		t.Fatalf("sandbox response missing network/resources/cleanup fields: %v", v)
	}

	// Fix plan
	rec = doReq(t, s.Handler(), "GET", "/api/v1/system/sandbox/fix/plan", token, "")
	if rec.Code != 200 {
		t.Fatalf("sandbox/fix/plan = %d: %s", rec.Code, rec.Body.String())
	}
	plan := decode(t, rec)
	if plan["platform"] == nil || plan["steps"] == nil {
		t.Fatalf("invalid fix plan: %v", plan)
	}
}

func TestSystemMemoryReturnsLessonsAndConfidence(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	mem := memory.New(s.DB, "mission-1")
	if _, err := mem.StoreLesson("10.0.0.1", "recon", "HTTP 80 exposed", []string{"http"}); err != nil {
		t.Fatal(err)
	}
	if _, err := mem.Remember("10.0.0.1", "nginx 1.18", "service", []string{"web"}, 0.9, map[string]any{"port": 80}); err != nil {
		t.Fatal(err)
	}

	rec := doReq(t, s.Handler(), "GET", "/api/v1/system/memory", token, "")
	if rec.Code != 200 {
		t.Fatalf("system/memory = %d: %s", rec.Code, rec.Body.String())
	}
	v := decode(t, rec)
	lessons, okL := v["lessons"].([]any)
	attackMem, okA := v["attack_memory"].([]any)
	if !okL || !okA || len(lessons) == 0 || len(attackMem) == 0 {
		t.Fatalf("expected non-empty lessons and attack_memory, got: %s", rec.Body.String())
	}
}

func TestRunSubroutesArtifactsLogsSwarmCampaignWorkspaceLootCredsSandbox(t *testing.T) {
	s, token, repDir := testServerWithFiles(t)
	runID := "run-subroutes-1"
	if err := s.DB.CreateRun(runID, "completed", "127.0.0.1", "attack", "", `{"target":"127.0.0.1"}`); err != nil {
		t.Fatal(err)
	}
	rdir := filepath.Join(repDir, runID)
	swDir := filepath.Join(rdir, "swarm_workspace")
	wsDir := filepath.Join(rdir, "exploit_workspace")
	credDir := filepath.Join(wsDir, "credentials", "127.0.0.1")
	lootDir := filepath.Join(wsDir, "loot")
	for _, d := range []string{rdir, swDir, wsDir, credDir, lootDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	_ = os.WriteFile(filepath.Join(rdir, "session_summary.md"), []byte("# Summary OK\n"), 0o644)
	_ = os.WriteFile(filepath.Join(rdir, "session_error.log"), []byte("line1\nline2\nline3\n"), 0o644)
	_ = os.WriteFile(filepath.Join(rdir, "errors.jsonl"), []byte(`{"kind":"tool_error","phase":"recon","message":"boom"}`+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(swDir, "swarm_state.json"), []byte(`{"blackboard":{"recon_complete":true}}`), 0o644)
	_ = os.WriteFile(filepath.Join(swDir, "attack_states.json"), []byte(`{"states":{"127.0.0.1":{"current_phase":"report"}}}`), 0o644)
	_ = os.WriteFile(filepath.Join(wsDir, "scan.txt"), []byte("nmap output"), 0o644)
	_ = os.WriteFile(filepath.Join(lootDir, "loot.jsonl"), []byte(`{"id":"loot-1","category":"file","description":"config dump"}`+"\n"), 0o644)
	_ = os.WriteFile(filepath.Join(credDir, "credentials.jsonl"), []byte(`{"username":"admin","password":"secretPassword123","target_host":"127.0.0.1","credential_type":"password","confirmed":false}`+"\n"), 0o644)

	// 1. Artifact download
	rec := doReq(t, s.Handler(), "GET", "/api/v1/runs/"+runID+"/artifacts/session_summary.md", token, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "# Summary OK") {
		t.Fatalf("artifact download = %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Log tail
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+runID+"/logs/session_error.log?tail=2", token, "")
	if rec.Code != 200 {
		t.Fatalf("log tail = %d: %s", rec.Code, rec.Body.String())
	}
	logResp := decode(t, rec)
	if int(logResp["total_lines_in_file"].(float64)) != 3 || int(logResp["total_lines_returned"].(float64)) != 2 {
		t.Fatalf("unexpected log counts: %v", logResp)
	}

	// 3. Swarm & Campaign state
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+runID+"/swarm", token, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "recon_complete") {
		t.Fatalf("swarm state = %d: %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+runID+"/campaign", token, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "current_phase") {
		t.Fatalf("campaign state = %d: %s", rec.Code, rec.Body.String())
	}

	// 4. Workspace list & file read
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+runID+"/workspace", token, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "scan.txt") {
		t.Fatalf("workspace list = %d: %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+runID+"/workspace/scan.txt", token, "")
	if rec.Code != 200 || rec.Body.String() != "nmap output" {
		t.Fatalf("workspace file = %d: %s", rec.Code, rec.Body.String())
	}

	// 5. Loot & Credentials (redacted list + reveal + confirm)
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+runID+"/loot", token, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "loot-1") {
		t.Fatalf("loot = %d: %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+runID+"/credentials", token, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "[REDACTED]") || strings.Contains(rec.Body.String(), "secretPassword123") {
		t.Fatalf("credentials list = %d: %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/"+runID+"/credentials/0/reveal", token, "{}")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "secretPassword123") {
		t.Fatalf("credential reveal = %d: %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/"+runID+"/credentials/0/confirm", token, "{}")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"confirmed":true`) {
		t.Fatalf("credential confirm = %d: %s", rec.Code, rec.Body.String())
	}

	// 6. Deep errors & per-run sandbox summary
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+runID+"/errors", token, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "tool_error") {
		t.Fatalf("errors = %d: %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+runID+"/sandbox", token, "")
	if rec.Code != 200 {
		t.Fatalf("run sandbox = %d: %s", rec.Code, rec.Body.String())
	}
	var sb map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &sb)
	if sb["executions"] == nil || sb["blocked"] == nil {
		t.Fatalf("run sandbox missing executions/blocked: %v", sb)
	}
}
