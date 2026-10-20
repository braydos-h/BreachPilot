package api_test

// Real-backend handler tests: goals CRUD, secrets store, skills on disk,
// plugin discovery, model persistence, ollama live/refresh, providers.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/api"
	"github.com/braydos-h/BreachPilot/internal/bench"
	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/runner"
	"github.com/braydos-h/BreachPilot/internal/store"
)

const testCfgYAML = "api:\n  host: 127.0.0.1\n  port: 8765\nmodels:\n  provider: ollama\n  default_alias: glm\n  registry:\n    glm: glm-5.0:cloud\nexploit:\n  allowed_targets: [127.0.0.1, localhost, '::1']\n  require_explicit_allowlist: true\nsandbox:\n  enabled: true\n"

func testServerWithFiles(t *testing.T) (*api.Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(testCfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(dir, "t.db"), filepath.Join(dir, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	const token = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	reg := events.NewRegistry()
	s := api.New(cfg, token, db, reg)
	s.ConfigPath = cfgPath
	s.SecretsPath = filepath.Join(dir, "secr.json")
	s.SkillsRoots = []string{filepath.Join(dir, "skills")}
	s.PluginsDir = filepath.Join(dir, "plugins")
	repDir := filepath.Join(dir, "reports")
	_ = os.MkdirAll(filepath.Join(dir, "skills"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "plugins"), 0o755)
	s.ReportsDir = repDir
	s.Bench = bench.New(filepath.Join(repDir, "benchmarks"), []string{"127.0.0.1", "localhost", "::1"}, true, reg)
	s.Runner = runner.New(db, reg, repDir, []string{"127.0.0.1", "localhost", "::1"}, true, 2)
	return s, token, repDir
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

func TestGoalsPresetsAndCustomCRUD(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "GET", "/api/v1/goals", token, "")
	if rec.Code != 200 {
		t.Fatalf("goals = %d", rec.Code)
	}
	v := decode(t, rec)
	presets, _ := v["goals"].([]any)
	if len(presets) != 14 {
		t.Fatalf("want 14 presets, got %d", len(presets))
	}
	first, _ := presets[0].(map[string]any)
	if first["name"] != "recon_only" || first["risk"] != "safe" || first["compatible"] != true || first["source"] != "preset" {
		t.Fatalf("preset shape: %v", first)
	}
	// Custom create.
	rec = doReq(t, s.Handler(), "POST", "/api/v1/goals", token, `{"name":"my-goal","objective":"do it"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	created := decode(t, rec)
	id, _ := created["id"].(string)
	// Preset-name clash -> 409.
	rec = doReq(t, s.Handler(), "POST", "/api/v1/goals", token, `{"name":"Recon_Only","objective":"x"}`)
	if rec.Code != 409 {
		t.Fatalf("preset clash = %d, want 409", rec.Code)
	}
	// Custom-name clash -> 409.
	rec = doReq(t, s.Handler(), "POST", "/api/v1/goals", token, `{"name":"MY-GOAL","objective":"x"}`)
	if rec.Code != 409 {
		t.Fatalf("custom clash = %d, want 409", rec.Code)
	}
	// Get / patch / delete.
	rec = doReq(t, s.Handler(), "GET", "/api/v1/goals/"+id, token, "")
	if rec.Code != 200 {
		t.Fatalf("get = %d", rec.Code)
	}
	rec = doReq(t, s.Handler(), "PATCH", "/api/v1/goals/"+id, token, `{"objective":"do it better"}`)
	if rec.Code != 200 || decode(t, rec)["objective"] != "do it better" {
		t.Fatalf("patch = %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "DELETE", "/api/v1/goals/"+id, token, "")
	if rec.Code != 200 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/goals/"+id, token, ""); rec.Code != 404 {
		t.Fatalf("get deleted = %d, want 404", rec.Code)
	}
}

func TestSecretsRealStore(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "GET", "/api/v1/secrets", token, "")
	keys, _ := decode(t, rec)["keys"].(map[string]any)
	if keys["NVD_API_KEY"] != "missing" || keys["OLLAMA_API_KEY"] != "missing" {
		t.Fatalf("initial keys: %v", keys)
	}
	rec = doReq(t, s.Handler(), "PUT", "/api/v1/secrets", token, `{"secrets":{"NVD_API_KEY":"k123"}}`)
	if rec.Code != 200 {
		t.Fatalf("put = %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/secrets", token, "")
	if decode(t, rec)["keys"].(map[string]any)["NVD_API_KEY"] != "configured" {
		t.Fatalf("after put: %s", rec.Body.String())
	}
	// Values never returned.
	if strings.Contains(rec.Body.String(), "k123") {
		t.Fatal("secret value leaked in GET")
	}
	rec = doReq(t, s.Handler(), "PUT", "/api/v1/secrets", token, `{"secrets":{"EVIL_KEY":"x"}}`)
	if rec.Code != 400 {
		t.Fatalf("unknown key = %d, want 400", rec.Code)
	}
}

func TestSkillsRealDiscovery(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	skillMD := "---\nname: web-enum\ndescription: Web enumeration.\ntags: [web, recon]\n---\n# Web enum\n\n## Workflow\nDo it.\n"
	rec := doReq(t, s.Handler(), "POST", "/api/v1/skills", token,
		`{"name":"web-enum","markdown":`+jsonString(skillMD)+`}`)
	if rec.Code != 200 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/skills", token, "")
	list, _ := decode(t, rec)["skills"].([]any)
	if len(list) != 1 {
		t.Fatalf("list: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/skills/web-enum", token, "")
	detail := decode(t, rec)
	if detail["body"] == "" || len(detail["sections"].([]any)) != 1 {
		t.Fatalf("detail: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/skills/search?q=web", token, "")
	if len(decode(t, rec)["results"].([]any)) != 1 {
		t.Fatalf("search: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "DELETE", "/api/v1/skills/web-enum", token, "")
	if rec.Code != 200 {
		t.Fatalf("delete = %d", rec.Code)
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/skills/web-enum", token, ""); rec.Code != 404 {
		t.Fatalf("get deleted = %d", rec.Code)
	}
}

func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func TestPluginsRealDiscovery(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	plugDir := filepath.Join(s.PluginsDir, "demo")
	_ = os.MkdirAll(plugDir, 0o755)
	_ = os.WriteFile(filepath.Join(plugDir, "plugin.yaml"),
		[]byte("name: demo_scan\nversion: 0.1.0\ndescription: Demo.\ncapabilities: [mcp_tool]\nenabled: false\n"), 0o644)
	rec := doReq(t, s.Handler(), "GET", "/api/v1/plugins", token, "")
	found, _ := decode(t, rec)["plugins"].([]any)
	if len(found) != 1 || found[0].(map[string]any)["name"] != "demo_scan" {
		t.Fatalf("plugins: %s", rec.Body.String())
	}
}

func TestModelsPersist(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "POST", "/api/v1/models", token, `{"alias":"kimi","model":"kimi-k2.6:cloud"}`)
	if rec.Code != 200 {
		t.Fatalf("alias = %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/models/provider", token, `{"provider":"opencode_go"}`)
	if rec.Code != 200 || decode(t, rec)["provider"] != "opencode_go" {
		t.Fatalf("provider = %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/models", token, "")
	if decode(t, rec)["provider"] != "opencode_go" {
		t.Fatalf("persisted provider: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "DELETE", "/api/v1/models/glm", token, "")
	if rec.Code != 400 {
		t.Fatalf("delete default = %d, want 400", rec.Code)
	}
	rec = doReq(t, s.Handler(), "DELETE", "/api/v1/models/kimi", token, "")
	if rec.Code != 200 {
		t.Fatalf("delete alias = %d %s", rec.Code, rec.Body.String())
	}
}

func ollamaStub(models []string, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		fmt.Fprint(w, `{"models":[`)
		for i, m := range models {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"name":%q}`, m)
		}
		fmt.Fprint(w, `]}`)
	}))
}

func TestModelsLiveAndRefresh(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	srv := ollamaStub([]string{"glm-5.2:cloud", "glm-5.1:cloud"}, 200)
	defer srv.Close()
	s.Cfg.Ollama.Host = srv.URL
	rec := doReq(t, s.Handler(), "GET", "/api/v1/models/live", token, "")
	v := decode(t, rec)
	if rec.Code != 200 || v["source"] != "live" || len(v["models"].([]any)) != 2 {
		t.Fatalf("live: %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/models/refresh", token, "")
	v = decode(t, rec)
	if v["ok"] != true || v["persisted"] != true {
		t.Fatalf("refresh: %s", rec.Body.String())
	}
	updates, _ := v["updates"].(map[string]any)
	if len(updates) != 1 {
		t.Fatalf("updates: %v", updates)
	}
	// Non-ollama provider: live falls back to registry, refresh rejected.
	s.Cfg.Models.Provider = "opencode_go"
	rec = doReq(t, s.Handler(), "GET", "/api/v1/models/live", token, "")
	if decode(t, rec)["source"] != "registry" {
		t.Fatalf("non-ollama live: %s", rec.Body.String())
	}
	if rec := doReq(t, s.Handler(), "POST", "/api/v1/models/refresh", token, ""); rec.Code != 400 {
		t.Fatalf("non-ollama refresh = %d, want 400", rec.Code)
	}
	// Downstream ollama: 503 with registry fallback.
	s.Cfg.Models.Provider = "ollama"
	s.Cfg.Ollama.Host = "http://127.0.0.1:1"
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/models/live", token, ""); rec.Code != 503 {
		t.Fatalf("down ollama = %d, want 503", rec.Code)
	}
}

func TestProvidersHonest(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "GET", "/api/v1/providers", token, "")
	chatgpt, _ := decode(t, rec)["chatgpt"].(map[string]any)
	// Authenticated iff a candidate auth file exists (mirrors the backend:
	// file existence only, never contents). This box may or may not have one.
	wantAuth := false
	if home, herr := os.UserHomeDir(); herr == nil {
		if _, serr := os.Stat(home + "/.codex/auth.json"); serr == nil {
			wantAuth = true
		}
	}
	if chatgpt["authenticated"] != wantAuth {
		t.Fatalf("authenticated=%v, want %v (file-existence semantics): %v", chatgpt["authenticated"], wantAuth, chatgpt)
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/providers/chatgpt/proxy/stop", token, "")
	v := decode(t, rec)
	if v["ok"] != true || v["stopped"] != false {
		t.Fatalf("stop: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/providers/chatgpt/login", token, "")
	if rec.Code != 503 {
		t.Fatalf("login = %d, want honest 503", rec.Code)
	}
	if v := decode(t, rec); v["error"] == nil || !strings.Contains(rec.Body.String(), "proxy_runtime_missing") {
		t.Fatalf("login should carry proxy_runtime_missing, got %s", rec.Body.String())
	}
}

func TestHonestUnsupported(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	if rec := doReq(t, s.Handler(), "POST", "/api/v1/benchmarks/run", token, "{}"); rec.Code != 400 {
		t.Fatalf("benchmark run empty = %d, want 400 missing_suite", rec.Code)
	}
	if rec := doReq(t, s.Handler(), "POST", "/api/v1/benchmarks/run", token, `{"suite":"nope"}`); rec.Code != 404 {
		t.Fatalf("benchmark unknown suite = %d, want 404", rec.Code)
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/connections/xyz", token, ""); rec.Code != 404 {
		t.Fatalf("unknown connection = %d, want 404", rec.Code)
	}
}

func pollBench(t *testing.T, s *api.Server, token, id, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		rec := doReq(t, s.Handler(), "GET", "/api/v1/benchmarks/runs/"+id, token, "")
		if rec.Code != 200 {
			t.Fatalf("bench get: %d", rec.Code)
		}
		v := decode(t, rec)
		if v["status"] == want {
			return v
		}
		if v["status"] == "failed" || v["status"] == "error" {
			t.Fatalf("bench failed: %s", rec.Body.String())
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for bench %s: %s", want, rec.Body.String())
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Native smoke benchmark: real trials against loopback, oracle solved,
// baseline save + compare gate.
func TestBenchmarkSmokeEndToEnd(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "GET", "/api/v1/benchmarks", token, "")
	suites, _ := decode(t, rec)["suites"].([]any)
	if len(suites) != 1 {
		t.Fatalf("suites: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/benchmarks/suites/native-smoke/scenarios", token, "")
	if len(decode(t, rec)["scenarios"].([]any)) != 1 {
		t.Fatalf("scenarios: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/benchmarks/suites/native-smoke/readiness", token, "")
	if decode(t, rec)["ready"] != true {
		t.Fatalf("readiness: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/benchmarks/run", token, `{"suite":"native-smoke","trials":2}`)
	if rec.Code != 200 {
		t.Fatalf("bench run = %d %s", rec.Code, rec.Body.String())
	}
	id, _ := decode(t, rec)["run_id"].(string)
	v := pollBench(t, s, token, id, "completed")
	sum, _ := v["summary"].(map[string]any)
	if int(sum["solved"].(float64)) != 2 || sum["verified_success_rate"] != 1.0 {
		t.Fatalf("summary: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/benchmarks/baseline", token, `{"run_id":"`+id+`"}`)
	if rec.Code != 200 {
		t.Fatalf("baseline save = %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/benchmarks/compare?run_a="+id+"&run_b="+id, token, "")
	comp, _ := decode(t, rec)["comparison"].([]any)
	if len(comp) != 1 || comp[0].(map[string]any)["severity"] != "unchanged" {
		t.Fatalf("compare: %s", rec.Body.String())
	}
}

func pollState(t *testing.T, s *api.Server, token, id, want string) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for {
		rec := doReq(t, s.Handler(), "GET", "/api/v1/runs/"+id, token, "")
		if rec.Code != 200 {
			t.Fatalf("get run: %d", rec.Code)
		}
		if decode(t, rec)["state"] == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s: %s", want, rec.Body.String())
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// Full vertical slice over HTTP: create (yes) -> runner executes real recon
// against loopback -> artifacts on disk -> completion visible via API.
func TestRunExecutesReconEndToEnd(t *testing.T) {
	s, token, repDir := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "POST", "/api/v1/runs", token,
		`{"target":"127.0.0.1","mode":"recon","kind":"agent","yes":true}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	id, _ := decode(t, rec)["run_id"].(string)
	pollState(t, s, token, id, "completed")
	for _, f := range []string{"recon_assessment.json", "goal_suggestions.json", "run.json", "session_summary.md"} {
		if _, err := os.Stat(filepath.Join(repDir, id, f)); err != nil {
			t.Fatalf("missing artifact %s: %v", f, err)
		}
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+id+"/events?after=0", token, "")
	types := map[string]bool{}
	for _, e := range decode(t, rec)["events"].([]any) {
		types[e.(map[string]any)["type"].(string)] = true
	}
	if !types["run_created"] || !types["recon_completed"] || !types["run_completed"] {
		t.Fatalf("event trail: %s", rec.Body.String())
	}
}

// Decision gate: attack start_confirm requires the exact text; answering it
// queues the run and the runner completes it.
func TestDecisionGateAndConfirm(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "POST", "/api/v1/runs", token,
		`{"target":"127.0.0.1","mode":"attack","kind":"agent"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d", rec.Code)
	}
	v := decode(t, rec)
	id, _ := v["run_id"].(string)
	dec, _ := v["decision"].(map[string]any)
	decID, _ := dec["id"].(string)
	if v["state"] != "awaiting_confirmation" || decID == "" {
		t.Fatalf("create: %s", rec.Body.String())
	}
	// Wrong answer on attack mode: rejected.
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+id+"/decisions", token, "")
	if len(decode(t, rec)["decisions"].([]any)) != 1 {
		t.Fatalf("decisions: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/"+id+"/decisions/"+decID, token, `{"answer":"yes"}`)
	if rec.Code != 400 {
		t.Fatalf("weak confirm on attack = %d, want 400", rec.Code)
	}
	// Exact text: answered -> queued -> runner picks up the attack phase,
	// which runs real safe probes and records proposed findings.
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/"+id+"/decisions/"+decID, token, `{"answer":"ALLOW 127.0.0.1"}`)
	if rec.Code != 200 {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	pollState(t, s, token, id, "completed")
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+id+"/proposed", token, "")
	v = decode(t, rec)
	if _, ok := v["proposed"].([]any); !ok {
		t.Fatalf("proposed must be a list: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+id+"/audit", token, "")
	if decode(t, rec)["chain_valid"] != true {
		t.Fatalf("audit chain: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/"+id+"/decisions/"+decID, token, `{"answer":"ALLOW 127.0.0.1"}`)
	if rec.Code != 409 {
		t.Fatalf("re-answer = %d, want 409", rec.Code)
	}
}

// Invalid targets are rejected at create with 400, never queued.
func TestInvalidTargetRejected(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "POST", "/api/v1/runs", token, `{"target":"not a host!","mode":"recon"}`)
	if rec.Code != 400 {
		t.Fatalf("bad target = %d, want 400", rec.Code)
	}
}

// Resume creates a re-confirmation run linked to the source; out-of-allowlist
// resume targets fail closed in the worker.
func TestResumeFlow(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "POST", "/api/v1/runs", token,
		`{"target":"127.0.0.1","mode":"recon","kind":"agent","yes":true}`)
	id, _ := decode(t, rec)["run_id"].(string)
	pollState(t, s, token, id, "completed")
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/"+id+"/resume", token, "")
	if rec.Code != 200 {
		t.Fatalf("resume = %d %s", rec.Code, rec.Body.String())
	}
	v := decode(t, rec)
	newID, _ := v["run_id"].(string)
	if v["resumed_from"] != id || newID == id {
		t.Fatalf("resume: %s", rec.Body.String())
	}
	dec, _ := v["decision"].(map[string]any)
	decID, _ := dec["id"].(string)
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/"+newID+"/decisions/"+decID, token, `{"answer":"y"}`)
	if rec.Code != 200 {
		t.Fatalf("resume confirm = %d %s", rec.Code, rec.Body.String())
	}
	pollState(t, s, token, newID, "completed")
}

// Manual tool calls: unknown tool 404, non-running run 409, out-of-scope
// target 403 with audit row, in-scope target executes for real.
func TestManualToolCalls(t *testing.T) {
	s, token, repDir := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "GET", "/api/v1/runs/nonexistent/tools", token, "")
	_ = rec
	// Seed a run row stuck in running state (no worker) for determinism.
	db := s.DB
	req := `{"target":"127.0.0.1","mode":"recon","kind":"agent","yes":true}`
	if err := db.CreateRun("run-manual", "running", "127.0.0.1", "recon", "", req); err != nil {
		t.Fatal(err)
	}
	_ = repDir
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/run-manual/tools", token, "")
	if len(decode(t, rec)["tools"].([]any)) < 91 {
		t.Fatalf("tools: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/run-manual/tools/nope/calls", token, `{"arguments":{"target":"127.0.0.1"}}`)
	if rec.Code != 404 {
		t.Fatalf("unknown tool = %d, want 404", rec.Code)
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/run-manual/tools/tcp_scan/calls", token, `{"arguments":{"target":"10.9.9.9","ports":"1"}}`)
	if rec.Code != 403 {
		t.Fatalf("out-of-scope = %d, want 403", rec.Code)
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/run-manual/tools/tcp_scan/calls", token, `{"arguments":{"target":"127.0.0.1","ports":"1"}}`)
	if rec.Code != 200 {
		t.Fatalf("call = %d %s", rec.Code, rec.Body.String())
	}
	if decode(t, rec)["tool"] != "tcp_scan" {
		t.Fatalf("result: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/run-manual/audit", token, "")
	v := decode(t, rec)
	if v["chain_valid"] != true || len(v["records"].([]any)) != 2 {
		t.Fatalf("audit rows (blocked+completed): %s", rec.Body.String())
	}
	// Completed run: manual calls are 409 no_session.
	_ = db.SetRunState("run-manual", "completed")
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/run-manual/tools/tcp_scan/calls", token, `{"arguments":{"target":"127.0.0.1"}}`)
	if rec.Code != 409 {
		t.Fatalf("post-run call = %d, want 409", rec.Code)
	}
}

// HITL finding decisions persist to proposed.json and emit events.
func TestHitlDecide(t *testing.T) {
	s, token, repDir := testServerWithFiles(t)
	req := `{"target":"127.0.0.1","mode":"recon","kind":"agent","yes":true}`
	if err := s.DB.CreateRun("run-hitl", "completed", "127.0.0.1", "recon", "", req); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(repDir, "run-hitl")
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "proposed.json"),
		[]byte(`[{"id":"finding-web-80","service":"http","port":80,"summary":"x","evidence":"e","status":"proposed"}]`), 0o644)
	rec := doReq(t, s.Handler(), "POST", "/api/v1/runs/run-hitl/decide", token, `{"finding_id":"finding-web-80","decision":"confirm","note":"verified"}`)
	if rec.Code != 200 {
		t.Fatalf("decide = %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/run-hitl/proposed", token, "")
	found := decode(t, rec)["proposed"].([]any)
	if len(found) != 1 || found[0].(map[string]any)["status"] != "confirmed" {
		t.Fatalf("proposed after decide: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/run-hitl/decide", token, `{"finding_id":"nope","decision":"confirm"}`)
	if rec.Code != 404 {
		t.Fatalf("unknown finding = %d, want 404", rec.Code)
	}
}
