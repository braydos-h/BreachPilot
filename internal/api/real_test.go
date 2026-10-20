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

	"github.com/braydos-h/BreachPilot/internal/api"
	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/store"
)

const testCfgYAML = "api:\n  host: 127.0.0.1\n  port: 8765\nmodels:\n  provider: ollama\n  default_alias: glm\n  registry:\n    glm: glm-5.0:cloud\nsandbox:\n  enabled: true\n"

func testServerWithFiles(t *testing.T) (*api.Server, string) {
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
	s := api.New(cfg, token, db, events.NewRegistry())
	s.ConfigPath = cfgPath
	s.SecretsPath = filepath.Join(dir, "secr.json")
	s.SkillsRoots = []string{filepath.Join(dir, "skills")}
	s.PluginsDir = filepath.Join(dir, "plugins")
	_ = os.MkdirAll(filepath.Join(dir, "skills"), 0o755)
	_ = os.MkdirAll(filepath.Join(dir, "plugins"), 0o755)
	return s, token
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
	s, token := testServerWithFiles(t)
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
	s, token := testServerWithFiles(t)
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
	s, token := testServerWithFiles(t)
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
	s, token := testServerWithFiles(t)
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
	s, token := testServerWithFiles(t)
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
	s, token := testServerWithFiles(t)
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
	s, token := testServerWithFiles(t)
	rec := doReq(t, s.Handler(), "GET", "/api/v1/providers", token, "")
	chatgpt, _ := decode(t, rec)["chatgpt"].(map[string]any)
	if chatgpt["authenticated"] != false {
		t.Fatalf("no auth file must read false: %v", chatgpt)
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/providers/chatgpt/proxy/stop", token, "")
	v := decode(t, rec)
	if v["ok"] != true || v["stopped"] != false {
		t.Fatalf("stop: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/providers/chatgpt/login", token, "")
	if rec.Code != 501 {
		t.Fatalf("login = %d, want explicit 501", rec.Code)
	}
}

func TestHonestUnsupported(t *testing.T) {
	s, token := testServerWithFiles(t)
	if rec := doReq(t, s.Handler(), "POST", "/api/v1/benchmarks/run", token, "{}"); rec.Code != 501 {
		t.Fatalf("benchmark run = %d, want 501", rec.Code)
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/connections/xyz", token, ""); rec.Code != 404 {
		t.Fatalf("unknown connection = %d, want 404", rec.Code)
	}
}
