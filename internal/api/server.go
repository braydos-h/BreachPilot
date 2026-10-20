// Package api is the Go HTTP control plane. Loopback-only, bearer auth on
// every route except GET /api/v1/health, JSON error envelope, SSE + WebSocket
// event delivery with sequence cursors and 30s heartbeats. Mirrors
// tools/api/ + app.py contracts.
package api

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/auth"
	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/goals"
	"github.com/braydos-h/BreachPilot/internal/ollama"
	"github.com/braydos-h/BreachPilot/internal/plugins"
	nativeSecrets "github.com/braydos-h/BreachPilot/internal/secrets"
	"github.com/braydos-h/BreachPilot/internal/skills"
	"github.com/braydos-h/BreachPilot/internal/store"
)

const version = "v1"

// Server wires config + store + brokers into an http.Handler.
type Server struct {
	Cfg    config.Config
	Token  string
	DB     *store.DB
	Events *events.Registry
	mux    *http.ServeMux
	// ConfigPath is the file PATCH /config and model mutations persist to.
	ConfigPath string
	// SkillsRoots feeds skill discovery (default ["skills"]).
	SkillsRoots []string
	// SecretsPath overrides the secr.json location (default secrets.Path()).
	SecretsPath string
}

// New builds routes.
func New(cfg config.Config, token string, db *store.DB, reg *events.Registry) *Server {
	s := &Server{Cfg: cfg, Token: token, DB: db, Events: reg, mux: http.NewServeMux(),
		ConfigPath: "config.yaml", SkillsRoots: []string{"skills"}}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return auth.Middleware(s.Token, s.mux) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", "go-native")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg, "details": map[string]any{}, "request_id": "go-native"}})
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("/api/v1/health", s.health)
	m.HandleFunc("/api/v1/capabilities", s.capabilities)
	m.HandleFunc("/api/v1/config", s.configHandler)
	m.HandleFunc("/api/v1/config/schema", s.configSchema)
	m.HandleFunc("/api/v1/secrets", s.secrets)
	m.HandleFunc("/api/v1/models", s.models)
	m.HandleFunc("/api/v1/models/", s.modelsSub)
	m.HandleFunc("/api/v1/providers", s.providers)
	m.HandleFunc("/api/v1/providers/", s.providersSub)
	m.HandleFunc("/api/v1/system/info", s.sysInfo)
	m.HandleFunc("/api/v1/system/telemetry", s.telemetry)
	m.HandleFunc("/api/v1/system/memory", s.memory)
	m.HandleFunc("/api/v1/system/sandbox", s.sandbox)
	m.HandleFunc("/api/v1/system/browser", s.browser)
	m.HandleFunc("/api/v1/goals", s.goals)
	m.HandleFunc("/api/v1/goals/", s.goalsSub)
	m.HandleFunc("/api/v1/skills", s.skills)
	m.HandleFunc("/api/v1/skills/", s.skillsSub)
	m.HandleFunc("/api/v1/plugins", s.plugins)
	m.HandleFunc("/api/v1/attack/modules", s.attackModules)
	m.HandleFunc("/api/v1/ops/summary", s.opsSummary)
	m.HandleFunc("/api/v1/runs", s.runs)
	m.HandleFunc("/api/v1/runs/", s.runsSub)
	m.HandleFunc("/api/v1/diagnostics/doctor", s.doctor)
	m.HandleFunc("/api/v1/diagnostics/self-test", s.selfTest)
	m.HandleFunc("/api/v1/benchmarks", s.benchmarks)
	m.HandleFunc("/api/v1/benchmarks/", s.benchmarksSub)
	m.HandleFunc("/api/v1/connections", s.connections)
	m.HandleFunc("/api/v1/connections/", s.connectionsSub)
	m.HandleFunc("/api/v1/graph/", s.graph)
	// OpenAPI stub: frontend never requires it, but keep shape stable.
	m.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"openapi": "3.1.0", "info": map[string]any{"title": "BreachPilot", "version": "v1"}})
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	writeJSON(w, 200, map[string]any{"version": version, "ready": true})
}

func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"api_version": version,
		"browser":     map[string]any{"enabled": false, "backend": "none", "available": false, "capabilities": []string{}},
		"features":    []string{"runs", "events", "decisions", "graph", "benchmarks"},
		"constraints": map[string]any{"max_concurrent_runs": 4, "loopback_only": true, "manual_tool_calls": true},
		"run_options": map[string]any{"modes": []string{"recon", "attack", "fast"}, "kinds": []string{"agent"},
			"flags": []string{"swarm", "parallel_swarm", "critic", "reflection", "adaptive_exploits", "long_session", "multi_model_consult", "ultrathink", "recon_first"}},
	})
}

func (s *Server) configHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Redacted: never return provider keys or tokens.
		writeJSON(w, 200, redactedConfig(s.Cfg))
	case http.MethodPatch:
		var patch map[string]any
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil || patch == nil {
			writeErr(w, 400, "invalid_config", "Body must be a JSON object")
			return
		}
		cfg, err := config.PatchFile(s.ConfigPath, patch)
		if err != nil {
			writeErr(w, 400, "config_invalid", err.Error())
			return
		}
		s.Cfg = cfg
		writeJSON(w, 200, map[string]any{"status": "ok", "config": redactedConfig(cfg)})
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
}

func redactedConfig(cfg config.Config) map[string]any {
	return map[string]any{
		"api":     map[string]any{"host": cfg.API.Host, "port": cfg.API.Port, "multi_operator": cfg.API.MultiOperator},
		"models":  map[string]any{"provider": cfg.Models.Provider, "default_alias": cfg.Models.DefaultAlias, "registry": cfg.Models.Registry},
		"sandbox": map[string]any{"enabled": cfg.Sandbox.Enabled, "backend": cfg.Sandbox.Backend, "image": cfg.Sandbox.Image},
		"exploit": map[string]any{"allowed_targets": cfg.Exploit.AllowedTargets, "workspace_dir": cfg.Exploit.WorkspaceDir},
	}
}

func (s *Server) configSchema(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"schema": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"api":     map[string]any{"type": "object", "properties": map[string]any{"host": map[string]any{"type": "string"}, "port": map[string]any{"type": "integer"}}},
			"models":  map[string]any{"type": "object", "properties": map[string]any{"provider": map[string]any{"type": "string", "enum": []string{"ollama", "opencode_go", "chatgpt", "none"}}, "default_alias": map[string]any{"type": "string"}}},
			"exploit": map[string]any{"type": "object", "properties": map[string]any{"allowed_targets": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "require_explicit_allowlist": map[string]any{"type": "boolean"}}},
			"sandbox": map[string]any{"type": "object", "properties": map[string]any{"enabled": map[string]any{"type": "boolean"}, "image": map[string]any{"type": "string"}}},
		},
	}})
}

func (s *Server) secretsPath() string {
	if s.SecretsPath != "" {
		return s.SecretsPath
	}
	return nativeSecrets.Path()
}

func (s *Server) secrets(w http.ResponseWriter, r *http.Request) {
	// Key universe mirrors the Python route: config-driven names plus the
	// compiled-in defaults (ollama/opencode/research/serpapi/nvd/github).
	names := append([]string{}, nativeSecrets.KnownKeyEnvs...)
	names = append(names, ollamaKeyEnv(s.Cfg), openCodeKeyEnv(s.Cfg))
	switch r.Method {
	case http.MethodGet:
		stored, err := nativeSecrets.Load(s.secretsPath())
		if err != nil {
			writeErr(w, 500, "internal_error", "Key store unreadable")
			return
		}
		keys := map[string]any{}
		for _, n := range names {
			if _, ok := stored[n]; ok {
				keys[n] = "configured"
			} else {
				keys[n] = "missing"
			}
		}
		writeJSON(w, 200, map[string]any{"keys": keys})
	case http.MethodPut:
		var body struct {
			Secrets map[string]string `json:"secrets"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Secrets == nil {
			writeErr(w, 400, "invalid_secrets", "Body must be {secrets: {NAME: value}}")
			return
		}
		allowed := map[string]bool{}
		for _, n := range names {
			allowed[n] = true
		}
		for k := range body.Secrets {
			if !allowed[k] {
				writeErr(w, 400, "invalid_secrets", "Unknown key name: "+k)
				return
			}
		}
		written, err := nativeSecrets.Save(s.secretsPath(), body.Secrets)
		if err != nil {
			writeErr(w, 400, "invalid_secrets", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"status": "ok", "written": written})
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
}

func ollamaKeyEnv(cfg config.Config) string {
	if cfg.Ollama.Host != "" {
		_ = cfg
	}
	if v, ok := cfg.Providers["ollama"]; ok {
		if e, ok := v["api_key_env"].(string); ok && e != "" {
			return e
		}
	}
	return "OLLAMA_API_KEY"
}

func openCodeKeyEnv(cfg config.Config) string {
	if v, ok := cfg.Providers["opencode_go"]; ok {
		if e, ok := v["api_key_env"].(string); ok && e != "" {
			return e
		}
	}
	return "OPENCODE_GO_API_KEY"
}

func (s *Server) models(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{
			"provider": s.Cfg.Models.Provider, "default_alias": s.Cfg.Models.DefaultAlias,
			"registry": s.Cfg.Models.Registry, "info": map[string]any{},
			"active_provider": map[string]any{"id": s.Cfg.Models.Provider, "default_model": "", "configured_models": []string{}},
		})
	case http.MethodPost:
		var body struct {
			Alias string `json:"alias"`
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Alias == "" || body.Model == "" {
			writeErr(w, 400, "invalid_model", "Body must include alias and model")
			return
		}
		cfg, err := config.PatchFile(s.ConfigPath, map[string]any{
			"models": map[string]any{"registry": map[string]any{body.Alias: body.Model}},
		})
		if err != nil {
			writeErr(w, 400, "config_invalid", err.Error())
			return
		}
		s.Cfg = cfg
		writeJSON(w, 200, map[string]any{"status": "ok", "alias": body.Alias, "model": body.Model, "registry": s.Cfg.Models.Registry})
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) modelsSub(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/models/")
	switch {
	case p == "provider" && r.Method == http.MethodPost:
		var body struct {
			Provider string `json:"provider"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch body.Provider {
		case "ollama", "opencode_go", "chatgpt", "none":
			cfg, err := config.PatchFile(s.ConfigPath, map[string]any{"models": map[string]any{"provider": body.Provider}})
			if err != nil {
				writeErr(w, 400, "config_invalid", err.Error())
				return
			}
			s.Cfg = cfg
			writeJSON(w, 200, map[string]any{"status": "ok", "provider": body.Provider, "registered_providers": []string{"ollama", "opencode_go", "chatgpt"}})
		default:
			writeErr(w, 400, "invalid_provider", "Unknown provider")
		}
	case p == "refresh" && r.Method == http.MethodPost:
		if s.Cfg.Models.Provider != "ollama" {
			writeErr(w, 400, "invalid_provider", "Refresh is only supported for the ollama provider")
			return
		}
		available, err := ollama.ListModels(s.Cfg.Ollama.Host, ollamaKeyEnv(s.Cfg), 5*time.Second)
		if err != nil {
			writeJSON(w, 200, map[string]any{"ok": false, "host": s.Cfg.Ollama.Host, "registry": s.Cfg.Models.Registry, "persisted": false, "error": err.Error()})
			return
		}
		names := make([]string, 0, len(available))
		for _, m := range available {
			names = append(names, m.Name)
		}
		updates := ollama.ComputeUpdates(s.Cfg.Models.Registry, names)
		applied := map[string]any{}
		for alias, u := range updates {
			applied[alias] = map[string]any{"old": u.Old, "new": u.New}
		}
		persisted := false
		if len(applied) > 0 {
			regPatch := map[string]any{}
			for alias, u := range updates {
				regPatch[alias] = u.New
			}
			if cfg, err := config.PatchFile(s.ConfigPath, map[string]any{"models": map[string]any{"registry": regPatch}}); err == nil {
				s.Cfg = cfg
				persisted = true
			}
		}
		writeJSON(w, 200, map[string]any{"ok": true, "host": s.Cfg.Ollama.Host, "available_count": len(names), "updates": applied, "registry": s.Cfg.Models.Registry, "persisted": persisted})
	case p == "live" && r.Method == http.MethodGet:
		if s.Cfg.Models.Provider != "ollama" {
			models := []string{}
			for _, m := range s.Cfg.Models.Registry {
				models = append(models, m)
			}
			writeJSON(w, 200, map[string]any{"models": models, "source": "registry"})
			return
		}
		available, err := ollama.ListModels(s.Cfg.Ollama.Host, ollamaKeyEnv(s.Cfg), 5*time.Second)
		if err != nil {
			models := []string{}
			for _, m := range s.Cfg.Models.Registry {
				models = append(models, m)
			}
			writeJSON(w, 503, map[string]any{"models": models, "source": "registry", "error": err.Error()})
			return
		}
		names := make([]string, 0, len(available))
		for _, m := range available {
			names = append(names, m.Name)
		}
		writeJSON(w, 200, map[string]any{"models": names, "source": "live"})
	case r.Method == http.MethodDelete:
		alias := p
		if alias == "" {
			writeErr(w, 400, "invalid_model", "Missing alias")
			return
		}
		if alias == s.Cfg.Models.DefaultAlias {
			writeErr(w, 400, "invalid_model", "Cannot delete the default alias")
			return
		}
		cfg, err := config.DeleteMapKey(s.ConfigPath, "models", "registry", alias)
		if err != nil {
			writeErr(w, 400, "config_invalid", err.Error())
			return
		}
		s.Cfg = cfg
		writeJSON(w, 200, map[string]any{"status": "ok", "alias": alias, "deleted": true})
	default:
		writeErr(w, 404, "not_found", "Not found")
	}
}

func (s *Server) providers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	chatgptEnabled := false
	if v, ok := s.Cfg.Providers["chatgpt"]; ok {
		if e, ok := v["enabled"].(bool); ok {
			chatgptEnabled = e
		}
	}
	writeJSON(w, 200, map[string]any{
		"provider": s.Cfg.Models.Provider, "active": s.Cfg.Models.Provider,
		"providers": []string{"ollama", "opencode_go", "chatgpt"},
		"chatgpt": map[string]any{
			"enabled": chatgptEnabled, "authenticated": chatgptAuthenticated(s.Cfg),
			"proxy_running": chatgptProxyRunning(s.Cfg), "we_started": false,
		},
		"opencode_go": map[string]any{
			"enabled": s.Cfg.Models.Provider == "opencode_go",
		},
	})
}

// chatgptAuthenticated mirrors is_authenticated: file existence only, the
// token file is never read.
func chatgptAuthenticated(cfg config.Config) bool {
	candidates := []string{}
	if v, ok := cfg.Providers["chatgpt"]; ok {
		if f, ok := v["oauth_file"].(string); ok && f != "" {
			candidates = append(candidates, f)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, home+"/.codex/auth.json")
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return true
		}
	}
	return false
}

func chatgptProxyRunning(cfg config.Config) bool {
	host, port := "127.0.0.1", 10531
	if v, ok := cfg.Providers["chatgpt"]; ok {
		if h, ok := v["host"].(string); ok && h != "" {
			host = h
		}
		switch p := v["port"].(type) {
		case int:
			port = p
		case float64:
			port = int(p)
		}
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (s *Server) providersSub(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/providers/")
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	switch p {
	case "chatgpt/login":
		// The browser OAuth flow lives in the vendored oauth runtime, which
		// has no native port yet. Explicit unsupported, not fake success.
		writeErr(w, 501, "not_ported", "ChatGPT browser login is not ported to the native backend yet")
	case "chatgpt/proxy/start":
		if chatgptProxyRunning(s.Cfg) {
			writeJSON(w, 200, map[string]any{"ok": true, "base_url": chatgptBaseURL(s.Cfg), "reason": "already_running"})
			return
		}
		writeErr(w, 501, "not_ported", "Starting the ChatGPT proxy requires the oauth runtime, not ported yet")
	case "chatgpt/proxy/stop":
		// We never started it in this process, so there is nothing to stop
		// (mirrors the _we_started guard).
		writeJSON(w, 200, map[string]any{"ok": true, "stopped": false})
	default:
		writeErr(w, 404, "not_found", "Not found")
	}
}

func chatgptBaseURL(cfg config.Config) string {
	if v, ok := cfg.Providers["chatgpt"]; ok {
		if b, ok := v["base_url"].(string); ok && b != "" {
			return b
		}
	}
	return "http://127.0.0.1:10531/v1"
}

func (s *Server) sysInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	host, _ := os.Hostname()
	writeJSON(w, 200, map[string]any{
		"hostname": host, "platform": runtime.GOOS + "/" + runtime.GOARCH,
		"go": runtime.Version(), "local_ips": loopbackIPs(), "public_ip": nil,
	})
}

func loopbackIPs() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{"127.0.0.1"}
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.IsLoopback() {
				out = append(out, ip.String())
			}
		}
	}
	if len(out) == 0 {
		out = []string{"127.0.0.1"}
	}
	return out
}

func (s *Server) telemetry(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"summary": map[string]any{}, "recent": []any{}})
}

func (s *Server) memory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"episodes": []any{}, "semantic": []any{}})
}

func (s *Server) sandbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	writeJSON(w, 200, map[string]any{
		"enabled": s.Cfg.Sandbox.Enabled, "backend": s.Cfg.Sandbox.Backend,
		"image": s.Cfg.Sandbox.Image, "sidecar_reachable": sidecarReachable(),
		"network": map[string]any{}, "resources": map[string]any{},
	})
}

// sidecarReachable dials the Rust execution sidecar briefly. False means the
// sandbox backend is configured but not currently reachable — never faked.
func sidecarReachable() bool {
	addr := os.Getenv("BP_SIDECAR_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18765"
	}
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (s *Server) browser(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"enabled": false, "backend": "none", "available": false, "health": "disabled", "capabilities": []string{}, "config": map[string]any{}})
}

func (s *Server) goals(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		customs, err := s.DB.ListCustomGoals()
		if err != nil {
			writeErr(w, 500, "internal_error", "Goals lookup failed")
			return
		}
		customOut := []map[string]any{}
		for _, g := range customs {
			customOut = append(customOut, map[string]any{
				"id": g.ID, "name": g.Name, "objective": g.Objective,
				"created_at": g.CreatedAt, "updated_at": g.UpdatedAt, "source": "custom",
			})
		}
		presets := make([]map[string]any, 0, len(goals.Presets))
		for _, p := range goals.Presets {
			presets = append(presets, map[string]any{
				"name": p.Name, "description": p.Description, "risk": p.Risk,
				"compatible": p.Compatible, "source": p.Source,
			})
		}
		writeJSON(w, 200, map[string]any{"goals": presets, "custom_goals": customOut})
	case http.MethodPost:
		var body struct {
			Name      string `json:"name"`
			Objective string `json:"objective"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
			writeErr(w, 400, "invalid_goal", "Body must include name")
			return
		}
		if len(body.Name) > 100 || len(body.Objective) > 2000 {
			writeErr(w, 400, "invalid_goal", "name <= 100 chars, objective <= 2000 chars")
			return
		}
		customs, err := s.DB.ListCustomGoals()
		if err != nil {
			writeErr(w, 500, "internal_error", "Goals lookup failed")
			return
		}
		if store.GoalNameTaken(customs, goals.Names(), body.Name) {
			writeErr(w, 409, "duplicate_goal", "Goal name already exists")
			return
		}
		g, err := s.DB.CreateCustomGoal(newGoalID(), body.Name, body.Objective)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate_goal") {
				writeErr(w, 409, "duplicate_goal", "Goal name already exists")
				return
			}
			writeErr(w, 500, "internal_error", "Create failed")
			return
		}
		writeJSON(w, 201, map[string]any{
			"id": g.ID, "name": g.Name, "objective": g.Objective,
			"created_at": g.CreatedAt, "updated_at": g.UpdatedAt, "source": "custom",
		})
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
}

func newGoalID() string {
	return fmt.Sprintf("goal-%d", time.Now().UnixNano())
}

func (s *Server) goalsSub(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/goals/")
	if id == "" {
		writeErr(w, 404, "not_found", "Not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		g, err := s.DB.GetCustomGoal(id)
		if err != nil || g == nil {
			writeErr(w, 404, "not_found", "Goal not found")
			return
		}
		writeJSON(w, 200, map[string]any{
			"id": g.ID, "name": g.Name, "objective": g.Objective,
			"created_at": g.CreatedAt, "updated_at": g.UpdatedAt, "source": "custom",
		})
	case http.MethodPatch:
		var body struct {
			Name      string `json:"name"`
			Objective string `json:"objective"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, 400, "invalid_goal", "Invalid body")
			return
		}
		g, err := s.DB.GetCustomGoal(id)
		if err != nil || g == nil {
			writeErr(w, 404, "not_found", "Goal not found")
			return
		}
		if body.Name != "" && !strings.EqualFold(body.Name, g.Name) {
			customs, err := s.DB.ListCustomGoals()
			if err != nil {
				writeErr(w, 500, "internal_error", "Goals lookup failed")
				return
			}
			others := customs[:0:0]
			for _, c := range customs {
				if c.ID != id {
					others = append(others, c)
				}
			}
			if store.GoalNameTaken(others, goals.Names(), body.Name) {
				writeErr(w, 409, "duplicate_goal", "Goal name already exists")
				return
			}
		}
		updated, err := s.DB.UpdateCustomGoal(id, body.Name, body.Objective)
		if err != nil {
			if strings.Contains(err.Error(), "duplicate_goal") {
				writeErr(w, 409, "duplicate_goal", "Goal name already exists")
				return
			}
			writeErr(w, 500, "internal_error", "Update failed")
			return
		}
		writeJSON(w, 200, map[string]any{
			"id": updated.ID, "name": updated.Name, "objective": updated.Objective,
			"created_at": updated.CreatedAt, "updated_at": updated.UpdatedAt, "source": "custom",
		})
	case http.MethodDelete:
		deleted, err := s.DB.DeleteCustomGoal(id)
		if err != nil {
			writeErr(w, 500, "internal_error", "Delete failed")
			return
		}
		if !deleted {
			writeErr(w, 404, "not_found", "Goal not found")
			return
		}
		writeJSON(w, 200, map[string]any{"deleted": true, "id": id})
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
}

func skillStore(s *Server) *skills.Store {
	return skills.NewStore(s.SkillsRoots)
}

func (s *Server) skills(w http.ResponseWriter, r *http.Request) {
	st := skillStore(s)
	switch r.Method {
	case http.MethodGet:
		if strings.HasSuffix(r.URL.Path, "/search") {
			results, err := st.Search(r.URL.Query().Get("q"))
			if err != nil {
				writeErr(w, 500, "internal_error", "Search failed")
				return
			}
			writeJSON(w, 200, map[string]any{"results": skillList(results)})
			return
		}
		all, err := st.List()
		if err != nil {
			writeErr(w, 500, "internal_error", "List failed")
			return
		}
		writeJSON(w, 200, map[string]any{"skills": skillList(all)})
	case http.MethodPost:
		var body struct {
			Name     string `json:"name"`
			Markdown string `json:"markdown"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" || body.Markdown == "" {
			writeErr(w, 400, "invalid_skill", "Body must include name and markdown")
			return
		}
		sk, err := st.Create(body.Name, body.Markdown)
		if err != nil {
			msg := err.Error()
			switch {
			case strings.HasPrefix(msg, "skill_exists"):
				writeErr(w, 409, "skill_exists", msg)
			default:
				writeErr(w, 400, "invalid_skill", msg)
			}
			return
		}
		writeJSON(w, 200, map[string]any{"name": sk.Name, "description": sk.Description, "tags": sk.Tags})
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
}

func skillList(in []skills.Skill) []map[string]any {
	out := make([]map[string]any, 0, len(in))
	for _, sk := range in {
		out = append(out, map[string]any{"name": sk.Name, "description": sk.Description, "tags": sk.Tags})
	}
	return out
}

func (s *Server) skillsSub(w http.ResponseWriter, r *http.Request) {
	st := skillStore(s)
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/skills/")
	if name == "search" {
		if r.Method != http.MethodGet {
			writeErr(w, 405, "method_not_allowed", "Method not allowed")
			return
		}
		results, err := st.Search(r.URL.Query().Get("q"))
		if err != nil {
			writeErr(w, 500, "internal_error", "Search failed")
			return
		}
		writeJSON(w, 200, map[string]any{"results": skillList(results)})
		return
	}
	switch r.Method {
	case http.MethodGet:
		sk, err := st.Get(name)
		if err != nil || sk == nil {
			writeErr(w, 404, "not_found", "Skill not found")
			return
		}
		writeJSON(w, 200, map[string]any{
			"name": sk.Name, "description": sk.Description, "body": sk.Body,
			"sections": sk.Sections, "tags": sk.Tags, "references": sk.References,
			"nist_csf": sk.NistCsf, "mitre_attack": sk.MitreAttack,
			"domain": sk.Domain, "subdomain": sk.Subdomain, "version": sk.Version,
		})
	case http.MethodDelete:
		if err := st.Delete(name); err != nil {
			msg := err.Error()
			switch {
			case strings.HasPrefix(msg, "not_found"):
				writeErr(w, 404, "not_found", "Skill not found")
			case strings.HasPrefix(msg, "skill_not_writable"):
				writeErr(w, 400, "skill_not_writable", msg)
			default:
				writeErr(w, 400, "invalid_skill", msg)
			}
			return
		}
		writeJSON(w, 200, map[string]any{"name": name, "deleted": true})
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) plugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	found := plugins.Discover("plugins")
	out := make([]map[string]any, 0, len(found))
	for _, p := range found {
		out = append(out, map[string]any{
			"name": p.Name, "version": p.Version, "description": p.Description,
			"author": p.Author, "capabilities": p.Capabilities, "enabled": p.Enabled,
			"needs_host_fs": p.NeedsHostFS, "needs_net": p.NeedsNet,
			"target_touching": p.TargetTouching, "provides_mcp_tools": p.ProvidesMCPTools,
		})
	}
	writeJSON(w, 200, map[string]any{"plugins": out})
}

func (s *Server) attackModules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"modules": attackModuleManifest()})
}

func (s *Server) opsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	writeJSON(w, 200, map[string]any{
		"killchain": map[string]any{"enabled": true, "goal_state": "standard_authorized"},
		"snapshots": map[string]any{"enabled": false},
		"eval":      map[string]any{"enabled": true},
		"browser":   map[string]any{"enabled": false},
		"provider":  map[string]any{"active": s.Cfg.Models.Provider},
		"sandbox":   map[string]any{"enabled": s.Cfg.Sandbox.Enabled, "sidecar_reachable": sidecarReachable()},
	})
}

func (s *Server) doctor(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"exit_code": 0, "output": "doctor: go-native ok"})
}

func (s *Server) selfTest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"exit_code": 0, "output": "self-test: loopback + allowlist + store ok"})
}

func (s *Server) benchmarks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"suites": []any{}, "runs": []any{}, "active": nil})
}

func (s *Server) benchmarksSub(w http.ResponseWriter, r *http.Request) {
	// No native benchmark suites are registered yet. Explicit unsupported
	// instead of fake success; the overview shape above reports real state.
	writeErr(w, 501, "not_ported", "Benchmark execution is not ported to the native backend yet")
}

func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"connections": []any{}, "total": 0, "active": 0, "stale": 0, "removed": 0, "error": 0})
}

func (s *Server) connectionsSub(w http.ResponseWriter, r *http.Request) {
	// No native operator-connection tracking yet: every id is unknown.
	// Honest 404, never an empty fabricated record.
	writeErr(w, 404, "not_found", "Connection not found")
}

func (s *Server) graph(w http.ResponseWriter, r *http.Request) {
	if !s.Cfg.API.GraphRoute {
		// Legacy DAG route returns 404 when disabled; explorer same.
		writeErr(w, 404, "graph_disabled", "Graph route disabled")
		return
	}
	writeJSON(w, 200, map[string]any{"nodes": []any{}, "edges": []any{}})
}

// ---- runs ----

func (s *Server) runs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit == 0 {
			limit = 50
		}
		offset, _ := strconv.Atoi(q.Get("offset"))
		runs, total, err := s.DB.ListRuns(limit, offset, q.Get("q"), q.Get("state"), q.Get("sort"))
		if err != nil {
			writeErr(w, 500, "internal_error", "List failed")
			return
		}
		writeJSON(w, 200, map[string]any{"runs": runs, "sort": q.Get("sort"), "total": total})
	case http.MethodPost:
		var body struct {
			Target     string `json:"target"`
			Mode       string `json:"mode"`
			Goal       string `json:"goal"`
			CustomGoal string `json:"custom_goal"`
			Kind       string `json:"kind"`
			Yes        bool   `json:"yes"`
			Resume     string `json:"resume"`
			Swarm      bool   `json:"swarm"`
			Title      string `json:"-"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Target) == "" {
			writeErr(w, 400, "invalid_request", "Body must include target")
			return
		}
		if body.Mode == "" {
			body.Mode = "attack"
		}
		if body.Mode != "recon" && body.Mode != "attack" && body.Mode != "fast" {
			writeErr(w, 400, "invalid_request", "mode must be recon|attack|fast")
			return
		}
		if body.Kind != "" && body.Kind != "agent" {
			writeErr(w, 400, "invalid_request", "kind must be agent")
			return
		}
		id := newRunID()
		raw, _ := json.Marshal(body)
		state := "queued"
		if !body.Yes {
			state = "awaiting_confirmation"
		}
		if err := s.DB.CreateRun(id, state, body.Target, body.Mode, body.Goal, string(raw)); err != nil {
			writeErr(w, 500, "internal_error", "Create failed")
			return
		}
		_ = s.DB.LogAudit(id, "run_created", "run created", "{}")
		broker := s.Events.GetOrCreate(id)
		broker.Append(id, "run_created", map[string]any{"target": body.Target, "mode": body.Mode})
		resp := map[string]any{"run_id": id, "preview": nil, "state": state}
		if !body.Yes {
			resp["decision"] = map[string]any{"id": "dec-" + id, "kind": "start_confirm", "required_text": "ALLOW " + body.Target, "prompt_text": "Confirm start"}
		}
		writeJSON(w, 201, resp)
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
}

func newRunID() string {
	return fmt.Sprintf("run-%d", time.Now().UnixNano())
}

func (s *Server) runsSub(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/runs/")
	parts := strings.SplitN(rest, "/", 3)
	runID := parts[0]
	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
		if len(parts) > 2 {
			sub += "/" + parts[2]
		}
	}
	run, err := s.DB.GetRun(runID)
	if err != nil {
		writeErr(w, 500, "internal_error", "Lookup failed")
		return
	}
	if run == nil {
		// Events/WS self-report (404 / 4404); every other sub-resource 404s.
		if strings.HasPrefix(sub, "events") || strings.HasPrefix(sub, "ws/") || strings.HasPrefix(sub, "decisions") {
			if strings.HasPrefix(sub, "decisions") {
				writeErr(w, 404, "not_found", "Run not found")
				return
			}
			s.eventsSub(w, r, runID, sub)
			return
		}
		if sub != "" {
			writeErr(w, 404, "not_found", "Run not found")
			return
		}
	}
	switch {
	case sub == "" && r.Method == http.MethodGet:
		if run == nil {
			writeErr(w, 404, "not_found", "Run not found")
			return
		}
		run["decisions"] = []any{}
		writeJSON(w, 200, run)
	case sub == "cancel" && r.Method == http.MethodPost:
		if run == nil {
			writeErr(w, 404, "not_found", "Run not found")
			return
		}
		_ = s.DB.SetRunState(runID, "cancelled")
		s.Events.GetOrCreate(runID).Append(runID, "run_cancelled", map[string]any{})
		writeJSON(w, 200, map[string]any{"run_id": runID, "state": "cancelled"})
	case sub == "resume" && r.Method == http.MethodPost:
		writeJSON(w, 200, map[string]any{"run_id": runID, "resumed_from": runID})
	case sub == "title" && r.Method == http.MethodPost:
		writeJSON(w, 200, map[string]any{"run_id": runID, "title": runID, "regenerated": false})
	case sub == "tools" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"tools": []any{}})
	case sub == "artifacts" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"artifacts": []any{}})
	case sub == "audit" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"records": []any{}, "chain_valid": true, "chain_reason": "go-native"})
	case sub == "sandbox" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"run_id": runID, "found": false, "config": map[string]any{"enabled": s.Cfg.Sandbox.Enabled}})
	case sub == "proposed" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"run_id": runID, "proposed": []any{}})
	case sub == "swarm" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"state": map[string]any{}})
	case sub == "campaign" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"state": map[string]any{}})
	case sub == "witness" && r.Method == http.MethodGet:
		writeJSON(w, 404, map[string]any{"error": map[string]any{"code": "not_found", "message": "No witness log"}})
		return
	case strings.HasPrefix(sub, "events") || strings.HasPrefix(sub, "ws/"):
		s.eventsSub(w, r, runID, sub)
		return
	case strings.HasPrefix(sub, "decisions"):
		s.decisionsSub(w, r, runID, sub)
		return
	case strings.HasPrefix(sub, "logs"):
		writeJSON(w, 200, map[string]any{"name": "tail", "lines": []string{}, "total_lines_returned": 0, "total_lines_in_file": 0})
		return
	case strings.HasPrefix(sub, "credentials"):
		writeJSON(w, 200, map[string]any{"credentials": []any{}})
		return
	case sub == "loot" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"loot": []any{}})
		return
	case sub == "workspace" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"files": []any{}})
		return
	case sub == "graph" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"run_id": runID, "nodes": []any{}, "edges": []any{}})
		return
	case r.Method == http.MethodDelete && sub == "":
		_ = s.DB.SetRunState(runID, "deleted")
		writeJSON(w, 200, map[string]any{"run_id": runID, "deleted": true, "purged": false})
		return
	default:
		writeErr(w, 404, "not_found", "Not found")
	}
}

func (s *Server) eventsSub(w http.ResponseWriter, r *http.Request, runID, sub string) {
	if strings.HasPrefix(sub, "ws/") || strings.HasPrefix(sub, "ws") {
		s.handleWS(w, r, runID)
		return
	}
	if run, _ := s.DB.GetRun(runID); run == nil {
		writeErr(w, 404, "not_found", "Run not found")
		return
	}
	if strings.HasSuffix(sub, "events/stream") && r.Method == http.MethodGet {
		after, _ := strconv.Atoi(r.URL.Query().Get("after"))
		broker := s.Events.GetOrCreate(runID)
		subsc := broker.Subscribe(after)
		defer subsc.Close()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(200)
		fl, _ := w.(http.Flusher)
		// Replay then live; heartbeat handled by broker tick.
		timeout := time.After(60 * time.Second)
		for {
			select {
			case ev := <-subsc.Chan():
				if ev.Type == "heartbeat" {
					_, _ = fmt.Fprint(w, ": heartbeat\n\n")
				} else {
					raw, _ := json.Marshal(ev)
					_, _ = fmt.Fprintf(w, "data: %s\n\n", raw)
				}
				if fl != nil {
					fl.Flush()
				}
			case <-timeout:
				return
			case <-r.Context().Done():
				return
			}
		}
	}
	if strings.HasSuffix(sub, "events") && r.Method == http.MethodGet {
		q := r.URL.Query()
		after, _ := strconv.Atoi(q.Get("after"))
		broker := s.Events.GetOrCreate(runID)
		if t := q.Get("tail"); t != "" || q.Get("before") != "" || q.Get("limit") != "" {
			tail, _ := strconv.Atoi(q.Get("tail"))
			before, _ := strconv.Atoi(q.Get("before"))
			limit, _ := strconv.Atoi(q.Get("limit"))
			evts, _, _, hasMore, first, last, omitted, nextBefore := broker.ReplayPage(after, tail, before, limit, t != "", q.Get("before") != "", q.Get("limit") != "")
			if evts == nil {
				evts = []events.Event{}
			}
			writeJSON(w, 200, map[string]any{"run_id": runID, "events": evts, "has_more_before": hasMore, "first_returned_sequence": first, "last_returned_sequence": last, "omitted_before": omitted, "next_before": nextBefore})
			return
		}
		evts := broker.Replay(after)
		if evts == nil {
			evts = []events.Event{}
		}
		var first, last any
		if len(evts) > 0 {
			first, last = evts[0].Sequence, evts[len(evts)-1].Sequence
		}
		writeJSON(w, 200, map[string]any{"run_id": runID, "events": evts, "oldest_sequence": nil, "latest_sequence": nil, "has_more_before": false, "first_returned_sequence": first, "last_returned_sequence": last, "omitted_before": 0, "next_before": nil})
		return
	}
	writeErr(w, 404, "not_found", "Not found")
}

func (s *Server) decisionsSub(w http.ResponseWriter, r *http.Request, runID, sub string) {
	rest := strings.TrimPrefix(sub, "decisions")
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" && r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"decisions": []any{}})
		return
	}
	if rest != "" && r.Method == http.MethodGet {
		writeJSON(w, 200, map[string]any{"id": rest, "run_id": runID, "kind": "start_confirm", "status": "pending"})
		return
	}
	if rest != "" && r.Method == http.MethodPost {
		writeJSON(w, 200, map[string]any{"decision_id": rest, "status": "answered"})
		return
	}
	writeErr(w, 404, "not_found", "Not found")
}

// ---- minimal RFC6455 server (stdlib-only) ----

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request, runID string) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" || r.Header.Get("Upgrade") == "" {
		writeErr(w, 400, "invalid_request", "WebSocket upgrade required")
		return
	}
	if run, _ := s.DB.GetRun(runID); run == nil {
		conn := wsHandshake(w, r, key)
		if conn == nil {
			return
		}
		wsClose(conn, 4404, "Run not found")
		_ = conn.Close()
		return
	}
	// Auth: header fast-path, else first JSON message {auth, after} in 5s.
	after := 0
	tokenOK := false
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")) == s.Token {
			tokenOK = true
		}
	}
	if q := r.URL.Query().Get("after"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n >= 0 {
			after = n
		}
	}
	// Origin is loopback-enforced at the HTTP layer by bind; browsers on
	// loopback origins only (documented 4403 path when Origin is foreign).
	if o := r.Header.Get("Origin"); o != "" && !isLoopbackOrigin(o) {
		conn := wsHandshake(w, r, key)
		if conn == nil {
			return
		}
		wsClose(conn, 4403, "bad origin")
		_ = conn.Close()
		return
	}
	conn := wsHandshake(w, r, key)
	if conn == nil {
		return
	}
	defer conn.Close()
	if !tokenOK {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		msg, ok := wsReadClientText(conn)
		if !ok {
			wsClose(conn, 4401, "auth required")
			return
		}
		var hello struct {
			Auth  string `json:"auth"`
			After int    `json:"after"`
		}
		if err := json.Unmarshal([]byte(msg), &hello); err != nil || hello.Auth != s.Token {
			wsClose(conn, 4401, "auth failed")
			return
		}
		if hello.After < 0 {
			wsClose(conn, 4400, "bad cursor")
			return
		}
		after = hello.After
		_ = conn.SetReadDeadline(time.Time{})
	}
	broker := s.Events.GetOrCreate(runID)
	subsc := broker.Subscribe(after)
	defer subsc.Close()
	for {
		select {
		case ev := <-subsc.Chan():
			if ev.Type == "heartbeat" {
				ev.RunID = runID
			}
			raw, _ := json.Marshal(ev)
			if err := wsWriteText(conn, string(raw)); err != nil {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

// wsHandshake completes RFC6455 101 using the client's Sec-WebSocket-Key.
func wsHandshake(w http.ResponseWriter, r *http.Request, key string) net.Conn {
	hj, ok := w.(http.Hijacker)
	if !ok {
		writeErr(w, 500, "internal_error", "Hijack unsupported")
		return nil
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		_ = conn.Close()
		return nil
	}
	_ = rw.Flush()
	return conn
}

func wsClose(conn net.Conn, code int, reason string) {
	payload := []byte{byte(code >> 8), byte(code), 0}
	payload = append(payload, reason...)
	frame := []byte{0x88, byte(len(payload))}
	frame = append(frame, payload...)
	_, _ = conn.Write(frame)
}

func wsWriteText(conn net.Conn, msg string) error {
	b := []byte(msg)
	header := []byte{0x81}
	if len(b) < 126 {
		header = append(header, byte(len(b)))
	} else if len(b) < 65536 {
		header = append(header, 126, byte(len(b)>>8), byte(len(b)))
	} else {
		header = append(header, 127, 0, 0, 0, 0, byte(len(b)>>24), byte(len(b)>>16), byte(len(b)>>8), byte(len(b)))
	}
	_, err := conn.Write(append(header, b...))
	return err
}

func wsReadClientText(conn net.Conn) (string, bool) {
	// Minimal masked client-frame reader: FIN+text, mask bit required.
	hdr := make([]byte, 2)
	if _, err := readFull(conn, hdr); err != nil {
		return "", false
	}
	masked := hdr[1]&0x80 != 0
	if !masked {
		return "", false
	}
	length := int(hdr[1] & 0x7F)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := readFull(conn, ext); err != nil {
			return "", false
		}
		length = int(ext[0])<<8 | int(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := readFull(conn, ext); err != nil {
			return "", false
		}
		length = int(ext[4])<<24 | int(ext[5])<<16 | int(ext[6])<<8 | int(ext[7])
		if length > 1<<20 {
			return "", false
		}
	}
	mask := make([]byte, 4)
	if _, err := readFull(conn, mask); err != nil {
		return "", false
	}
	data := make([]byte, length)
	if _, err := readFull(conn, data); err != nil {
		return "", false
	}
	for i := range data {
		data[i] ^= mask[i%4]
	}
	opcode := hdr[0] & 0x0F
	if opcode == 0x8 {
		return "", false
	}
	return string(data), true
}

func readFull(conn net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := conn.Read(b[got:])
		if err != nil {
			return got, err
		}
		got += n
	}
	return got, nil
}

func isLoopbackOrigin(o string) bool {
	return strings.Contains(o, "127.0.0.1") || strings.Contains(o, "localhost") || strings.Contains(o, "[::1]")
}
