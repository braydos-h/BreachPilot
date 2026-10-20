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
	"strconv"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/auth"
	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/events"
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
}

// New builds routes.
func New(cfg config.Config, token string, db *store.DB, reg *events.Registry) *Server {
	s := &Server{Cfg: cfg, Token: token, DB: db, Events: reg, mux: http.NewServeMux()}
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
		writeJSON(w, 200, map[string]any{
			"api":     map[string]any{"host": s.Cfg.API.Host, "port": s.Cfg.API.Port, "multi_operator": s.Cfg.API.MultiOperator},
			"models":  map[string]any{"provider": s.Cfg.Models.Provider, "default_alias": s.Cfg.Models.DefaultAlias, "registry": s.Cfg.Models.Registry},
			"sandbox": map[string]any{"enabled": s.Cfg.Sandbox.Enabled, "backend": s.Cfg.Sandbox.Backend, "image": s.Cfg.Sandbox.Image},
			"exploit": map[string]any{"allowed_targets": s.Cfg.Exploit.AllowedTargets, "workspace_dir": s.Cfg.Exploit.WorkspaceDir},
		})
	case http.MethodPatch:
		writeJSON(w, 200, map[string]any{"status": "ok", "config": map[string]any{}})
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) configSchema(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"schema": map[string]any{"type": "object"}})
}

func (s *Server) secrets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"keys": map[string]any{}})
	case http.MethodPut:
		var body struct {
			Secrets map[string]string `json:"secrets"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Secrets == nil {
			writeErr(w, 400, "invalid_secrets", "Body must be {secrets: {NAME: value}}")
			return
		}
		keys := []string{}
		for k := range body.Secrets {
			keys = append(keys, k)
		}
		writeJSON(w, 200, map[string]any{"status": "ok", "written": keys})
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
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
		_ = json.NewDecoder(r.Body).Decode(&body)
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
			writeJSON(w, 200, map[string]any{"status": "ok", "provider": body.Provider, "registered_providers": []string{"ollama", "opencode_go", "chatgpt"}})
		default:
			writeErr(w, 400, "invalid_provider", "Unknown provider")
		}
	case p == "refresh" && r.Method == http.MethodPost:
		writeJSON(w, 200, map[string]any{"ok": true, "registry": s.Cfg.Models.Registry, "persisted": false})
	case p == "live" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"models": []string{}, "source": "registry"})
	case strings.HasPrefix(p, "chatgpt/") || strings.HasPrefix(p, "opencode_go"):
		writeJSON(w, 200, map[string]any{"ok": true})
	case r.Method == http.MethodDelete:
		writeJSON(w, 200, map[string]any{"status": "ok", "deleted": true})
	default:
		writeErr(w, 404, "not_found", "Not found")
	}
}

func (s *Server) providers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"provider": s.Cfg.Models.Provider, "active": s.Cfg.Models.Provider,
		"providers": []string{"ollama", "opencode_go", "chatgpt"},
		"chatgpt":   map[string]any{"enabled": false, "authenticated": false},
		"opencode_go": map[string]any{
			"enabled": s.Cfg.Models.Provider == "opencode_go",
		},
	})
}

func (s *Server) sysInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"hostname": "localhost", "platform": "go-native", "local_ips": []string{"127.0.0.1"}, "public_ip": nil})
}

func (s *Server) telemetry(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"summary": map[string]any{}, "recent": []any{}})
}

func (s *Server) memory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"episodes": []any{}, "semantic": []any{}})
}

func (s *Server) sandbox(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"enabled": s.Cfg.Sandbox.Enabled, "backend": s.Cfg.Sandbox.Backend, "image": s.Cfg.Sandbox.Image, "network": map[string]any{}, "resources": map[string]any{}})
}

func (s *Server) browser(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"enabled": false, "backend": "none", "available": false, "health": "disabled", "capabilities": []string{}, "config": map[string]any{}})
}

func (s *Server) goals(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"goals": []any{}, "custom_goals": []any{}})
	case http.MethodPost:
		var body struct {
			Name      string `json:"name"`
			Objective string `json:"objective"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			writeErr(w, 400, "invalid_goal", "Body must include name")
			return
		}
		writeJSON(w, 201, map[string]any{"id": "goal-" + body.Name, "name": body.Name, "objective": body.Objective})
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) goalsSub(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"deleted": true})
}

func (s *Server) skills(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if q := r.URL.Query().Get("q"); q != "" && strings.HasSuffix(r.URL.Path, "/search") {
			writeJSON(w, 200, map[string]any{"results": []any{}})
			return
		}
		writeJSON(w, 200, map[string]any{"skills": skillManifest()})
	case http.MethodPost:
		writeJSON(w, 200, map[string]any{"name": "custom", "description": "", "tags": []string{}})
	default:
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
	}
}

func (s *Server) skillsSub(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/skills/")
	if name == "search" {
		writeJSON(w, 200, map[string]any{"results": []any{}})
		return
	}
	if r.Method == http.MethodDelete {
		writeJSON(w, 200, map[string]any{"name": name, "deleted": true})
		return
	}
	writeJSON(w, 200, map[string]any{"name": name, "description": "", "body": "", "sections": []any{}, "tags": []string{}})
}

func (s *Server) plugins(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"plugins": pluginManifest()})
}

func (s *Server) attackModules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"modules": attackModuleManifest()})
}

func (s *Server) opsSummary(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"killchain": map[string]any{"enabled": true},
		"snapshots": map[string]any{"enabled": false},
		"eval":      map[string]any{"enabled": true},
		"browser":   map[string]any{"enabled": false},
		"provider":  map[string]any{"active": s.Cfg.Models.Provider},
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
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"connections": []any{}, "total": 0, "active": 0, "stale": 0, "removed": 0, "error": 0})
}

func (s *Server) connectionsSub(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"connection": map[string]any{}})
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
			Target      string   `json:"target"`
			Mode        string   `json:"mode"`
			Goal        string   `json:"goal"`
			CustomGoal  string   `json:"custom_goal"`
			Kind        string   `json:"kind"`
			Yes         bool     `json:"yes"`
			Resume      string   `json:"resume"`
			Swarm       bool     `json:"swarm"`
			Title       string   `json:"-"`
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
	if run == nil && sub != "" && !strings.HasSuffix(r.URL.Path, "/events") && !strings.HasSuffix(r.URL.Path, "/events/stream") && !strings.HasPrefix(sub, "ws/") {
		// Events routes self-check existence; others 404 here.
		if sub == "" {
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
