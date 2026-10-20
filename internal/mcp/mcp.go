// Package mcp implements native Model Context Protocol (MCP) servers for
// BreachPilot:
//   - Engine/Advisory MCP server (read-only skills, CVE lookup, run history)
//   - Defensive MCP server (scope-enforced scanning + CIDR-subset allowlist +
//     allowlisted nmap command gate + vuln intel)
//   - Assessment/Execution MCP server (allowlist-gated native probes, workspace
//     files, runtime skills, and Rust sidecar Docker-sandboxed execution that
//     fails closed with SANDBOX_* when isolation is unavailable).
//
// Preserves JSON-RPC 2.0 MCP method contracts (initialize, ping, tools/list,
// tools/call) over both stdio and HTTP, and only advertises tools whose native
// backend is operational.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/braydos-h/BreachPilot/internal/audit"
	"github.com/braydos-h/BreachPilot/internal/intel"
	"github.com/braydos-h/BreachPilot/internal/ipc"
	"github.com/braydos-h/BreachPilot/internal/modules"
	"github.com/braydos-h/BreachPilot/internal/recon"
	"github.com/braydos-h/BreachPilot/internal/skills"
	"github.com/braydos-h/BreachPilot/internal/store"
)

const ProtocolVersion = "2024-11-05"

// ToolSchema describes one MCP tool's input schema.
type ToolSchema struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ToolHandler executes one MCP tool call and returns structured result data.
type ToolHandler func(ctx context.Context, args map[string]any) (any, error)

type registeredTool struct {
	schema  ToolSchema
	handler ToolHandler
}

// Server is a native MCP JSON-RPC 2.0 server instance.
type Server struct {
	Name         string
	Version      string
	Instructions string
	tools        []registeredTool
	byName       map[string]registeredTool
}

// NewServer constructs an empty MCP server with metadata.
func NewServer(name, instructions string) *Server {
	return &Server{
		Name:         name,
		Version:      "1.0.0-native",
		Instructions: instructions,
		byName:       map[string]registeredTool{},
	}
}

// Register adds an operational tool to the server.
func (s *Server) Register(schema ToolSchema, handler ToolHandler) {
	if schema.InputSchema == nil {
		schema.InputSchema = map[string]any{"type": "object", "properties": map[string]any{}}
	}
	rt := registeredTool{schema: schema, handler: handler}
	s.tools = append(s.tools, rt)
	s.byName[schema.Name] = rt
}

// Tools returns all registered operational tool schemas.
func (s *Server) Tools() []ToolSchema {
	out := make([]ToolSchema, 0, len(s.tools))
	for _, t := range s.tools {
		out = append(out, t.schema)
	}
	return out
}

// Call invokes a registered tool directly.
func (s *Server) Call(ctx context.Context, name string, args map[string]any) (any, error) {
	t, ok := s.byName[name]
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", name)
	}
	if args == nil {
		args = map[string]any{}
	}
	return t.handler(ctx, args)
}

// RPCRequest is a JSON-RPC 2.0 request envelope.
type RPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id,omitempty"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

// RPCResponse is a JSON-RPC 2.0 response envelope.
type RPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *RPCError `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// HandleRPC processes one MCP JSON-RPC 2.0 message. Returns nil for notifications.
func (s *Server) HandleRPC(ctx context.Context, req RPCRequest) *RPCResponse {
	if strings.HasPrefix(req.Method, "notifications/") {
		return nil
	}
	switch req.Method {
	case "initialize":
		return &RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": ProtocolVersion,
				"capabilities": map[string]any{
					"tools": map[string]any{"listChanged": false},
				},
				"serverInfo": map[string]any{
					"name":    s.Name,
					"version": s.Version,
				},
				"instructions": s.Instructions,
			},
		}
	case "ping":
		return &RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}
	case "tools/list":
		return &RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": s.Tools(),
			},
		}
	case "tools/call":
		name, _ := req.Params["name"].(string)
		args, _ := req.Params["arguments"].(map[string]any)
		if name == "" {
			return &RPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &RPCError{Code: -32602, Message: "missing tool name"},
			}
		}
		res, err := s.Call(ctx, name, args)
		if err != nil {
			if strings.HasPrefix(err.Error(), "unknown tool") {
				return &RPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error:   &RPCError{Code: -32601, Message: err.Error()},
				}
			}
			return &RPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]any{
					"isError": true,
					"content": []map[string]any{
						{"type": "text", "text": err.Error()},
					},
				},
			}
		}
		var text string
		switch v := res.(type) {
		case string:
			text = v
		default:
			raw, _ := json.Marshal(v)
			text = string(raw)
		}
		return &RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"isError":           false,
				"structuredContent": res,
				"content": []map[string]any{
					{"type": "text", "text": text},
				},
			},
		}
	default:
		return &RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: -32601, Message: "method not found: " + req.Method},
		}
	}
}

// ServeStdio serves line-delimited JSON-RPC 2.0 over r and w.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req RPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			resp := RPCResponse{
				JSONRPC: "2.0",
				Error:   &RPCError{Code: -32700, Message: "parse error"},
			}
			raw, _ := json.Marshal(resp)
			_, _ = fmt.Fprintf(w, "%s\n", raw)
			continue
		}
		if resp := s.HandleRPC(ctx, req); resp != nil {
			raw, _ := json.Marshal(resp)
			_, _ = fmt.Fprintf(w, "%s\n", raw)
		}
	}
	return scanner.Err()
}

// HTTPHandler exposes the MCP server over HTTP (GET returns server/tool catalog;
// POST processes JSON-RPC 2.0 requests).
func (s *Server) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":             s.Name,
				"version":          s.Version,
				"protocol_version": ProtocolVersion,
				"tools":            s.Tools(),
			})
		case http.MethodPost:
			var req RPCRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(RPCResponse{
					JSONRPC: "2.0",
					Error:   &RPCError{Code: -32700, Message: "parse error"},
				})
				return
			}
			resp := s.HandleRPC(r.Context(), req)
			if resp == nil {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// ValidateBindHost enforces the MCP HTTP bind rule: loopback by default;
// non-loopback requires both --allow-public-bind AND MCP_ALLOW_PUBLIC_BIND=1
// AND a non-empty MCP_HTTP_TOKEN.
func ValidateBindHost(host string, allowPublicFlag bool) error {
	h := strings.TrimSpace(host)
	if h == "127.0.0.1" || strings.EqualFold(h, "localhost") || h == "::1" {
		return nil
	}
	if !allowPublicFlag || os.Getenv("MCP_ALLOW_PUBLIC_BIND") != "1" {
		return fmt.Errorf("refusing non-loopback MCP bind %q: requires both --allow-public-bind and MCP_ALLOW_PUBLIC_BIND=1", host)
	}
	if strings.TrimSpace(os.Getenv("MCP_HTTP_TOKEN")) == "" {
		return fmt.Errorf("refusing non-loopback MCP bind %q without MCP_HTTP_TOKEN", host)
	}
	return nil
}

// IsInDefensiveScope checks whether asset (IP, FQDN, or CIDR) is within allow,
// including CIDR-subset-of-CIDR (e.g. 10.0.0.0/24 inside 10.0.0.0/16).
func IsInDefensiveScope(asset string, allow []string) bool {
	a := strings.TrimSpace(asset)
	if a == "" || len(allow) == 0 {
		return false
	}
	if allowlist.Check(a, allow, true) {
		return true
	}
	_, assetNet, err := net.ParseCIDR(a)
	if err != nil || assetNet == nil {
		return false
	}
	assetOnes, assetBits := assetNet.Mask.Size()
	for _, entry := range allow {
		_, allowNet, err := net.ParseCIDR(strings.TrimSpace(entry))
		if err != nil || allowNet == nil {
			continue
		}
		allowOnes, allowBits := allowNet.Mask.Size()
		if assetBits == allowBits && assetOnes >= allowOnes && allowNet.Contains(assetNet.IP) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 1. Engine / Advisory MCP Server (mirrors mcp_engine_server.py)
// ---------------------------------------------------------------------------

// NewEngineServer builds the read-only advisory MCP server.
func NewEngineServer(db *store.DB, skillStore *skills.Store, nvd *intel.NVDClient) *Server {
	srv := NewServer(
		"breachpilot-engine",
		"BreachPilot engine advisory surface. Tools are read-only: skill search, skill body retrieval, NVD CVE lookup, and run history.",
	)

	srv.Register(ToolSchema{
		Name:        "search_skills",
		Description: "Lexical + field-weighted search over the runtime skill catalog.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string"},
				"limit": map[string]any{"type": "integer"},
			},
			"required": []string{"query"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		q, _ := args["query"].(string)
		limit := intArg(args, "limit", 10, 1, 50)
		if skillStore == nil {
			return map[string]any{"count": 0, "skills": []any{}}, nil
		}
		matches, err := skillStore.Search(q)
		if err != nil {
			return nil, err
		}
		if len(matches) > limit {
			matches = matches[:limit]
		}
		out := make([]map[string]any, 0, len(matches))
		for _, m := range matches {
			out = append(out, map[string]any{
				"name":        m.Name,
				"description": m.Description,
				"tags":        m.Tags,
				"domain":      m.Domain,
			})
		}
		return map[string]any{"count": len(out), "skills": out}, nil
	})

	srv.Register(ToolSchema{
		Name:        "get_skill",
		Description: "Return one skill's full body + metadata by name.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{"type": "string"},
			},
			"required": []string{"name"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		name, _ := args["name"].(string)
		if skillStore == nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("skill %q not found", name)}, nil
		}
		sk, err := skillStore.Get(name)
		if err != nil || sk == nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("skill %q not found", name)}, nil
		}
		return map[string]any{
			"ok":           true,
			"name":         sk.Name,
			"description":  sk.Description,
			"tags":         sk.Tags,
			"domain":       sk.Domain,
			"subdomain":    sk.Subdomain,
			"version":      sk.Version,
			"nist_csf":     sk.NistCsf,
			"mitre_attack": sk.MitreAttack,
			"sections":     sk.Sections,
			"body":         sk.Body,
		}, nil
	})

	srv.Register(ToolSchema{
		Name:        "cve_lookup",
		Description: "NVD CVE lookup for a known product/version string.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string"},
			},
			"required": []string{"query"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		q, _ := args["query"].(string)
		if nvd == nil {
			return fmt.Sprintf("No CVEs found for %q.", q), nil
		}
		entries, err := nvd.Search(ctx, q)
		if err != nil {
			return nil, err
		}
		return intel.FormatCVEResults(entries, q), nil
	})

	srv.Register(ToolSchema{
		Name:        "list_runs",
		Description: "List recent assessment runs (read-only history). Newest first.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"limit": map[string]any{"type": "integer"},
			},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		limit := intArg(args, "limit", 20, 1, 100)
		if db == nil {
			return map[string]any{"count": 0, "runs": []any{}}, nil
		}
		rows, _, err := db.ListRuns(limit, 0, "", "", "created_desc")
		if err != nil {
			return nil, err
		}
		return map[string]any{"count": len(rows), "runs": rows}, nil
	})

	srv.Register(ToolSchema{
		Name:        "get_run",
		Description: "Return one run's details: state, request, result.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"run_id": map[string]any{"type": "string"},
			},
			"required": []string{"run_id"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		runID, _ := args["run_id"].(string)
		if db == nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("run %q not found", runID)}, nil
		}
		run, err := db.GetRun(runID)
		if err != nil || run == nil {
			return map[string]any{"ok": false, "error": fmt.Sprintf("run %q not found", runID)}, nil
		}
		return map[string]any{"ok": TrueVal(), "run": run}, nil
	})

	return srv
}

func TrueVal() bool { return true }

// ---------------------------------------------------------------------------
// 2. Defensive MCP Server (mirrors mcp_server.py)
// ---------------------------------------------------------------------------

var nmapBadChars = regexp.MustCompile(`[;&|` + "`" + `$<>\n\r]`)

// NewDefensiveServer builds the scope-enforced defensive MCP server.
func NewDefensiveServer(allowedAssets []string, nvd *intel.NVDClient, skillStore *skills.Store) *Server {
	srv := NewServer(
		"ai-nmap-defensive",
		"Defensive scope-enforced reconnaissance and vulnerability intelligence MCP server.",
	)

	scanHost := func(ctx context.Context, target string, ports []int) (map[string]any, error) {
		if !IsInDefensiveScope(target, allowedAssets) {
			return map[string]any{"ok": false, "error": fmt.Sprintf("target %q is not in scope", target)}, nil
		}
		ip, _, err := recon.Resolve(ctx, target)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
		start := time.Now()
		results := recon.ScanPorts(ctx, ip, ports)
		assess := recon.BuildAssessment(ip, results)
		return map[string]any{
			"ok":         true,
			"target_ip":  ip,
			"open_ports": assess.OpenPorts,
			"services":   assess.Services,
			"os_verdict": assess.OSVerdict,
			"os_hints":   assess.OSHints,
			"exit_code":  0,
			"duration_s": time.Since(start).Seconds(),
		}, nil
	}

	srv.Register(ToolSchema{
		Name:        "run_nmap_ping_sweep",
		Description: "Discover live hosts in an approved subnet or host.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"subnet": map[string]any{"type": "string"}},
			"required":   []string{"subnet"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		subnet, _ := args["subnet"].(string)
		if !IsInDefensiveScope(subnet, allowedAssets) {
			return map[string]any{"ok": false, "error": fmt.Sprintf("subnet %q is not in scope", subnet)}, nil
		}
		host := strings.Split(subnet, "/")[0]
		return scanHost(ctx, host, []int{22, 80, 443, 445, 3389})
	})

	srv.Register(ToolSchema{
		Name:        "run_nmap_triage_scan",
		Description: "Top-port triage scan against an approved subnet or host.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"subnet":    map[string]any{"type": "string"},
				"top_ports": map[string]any{"type": "integer"},
			},
			"required": []string{"subnet"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		subnet, _ := args["subnet"].(string)
		if !IsInDefensiveScope(subnet, allowedAssets) {
			return map[string]any{"ok": false, "error": fmt.Sprintf("subnet %q is not in scope", subnet)}, nil
		}
		host := strings.Split(subnet, "/")[0]
		return scanHost(ctx, host, recon.DefaultFastPorts)
	})

	srv.Register(ToolSchema{
		Name:        "run_nmap_basic_scan",
		Description: "Per-host service/version detection on approved target.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target_ip": map[string]any{"type": "string"},
				"ports":     map[string]any{"type": "string"},
			},
			"required": []string{"target_ip"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		target, _ := args["target_ip"].(string)
		portsStr, _ := args["ports"].(string)
		return scanHost(ctx, target, parsePortList(portsStr, recon.DefaultFastPorts))
	})

	srv.Register(ToolSchema{
		Name:        "run_nmap_service_scan",
		Description: "Per-host service, banner, and OS fingerprint scan on approved target.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target_ip": map[string]any{"type": "string"},
				"ports":     map[string]any{"type": "string"},
			},
			"required": []string{"target_ip"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		target, _ := args["target_ip"].(string)
		portsStr, _ := args["ports"].(string)
		return scanHost(ctx, target, parsePortList(portsStr, recon.DefaultFastPorts))
	})

	srv.Register(ToolSchema{
		Name:        "run_nmap_vuln_scan",
		Description: "Service scan + NVD CVE vulnerability enrichment on approved target.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target_ip": map[string]any{"type": "string"},
				"ports":     map[string]any{"type": "string"},
			},
			"required": []string{"target_ip"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		target, _ := args["target_ip"].(string)
		if !IsInDefensiveScope(target, allowedAssets) {
			return map[string]any{"ok": false, "error": fmt.Sprintf("target %q is not in scope", target)}, nil
		}
		ip, _, err := recon.Resolve(ctx, target)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
		portsStr, _ := args["ports"].(string)
		results := recon.ScanPorts(ctx, ip, parsePortList(portsStr, recon.DefaultFastPorts))
		assess := recon.BuildAssessment(ip, results)
		recon.EnrichAssessmentCVEs(ctx, &assess, nvd)
		return map[string]any{
			"ok":           true,
			"target_ip":    ip,
			"open_ports":   assess.OpenPorts,
			"services":     assess.Services,
			"cve_findings": assess.CVEFindings,
			"risk_score":   assess.OverallRiskScore,
		}, nil
	})

	srv.Register(ToolSchema{
		Name:        "run_limited_terminal",
		Description: "Execute an allowlisted nmap command against an in-scope target.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"command": map[string]any{"type": "string"}},
			"required":   []string{"command"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		cmdStr, _ := args["command"].(string)
		cmdStr = strings.TrimSpace(cmdStr)
		if cmdStr == "" || nmapBadChars.MatchString(cmdStr) {
			return map[string]any{"ok": false, "error": "rejected: command contains forbidden shell metacharacters"}, nil
		}
		tokens := strings.Fields(cmdStr)
		if len(tokens) < 2 || tokens[0] != "nmap" {
			return map[string]any{"ok": false, "error": "rejected: only nmap commands are permitted in run_limited_terminal"}, nil
		}
		target := tokens[len(tokens)-1]
		if strings.HasPrefix(target, "-") {
			return map[string]any{"ok": false, "error": "rejected: missing target argument"}, nil
		}
		if !IsInDefensiveScope(target, allowedAssets) {
			return map[string]any{"ok": false, "error": fmt.Sprintf("target %q is not in scope", target)}, nil
		}
		downgraded, note := recon.ApplyNmapPrivilege(tokens, false, false, true)
		res, err := scanHost(ctx, strings.Split(target, "/")[0], recon.DefaultFastPorts)
		if err != nil {
			return nil, err
		}
		res["downgraded_argv"] = downgraded
		if note != "" {
			res["downgrade_note"] = note
		}
		return res, nil
	})

	srv.Register(ToolSchema{
		Name:        "search_cve_intel",
		Description: "NVD CVE lookup, rate-limited and cached.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"query": map[string]any{"type": "string"}},
			"required":   []string{"query"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		q, _ := args["query"].(string)
		if nvd == nil {
			return fmt.Sprintf("No CVEs found for %q.", q), nil
		}
		entries, err := nvd.Search(ctx, q)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
		return intel.FormatCVEResults(entries, q), nil
	})

	srv.Register(ToolSchema{
		Name:        "search_vulnerability_intel",
		Description: "Sanitized public vulnerability and methodology advisory search.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"query": map[string]any{"type": "string"}},
			"required":   []string{"query"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		q, _ := args["query"].(string)
		clean, err := intel.SanitizeQuery(q)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}, nil
		}
		var cves []intel.CVEEntry
		if nvd != nil {
			cves, _ = nvd.Search(ctx, clean)
		}
		var skMatches []skills.Skill
		if skillStore != nil {
			skMatches, _ = skillStore.Search(clean)
			if len(skMatches) > 5 {
				skMatches = skMatches[:5]
			}
		}
		return map[string]any{
			"ok":     true,
			"query":  clean,
			"cves":   cves,
			"skills": skMatches,
		}, nil
	})

	return srv
}

// ---------------------------------------------------------------------------
// 3. Assessment / Execution MCP Server (mirrors mcp_exploit_server.py)
// ---------------------------------------------------------------------------

// AssessmentConfig configures the native assessment/execution MCP server.
type AssessmentConfig struct {
	RunID            string
	WorkspaceDir     string
	AllowedTargets   []string
	RequireAllowlist bool
	SandboxEnabled   bool
	SandboxImage     string
	Sidecar          *ipc.Client
	SkillStore       *skills.Store
	NVD              *intel.NVDClient
}

// NewAssessmentServer builds the native assessment MCP server integrated with
// the Go control plane and the Rust execution sidecar.
func NewAssessmentServer(cfg AssessmentConfig) *Server {
	if cfg.RunID == "" {
		cfg.RunID = "mcp-session"
	}
	if cfg.WorkspaceDir == "" {
		cfg.WorkspaceDir = "exploit_workspace"
	}
	if cfg.SandboxImage == "" {
		cfg.SandboxImage = "breachpilot-sandbox:latest"
	}
	_ = os.MkdirAll(cfg.WorkspaceDir, 0o755)
	entries := allowlist.ApprovalEntries(cfg.AllowedTargets, nil)

	srv := NewServer(
		"AI Exploitation Tools",
		"Native assessment and isolated sandbox execution MCP server. Target-touching tools enforce the allowlist lock; command execution routes strictly through the Rust Docker sandbox sidecar and fails closed (SANDBOX_*) when isolation is unavailable.",
	)

	recordAudit := func(tool, target, status string) {
		_, _ = audit.Append(cfg.WorkspaceDir, cfg.RunID, tool, target, status, tool, "mcp")
	}

	requireTarget := func(tool, target string) error {
		t := strings.TrimSpace(target)
		if t == "" || !allowlist.Check(t, entries, cfg.RequireAllowlist) {
			recordAudit(tool, t, "blocked")
			return fmt.Errorf("SANDBOX_SCOPE_DENIED: target %q is not in allowlist", target)
		}
		return nil
	}

	srv.Register(ToolSchema{
		Name:        "check_os",
		Description: "Probe target ports and banners to infer OS family (allowlist-gated).",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"target_ip": map[string]any{"type": "string"}},
			"required":   []string{"target_ip"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		target, _ := args["target_ip"].(string)
		if err := requireTarget("check_os", target); err != nil {
			return nil, err
		}
		ip, _, err := recon.Resolve(ctx, target)
		if err != nil {
			recordAudit("check_os", target, "failed")
			return nil, err
		}
		res := recon.ScanPorts(ctx, ip, []int{22, 80, 135, 139, 443, 445, 3389, 8080})
		assess := recon.BuildAssessment(ip, res)
		recordAudit("check_os", target, "completed")
		return map[string]any{
			"target_ip":  ip,
			"os_verdict": assess.OSVerdict,
			"os_hints":   assess.OSHints,
			"open_ports": assess.OpenPorts,
		}, nil
	})

	srv.Register(ToolSchema{
		Name:        "scan_ports",
		Description: "Run native TCP connect scan with banner and version extraction (allowlist-gated).",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target_ip": map[string]any{"type": "string"},
				"ports":     map[string]any{"type": "string"},
			},
			"required": []string{"target_ip"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		target, _ := args["target_ip"].(string)
		if err := requireTarget("scan_ports", target); err != nil {
			return nil, err
		}
		ip, _, err := recon.Resolve(ctx, target)
		if err != nil {
			recordAudit("scan_ports", target, "failed")
			return nil, err
		}
		portsStr, _ := args["ports"].(string)
		res := recon.ScanPorts(ctx, ip, parsePortList(portsStr, recon.DefaultFastPorts))
		assess := recon.BuildAssessment(ip, res)
		recon.EnrichAssessmentCVEs(ctx, &assess, cfg.NVD)
		recordAudit("scan_ports", target, "completed")
		return assess, nil
	})

	srv.Register(ToolSchema{
		Name:        "http_probe",
		Description: "Safe HTTP GET/HEAD probe on an allowlisted target.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string"},
				"port":   map[string]any{"type": "integer"},
				"tls":    map[string]any{"type": "boolean"},
				"path":   map[string]any{"type": "string"},
			},
			"required": []string{"target"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		target, _ := args["target"].(string)
		if err := requireTarget("http_probe", target); err != nil {
			return nil, err
		}
		tool := modules.Registry["http_probe"]
		out, err := tool.Run(ctx, args, modules.Env{Entries: entries, Timeout: 10 * time.Second})
		if err != nil {
			recordAudit("http_probe", target, "failed")
			return nil, err
		}
		recordAudit("http_probe", target, "completed")
		return out, nil
	})

	srv.Register(ToolSchema{
		Name:        "tls_probe",
		Description: "Inspect TLS handshake and certificate metadata on an allowlisted target.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string"},
				"port":   map[string]any{"type": "integer"},
			},
			"required": []string{"target"},
		},
	}, func(ctx context.Context, args map[string]any) (any, error) {
		target, _ := args["target"].(string)
		if err := requireTarget("tls_probe", target); err != nil {
			return nil, err
		}
		tool := modules.Registry["tls_probe"]
		out, err := tool.Run(ctx, args, modules.Env{Entries: entries, Timeout: 10 * time.Second})
		if err != nil {
			recordAudit("tls_probe", target, "failed")
			return nil, err
		}
		recordAudit("tls_probe", target, "completed")
		return out, nil
	})

	srv.Register(ToolSchema{
		Name:        "read_workspace_file",
		Description: "Read a file inside the isolated run workspace.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"filename": map[string]any{"type": "string"}},
			"required":   []string{"filename"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		name, _ := args["filename"].(string)
		full, err := safeWorkspacePath(cfg.WorkspaceDir, name)
		if err != nil {
			recordAudit("read_workspace_file", "", "blocked")
			return nil, err
		}
		raw, err := os.ReadFile(full)
		if err != nil {
			recordAudit("read_workspace_file", "", "failed")
			return nil, err
		}
		recordAudit("read_workspace_file", "", "completed")
		return map[string]any{"filename": name, "content": string(raw)}, nil
	})

	srv.Register(ToolSchema{
		Name:        "write_workspace_file",
		Description: "Write a file inside the isolated run workspace.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"filename": map[string]any{"type": "string"},
				"content":  map[string]any{"type": "string"},
			},
			"required": []string{"filename", "content"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		name, _ := args["filename"].(string)
		content, _ := args["content"].(string)
		full, err := safeWorkspacePath(cfg.WorkspaceDir, name)
		if err != nil {
			recordAudit("write_workspace_file", "", "blocked")
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			recordAudit("write_workspace_file", "", "failed")
			return nil, err
		}
		recordAudit("write_workspace_file", "", "completed")
		return map[string]any{"filename": name, "bytes": len(content), "written": true}, nil
	})

	srv.Register(ToolSchema{
		Name:        "list_workspace",
		Description: "List files in the isolated run workspace.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, func(_ context.Context, _ map[string]any) (any, error) {
		var files []string
		root, err := filepath.Abs(cfg.WorkspaceDir)
		if err != nil {
			return map[string]any{"files": []string{}}, nil
		}
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if rel, err := filepath.Rel(root, p); err == nil {
				files = append(files, filepath.ToSlash(rel))
			}
			return nil
		})
		if files == nil {
			files = []string{}
		}
		recordAudit("list_workspace", "", "completed")
		return map[string]any{"files": files}, nil
	})

	srv.Register(ToolSchema{
		Name:        "list_runtime_skills",
		Description: "List available methodology skills.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, func(_ context.Context, _ map[string]any) (any, error) {
		if cfg.SkillStore == nil {
			return map[string]any{"skills": []any{}}, nil
		}
		all, err := cfg.SkillStore.List()
		if err != nil {
			return nil, err
		}
		return map[string]any{"skills": all}, nil
	})

	srv.Register(ToolSchema{
		Name:        "search_runtime_skills",
		Description: "Search methodology skills by keyword.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"query": map[string]any{"type": "string"}},
			"required":   []string{"query"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		q, _ := args["query"].(string)
		if cfg.SkillStore == nil {
			return map[string]any{"results": []any{}}, nil
		}
		res, err := cfg.SkillStore.Search(q)
		if err != nil {
			return nil, err
		}
		return map[string]any{"results": res}, nil
	})

	srv.Register(ToolSchema{
		Name:        "load_runtime_skill",
		Description: "Load a methodology skill body by name.",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"name": map[string]any{"type": "string"}},
			"required":   []string{"name"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		name, _ := args["name"].(string)
		if cfg.SkillStore == nil {
			return nil, fmt.Errorf("skill %q not found", name)
		}
		sk, err := cfg.SkillStore.Get(name)
		if err != nil || sk == nil {
			return nil, fmt.Errorf("skill %q not found", name)
		}
		return sk, nil
	})

	srv.Register(ToolSchema{
		Name:        "check_environment",
		Description: "Probe the Rust sidecar and Docker sandbox isolation readiness.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
	}, func(_ context.Context, _ map[string]any) (any, error) {
		if cfg.Sidecar == nil {
			recordAudit("check_environment", "", "failed")
			return map[string]any{"sidecar_reachable": false, "isolated_ready": false}, nil
		}
		st, err := cfg.Sidecar.SandboxStatus()
		if err != nil {
			recordAudit("check_environment", "", "failed")
			return map[string]any{"sidecar_reachable": false, "isolated_ready": false, "error": err.Error()}, nil
		}
		st["sidecar_reachable"] = true
		recordAudit("check_environment", "", "completed")
		return st, nil
	})

	srv.Register(ToolSchema{
		Name:        "run_sandbox_command",
		Description: "Execute an argv command inside the isolated Rust/Docker worker sandbox. Fails closed with SANDBOX_* when out of scope or when Docker isolation is unavailable.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"argv":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"target_ip": map[string]any{"type": "string"},
			},
			"required": []string{"argv", "target_ip"},
		},
	}, func(_ context.Context, args map[string]any) (any, error) {
		target, _ := args["target_ip"].(string)
		if err := requireTarget("run_sandbox_command", target); err != nil {
			return nil, err
		}
		var argv []string
		switch raw := args["argv"].(type) {
		case []string:
			argv = raw
		case []any:
			for _, item := range raw {
				if s, ok := item.(string); ok && s != "" {
					argv = append(argv, s)
				}
			}
		}
		if len(argv) == 0 {
			recordAudit("run_sandbox_command", target, "blocked")
			return nil, errors.New("SANDBOX_INVALID: argv must be non-empty")
		}
		if cfg.Sidecar == nil {
			recordAudit("run_sandbox_command", target, "blocked")
			return nil, errors.New("SANDBOX_UNAVAILABLE: Rust execution sidecar is not configured; refusing host execution")
		}
		absWS, _ := filepath.Abs(cfg.WorkspaceDir)
		resp, err := cfg.Sidecar.ExecSandboxed(
			cfg.RunID, absWS, cfg.SandboxImage, "run_sandbox_command",
			argv, []string{target}, entries, cfg.RequireAllowlist, 60,
		)
		if err != nil {
			recordAudit("run_sandbox_command", target, "blocked")
			return nil, fmt.Errorf("SANDBOX_UNAVAILABLE: sidecar unreachable (%v); refusing host execution", err)
		}
		if !resp.OK {
			code := "SANDBOX_UNAVAILABLE"
			msg := "sandbox execution blocked"
			if resp.Error != nil {
				code = resp.Error.Code
				msg = resp.Error.Message
			}
			recordAudit("run_sandbox_command", target, "blocked")
			return nil, fmt.Errorf("%s: %s", code, msg)
		}
		recordAudit("run_sandbox_command", target, "completed")
		return resp.Result, nil
	})

	return srv
}

func safeWorkspacePath(wsRoot, rel string) (string, error) {
	cleanRel := strings.TrimSpace(rel)
	if cleanRel == "" || cleanRel == "." || cleanRel == ".." {
		return "", errors.New("SANDBOX_WORKSPACE_FAILED: invalid workspace filename")
	}
	if filepath.IsAbs(cleanRel) || strings.HasPrefix(cleanRel, "/") || strings.HasPrefix(cleanRel, `\`) {
		return "", errors.New("SANDBOX_WORKSPACE_FAILED: absolute paths are forbidden")
	}
	for _, part := range strings.Split(filepath.ToSlash(cleanRel), "/") {
		if part == ".." {
			return "", errors.New("SANDBOX_WORKSPACE_FAILED: path traversal '..' is forbidden")
		}
	}
	absRoot, err := filepath.Abs(wsRoot)
	if err != nil {
		return "", err
	}
	full := filepath.Join(absRoot, filepath.FromSlash(cleanRel))
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(absFull, absRoot+string(os.PathSeparator)) {
		return "", errors.New("SANDBOX_WORKSPACE_FAILED: path escapes workspace")
	}
	return absFull, nil
}

func intArg(args map[string]any, key string, def, minVal, maxVal int) int {
	v, ok := args[key]
	if !ok {
		return def
	}
	var n int
	switch x := v.(type) {
	case int:
		n = x
	case float64:
		n = int(x)
	case string:
		p, err := strconv.Atoi(x)
		if err != nil {
			return def
		}
		n = p
	default:
		return def
	}
	if n < minVal {
		return minVal
	}
	if n > maxVal {
		return maxVal
	}
	return n
}

func parsePortList(s string, def []int) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	var out []int
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if p, err := strconv.Atoi(tok); err == nil && p >= 1 && p <= 65535 {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}
