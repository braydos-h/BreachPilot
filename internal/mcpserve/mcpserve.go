// Package mcpserve wires the native MCP servers (internal/mcp) to the
// stdio/HTTP transports behind the bp-mcp-* binaries. It mirrors the CLI
// surface of mcp_server.py (defensive, :8000), mcp_exploit_server.py
// (assessment, :8001) and mcp_engine_server.py (engine, :8002): --transport
// stdio|http, loopback-only HTTP with the --allow-public-bind +
// MCP_ALLOW_PUBLIC_BIND=1 two-person override, and --expected-config-sha256
// fingerprint verification for API-attached sessions.
package mcpserve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/intel"
	"github.com/braydos-h/BreachPilot/internal/ipc"
	"github.com/braydos-h/BreachPilot/internal/mcp"
	"github.com/braydos-h/BreachPilot/internal/skills"
	"github.com/braydos-h/BreachPilot/internal/store"
	"github.com/braydos-h/BreachPilot/internal/threatintel"
)

// CheckConfigFingerprint compares the hex sha256 of the config file against
// expected. Empty expected skips the check (standalone CLI launches).
// Mirrors verify_config_fingerprint for the --expected-config-sha256 gate.
func CheckConfigFingerprint(configPath, expected string) error {
	if strings.TrimSpace(expected) == "" {
		return nil
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, strings.TrimSpace(expected)) {
		return fmt.Errorf("config fingerprint mismatch: file digest does not match --expected-config-sha256")
	}
	return nil
}

// Serve runs srv on transport ("stdio" or "http"). HTTP binds are
// loopback-only unless allowPublicBind plus the MCP_ALLOW_PUBLIC_BIND=1
// environment override both hold (enforced by mcp.ValidateBindHost).
func Serve(ctx context.Context, srv *mcp.Server, transport, host string, port int, allowPublicBind bool) error {
	switch transport {
	case "stdio":
		return srv.ServeStdio(ctx, os.Stdin, os.Stdout)
	case "http":
		if err := mcp.ValidateBindHost(host, allowPublicBind); err != nil {
			return err
		}
		addr := fmt.Sprintf("%s:%d", host, port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		s := &http.Server{Handler: srv.HTTPHandler()}
		go func() {
			<-ctx.Done()
			_ = s.Close()
		}()
		return s.Serve(ln)
	default:
		return fmt.Errorf("unknown transport %q: want stdio or http", transport)
	}
}

// threatintelFor builds the OSV/GHSA/KEV feed client, or nil when the
// threat_intel block is disabled. The KEV catalog is shared with the NVD
// client so the feed is fetched once per process.
func threatintelFor(cfg config.Config, nvd *intel.NVDClient) *threatintel.Client {
	if !cfg.ThreatIntel.Enabled {
		return nil
	}
	s := threatintel.SettingsFor(cfg)
	var kev *intel.KEVCatalog
	if nvd != nil {
		kev = nvd.KEV
	} else if s.Sources["kev"] {
		kev = intel.NewKEVCatalog(intel.SettingsFor(cfg))
	}
	return threatintel.NewClient(s, kev, nil)
}

func sharedDeps(cfgPath string) (config.Config, *skills.Store, *intel.NVDClient, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return cfg, nil, nil, err
	}
	return cfg, skills.NewStore([]string{"skills"}), intel.NewNVDClient(intel.SettingsFor(cfg)), nil
}

// DefensiveFromConfig builds the scope-enforced defensive server (mirrors
// mcp_server.py: ping/triage/basic/service/vuln scans, limited terminal,
// CVE + vulnerability intel).
func DefensiveFromConfig(cfgPath string) (*mcp.Server, config.Config, error) {
	cfg, skillStore, nvd, err := sharedDeps(cfgPath)
	if err != nil {
		return nil, cfg, err
	}
	return mcp.NewDefensiveServer(cfg.Exploit.AllowedTargets, nvd, skillStore, threatintelFor(cfg, nvd)), cfg, nil
}

// EngineFromConfig builds the read-only advisory server (mirrors
// mcp_engine_server.py: skill search/body, CVE lookup, run history).
func EngineFromConfig(cfgPath string) (*mcp.Server, config.Config, error) {
	cfg, skillStore, nvd, err := sharedDeps(cfgPath)
	if err != nil {
		return nil, cfg, err
	}
	db, err := store.Open("api_runtime.db", "reports")
	if err != nil {
		return nil, cfg, err
	}
	return mcp.NewEngineServer(db, skillStore, nvd), cfg, nil
}

// AssessOptions configures the assessment server build.
type AssessOptions struct {
	WorkspaceDir string
	RunID        string
	SidecarAddr  string
}

// AssessFromConfig builds the allowlist-gated assessment server (mirrors
// mcp_exploit_server.py). A nil sidecar (SidecarAddr "") keeps sandbox
// execution fail-closed: run_sandbox_command reports SANDBOX_UNAVAILABLE
// instead of running on the host.
func AssessFromConfig(cfgPath string, opts AssessOptions) (*mcp.Server, config.Config, error) {
	cfg, skillStore, nvd, err := sharedDeps(cfgPath)
	if err != nil {
		return nil, cfg, err
	}
	ws := opts.WorkspaceDir
	if ws == "" {
		ws = cfg.Exploit.WorkspaceDir
	}
	if ws == "" {
		ws = "exploit_workspace"
	}
	runID := opts.RunID
	if runID == "" {
		runID = "mcp-session"
	}
	var sidecar *ipc.Client
	if strings.TrimSpace(opts.SidecarAddr) != "" {
		sidecar = &ipc.Client{Addr: strings.TrimSpace(opts.SidecarAddr)}
	}
	return mcp.NewAssessmentServer(mcp.AssessmentConfig{
		RunID: runID, WorkspaceDir: ws,
		AllowedTargets:   cfg.Exploit.AllowedTargets,
		RequireAllowlist: cfg.Exploit.RequireExplicitAllowlist,
		SandboxEnabled:   cfg.Sandbox.Enabled, SandboxImage: cfg.Sandbox.Image,
		Sidecar: sidecar, SkillStore: skillStore, NVD: nvd,
	}), cfg, nil
}
