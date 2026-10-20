// Command bp-mcp-assess is the native assessment MCP server:
// allowlist-gated probes, workspace files, and fail-closed sandbox execution
// over stdio or loopback HTTP. Mirrors mcp_exploit_server.py flags
// (HTTP on :8001, --workspace, --expected-config-sha256 fingerprint gate).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/braydos-h/BreachPilot/internal/mcpserve"
)

func main() {
	transport := flag.String("transport", "stdio", "stdio|http")
	configPath := flag.String("config", "config.yaml", "Config file")
	host := flag.String("host", "127.0.0.1", "HTTP bind host (loopback only)")
	port := flag.Int("port", 8001, "HTTP bind port")
	allowPublic := flag.Bool("allow-public-bind", false, "Allow non-loopback bind (requires MCP_ALLOW_PUBLIC_BIND=1)")
	workspace := flag.String("workspace", "", "Isolated workspace dir (default exploit.workspace_dir)")
	runID := flag.String("run-id", "", "Run ID for audit isolation (default mcp-session)")
	sidecar := flag.String("sidecar-addr", "", "Rust sidecar addr (default fail-closed: sandbox commands blocked)")
	wantSHA := flag.String("expected-config-sha256", "", "Require this hex sha256 of the config file")
	flag.Parse()
	if err := mcpserve.CheckConfigFingerprint(*configPath, *wantSHA); err != nil {
		fmt.Fprintln(os.Stderr, "fingerprint:", err)
		os.Exit(1)
	}
	srv, _, err := mcpserve.AssessFromConfig(*configPath, mcpserve.AssessOptions{
		WorkspaceDir: *workspace, RunID: *runID, SidecarAddr: *sidecar,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()
	if err := mcpserve.Serve(ctx, srv, *transport, *host, *port, *allowPublic); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}
