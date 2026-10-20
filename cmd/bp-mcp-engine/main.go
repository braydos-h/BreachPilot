// Command bp-mcp-engine is the native engine MCP server: read-only skill
// search/body, CVE lookup, and run history over stdio or loopback HTTP.
// Mirrors mcp_engine_server.py flags (default stdio, HTTP on :8002).
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
	port := flag.Int("port", 8002, "HTTP bind port")
	allowPublic := flag.Bool("allow-public-bind", false, "Allow non-loopback bind (requires MCP_ALLOW_PUBLIC_BIND=1)")
	flag.Parse()
	srv, _, err := mcpserve.EngineFromConfig(*configPath)
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
