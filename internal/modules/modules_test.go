package modules_test

import (
	"context"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/modules"
)

func TestRegistryHasNetworkFamily(t *testing.T) {
	for _, name := range []string{"resolve", "tcp_scan", "http_probe", "tls_probe"} {
		tool, ok := modules.Registry[name]
		if !ok || tool.Family != "network" || tool.Description == "" {
			t.Fatalf("tool %q missing metadata", name)
		}
	}
	if len(modules.List()) != 4 {
		t.Fatalf("registry size: %d", len(modules.List()))
	}
}

func TestResolveLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := modules.Registry["resolve"].Run(ctx, map[string]any{"target": "127.0.0.1"}, modules.Env{})
	if err != nil || res["ip"] != "127.0.0.1" {
		t.Fatalf("resolve: %+v %v", res, err)
	}
}

func TestTCPScanClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := modules.Registry["tcp_scan"].Run(ctx,
		map[string]any{"target": "127.0.0.1", "ports": "1"}, modules.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res["open"].([]map[string]any)) != 0 || res["scanned"] != 1 {
		t.Fatalf("scan: %+v", res)
	}
}

func TestModulesRejectBadInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := modules.Registry["resolve"].Run(ctx, map[string]any{"target": "not a host!"}, modules.Env{}); err == nil {
		t.Fatal("bad target must fail")
	}
	if _, err := modules.Registry["http_probe"].Run(ctx, map[string]any{"target": "127.0.0.1", "port": float64(9), "path": "nope"}, modules.Env{}); err == nil {
		t.Fatal("relative path must fail")
	}
	// Closed port: connection refused surfaces as a real error, not fake data.
	if _, err := modules.Registry["http_probe"].Run(ctx, map[string]any{"target": "127.0.0.1", "port": float64(9)}, modules.Env{}); err == nil {
		t.Fatal("closed port must fail")
	}
}
