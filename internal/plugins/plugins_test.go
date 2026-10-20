package plugins_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/plugins"
)

const manifest = `name: demo_scan
version: 0.1.0
description: Demo scanner.
author: BreachPilot
capabilities: [mcp_tool, attack_module]
enabled: false
target_touching: true
provides_mcp_tools: [demo_scan]
`

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	plugDir := filepath.Join(dir, "demo")
	if err := os.MkdirAll(plugDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugDir, "plugin.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	// Dir without manifest is skipped.
	_ = os.MkdirAll(filepath.Join(dir, "empty"), 0o755)
	found := plugins.Discover(dir)
	if len(found) != 1 {
		t.Fatalf("discover: %+v", found)
	}
	p := found[0]
	if p.Name != "demo_scan" || len(p.Capabilities) != 2 || !p.TargetTouching || p.Enabled {
		t.Fatalf("manifest: %+v", p)
	}
}

func TestDiscoverMissingDir(t *testing.T) {
	if found := plugins.Discover(filepath.Join(t.TempDir(), "nope")); len(found) != 0 {
		t.Fatalf("missing dir must yield empty: %+v", found)
	}
}
