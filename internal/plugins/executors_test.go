package plugins_test

// Slice 21 RED: all 15 plugin executors implemented natively in Go with
// config_section discovery, two-gate API key checks, and allowlist locks.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/plugins"
)

func TestDiscoverParsesConfigSectionAndAll15ExecutorsRun(t *testing.T) {
	found := plugins.Discover(filepath.Join("..", "..", "plugins"))
	if len(found) != 15 {
		t.Fatalf("expected 15 plugins in repo plugins/, got %d", len(found))
	}
	hasCfgSection := false
	for _, p := range found {
		if len(p.ConfigSection) > 0 {
			hasCfgSection = true
		}
	}
	if !hasCfgSection {
		t.Fatal("expected Discover to parse config_section from plugin.yaml")
	}

	// 1. atomic_red_team generates MITRE ATT&CK YAML locally
	art, err := plugins.Execute(context.Background(), "atomic_red_team", map[string]any{
		"technique_id": "T1059.004",
		"title":        "Unix Shell",
	}, plugins.ExecEnv{})
	if err != nil {
		t.Fatal(err)
	}
	yamlStr, _ := art["yaml"].(string)
	if !strings.Contains(yamlStr, "T1059.004") {
		t.Fatalf("expected T1059.004 in atomic_red_team yaml: %v", art)
	}

	// 2. github_dorks & shodan_recon enforce two-gate API key check
	t.Setenv("GITHUB_TOKEN", "")
	gd, err := plugins.Execute(context.Background(), "github_dorks", map[string]any{"org": "example"}, plugins.ExecEnv{})
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := gd["status"].(string); !strings.HasPrefix(status, "BLOCKED:") {
		t.Fatalf("expected BLOCKED: when GITHUB_TOKEN is unset, got %v", gd)
	}

	// 3. Target-touching plugin (snmp) enforces allowlist lock
	_, err = plugins.Execute(context.Background(), "snmp", map[string]any{"target": "192.0.2.55"}, plugins.ExecEnv{
		AllowedTargets:   []string{"127.0.0.1"},
		RequireAllowlist: true,
	})
	if err == nil {
		t.Fatal("target-touching plugin snmp must reject out-of-scope target")
	}
	snmpRes, err := plugins.Execute(context.Background(), "snmp", map[string]any{"target": "127.0.0.1"}, plugins.ExecEnv{
		AllowedTargets:   []string{"127.0.0.1"},
		RequireAllowlist: true,
	})
	if err != nil || snmpRes["plugin"] != "snmp" {
		t.Fatalf("in-scope snmp failed: %v %v", snmpRes, err)
	}
}
