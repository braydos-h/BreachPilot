package config_test

// Slice 5 RED: the cve_lookup block (epss/kev enablement + tunables) must be
// parsed into Config.Intel instead of silently ignored.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/config"
)

func TestIntelBlockParsed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	body := "api:\n  host: 127.0.0.1\n  port: 8765\nmodels:\n  provider: ollama\n  default_alias: glm\n" +
		"cve_lookup:\n  enabled: true\n  max_results: 7\n  rate_limit_seconds: 6.0\n" +
		"  timeout_seconds: 30\n  cache_ttl_seconds: 3600\n  cache_max_entries: 100\n" +
		"  circuit_failure_threshold: 5\n  circuit_recovery_timeout: 60.0\n" +
		"  epss_enabled: true\n  kev_enabled: true\n  kev_cache_ttl_seconds: 86400\n  kev_cache_path: /tmp/kev.json\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Intel.EPSSEnabled || !cfg.Intel.KEVEnabled {
		t.Fatalf("epss/kev enablement lost: %+v", cfg.Intel)
	}
	if cfg.Intel.MaxResults != 7 || cfg.Intel.KEVCachePath != "/tmp/kev.json" {
		t.Fatalf("intel tunables lost: %+v", cfg.Intel)
	}
}

func TestIntelDefaultsSafe(t *testing.T) {
	cfg := config.Default()
	if !cfg.Intel.Enabled || !cfg.Intel.EPSSEnabled || !cfg.Intel.KEVEnabled {
		t.Fatalf("intel defaults must mirror config.yaml (enabled + epss/kev on): %+v", cfg.Intel)
	}
}
