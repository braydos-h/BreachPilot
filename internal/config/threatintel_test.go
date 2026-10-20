package config_test

// Slice 8 RED: the threat_intel block must be parsed into Config.ThreatIntel.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/config"
)

func TestThreatIntelBlockParsed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	body := "api:\n  host: 127.0.0.1\n  port: 8765\nmodels:\n  provider: ollama\n  default_alias: glm\n" +
		"threat_intel:\n  enabled: true\n  cache_ttl_seconds: 3600\n  max_results: 5\n" +
		"  github_token_env: GH_TOKEN\n  timeout_seconds: 10\n" +
		"  sources:\n    osv: true\n    ghsa: false\n    kev: true\n    exploitdb_rss: false\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	ti := cfg.ThreatIntel
	if !ti.Enabled || ti.MaxResults != 5 || ti.TimeoutSeconds != 10 || ti.GitHubTokenEnv != "GH_TOKEN" {
		t.Fatalf("threat_intel tunables lost: %+v", ti)
	}
	if !ti.Sources["osv"] || ti.Sources["ghsa"] || !ti.Sources["kev"] {
		t.Fatalf("threat_intel sources lost: %+v", ti.Sources)
	}
}
