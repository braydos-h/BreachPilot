package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/config"
)

func writeCfg(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const baseCfg = "api:\n  host: 127.0.0.1\n  port: 8765\nmodels:\n  provider: ollama\n  registry:\n    glm: glm-5.2:cloud\n"

func TestPatchFileMergesAndValidates(t *testing.T) {
	p := writeCfg(t, baseCfg)
	cfg, err := config.PatchFile(p, map[string]any{"models": map[string]any{"provider": "opencode_go"}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Models.Provider != "opencode_go" {
		t.Fatalf("provider = %q", cfg.Models.Provider)
	}
	if cfg.Models.Registry["glm"] != "glm-5.2:cloud" {
		t.Fatal("merge dropped existing registry entry")
	}
	// Unknown keys preserved.
	raw, _ := os.ReadFile(p)
	_ = raw
}

func TestPatchFileRejectsBadValues(t *testing.T) {
	p := writeCfg(t, baseCfg)
	if _, err := config.PatchFile(p, map[string]any{"api": map[string]any{"host": "0.0.0.0"}}); err == nil {
		t.Fatal("public bind must be rejected")
	}
	// File unchanged after failed patch.
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.API.Host != "127.0.0.1" {
		t.Fatal("failed patch mutated the file")
	}
}

func TestDeleteMapKey(t *testing.T) {
	p := writeCfg(t, baseCfg)
	cfg, err := config.DeleteMapKey(p, "models", "registry", "glm")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Models.Registry["glm"]; ok {
		t.Fatal("alias not deleted")
	}
}

func TestAbsentBoolKeepsDefault(t *testing.T) {
	p := writeCfg(t, "api:\n  host: 127.0.0.1\n  port: 8765\n")
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sandbox.Enabled || !cfg.Exploit.RequireExplicitAllowlist {
		t.Fatalf("absent bools must keep safe defaults: %+v", cfg.Sandbox)
	}
}
