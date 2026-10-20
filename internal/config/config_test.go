package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/config"
)

func TestLoopbackGate(t *testing.T) {
	cfg := config.Default()
	cfg.API.Host = "0.0.0.0"
	if err := cfg.Validate(); err == nil {
		t.Fatal("public bind must be rejected")
	}
	cfg.API.Host = "127.0.0.1"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMissingFileGivesDefaults(t *testing.T) {
	cfg, err := config.Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.API.Port != 8765 || !cfg.Sandbox.Enabled {
		t.Fatalf("defaults: %+v", cfg.API)
	}
}

func TestOverlay(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(p, []byte("api:\n  port: 9999\nmodels:\n  provider: ollama\n"), 0o600)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.API.Port != 9999 || cfg.Models.Provider != "ollama" {
		t.Fatalf("overlay: %+v", cfg)
	}
}
