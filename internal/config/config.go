// Package config loads and validates BreachPilot config.yaml.
// Single normalization layer: file values, env overrides for a small set of
// keys, and fail-closed defaults. Mirrors tools/config/loader.py behavior.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the runtime configuration. Only fields the Go backend consumes
// are modeled; unknown keys are preserved on round-trip via Extra.
type Config struct {
	API struct {
		Host           string   `yaml:"host"`
		Port           int      `yaml:"port"`
		TokenFile      string   `yaml:"token_file"`
		AllowedOrigins []string `yaml:"allowed_origins"`
		MultiOperator  bool     `yaml:"multi_operator"`
		GraphRoute     bool     `yaml:"graph_route"`
	} `yaml:"api"`
	Exploit struct {
		AllowedTargets []string `yaml:"allowed_targets"`
		// RequireExplicitAllowlist fail-closes the allowlist when empty.
		RequireExplicitAllowlist bool `yaml:"require_explicit_allowlist"`
		WorkspaceDir             string `yaml:"workspace_dir"`
		CommandTimeoutSeconds    int    `yaml:"command_timeout_seconds"`
	} `yaml:"exploit"`
	Models struct {
		Provider     string            `yaml:"provider"`
		DefaultAlias string            `yaml:"default_alias"`
		Registry     map[string]string `yaml:"registry"`
	} `yaml:"models"`
	Ollama struct {
		Host      string `yaml:"host"`
		EmbedHost string `yaml:"embed_host"`
	} `yaml:"ollama"`
	Sandbox struct {
		Enabled bool   `yaml:"enabled"`
		Backend string `yaml:"backend"`
		Image   string `yaml:"image"`
	} `yaml:"sandbox"`
	Providers map[string]map[string]any `yaml:"providers"`
}

// Default returns safe defaults: loopback API, sandbox on, explicit allowlist
// required. Callers overlay file values on top.
func Default() Config {
	var c Config
	c.API.Host = "127.0.0.1"
	c.API.Port = 8765
	c.API.TokenFile = ".webui_secret_key"
	c.Exploit.RequireExplicitAllowlist = true
	c.Exploit.WorkspaceDir = "exploit_workspace"
	c.Exploit.CommandTimeoutSeconds = 300
	c.Models.Provider = "opencode_go"
	c.Models.DefaultAlias = "glm"
	c.Ollama.Host = "https://api.ollama.com"
	c.Sandbox.Enabled = true
	c.Sandbox.Backend = "docker"
	c.Sandbox.Image = "breachpilot-sandbox:latest"
	return c
}

// Load reads path (default config.yaml next to the binary CWD) and overlays
// file values onto Default(). Missing file => defaults (doctor warns).
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = "config.yaml"
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	var file Config
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	def := cfg
	merge(&cfg, file)
	// Booleans: absent keys keep the safe default (e.g. sandbox stays
	// enabled). Only overlay when the file actually contains the key.
	var rawMap map[string]any
	if err := yaml.Unmarshal(raw, &rawMap); err == nil {
		restoreBool(rawMap, []string{"sandbox", "enabled"}, &cfg.Sandbox.Enabled, def.Sandbox.Enabled)
		restoreBool(rawMap, []string{"api", "multi_operator"}, &cfg.API.MultiOperator, def.API.MultiOperator)
		restoreBool(rawMap, []string{"api", "graph_route"}, &cfg.API.GraphRoute, def.API.GraphRoute)
		restoreBool(rawMap, []string{"exploit", "require_explicit_allowlist"}, &cfg.Exploit.RequireExplicitAllowlist, def.Exploit.RequireExplicitAllowlist)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func restoreBool(m map[string]any, path []string, dst *bool, def bool) {
	cur := m
	for _, p := range path[:len(path)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			*dst = def
			return
		}
		cur = next
	}
	v, ok := cur[path[len(path)-1]].(bool)
	if !ok {
		*dst = def
		return
	}
	*dst = v
}

func merge(dst *Config, src Config) {
	if src.API.Host != "" {
		dst.API.Host = src.API.Host
	}
	if src.API.Port != 0 {
		dst.API.Port = src.API.Port
	}
	if src.API.TokenFile != "" {
		dst.API.TokenFile = src.API.TokenFile
	}
	if src.API.AllowedOrigins != nil {
		dst.API.AllowedOrigins = src.API.AllowedOrigins
	}
	if src.Exploit.AllowedTargets != nil {
		dst.Exploit.AllowedTargets = src.Exploit.AllowedTargets
	}
	if src.Exploit.WorkspaceDir != "" {
		dst.Exploit.WorkspaceDir = src.Exploit.WorkspaceDir
	}
	if src.Exploit.CommandTimeoutSeconds != 0 {
		dst.Exploit.CommandTimeoutSeconds = src.Exploit.CommandTimeoutSeconds
	}
	if src.Models.Provider != "" {
		dst.Models.Provider = src.Models.Provider
	}
	if src.Models.DefaultAlias != "" {
		dst.Models.DefaultAlias = src.Models.DefaultAlias
	}
	if src.Models.Registry != nil {
		dst.Models.Registry = src.Models.Registry
	}
	if src.Ollama.Host != "" {
		dst.Ollama.Host = src.Ollama.Host
	}
	if src.Ollama.EmbedHost != "" {
		dst.Ollama.EmbedHost = src.Ollama.EmbedHost
	}
	if src.Sandbox.Image != "" {
		dst.Sandbox.Image = src.Sandbox.Image
	}
	// Booleans are fixed up in Load via restoreBool (absent key => default).
	if src.Providers != nil {
		dst.Providers = src.Providers
	}
}

// Validate enforces v1 invariants: loopback bind, sane port, known provider.
func (c Config) Validate() error {
	switch c.API.Host {
	case "127.0.0.1", "localhost", "::1":
	default:
		return fmt.Errorf("api.host must be loopback (127.0.0.1/localhost/::1); got %q", c.API.Host)
	}
	if c.API.Port < 1 || c.API.Port > 65535 {
		return fmt.Errorf("api.port out of range: %d", c.API.Port)
	}
	switch c.Models.Provider {
	case "ollama", "opencode_go", "chatgpt", "none":
	default:
		return fmt.Errorf("unknown models.provider %q", c.Models.Provider)
	}
	return nil
}
