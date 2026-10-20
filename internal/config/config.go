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
		RequireExplicitAllowlist bool   `yaml:"require_explicit_allowlist"`
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
	// Intel mirrors the cve_lookup block: NVD lookup plus EPSS/KEV enrichment.
	Intel struct {
		Enabled                   bool    `yaml:"enabled"`
		MaxResults                int     `yaml:"max_results"`
		RateLimitSeconds          float64 `yaml:"rate_limit_seconds"`
		TimeoutSeconds            float64 `yaml:"timeout_seconds"`
		CacheTTLSeconds           float64 `yaml:"cache_ttl_seconds"`
		CacheMaxEntries           int     `yaml:"cache_max_entries"`
		APIKeyEnv                 string  `yaml:"api_key_env"`
		CircuitFailureThreshold   int     `yaml:"circuit_failure_threshold"`
		CircuitRecoveryTimeoutSec float64 `yaml:"circuit_recovery_timeout"`
		EPSSEnabled               bool    `yaml:"epss_enabled"`
		KEVEnabled                bool    `yaml:"kev_enabled"`
		KEVCacheTTLSeconds        float64 `yaml:"kev_cache_ttl_seconds"`
		KEVCachePath              string  `yaml:"kev_cache_path"`
	} `yaml:"cve_lookup"`
	// ThreatIntel mirrors the threat_intel block: OSV/GHSA/KEV feed client.
	ThreatIntel struct {
		Enabled         bool            `yaml:"enabled"`
		CacheDir        string          `yaml:"cache_dir"`
		CacheTTLSeconds float64         `yaml:"cache_ttl_seconds"`
		Sources         map[string]bool `yaml:"sources"`
		MaxResults      int             `yaml:"max_results"`
		GitHubTokenEnv  string          `yaml:"github_token_env"`
		TimeoutSeconds  float64         `yaml:"timeout_seconds"`
	} `yaml:"threat_intel"`
	Browser struct {
		Enabled     bool `yaml:"enabled"`
		Headless    bool `yaml:"headless"`
		MaxSessions int  `yaml:"max_sessions"`
	} `yaml:"browser"`
	MultiModel struct {
		Enabled          bool     `yaml:"enabled"`
		ConsultAliases   []string `yaml:"consult_aliases"`
		MaxConsultations int      `yaml:"max_consultations"`
		MaxQuestionChars int      `yaml:"max_question_chars"`
		MaxAnswerChars   int      `yaml:"max_answer_chars"`
	} `yaml:"multi_model"`
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
	c.Intel.Enabled = true
	c.Intel.MaxResults = 5
	c.Intel.RateLimitSeconds = 6.0
	c.Intel.TimeoutSeconds = 30
	c.Intel.CacheTTLSeconds = 3600
	c.Intel.CacheMaxEntries = 100
	c.Intel.APIKeyEnv = "NVD_API_KEY"
	c.Intel.CircuitFailureThreshold = 5
	c.Intel.CircuitRecoveryTimeoutSec = 60.0
	c.Intel.EPSSEnabled = true
	c.Intel.KEVEnabled = true
	c.Intel.KEVCacheTTLSeconds = 86400
	c.ThreatIntel.Enabled = false
	c.ThreatIntel.CacheDir = "exploit_workspace/.threat_intel"
	c.ThreatIntel.CacheTTLSeconds = 86400
	c.ThreatIntel.Sources = map[string]bool{"osv": true, "ghsa": true, "kev": true, "exploitdb_rss": false}
	c.ThreatIntel.MaxResults = 20
	c.ThreatIntel.GitHubTokenEnv = "GITHUB_TOKEN"
	c.ThreatIntel.TimeoutSeconds = 30
	c.Browser.Enabled = false
	c.Browser.Headless = true
	c.Browser.MaxSessions = 2
	c.MultiModel.Enabled = true
	c.MultiModel.ConsultAliases = []string{"kimi", "deepseek", "deepseek_flash", "glm", "minimax"}
	c.MultiModel.MaxConsultations = 10
	c.MultiModel.MaxQuestionChars = 4000
	c.MultiModel.MaxAnswerChars = 8000
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
		restoreBool(rawMap, []string{"browser", "enabled"}, &cfg.Browser.Enabled, def.Browser.Enabled)
		restoreBool(rawMap, []string{"browser", "headless"}, &cfg.Browser.Headless, def.Browser.Headless)
		restoreBool(rawMap, []string{"api", "multi_operator"}, &cfg.API.MultiOperator, def.API.MultiOperator)
		restoreBool(rawMap, []string{"api", "graph_route"}, &cfg.API.GraphRoute, def.API.GraphRoute)
		restoreBool(rawMap, []string{"exploit", "require_explicit_allowlist"}, &cfg.Exploit.RequireExplicitAllowlist, def.Exploit.RequireExplicitAllowlist)
		restoreBool(rawMap, []string{"cve_lookup", "enabled"}, &cfg.Intel.Enabled, def.Intel.Enabled)
		restoreBool(rawMap, []string{"cve_lookup", "epss_enabled"}, &cfg.Intel.EPSSEnabled, def.Intel.EPSSEnabled)
		restoreBool(rawMap, []string{"cve_lookup", "kev_enabled"}, &cfg.Intel.KEVEnabled, def.Intel.KEVEnabled)
		restoreBool(rawMap, []string{"threat_intel", "enabled"}, &cfg.ThreatIntel.Enabled, def.ThreatIntel.Enabled)
		restoreBool(rawMap, []string{"multi_model", "enabled"}, &cfg.MultiModel.Enabled, def.MultiModel.Enabled)
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
	if src.Intel.MaxResults != 0 {
		dst.Intel.MaxResults = src.Intel.MaxResults
	}
	if src.Intel.RateLimitSeconds != 0 {
		dst.Intel.RateLimitSeconds = src.Intel.RateLimitSeconds
	}
	if src.Intel.TimeoutSeconds != 0 {
		dst.Intel.TimeoutSeconds = src.Intel.TimeoutSeconds
	}
	if src.Intel.CacheTTLSeconds != 0 {
		dst.Intel.CacheTTLSeconds = src.Intel.CacheTTLSeconds
	}
	if src.Intel.CacheMaxEntries != 0 {
		dst.Intel.CacheMaxEntries = src.Intel.CacheMaxEntries
	}
	if src.Intel.APIKeyEnv != "" {
		dst.Intel.APIKeyEnv = src.Intel.APIKeyEnv
	}
	if src.Intel.CircuitFailureThreshold != 0 {
		dst.Intel.CircuitFailureThreshold = src.Intel.CircuitFailureThreshold
	}
	if src.Intel.CircuitRecoveryTimeoutSec != 0 {
		dst.Intel.CircuitRecoveryTimeoutSec = src.Intel.CircuitRecoveryTimeoutSec
	}
	if src.Intel.KEVCacheTTLSeconds != 0 {
		dst.Intel.KEVCacheTTLSeconds = src.Intel.KEVCacheTTLSeconds
	}
	if src.Intel.KEVCachePath != "" {
		dst.Intel.KEVCachePath = src.Intel.KEVCachePath
	}
	if src.ThreatIntel.CacheDir != "" {
		dst.ThreatIntel.CacheDir = src.ThreatIntel.CacheDir
	}
	if src.ThreatIntel.CacheTTLSeconds != 0 {
		dst.ThreatIntel.CacheTTLSeconds = src.ThreatIntel.CacheTTLSeconds
	}
	if src.ThreatIntel.Sources != nil {
		dst.ThreatIntel.Sources = src.ThreatIntel.Sources
	}
	if src.ThreatIntel.MaxResults != 0 {
		dst.ThreatIntel.MaxResults = src.ThreatIntel.MaxResults
	}
	if src.ThreatIntel.GitHubTokenEnv != "" {
		dst.ThreatIntel.GitHubTokenEnv = src.ThreatIntel.GitHubTokenEnv
	}
	if src.ThreatIntel.TimeoutSeconds != 0 {
		dst.ThreatIntel.TimeoutSeconds = src.ThreatIntel.TimeoutSeconds
	}
	if src.Browser.MaxSessions != 0 {
		dst.Browser.MaxSessions = src.Browser.MaxSessions
	}
	if src.MultiModel.ConsultAliases != nil {
		dst.MultiModel.ConsultAliases = src.MultiModel.ConsultAliases
	}
	if src.MultiModel.MaxConsultations != 0 {
		dst.MultiModel.MaxConsultations = src.MultiModel.MaxConsultations
	}
	if src.MultiModel.MaxQuestionChars != 0 {
		dst.MultiModel.MaxQuestionChars = src.MultiModel.MaxQuestionChars
	}
	if src.MultiModel.MaxAnswerChars != 0 {
		dst.MultiModel.MaxAnswerChars = src.MultiModel.MaxAnswerChars
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
