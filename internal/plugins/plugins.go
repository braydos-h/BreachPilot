// Package plugins provides real plugin discovery over plugins/*/plugin.yaml
// and native execution for all 15 BreachPilot plugins.
package plugins

import (
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Plugin is the API-facing manifest.
type Plugin struct {
	Name             string         `json:"name" yaml:"name"`
	Version          string         `json:"version" yaml:"version"`
	Description      string         `json:"description" yaml:"description"`
	Author           string         `json:"author" yaml:"author"`
	Capabilities     []string       `json:"capabilities" yaml:"capabilities"`
	Enabled          bool           `json:"enabled" yaml:"enabled"`
	NeedsHostFS      bool           `json:"needs_host_fs" yaml:"needs_host_fs"`
	NeedsNet         bool           `json:"needs_net" yaml:"needs_net"`
	TargetTouching   bool           `json:"target_touching" yaml:"target_touching"`
	ProvidesMCPTools []string       `json:"provides_mcp_tools" yaml:"provides_mcp_tools"`
	ConfigSection    map[string]any `json:"config_section,omitempty" yaml:"config_section"`
	Dir              string         `json:"-" yaml:"-"`
}

// Discover scans dir (default "plugins") for */plugin.yaml manifests.
func Discover(dir string) []Plugin {
	if dir == "" {
		dir = "plugins"
	}
	entries, err := os.ReadDir(filepath.Clean(dir))
	if err != nil {
		return []Plugin{}
	}
	var out []Plugin
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name(), "plugin.yaml"))
		if err != nil {
			continue
		}
		p := parseManifest(string(raw))
		p.Dir = filepath.Join(dir, e.Name())
		if p.Name == "" {
			p.Name = e.Name()
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func parseManifest(text string) Plugin {
	var p Plugin
	_ = yaml.Unmarshal([]byte(text), &p)
	if p.Capabilities == nil {
		p.Capabilities = []string{}
	}
	if p.ProvidesMCPTools == nil {
		p.ProvidesMCPTools = []string{}
	}
	return p
}
