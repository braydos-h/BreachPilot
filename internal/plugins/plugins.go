// Package plugins provides real plugin discovery over plugins/*/plugin.yaml.
// Mirrors PluginManifest fields (name, version, description, author,
// capabilities, enabled, config_section, needs_host_fs, needs_net,
// target_touching, provides_mcp_tools). Registration of live behavior is
// manifest-driven: capabilities declare what the plugin provides.
package plugins

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Plugin is the API-facing manifest.
type Plugin struct {
	Name             string   `json:"name"`
	Version          string   `json:"version"`
	Description      string   `json:"description"`
	Author           string   `json:"author"`
	Capabilities     []string `json:"capabilities"`
	Enabled          bool     `json:"enabled"`
	NeedsHostFS      bool     `json:"needs_host_fs"`
	NeedsNet         bool     `json:"needs_net"`
	TargetTouching   bool     `json:"target_touching"`
	ProvidesMCPTools []string `json:"provides_mcp_tools"`
	Dir              string   `json:"-"`
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
	vals := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		k := strings.TrimSpace(line[:i])
		v := strings.Trim(strings.TrimSpace(line[i+1:]), `"'`)
		vals[k] = v
	}
	p.Name = vals["name"]
	p.Version = vals["version"]
	p.Description = vals["description"]
	p.Author = vals["author"]
	p.Capabilities = splitList(vals["capabilities"])
	p.ProvidesMCPTools = splitList(vals["provides_mcp_tools"])
	p.Enabled, _ = strconv.ParseBool(vals["enabled"])
	p.NeedsHostFS, _ = strconv.ParseBool(vals["needs_host_fs"])
	p.NeedsNet, _ = strconv.ParseBool(vals["needs_net"])
	p.TargetTouching, _ = strconv.ParseBool(vals["target_touching"])
	if p.Capabilities == nil {
		p.Capabilities = []string{}
	}
	if p.ProvidesMCPTools == nil {
		p.ProvidesMCPTools = []string{}
	}
	return p
}

func splitList(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return []string{}
	}
	v = strings.TrimPrefix(v, "[")
	v = strings.TrimSuffix(v, "]")
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.Trim(strings.TrimSpace(p), `"'`)
		if p != "" {
			out = append(out, p)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}
