// Package ollama implements the Ollama discovery surface over plain HTTP:
// GET {host}/api/tags (5s timeout, optional Bearer from the key env),
// registry refresh computation (family index, max version wins, same-tag
// preferred), and health. Mirrors tools/providers/ollama_provider.py.
package ollama

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Model is a live model entry.
type Model struct {
	Name string `json:"name"`
}

// ListModels queries /api/tags. On failure it returns the error so callers
// can fall back to the configured registry with a 503 (Python parity).
func ListModels(host, apiKeyEnv string, timeout time.Duration) ([]Model, error) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	url := strings.TrimRight(host, "/") + "/api/tags"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if key := os.Getenv(apiKeyEnv); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama tags: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ollama tags: status %d", resp.StatusCode)
	}
	var data struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	var out []Model
	for _, m := range data.Models {
		if m.Name != "" {
			out = append(out, Model{Name: m.Name})
		}
	}
	return out, nil
}

// RegistryUpdate describes one alias change.
type RegistryUpdate struct {
	Old string `json:"old"`
	New string `json:"new"`
}

var versionRe = regexp.MustCompile(`[-._]?v?(\d+(?:\.\d+)*)$`)

// parseModelSpec splits a spec into (family, version), mirroring
// parse_model_spec: base is the pre-tag part, family is base minus a
// trailing version suffix, version is the numeric tuple (nil when absent).
func parseModelSpec(spec string) (string, []int) {
	base := spec
	if i := strings.Index(base, ":"); i >= 0 {
		base = base[:i]
	}
	base = strings.TrimSpace(base)
	m := versionRe.FindStringSubmatch(base)
	if m == nil {
		return base, nil
	}
	var ver []int
	for _, p := range strings.Split(m[1], ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return base, nil
		}
		ver = append(ver, n)
	}
	fam := base[:len(base)-len(m[0])]
	if fam == "" {
		fam = base
	}
	return fam, ver
}

func cmpVersion(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// ComputeUpdates ports compute_registry_updates: per alias, find available
// models in the same family, take the max version (skip when not newer),
// prefer the spec's tag among max-version candidates.
func ComputeUpdates(registry map[string]string, available []string) map[string]RegistryUpdate {
	type cand struct {
		ver  []int
		tag  string
		name string
	}
	index := map[string][]cand{}
	for _, name := range available {
		fam, ver := parseModelSpec(name)
		if ver == nil || fam == "" {
			continue
		}
		index[fam] = append(index[fam], cand{ver: ver, tag: tagOf(name), name: name})
	}
	updates := map[string]RegistryUpdate{}
	for alias, spec := range registry {
		fam, ver := parseModelSpec(spec)
		if ver == nil {
			continue
		}
		cands := index[fam]
		if len(cands) == 0 {
			continue
		}
		best := cands[0]
		for _, c := range cands[1:] {
			if cmpVersion(c.ver, best.ver) > 0 {
				best = c
			}
		}
		if cmpVersion(best.ver, ver) <= 0 {
			continue
		}
		tag := tagOf(spec)
		newSpec := best.name
		for _, c := range cands {
			if cmpVersion(c.ver, best.ver) == 0 && c.tag == tag {
				newSpec = c.name
				break
			}
		}
		if newSpec != spec {
			updates[alias] = RegistryUpdate{Old: spec, New: newSpec}
		}
	}
	return updates
}

func tagOf(spec string) string {
	if i := strings.Index(spec, ":"); i >= 0 {
		return strings.ToLower(spec[i+1:])
	}
	return ""
}
