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
	"sort"
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

// ComputeUpdates ports compute_registry_updates: for each alias->spec, find
// available models in the same family (prefix before ':'); prefer the exact
// same tag; else take the max version. Returns alias->{old,new}.
func ComputeUpdates(registry map[string]string, available []string) map[string]RegistryUpdate {
	families := map[string][]string{}
	for _, a := range available {
		fam := familyOf(a)
		families[fam] = append(families[fam], a)
	}
	updates := map[string]RegistryUpdate{}
	for alias, spec := range registry {
		fam := familyOf(spec)
		cands := families[fam]
		if len(cands) == 0 {
			continue
		}
		best := ""
		for _, c := range cands {
			if tagOf(c) == tagOf(spec) {
				best = c
				break
			}
		}
		if best == "" {
			pool := append([]string{}, cands...)
			sort.Strings(pool)
			best = pool[len(pool)-1]
		}
		if best != spec {
			updates[alias] = RegistryUpdate{Old: spec, New: best}
		}
	}
	return updates
}

func familyOf(spec string) string {
	if i := strings.Index(spec, ":"); i >= 0 {
		return strings.ToLower(spec[:i])
	}
	return strings.ToLower(spec)
}

func tagOf(spec string) string {
	if i := strings.Index(spec, ":"); i >= 0 {
		return strings.ToLower(spec[i+1:])
	}
	return ""
}
