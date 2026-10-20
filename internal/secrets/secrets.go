// Package secrets implements the local API-key store (secr.json).
// Mirrors tools/api_key_store.py: {"version":1,"updated_at":iso,
// "api_keys":{ENV:value}}, atomic write, 0600, loader tolerates bare maps.
// Values are never returned through the API — only configured|missing.
package secrets

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// KnownKeyEnvs is the universe of key names PUT /secrets accepts, mirroring
// configured_api_key_env_names (config-driven names resolved by the caller;
// these are the compiled-in defaults).
var KnownKeyEnvs = []string{
	"OLLAMA_API_KEY",
	"OPENCODE_GO_API_KEY",
	"SERPAPI_API_KEY",
	"NVD_API_KEY",
	"GITHUB_TOKEN",
}

func Known(name string) bool {
	for _, k := range KnownKeyEnvs {
		if k == name {
			return true
		}
	}
	return false
}

// Path resolves the store file: BREACHPILOT_API_KEY_FILE else secr.json.
func Path() string {
	if p := os.Getenv("BREACHPILOT_API_KEY_FILE"); p != "" {
		return p
	}
	return "secr.json"
}

// Load reads the store, tolerating bare {ENV: secret} maps. Missing file
// yields an empty map (all keys missing), never an error.
func Load(path string) (map[string]string, error) {
	out := map[string]string{}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("read key store: %w", err)
	}
	var wrapped struct {
		APIKeys map[string]string `json:"api_keys"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("parse key store: %w", err)
	}
	if wrapped.APIKeys != nil {
		return wrapped.APIKeys, nil
	}
	// Bare-map fallback.
	var bare map[string]string
	if err := json.Unmarshal(raw, &bare); err != nil {
		return nil, fmt.Errorf("parse key store: %w", err)
	}
	return bare, nil
}

// Save merges entries into the store atomically (temp + rename, 0600) and
// mirrors them into the process environment like the Python route does.
func Save(path string, entries map[string]string) ([]string, error) {
	current, err := Load(path)
	if err != nil {
		return nil, err
	}
	written := []string{}
	for k, v := range entries {
		if v == "" {
			return nil, fmt.Errorf("empty value for %s", k)
		}
		current[k] = v
		_ = os.Setenv(k, v)
		written = append(written, k)
	}
	doc := map[string]any{
		"version":    1,
		"updated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"api_keys":   current,
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	clean := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(clean), 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(clean), ".secr-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return nil, err
	}
	if err := os.Rename(tmpName, clean); err != nil {
		_ = os.Remove(tmpName)
		return nil, err
	}
	_ = os.Chmod(clean, 0o600)
	return written, nil
}
