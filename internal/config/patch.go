package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// PatchFile atomically merges patch into the YAML file at path (recursive
// map merge, scalars/lists replaced), fixes permissions to 0600, reloads
// and validates. Unknown keys are preserved. Used by PATCH /config,
// POST /models, POST /models/provider so those endpoints persist for real.
func PatchFile(path string, patch map[string]any) (Config, error) {
	clean := filepath.Clean(path)
	raw, err := os.ReadFile(clean)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	mergeMaps(doc, patch)
	out, err := yaml.Marshal(doc)
	if err != nil {
		return Config{}, fmt.Errorf("encode config: %w", err)
	}
	dir := filepath.Dir(clean)
	tmp, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return Config{}, err
	}
	tmpName := tmp.Name()
	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return Config{}, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return Config{}, err
	}
	if err := os.Rename(tmpName, clean); err != nil {
		_ = os.Remove(tmpName)
		return Config{}, err
	}
	_ = os.Chmod(clean, 0o600)
	cfg, err := Load(clean)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func mergeMaps(dst, src map[string]any) {
	for k, v := range src {
		if vm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				mergeMaps(dm, vm)
				continue
			}
		}
		dst[k] = v
	}
}

// DeleteMapKey removes a nested key (e.g. "models","registry",alias) from the
// YAML file, then reloads and validates. Used by DELETE /models/{alias}.
func DeleteMapKey(path string, keyPath ...string) (Config, error) {
	clean := filepath.Clean(path)
	raw, err := os.ReadFile(clean)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	cur := doc
	for _, k := range keyPath[:len(keyPath)-1] {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return Load(clean)
		}
		cur = next
	}
	delete(cur, keyPath[len(keyPath)-1])
	out, err := yaml.Marshal(doc)
	if err != nil {
		return Config{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(clean), ".config-*")
	if err != nil {
		return Config{}, err
	}
	tmpName := tmp.Name()
	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return Config{}, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return Config{}, err
	}
	if err := os.Rename(tmpName, clean); err != nil {
		_ = os.Remove(tmpName)
		return Config{}, err
	}
	return Load(clean)
}
