// Package zeropython is the native zero-Python migration gate. It scans a
// checkout for first-party Python and active Python runtime/build/test
// references without invoking Python. Report mode powers docs + CI
// visibility mid-migration; Strict (Report.Failing) is the release gate.
package zeropython

import (
	"os"
	"path/filepath"
	"strings"
)

// Manifests that must disappear at cutover.
var manifests = []string{
	"pyproject.toml",
	"requirements.txt",
	"constraints-dev.txt",
	"conftest.py",
	"MANIFEST.in",
}

// RuntimePaths searched for active Python references (docs/history excluded).
var runtimePaths = []string{
	"Dockerfile.native",
	"Makefile",
	"install.sh",
	"install.ps1",
	"install.bat",
	"START.bat",
	"go.mod",
}

// Report is the gate outcome. Failing is true when Python remains.
type Report struct {
	PyFiles     []string
	Manifests   []string
	References  []string
	NativeCalls []string
	Failing     bool
}

// Strict reports whether --strict would fail.
func (r Report) Strict() bool { return r.Failing }

// Scan walks root, skipping VCS/build/output dirs.
func Scan(root string) (Report, error) {
	var rep Report
	skip := map[string]bool{
		".git": true, "node_modules": true, "target": true,
		"dist": true, ".venv": true, "venv": true, "__pycache__": true,
	}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".py") {
			rel, _ := filepath.Rel(root, p)
			rep.PyFiles = append(rep.PyFiles, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return rep, err
	}
	for _, m := range manifests {
		if st, err := os.Stat(filepath.Join(root, m)); err == nil && !st.IsDir() {
			rep.Manifests = append(rep.Manifests, m)
		}
	}
	needles := []string{"python", "pip install", "pytest", "uvicorn", "requirements.txt"}
	for _, rp := range runtimePaths {
		raw, err := os.ReadFile(filepath.Join(root, rp))
		if err != nil {
			continue
		}
		low := strings.ToLower(string(raw))
		for _, n := range needles {
			// shortcut: go.mod only fails on a python package path, not on
			// words like "pip" inside unrelated strings; keep the check
			// literal and case-insensitive.
			if strings.Contains(low, n) {
				rel := filepath.ToSlash(rp)
				rep.References = append(rep.References, rel+":"+n)
				break
			}
		}
	}
	// Native subprocess invocation of Python (the gate's own scanner strings
	// are excluded so the gate does not flag itself).
	for _, dir := range []string{"internal", "cmd", filepath.Join("rust", "crates")} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, ".rs") {
				return nil
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			if filepath.ToSlash(rel) == "internal/zeropython/zeropython.go" {
				return nil
			}
			s := string(raw)
			if strings.Contains(s, `"python"`) || strings.Contains(s, `"python3"`) {
				rel, _ := filepath.Rel(root, p)
				rep.NativeCalls = append(rep.NativeCalls, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	rep.Failing = len(rep.PyFiles) > 0 || len(rep.Manifests) > 0 ||
		len(rep.References) > 0 || len(rep.NativeCalls) > 0
	return rep, nil
}
