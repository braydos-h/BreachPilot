package secrets_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/secrets"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secr.json")
	written, err := secrets.Save(p, map[string]string{"NVD_API_KEY": "s3cr3t"})
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 || written[0] != "NVD_API_KEY" {
		t.Fatalf("written: %v", written)
	}
	loaded, err := secrets.Load(p)
	if err != nil || loaded["NVD_API_KEY"] != "s3cr3t" {
		t.Fatalf("loaded: %v %v", loaded, err)
	}
	if v := os.Getenv("NVD_API_KEY"); v != "s3cr3t" {
		t.Fatal("save must mirror into environment")
	}
	_ = os.Unsetenv("NVD_API_KEY")
	fi, _ := os.Stat(p)
	// Windows Go only honours the read-only bit: 0600 is best-effort there
	// (same caveat as the Python implementation). Enforce on POSIX.
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("store must be 0600, got %o", fi.Mode().Perm())
	}
}

func TestBareMapFallback(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secr.json")
	_ = os.WriteFile(p, []byte(`{"GITHUB_TOKEN":"abc"}`), 0o600)
	loaded, err := secrets.Load(p)
	if err != nil || loaded["GITHUB_TOKEN"] != "abc" {
		t.Fatalf("bare: %v %v", loaded, err)
	}
}

func TestMissingFileYieldsEmpty(t *testing.T) {
	loaded, err := secrets.Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || len(loaded) != 0 {
		t.Fatalf("missing: %v %v", loaded, err)
	}
}

func TestEmptyValueRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secr.json")
	if _, err := secrets.Save(p, map[string]string{"NVD_API_KEY": ""}); err == nil {
		t.Fatal("empty value must be rejected")
	}
}
