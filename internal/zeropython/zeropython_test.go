package zeropython

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanFlagsPyAndManifests(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tools", "x.py"), "print(1)\n")
	writeFile(t, filepath.Join(root, "pyproject.toml"), "[project]\n")
	rep, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.PyFiles) != 1 {
		t.Fatalf("PyFiles = %v, want 1", rep.PyFiles)
	}
	if len(rep.Manifests) != 1 {
		t.Fatalf("Manifests = %v, want 1", rep.Manifests)
	}
	if !rep.Strict() {
		t.Fatal("Strict should fail while Python remains")
	}
}

func TestScanCleanTreePasses(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "internal", "a", "a.go"), "package a\n")
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.24\n")
	rep, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Strict() {
		t.Fatalf("clean tree should pass, got %+v", rep)
	}
}

func TestScanSkipsBuildDirs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".git", "hook.py"), "x\n")
	writeFile(t, filepath.Join(root, "webui", "dist", "bundle.py"), "x\n")
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/x\n\ngo 1.24\n")
	rep, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.PyFiles) != 0 {
		t.Fatalf("build/VCS dirs must be skipped, got %v", rep.PyFiles)
	}
}

func TestMigrationDocsExist(t *testing.T) {
	// Guard the audit trail: these docs must travel with the migration.
	for _, f := range []string{
		"docs/native-migration/PLAN.md",
		"docs/native-migration/INVENTORY.md",
		"docs/native-migration/PARITY.md",
		"docs/native-migration/PROGRESS.md",
		"docs/native-migration/BLOCKERS.md",
	} {
		if _, err := os.Stat(filepath.Join("..", "..", f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
}

func TestRepositoryPassesStrictZeroPythonGate(t *testing.T) {
	rep, err := Scan(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Strict() {
		t.Fatalf("repository failed strict zero-Python gate: py=%v manifests=%v refs=%v native=%v",
			rep.PyFiles, rep.Manifests, rep.References, rep.NativeCalls)
	}
}
