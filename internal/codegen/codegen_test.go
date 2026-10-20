package codegen_test

// Slice 22 RED: native Go replacement for scripts/*.py (skill catalog,
// MCP tool catalog, capability counts, and release gate).

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/codegen"
)

func TestNativeCodegenAndReleaseGate(t *testing.T) {
	root := filepath.Join("..", "..")
	counts, err := codegen.CapabilityCounts(root)
	if err != nil {
		t.Fatal(err)
	}
	if counts.AttackModules < 91 || counts.Plugins < 15 || counts.Skills < 100 {
		t.Fatalf("unexpected capability counts: %+v", counts)
	}

	skCat, err := codegen.SkillCatalogMarkdown(filepath.Join(root, "skills"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(skCat, "# Skill Catalog") {
		t.Fatalf("invalid skill catalog markdown")
	}

	mcpCat := codegen.MCPCatalogMarkdown()
	if !strings.Contains(mcpCat, "search_skills") || !strings.Contains(mcpCat, "run_nmap_triage_scan") {
		t.Fatalf("invalid MCP catalog markdown: %s", mcpCat)
	}

	gate := codegen.RunReleaseGate(root, false)
	if !gate.VersionsMatch {
		t.Fatalf("expected version check pass: %+v", gate)
	}
}
