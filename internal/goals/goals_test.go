package goals_test

// Pin the 14 goal presets: unique names, valid risk tiers, and the safety
// invariant that high-risk goals are never auto-compatible.

import (
	"testing"

	"github.com/braydos-h/BreachPilot/internal/goals"
)

func TestPresetsShape(t *testing.T) {
	if len(goals.Presets) != 14 {
		t.Fatalf("presets = %d, want 14", len(goals.Presets))
	}
	seen := map[string]bool{}
	for _, p := range goals.Presets {
		if p.Name == "" || p.Description == "" {
			t.Fatalf("preset missing name/description: %+v", p)
		}
		if seen[p.Name] {
			t.Fatalf("duplicate preset %q", p.Name)
		}
		seen[p.Name] = true
		switch p.Risk {
		case "safe", "gated", "high":
		default:
			t.Fatalf("preset %q has invalid risk %q", p.Name, p.Risk)
		}
		if p.Risk == "high" && p.Compatible {
			t.Fatalf("high-risk preset %q must not be auto-compatible", p.Name)
		}
		if p.Risk == "safe" && !p.Compatible {
			t.Fatalf("safe preset %q must be auto-compatible", p.Name)
		}
	}
	if len(goals.Names()) != 14 {
		t.Fatalf("Names() = %d, want 14", len(goals.Names()))
	}
}

func TestIsPresetCaseInsensitive(t *testing.T) {
	for _, n := range []string{"recon_only", "RECON_ONLY", "Verify_CVEs"} {
		if !goals.IsPreset(n) {
			t.Fatalf("IsPreset(%q) = false, want true", n)
		}
	}
	if goals.IsPreset("nope") {
		t.Fatal("IsPreset(nope) = true, want false")
	}
}
