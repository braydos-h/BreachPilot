package intel_test

// Slice 5 RED: SettingsFor must translate Config.Intel (+NVD_API_KEY) into
// client settings so EPSS/KEV enrichment actually runs when configured.

import (
	"testing"

	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/intel"
)

func TestSettingsForMapsIntel(t *testing.T) {
	cfg := config.Default()
	cfg.Intel.MaxResults = 7
	cfg.Intel.EPSSEnabled = true
	cfg.Intel.KEVEnabled = true
	t.Setenv("NVD_API_KEY", "test-key-123")
	s := intel.SettingsFor(cfg)
	if s.MaxResults != 7 {
		t.Fatalf("MaxResults = %d, want 7", s.MaxResults)
	}
	if !s.EPSSEnabled || !s.KEVEnabled {
		t.Fatalf("epss/kev flags lost: %+v", s)
	}
	if s.APIKey != "test-key-123" {
		t.Fatalf("NVD_API_KEY not picked up: %q", s.APIKey)
	}
}
