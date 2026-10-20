package diag_test

import (
	"testing"

	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/diag"
)

func TestDoctorClean(t *testing.T) {
	cfg := config.Default()
	code, out := diag.Doctor(cfg)
	if code != 0 {
		t.Fatalf("doctor exit %d: %s", code, out)
	}
}

func TestDoctorFailsClosed(t *testing.T) {
	cfg := config.Default()
	cfg.Exploit.AllowedTargets = nil
	cfg.Exploit.RequireExplicitAllowlist = true
	code, out := diag.Doctor(cfg)
	if code == 0 {
		t.Fatalf("empty allowlist must fail: %s", out)
	}
}

func TestSelfTestPasses(t *testing.T) {
	if code, out := diag.SelfTest(config.Default()); code != 0 {
		t.Fatalf("self-test exit %d: %s", code, out)
	}
}

func TestSidecarProbeShape(t *testing.T) {
	// No assertion on reachability (env-dependent); must simply not panic.
	_ = diag.SidecarReachable()
}
