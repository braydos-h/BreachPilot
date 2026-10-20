package skills_test

// Slice 22 RED: native skill executor engine covering all skill archetypes
// (web/XSS/SQLi, AD/ACL/network, SLA/aging/KPI processors, CVE/KEV/EPSS)
// with allowlist enforcement.

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/skills"
)

func TestExecuteSkillNativeArchetypesAndAllowlist(t *testing.T) {
	st := skills.NewStore([]string{filepath.Join("..", "..", "skills")})

	// 1. Out-of-scope target is rejected when target is supplied
	_, err := st.Execute(context.Background(), "analyzing-active-directory-acl-abuse", map[string]any{
		"target": "192.0.2.88",
	}, []string{"127.0.0.1"}, true)
	if err == nil {
		t.Fatal("skill execution with out-of-scope target must be rejected")
	}

	// 2. In-scope AD/network skill executes mapped native modules and returns methodology
	res, err := st.Execute(context.Background(), "analyzing-active-directory-acl-abuse", map[string]any{
		"target": "127.0.0.1",
	}, []string{"127.0.0.1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res["skill"] != "analyzing-active-directory-acl-abuse" || res["status"] != "completed" {
		t.Fatalf("unexpected skill execution result: %+v", res)
	}

	// 3. Vulnerability aging & SLA processor skill computes aging + SLA compliance natively
	slaRes, err := st.Execute(context.Background(), "building-vulnerability-aging-and-sla-tracking", map[string]any{
		"vulnerabilities": []map[string]any{
			{"cve_id": "CVE-2024-0001", "severity": "Critical", "age_days": 20, "open": true},
			{"cve_id": "CVE-2024-0002", "severity": "High", "age_days": 10, "open": false},
		},
	}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	metrics, ok := slaRes["sla_metrics"].(map[string]any)
	if !ok || metrics["overdue_count"] != 1 {
		t.Fatalf("expected overdue_count=1 in sla_metrics, got %+v", slaRes)
	}
}
