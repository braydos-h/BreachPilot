package mcp_test

// Slice 8: search_vulnerability_intel gains the native OSV/GHSA/KEV feed
// (additive key, nil-safe omission) for feed-shaped queries.

import (
	"context"
	"strings"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/mcp"
	"github.com/braydos-h/BreachPilot/internal/threatintel"
)

func TestVulnIntelIncludesThreatFeed(t *testing.T) {
	fetch := func(url, method, body string, headers map[string]string) (any, error) {
		return map[string]any{"vulns": []any{
			map[string]any{"id": "CVE-2024-1234", "summary": "s"},
		}}, nil
	}
	dir := t.TempDir()
	cfg := threatintel.Settings{Enabled: true, CacheDir: dir, CacheTTLSeconds: 60,
		Sources:    map[string]bool{"osv": true, "ghsa": false, "kev": false},
		MaxResults: 20, TimeoutSeconds: 5}
	ti := threatintel.NewClient(cfg, nil, fetch)
	srv := mcp.NewDefensiveServer([]string{"127.0.0.1/32"}, nil, nil, ti)
	res, err := srv.Call(context.Background(), "search_vulnerability_intel", map[string]any{"query": "CVE-2024-1234"})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("unexpected shape %T", res)
	}
	fed, ok := m["threat_intel"].(map[string]any)
	if !ok {
		t.Fatalf("missing threat_intel key: %v", m)
	}
	if !strings.Contains(m["query"].(string), "CVE-2024-1234") {
		t.Fatalf("query not echoed: %v", m)
	}
	osv, _ := fed["sources"].(map[string]any)["osv"].(map[string]any)
	vulns, _ := osv["vulns"].([]any)
	if len(vulns) != 1 {
		t.Fatalf("expected stubbed osv vuln, got %v", fed)
	}
}

func TestVulnIntelOmitsFeedWhenNil(t *testing.T) {
	srv := mcp.NewDefensiveServer([]string{"127.0.0.1/32"}, nil, nil, nil)
	res, err := srv.Call(context.Background(), "search_vulnerability_intel", map[string]any{"query": "CVE-2024-1234"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := res.(map[string]any)["threat_intel"]; ok {
		t.Fatalf("nil client must omit threat_intel, got %v", res)
	}
}
