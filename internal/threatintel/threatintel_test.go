package threatintel_test

// Slice 8 RED: native OSV/GHSA/KEV threat intel must validate queries
// (SSRF guard), sanitize wire output (prompt-injection hardening), cache,
// and degrade without a GitHub token — before the implementation exists.

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/threatintel"
)

func TestValidateQuery(t *testing.T) {
	if q, err := threatintel.ValidateQuery("cve-2024-1234"); err != nil || q != "CVE-2024-1234" {
		t.Fatalf("CVE should normalize to upper: %q %v", q, err)
	}
	if q, err := threatintel.ValidateQuery("lodash"); err != nil || q != "lodash" {
		t.Fatalf("package should pass: %q %v", q, err)
	}
	for _, bad := range []string{"", "http://169.254.169.254/", "a; rm -rf /", strings.Repeat("a", 129), "foo bar"} {
		if _, err := threatintel.ValidateQuery(bad); err == nil {
			t.Fatalf("query %q must be rejected", bad)
		}
	}
}

func TestCleanugeotHardening(t *testing.T) {
	out := threatintel.Clean("ab\x00cd\n" + strings.Repeat("x", 300))
	s, ok := out.(string)
	if !ok {
		t.Fatalf("Clean should return a string, got %T", out)
	}
	if strings.ContainsAny(s, "\x00\n\r\t") {
		t.Fatalf("control chars must be stripped: %q", s)
	}
	if len(s) > 200 {
		t.Fatalf("output must be capped at 200 chars, got %d", len(s))
	}
}

func TestSearchOSVWithCache(t *testing.T) {
	var calls atomic.Int32
	fetch := func(url, method, body string, headers map[string]string) (any, error) {
		calls.Add(1)
		if !strings.Contains(url, "osv.dev") {
			t.Fatalf("unexpected endpoint %s", url)
		}
		return map[string]any{"vulns": []any{
			map[string]any{"id": "CVE-2024-0001\x00", "summary": "s", "aliases": []any{"A"},
				"published": "2024-01-01", "references": []any{map[string]any{"url": "https://x"}}},
		}}, nil
	}
	dir := t.TempDir()
	cfg := threatintel.Settings{Enabled: true, CacheDir: dir, CacheTTLSeconds: 86400, Sources: map[string]bool{"osv": true}, MaxResults: 20, TimeoutSeconds: 5}
	c := threatintel.NewClient(cfg, nil, fetch)
	res, err := c.Search(context.Background(), "lodash", "osv")
	if err != nil {
		t.Fatal(err)
	}
	src, ok := res["sources"].(map[string]any)["osv"].(map[string]any)
	if !ok {
		t.Fatalf("missing osv sources: %v", res)
	}
	vulns, _ := src["vulns"].([]any)
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %v", src)
	}
	if _, err := c.Search(context.Background(), "lodash", "osv"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("second identical query must hit cache, fetch calls = %d", calls.Load())
	}
}

func TestSearchDegradesWithoutToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	dir := t.TempDir()
	cfg := threatintel.Settings{Enabled: true, CacheDir: dir, CacheTTLSeconds: 86400,
		Sources: map[string]bool{"osv": false, "ghsa": true, "kev": false}, MaxResults: 20, TimeoutSeconds: 5, GitHubTokenEnv: "GITHUB_TOKEN"}
	c := threatintel.NewClient(cfg, nil, nil)
	res, err := c.Search(context.Background(), "CVE-2024-1234", "ghsa,kev")
	if err != nil {
		t.Fatal(err)
	}
	ghsa, _ := res["sources"].(map[string]any)["ghsa"].(map[string]any)
	if ghsa["skipped"] == nil {
		t.Fatalf("ghsa without token must degrade to skipped, got %v", res)
	}
}
