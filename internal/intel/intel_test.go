package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const sampleNVDJSON = `{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-41773",
        "published": "2021-10-05T09:15:00.000",
        "descriptions": [
          {"lang": "en", "value": "Path traversal and file disclosure in Apache HTTP Server 2.4.49."}
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}
            }
          ]
        },
        "weaknesses": [
          {
            "description": [{"lang": "en", "value": "CWE-22"}]
          }
        ],
        "references": [
          {"url": "https://httpd.apache.org/security/vulnerabilities_24.html"}
        ]
      }
    }
  ]
}`

func TestSanitizeQuery(t *testing.T) {
	if _, err := SanitizeQuery("   "); err == nil {
		t.Fatal("expected empty query error")
	}
	if _, err := SanitizeQuery("apache 2.4.49; id"); err == nil {
		t.Fatal("expected metacharacter error")
	}
	if _, err := SanitizeQuery(strings.Repeat("a", 181)); err == nil {
		t.Fatal("expected too long error")
	}
	q, err := SanitizeQuery("  apache   2.4.49  ")
	if err != nil || q != "apache 2.4.49" {
		t.Fatalf("got %q, err %v", q, err)
	}
}

func TestNVDClientWithEPSSAndKEVEnrichmentAndCache(t *testing.T) {
	var nvdHits atomic.Int32
	nvdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nvdHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sampleNVDJSON))
	}))
	defer nvdSrv.Close()

	epssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"cve":"CVE-2021-41773","epss":"0.9742","percentile":"0.9991"}]}`))
	}))
	defer epssSrv.Close()

	kevSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2021-41773"}]}`))
	}))
	defer kevSrv.Close()

	s := DefaultSettings()
	s.NVDBaseURL = nvdSrv.URL
	s.EPSSBaseURL = epssSrv.URL
	s.KEVURL = kevSrv.URL
	s.EPSSEnabled = true
	s.KEVEnabled = true
	s.KEVCachePath = filepath.Join(t.TempDir(), "kev.json")

	client := NewNVDClient(s)
	ctx := context.Background()
	entries, err := client.Search(ctx, "apache 2.4.49")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.CVEID != "CVE-2021-41773" || e.Severity != "HIGH" || e.CWE != "CWE-22" || e.Published != "2021-10-05" {
		t.Fatalf("unexpected entry fields: %+v", e)
	}
	if !e.KEV || e.EPSS == nil || *e.EPSS < 0.97 {
		t.Fatalf("expected EPSS + KEV enrichment, got %+v", e)
	}

	// Second call must hit LRU cache without hitting NVD server again.
	entries2, err := client.Search(ctx, "Apache  2.4.49")
	if err != nil || len(entries2) != 1 || nvdHits.Load() != 1 {
		t.Fatalf("cache miss: hits=%d err=%v", nvdHits.Load(), err)
	}

	formatted := FormatCVEResults(entries, "apache 2.4.49")
	if !strings.Contains(formatted, "CVE-2021-41773 (HIGH)") || !strings.Contains(formatted, "KEV: yes") || !strings.Contains(formatted, "EPSS: 0.9742") {
		t.Fatalf("unexpected formatted output:\n%s", formatted)
	}
}

func TestCircuitBreaker5xxTripsBut4xxDoesNot(t *testing.T) {
	status := http.StatusNotFound
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	defer srv.Close()

	s := DefaultSettings()
	s.NVDBaseURL = srv.URL
	s.CircuitFailureThreshold = 2
	s.CircuitRecoveryTimeout = 10 * time.Second
	c := NewNVDClient(s)
	ctx := context.Background()

	// 404 is a soft miss: returns empty slice, no error, breaker stays closed.
	for i := 0; i < 3; i++ {
		res, err := c.Search(ctx, "nonexistent-product-"+string(rune('a'+i)))
		if err != nil || len(res) != 0 {
			t.Fatalf("404 should return empty slice without error, got %v %v", res, err)
		}
	}
	if c.breakerOpen() {
		t.Fatal("4xx must not trip circuit breaker")
	}

	// 503 trips breaker after threshold (2 failures).
	status = http.StatusServiceUnavailable
	for i := 0; i < 2; i++ {
		if _, err := c.Search(ctx, "fail-query-"+string(rune('a'+i))); err == nil {
			t.Fatal("expected 503 error while breaker closed")
		}
	}
	if !c.breakerOpen() {
		t.Fatal("expected breaker open after 2 consecutive 503s")
	}
	// While open, Search short-circuits gracefully to empty slice.
	res, err := c.Search(ctx, "short-circuit-query")
	if err != nil || len(res) != 0 {
		t.Fatalf("expected open breaker to short-circuit to empty slice, got %v %v", res, err)
	}
}
