package api_test

// Slice 1 of zero-not_ported: benchmarks must work without explicit Bench
// wiring (lazy default service), and ChatGPT proxy endpoints must return
// honest precondition errors, never the unported sentinel.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBenchmarksWithoutWiring(t *testing.T) {
	s, token := testServer(t) // no Bench set
	rec := doReq(t, s.Handler(), "GET", "/api/v1/benchmarks", token, "")
	if rec.Code != 200 {
		t.Fatalf("benchmarks = %d, want 200 with default service: %s", rec.Code, rec.Body.String())
	}
	var v map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	suites, _ := v["suites"].([]any)
	if len(suites) == 0 {
		t.Fatalf("expected built-in suites, got %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/benchmarks/suites", token, "")
	if rec.Code != 200 {
		t.Fatalf("benchmark suites = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestChatGPTProxyHonestErrors(t *testing.T) {
	s, token := testServer(t)
	rec := doReq(t, s.Handler(), "POST", "/api/v1/providers/chatgpt/login", token, "")
	if rec.Code == 501 {
		t.Fatalf("login = 501 not_ported sentinel, want honest precondition error")
	}
	if !strings.Contains(rec.Body.String(), "proxy_runtime_missing") && !strings.Contains(rec.Body.String(), "oauth") {
		t.Fatalf("login should explain the missing oauth runtime, got %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/providers/chatgpt/proxy/start", token, "")
	if rec.Code == 501 {
		t.Fatalf("proxy start = 501 not_ported sentinel, want honest precondition error")
	}
}
