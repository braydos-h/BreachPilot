package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/api"
	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/store"
)

func testServer(t *testing.T) (*api.Server, string) {
	t.Helper()
	cfg := config.Default()
	db, err := store.Open(t.TempDir()+"/test.db", t.TempDir()+"/reports")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	const token = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
	return api.New(cfg, token, db, events.NewRegistry()), token
}

func doReq(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *strings.Reader
	if body == "" {
		r = strings.NewReader("")
	} else {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthNoAuth(t *testing.T) {
	s, _ := testServer(t)
	rec := doReq(t, s.Handler(), "GET", "/api/v1/health", "", "")
	if rec.Code != 200 {
		t.Fatalf("health = %d", rec.Code)
	}
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v["version"] != "v1" || v["ready"] != true {
		t.Fatalf("health shape: %s", rec.Body.String())
	}
}

func TestAuthGate(t *testing.T) {
	s, token := testServer(t)
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/capabilities", "", ""); rec.Code != 401 {
		t.Fatalf("no token = %d, want 401", rec.Code)
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/capabilities", "wrong", ""); rec.Code != 401 {
		t.Fatalf("bad token = %d, want 401", rec.Code)
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/capabilities", token, ""); rec.Code != 200 {
		t.Fatalf("good token = %d, want 200", rec.Code)
	}
}

func TestErrorEnvelope(t *testing.T) {
	s, token := testServer(t)
	rec := doReq(t, s.Handler(), "GET", "/api/v1/runs/nope", token, "")
	if rec.Code != 404 {
		t.Fatalf("code = %d", rec.Code)
	}
	if rid := rec.Header().Get("X-Request-ID"); rid == "" {
		t.Fatal("missing X-Request-ID")
	}
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	e, _ := v["error"].(map[string]any)
	if e["code"] == nil || e["message"] == nil {
		t.Fatalf("envelope shape: %s", rec.Body.String())
	}
}

func TestRunLifecycle(t *testing.T) {
	s, token := testServer(t)
	rec := doReq(t, s.Handler(), "POST", "/api/v1/runs", token, `{"target":"10.0.0.5","mode":"recon","kind":"agent"}`)
	if rec.Code != 201 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id, _ := created["run_id"].(string)
	if id == "" {
		t.Fatal("missing run_id")
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+id, token, "")
	if rec.Code != 200 {
		t.Fatalf("get = %d", rec.Code)
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+id+"/events?after=0", token, "")
	if rec.Code != 200 {
		t.Fatalf("events = %d", rec.Code)
	}
	var ev map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &ev)
	list, _ := ev["events"].([]any)
	if len(list) == 0 {
		t.Fatal("expected run_created replay event")
	}
	first, _ := list[0].(map[string]any)["sequence"].(float64)
	rec = doReq(t, s.Handler(), "GET", "/api/v1/runs/"+id+"/events?after="+itoa(int(first)), token, "")
	var ev2 map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &ev2)
	if len(ev2["events"].([]any)) != 0 {
		t.Fatal("after cursor must exclude replayed event")
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/runs/"+id+"/cancel", token, "")
	if rec.Code != 200 {
		t.Fatalf("cancel = %d", rec.Code)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestSSEHeaders(t *testing.T) {
	// SSE stream tested for headers + first replay frame via short timeout is
	// racy; assert route exists and auth gates it.
	s, _ := testServer(t)
	rec := doReq(t, s.Handler(), "GET", "/api/v1/runs/x/events/stream", "", "")
	if rec.Code != 401 {
		t.Fatalf("sse no-auth = %d, want 401", rec.Code)
	}
}
