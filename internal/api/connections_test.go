package api_test

// Slice 13: the connections endpoints must serve the real registry —
// list with filters + counts, get, check (honest stale without a listener
// backend), remove (audit-preserving) — with 400s for bad ids/status.

import (
	"encoding/json"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/operator"
)

func seedOperator(t *testing.T, dir string) (string, string) {
	t.Helper()
	m, err := operator.Open(dir, []string{"10.0.0.50"}, true)
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.Create(operator.CreateArgs{TargetIP: "10.0.0.50", Method: "linux_cron", CallbackHost: "127.0.0.1", CallbackPort: 4444})
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Create(operator.CreateArgs{TargetIP: "10.0.0.50", Method: "windows_schtask", CallbackHost: "127.0.0.1", CallbackPort: 5555})
	if err != nil {
		t.Fatal(err)
	}
	m.MarkRemoved(b.ConnectionID)
	return a.ConnectionID, b.ConnectionID
}

func TestConnectionsEndpoints(t *testing.T) {
	s, token, _ := testServerWithFiles(t)
	dir := t.TempDir()
	a, b := seedOperator(t, dir)
	_ = b
	s.OperatorDir = dir

	rec := doReq(t, s.Handler(), "GET", "/api/v1/connections", token, "")
	if rec.Code != 200 {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Connections []map[string]any `json:"connections"`
		Total       int              `json:"total"`
		Active      int              `json:"active"`
		Removed     int              `json:"removed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 2 || list.Active != 1 || list.Removed != 1 {
		t.Fatalf("bad counts: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/connections?status=active", token, "")
	var filtered struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &filtered); err != nil || filtered.Total != 1 {
		t.Fatalf("status filter broken: %s", rec.Body.String())
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/connections?status=bogus", token, ""); rec.Code != 400 {
		t.Fatalf("bad status = %d, want 400", rec.Code)
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/connections/"+a, token, "")
	if rec.Code != 200 {
		t.Fatalf("get = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/connections/conn-abc\\x", token, ""); rec.Code != 400 {
		t.Fatalf("bad id = %d, want 400", rec.Code)
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/connections/conn-deadbeef", token, ""); rec.Code != 404 {
		t.Fatalf("missing = %d, want 404", rec.Code)
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/connections/"+a+"/check", token, "")
	if rec.Code != 200 {
		t.Fatalf("check = %d: %s", rec.Code, rec.Body.String())
	}
	var checked map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &checked); err != nil {
		t.Fatal(err)
	}
	if checked["status"] != "stale" {
		t.Fatalf("check without listener backend must mark stale: %v", checked)
	}
	rec = doReq(t, s.Handler(), "POST", "/api/v1/connections/"+a+"/remove", token, "")
	var removed struct {
		Connection map[string]any `json:"connection"`
		Removed    bool           `json:"removed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &removed); err != nil || !removed.Removed {
		t.Fatalf("remove broken: %s", rec.Body.String())
	}
	if removed.Connection["status"] != "removed" {
		t.Fatalf("remove must preserve record as removed: %v", removed.Connection)
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/connections/"+a+"/listener?lines=10", token, "")
	if rec.Code != 404 {
		t.Fatalf("listener = %d, want honest 404 without backend", rec.Code)
	}
}
