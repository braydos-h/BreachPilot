package api_test

// Slice 9: the graph explorer endpoints must serve the real artifact-built
// graph (nodes/edges/summary), with 404s only for missing runs or
// unported traversal — never fabricated data.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func seedGraphRun(t *testing.T, repDir, runID string) {
	t.Helper()
	dir := filepath.Join(repDir, runID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("recon_assessment.json", `{"target_ip":"10.0.0.50","open_ports":[80],"services":[{"port":80,"protocol":"tcp","service":"http","version":"nginx","banner":""}],"os_verdict":"Linux"}`)
	write("proposed.json", `[{"id":"finding-web-80","service":"http","port":80,"summary":"Version disclosed","evidence":"server: nginx","status":"proposed"}]`)
}

func TestGraphRunServesRealNodes(t *testing.T) {
	s, token, repDir := testServerWithFiles(t)
	s.Cfg.API.GraphRoute = true
	if err := s.DB.CreateRun("run-graph1", "completed", "10.0.0.50", "recon", "", `{"target":"10.0.0.50"}`); err != nil {
		t.Fatal(err)
	}
	seedGraphRun(t, repDir, "run-graph1")
	rec := doReq(t, s.Handler(), "GET", "/api/v1/graph/runs/run-graph1", token, "")
	if rec.Code != 200 {
		t.Fatalf("graph = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var v struct {
		RunID string `json:"run_id"`
		Scope string `json:"scope"`
		Nodes []struct {
			NodeID   string `json:"node_id"`
			NodeType string `json:"node_type"`
		} `json:"nodes"`
		Edges []struct {
			EdgeID   string `json:"edge_id"`
			EdgeType string `json:"edge_type"`
		} `json:"edges"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Scope != "run:run-graph1" || len(v.Nodes) == 0 || len(v.Edges) == 0 {
		t.Fatalf("expected real scoped graph, got %+v", v)
	}
	types := map[string]bool{}
	for _, n := range v.Nodes {
		types[n.NodeType] = true
	}
	for _, want := range []string{"ip", "service", "port", "finding"} {
		if !types[want] {
			t.Fatalf("missing %s node: %+v", want, v.Nodes)
		}
	}
}

func TestGraphTraversalRoutes(t *testing.T) {
	s, token, repDir := testServerWithFiles(t)
	s.Cfg.API.GraphRoute = true
	if err := s.DB.CreateRun("run-graph3", "completed", "10.0.0.50", "recon", "", `{"target":"10.0.0.50"}`); err != nil {
		t.Fatal(err)
	}
	seedGraphRun(t, repDir, "run-graph3")
	ipID := "run:run-graph3|ip|10-0-0-50"
	rec := doReq(t, s.Handler(), "GET", "/api/v1/graph/runs/run-graph3/nodes/"+ipID, token, "")
	if rec.Code != 200 {
		t.Fatalf("node = %d: %s", rec.Code, rec.Body.String())
	}
	var detail struct {
		Node struct {
			NodeID string `json:"node_id"`
		} `json:"node"`
		Neighbors []any `json:"neighbors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Node.NodeID != ipID || len(detail.Neighbors) == 0 {
		t.Fatalf("bad node detail: %s", rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/graph/runs/run-graph3/nodes/"+ipID+"/neighbors?max_hops=2", token, "")
	if rec.Code != 200 {
		t.Fatalf("neighbors = %d: %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s.Handler(), "GET", "/api/v1/graph/runs/run-graph3/paths?start=run:run-graph3|finding|finding-web-80&end=run:run-graph3|port|80", token, "")
	if rec.Code != 200 {
		t.Fatalf("paths = %d: %s", rec.Code, rec.Body.String())
	}
	var paths struct {
		Paths []any `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &paths); err != nil {
		t.Fatal(err)
	}
	if len(paths.Paths) == 0 {
		t.Fatalf("expected paths, got %s", rec.Body.String())
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/graph/runs/run-graph3/nodes/nope", token, ""); rec.Code != 404 {
		t.Fatalf("missing node = %d, want 404", rec.Code)
	}
}

func TestGraphSummaryAndHonestGaps(t *testing.T) {
	s, token, repDir := testServerWithFiles(t)
	s.Cfg.API.GraphRoute = true
	if err := s.DB.CreateRun("run-graph2", "completed", "10.0.0.50", "recon", "", `{"target":"10.0.0.50"}`); err != nil {
		t.Fatal(err)
	}
	seedGraphRun(t, repDir, "run-graph2")
	rec := doReq(t, s.Handler(), "GET", "/api/v1/graph/runs/run-graph2/summary", token, "")
	if rec.Code != 200 {
		t.Fatalf("summary = %d: %s", rec.Code, rec.Body.String())
	}
	var sum struct {
		Stats map[string]any `json:"stats"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Stats["services"] == nil || sum.Stats["findings"] == nil {
		t.Fatalf("summary missing stats: %v", sum.Stats)
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/graph/runs/missing", token, ""); rec.Code != 404 {
		t.Fatalf("missing run = %d, want 404", rec.Code)
	}
	if rec := doReq(t, s.Handler(), "GET", "/api/v1/graph/runs/run-graph2/nodes/x/neighbors", token, ""); rec.Code != 404 {
		t.Fatalf("traversal = %d, want honest 404", rec.Code)
	}
}
