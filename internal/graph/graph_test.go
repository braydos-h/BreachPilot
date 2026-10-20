package graph_test

// Slice 9 RED: the attack graph must be built from real run artifacts —
// recon services become ip/service/port nodes, findings become finding
// nodes with affected_by edges, evidence strings become evidence nodes —
// with the run:{id} scope and type|slug node IDs the WebUI expects.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/braydos-h/BreachPilot/internal/graph"
)

func fixtureRun(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("recon_assessment.json", `{"target_ip":"10.0.0.50","open_ports":[80,443],"services":[{"port":80,"protocol":"tcp","service":"http","version":"nginx 1.18","banner":"nginx"}],"os_verdict":"Linux"}`)
	write("proposed.json", `[{"id":"finding-web-80","service":"http","port":80,"summary":"Version disclosed","evidence":"server: nginx","status":"proposed"}]`)
	write("enhanced_report.json", `{"report_metadata":{"generated_at":"2026-10-20T00:00:00Z"},"technical_findings":[{"id":"F-1","title":"SMBv1 enabled","asset":"10.0.0.50","status":"verified","summary":"SMBv1 enabled.","evidence":"smb banner"}],"proposed_findings":[],"attack_timeline":[]}`)
	return dir
}

func nodeIDs(g graph.Graph) map[string]string {
	out := map[string]string{}
	for _, n := range g.Nodes {
		out[n.NodeID] = n.NodeType
	}
	return out
}

func TestBuildRealNodes(t *testing.T) {
	g, err := graph.Build(fixtureRun(t), "run-g1")
	if err != nil {
		t.Fatal(err)
	}
	if g.Scope != "run:run-g1" {
		t.Fatalf("scope = %q, want run:run-g1", g.Scope)
	}
	ids := nodeIDs(g)
	if ids["run:run-g1|ip|10-0-0-50"] != "ip" {
		t.Fatalf("missing ip node: %v", ids)
	}
	if ids["run:run-g1|service|http"] != "service" {
		t.Fatalf("missing service node: %v", ids)
	}
	if ids["run:run-g1|port|80"] != "port" {
		t.Fatalf("missing port node: %v", ids)
	}
	if ids["run:run-g1|finding|finding-web-80"] != "finding" {
		t.Fatalf("missing proposed finding node: %v", ids)
	}
	if ids["run:run-g1|finding|f-1"] != "finding" {
		t.Fatalf("missing vetted finding node: %v", ids)
	}
	foundAffected := false
	for _, e := range g.Edges {
		if e.EdgeType == "affected_by" {
			foundAffected = true
		}
	}
	if !foundAffected {
		t.Fatalf("expected affected_by edges, got %+v", g.Edges)
	}
}

func TestSummaryCounts(t *testing.T) {
	g, err := graph.Build(fixtureRun(t), "run-g1")
	if err != nil {
		t.Fatal(err)
	}
	s := graph.Summarize(g)
	raw, _ := json.Marshal(s)
	asInt := func(v any) int {
		switch x := v.(type) {
		case int:
			return x
		case float64:
			return int(x)
		default:
			return -1
		}
	}
	if asInt(s.Stats["services"]) < 1 || asInt(s.Stats["findings"]) != 2 {
		t.Fatalf("bad summary stats: %s", raw)
	}
	sum, _ := s.Summary["total_nodes"]
	tot := asInt(sum)
	sume, _ := s.Summary["total_edges"]
	tote := asInt(sume)
	if tot != len(g.Nodes) || tote != len(g.Edges) {
		t.Fatalf("summary totals mismatch: %s", raw)
	}
}

func TestBuildMissingDir(t *testing.T) {
	if _, err := graph.Build(filepath.Join(t.TempDir(), "nope"), "run-x"); err == nil {
		t.Fatal("missing run dir must fail, not return an empty graph")
	}
}
