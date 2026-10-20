package graph_test

// Slice 10 RED: traversal over the built graph — node detail with incident
// edges + neighbors, bounded multi-hop neighbor expansion, and BFS shortest
// paths — must exist before the API can serve the explorer's detail,
// neighborhood, and path-finder views.

import (
	"testing"

	"github.com/braydos-h/BreachPilot/internal/graph"
)

func testGraph(t *testing.T) graph.Graph {
	t.Helper()
	g, err := graph.Build(fixtureRun(t), "run-g1")
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestNodeDetail(t *testing.T) {
	g := testGraph(t)
	n, edges, neighbors, ok := graph.Detail(g, "run:run-g1|ip|10-0-0-50")
	if !ok {
		t.Fatal("ip node must be found")
	}
	if n.NodeType != "ip" {
		t.Fatalf("wrong node: %+v", n)
	}
	if len(edges) == 0 || len(neighbors) == 0 {
		t.Fatalf("detail must include incident edges + neighbors, got %d/%d", len(edges), len(neighbors))
	}
	if _, _, _, ok := graph.Detail(g, "run:run-g1|ip|nope"); ok {
		t.Fatal("missing node must report not-found")
	}
}

func TestNeighborsBounded(t *testing.T) {
	g := testGraph(t)
	nodes, edges, start := graph.Neighbors(g, "run:run-g1|ip|10-0-0-50", 2, 200)
	if start == nil {
		t.Fatal("start node must be returned")
	}
	if len(nodes) == 0 || len(edges) == 0 {
		t.Fatal("2-hop neighborhood must be non-empty")
	}
	found := false
	for _, n := range nodes {
		if n.NodeType == "version" {
			found = true
		}
	}
	if !found {
		t.Fatalf("2 hops from ip must reach version nodes: %+v", nodes)
	}
	nodes1, _, _ := graph.Neighbors(g, "run:run-g1|ip|10-0-0-50", 1, 200)
	if len(nodes1) >= len(nodes) {
		t.Fatalf("1-hop (%d) must be smaller than 2-hop (%d)", len(nodes1), len(nodes))
	}
	if _, _, start := graph.Neighbors(g, "run:run-g1|ip|nope", 1, 50); start != nil {
		t.Fatal("missing start must return nil")
	}
}

func TestPathsBFS(t *testing.T) {
	g := testGraph(t)
	paths := graph.Paths(g, "run:run-g1|finding|finding-web-80", "run:run-g1|port|80", 4, 5)
	if len(paths) == 0 {
		t.Fatal("expected a path from finding to port via the asset")
	}
	for _, p := range paths {
		if len(p) == 0 || len(p) > 4 {
			t.Fatalf("path length out of bounds: %d", len(p))
		}
		if last := p[len(p)-1].Node.NodeID; last != "run:run-g1|port|80" {
			t.Fatalf("path must end at the port, ended at %s", last)
		}
	}
	if got := graph.Paths(g, "run:run-g1|finding|finding-web-80", "run:run-g1|ip|nope", 4, 5); len(got) != 0 {
		t.Fatalf("unreachable end must yield no paths, got %d", len(got))
	}
	if got := graph.Paths(g, "run:run-g1|ip|nope", "run:run-g1|port|80", 4, 5); len(got) != 0 {
		t.Fatalf("missing start must yield no paths, got %d", len(got))
	}
}
