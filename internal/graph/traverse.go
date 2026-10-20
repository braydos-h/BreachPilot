// Graph traversal: node detail, bounded multi-hop neighborhoods, and BFS
// shortest paths. Powers the explorer's detail panel, neighborhood view,
// and path finder over the artifact-built graph.

package graph

import (
	"sort"
)

// PathStep is one BFS path step: the node reached plus the edge taken.
type PathStep struct {
	Distance int  `json:"distance"`
	Node     Node `json:"node"`
	Edge     Edge `json:"edge"`
}

func indexByID(g Graph) map[string]Node {
	m := make(map[string]Node, len(g.Nodes))
	for _, n := range g.Nodes {
		m[n.NodeID] = n
	}
	return m
}

func incident(g Graph, id string) []Edge {
	var out []Edge
	for _, e := range g.Edges {
		if e.SourceNodeID == id || e.TargetNodeID == id {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EdgeID < out[j].EdgeID })
	return out
}

func adjacent(g Graph, id string) []Node {
	byID := indexByID(g)
	seen := map[string]bool{}
	var out []Node
	for _, e := range incident(g, id) {
		other := e.TargetNodeID
		if other == id {
			other = e.SourceNodeID
		}
		if n, ok := byID[other]; ok && !seen[other] {
			seen[other] = true
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

// Detail returns the node plus its incident edges and 1-hop neighbors.
// ok is false when the node is absent.
func Detail(g Graph, id string) (node Node, edges []Edge, neighbors []Node, ok bool) {
	byID := indexByID(g)
	n, found := byID[id]
	if !found {
		return Node{}, nil, nil, false
	}
	return n, incident(g, id), adjacent(g, id), true
}

// Neighbors expands maxHops (clamped 1..4) around id, capped at maxNodes
// (clamped 1..200). Returns the start node (nil when absent) plus the
// visited nodes and the induced edges.
func Neighbors(g Graph, id string, maxHops, maxNodes int) (nodes []Node, edges []Edge, start *Node) {
	if maxHops < 1 {
		maxHops = 1
	}
	if maxHops > 4 {
		maxHops = 4
	}
	if maxNodes < 1 {
		maxNodes = 1
	}
	if maxNodes > 200 {
		maxNodes = 200
	}
	byID := indexByID(g)
	s, ok := byID[id]
	if !ok {
		return nil, nil, nil
	}
	visited := map[string]bool{id: true}
	frontier := []string{id}
	for h := 0; h < maxHops && len(visited) < maxNodes; h++ {
		var next []string
		for _, cur := range frontier {
			for _, e := range incident(g, cur) {
				other := e.TargetNodeID
				if other == cur {
					other = e.SourceNodeID
				}
				if !visited[other] && len(visited) < maxNodes {
					visited[other] = true
					next = append(next, other)
				}
			}
		}
		if len(next) == 0 {
			break
		}
		frontier = next
	}
	for vid := range visited {
		nodes = append(nodes, byID[vid])
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })
	for _, e := range g.Edges {
		if visited[e.SourceNodeID] && visited[e.TargetNodeID] {
			edges = append(edges, e)
		}
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].EdgeID < edges[j].EdgeID })
	sc := s
	return nodes, edges, &sc
}

// Paths returns up to maxPaths shortest paths (each at most maxLength edges)
// from start to end via BFS. Empty when either endpoint is absent.
func Paths(g Graph, start, end string, maxLength, maxPaths int) [][]PathStep {
	if maxLength < 1 {
		maxLength = 1
	}
	if maxLength > 8 {
		maxLength = 8
	}
	if maxPaths < 1 {
		maxPaths = 1
	}
	if maxPaths > 8 {
		maxPaths = 8
	}
	byID := indexByID(g)
	if _, ok := byID[start]; !ok {
		return nil
	}
	if _, ok := byID[end]; !ok {
		return nil
	}
	type state struct {
		id    string
		steps []PathStep
	}
	queue := []state{{id: start}}
	var out [][]PathStep
	for len(queue) > 0 && len(out) < maxPaths {
		cur := queue[0]
		queue = queue[1:]
		if cur.id == end {
			out = append(out, cur.steps)
			continue
		}
		depth := len(cur.steps)
		if depth >= maxLength {
			continue
		}
		onPath := map[string]bool{start: true}
		for _, s := range cur.steps {
			onPath[s.Node.NodeID] = true
		}
		for _, e := range incident(g, cur.id) {
			other := e.TargetNodeID
			if other == cur.id {
				other = e.SourceNodeID
			}
			if onPath[other] {
				continue
			}
			nxt := append(append([]PathStep{}, cur.steps...), PathStep{
				Distance: depth + 1, Node: byID[other], Edge: e,
			})
			queue = append(queue, state{id: other, steps: nxt})
		}
	}
	if out == nil {
		return [][]PathStep{}
	}
	return out
}
