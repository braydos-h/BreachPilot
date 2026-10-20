// Package graph builds the native attack graph from finished-run artifacts:
// recon services become ip/service/port/version nodes, proposed and vetted
// findings become finding nodes with affected_by edges and evidence nodes,
// CVE findings become vulnerability_candidate nodes. Node IDs follow the
// Python convention (scope|type|slug, scope "run:{id}") so the WebUI
// explorer renders them without changes. No model inference: statuses are
// observed (suspected for proposed, confirmed for verified/approved).
package graph

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Node mirrors the WebUI GraphExplorerNode shape.
type Node struct {
	NodeID             string         `json:"node_id"`
	NodeType           string         `json:"node_type"`
	Value              string         `json:"value"`
	Scope              string         `json:"scope"`
	Properties         map[string]any `json:"properties"`
	Confidence         float64        `json:"confidence"`
	FirstSeen          string         `json:"first_seen"`
	LastSeen           string         `json:"last_seen"`
	EvidenceRefs       []string       `json:"evidence_refs"`
	ObservationCount   int            `json:"observation_count"`
	ContradictionCount int            `json:"contradiction_count"`
	Status             string         `json:"status"`
	Source             string         `json:"source"`
}

// Edge mirrors the WebUI GraphExplorerEdge shape.
type Edge struct {
	EdgeID             string         `json:"edge_id"`
	SourceNodeID       string         `json:"source_node_id"`
	TargetNodeID       string         `json:"target_node_id"`
	EdgeType           string         `json:"edge_type"`
	Scope              string         `json:"scope"`
	Properties         map[string]any `json:"properties"`
	Confidence         float64        `json:"confidence"`
	Source             string         `json:"source"`
	FirstSeen          string         `json:"first_seen"`
	LastSeen           string         `json:"last_seen"`
	EvidenceRefs       []string       `json:"evidence_refs"`
	ObservationCount   int            `json:"observation_count"`
	ContradictionCount int            `json:"contradiction_count"`
}

// Graph is one run's attack graph.
type Graph struct {
	RunID string `json:"run_id"`
	Scope string `json:"scope"`
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Summary mirrors the WebUI GraphSummaryResponse shape.
type Summary struct {
	RunID   string         `json:"run_id"`
	Summary map[string]any `json:"summary"`
	Stats   map[string]any `json:"stats"`
}

var slugRe = regexp.MustCompile(`[^0-9a-zA-Z]+`)

func slug(v string, maxLen int) string {
	s := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(v)), "-"), "-")
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	if s == "" {
		s = "unknown"
	}
	return s
}

type builder struct {
	scope string
	now   string
	nodes map[string]Node
	edges map[string]Edge
}

func nodeID(scope, typ, value string) string {
	return scope + "|" + typ + "|" + slug(value, 60)
}

func (b *builder) addNode(typ, value, status string, confidence float64, props map[string]any, source string) string {
	if props == nil {
		props = map[string]any{}
	}
	id := nodeID(b.scope, typ, value)
	if n, ok := b.nodes[id]; ok {
		n.ObservationCount++
		n.LastSeen = b.now
		b.nodes[id] = n
		return id
	}
	b.nodes[id] = Node{
		NodeID: id, NodeType: typ, Value: value, Scope: b.scope,
		Properties: props, Confidence: confidence,
		FirstSeen: b.now, LastSeen: b.now,
		EvidenceRefs: []string{}, Status: status, Source: source,
	}
	return id
}

func (b *builder) addEdge(src, dst, typ, source string, confidence float64) {
	id := src + "->" + dst + "|" + typ
	if _, ok := b.edges[id]; ok {
		return
	}
	b.edges[id] = Edge{
		EdgeID: id, SourceNodeID: src, TargetNodeID: dst, EdgeType: typ,
		Scope: b.scope, Properties: map[string]any{}, Confidence: confidence,
		Source: source, FirstSeen: b.now, LastSeen: b.now, EvidenceRefs: []string{},
	}
}

// Build assembles the attack graph for a finished run directory.
func Build(runDir, runID string) (Graph, error) {
	if fi, err := os.Stat(runDir); err != nil || !fi.IsDir() {
		return Graph{}, fmt.Errorf("graph: no such run dir %s", runDir)
	}
	b := &builder{
		scope: "run:" + runID,
		now:   time.Now().UTC().Format(time.RFC3339Nano),
		nodes: map[string]Node{},
		edges: map[string]Edge{},
	}
	b.fromRecon(runDir)
	b.fromProposed(runDir)
	b.fromEnhanced(runDir)
	nodes := make([]Node, 0, len(b.nodes))
	for _, n := range b.nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })
	edges := make([]Edge, 0, len(b.edges))
	for _, e := range b.edges {
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].EdgeID < edges[j].EdgeID })
	return Graph{RunID: runID, Scope: b.scope, Nodes: nodes, Edges: edges}, nil
}

func (b *builder) fromRecon(runDir string) {
	raw, err := os.ReadFile(filepath.Join(runDir, "recon_assessment.json"))
	if err != nil {
		return
	}
	var a struct {
		TargetIP  string `json:"target_ip"`
		OSVerdict string `json:"os_verdict"`
		OpenPorts []int  `json:"open_ports"`
		Services  []struct {
			Port    int    `json:"port"`
			Service string `json:"service"`
			Version string `json:"version"`
		} `json:"services"`
		CVEFindings []struct {
			CVEID   string `json:"cve_id"`
			Service string `json:"service"`
			Version string `json:"version"`
		} `json:"cve_findings"`
	}
	if json.Unmarshal(raw, &a) != nil || a.TargetIP == "" {
		return
	}
	typ := "ip"
	if net.ParseIP(strings.TrimSpace(a.TargetIP)) == nil {
		typ = "domain"
	}
	asset := b.addNode(typ, a.TargetIP, "likely", 0.8,
		map[string]any{"os_verdict": a.OSVerdict}, "recon_assessment")
	for _, s := range a.Services {
		name := s.Service
		if name == "" {
			name = "port-" + strconv.Itoa(s.Port)
		}
		svc := b.addNode("service", name, "likely", 0.7,
			map[string]any{"port": s.Port, "version": s.Version}, "recon_assessment")
		b.addEdge(asset, svc, "hosts", "recon_assessment", 0.7)
		port := b.addNode("port", strconv.Itoa(s.Port), "confirmed", 0.9,
			map[string]any{"port": s.Port}, "recon_assessment")
		b.addEdge(asset, port, "exposes", "recon_assessment", 0.9)
		b.addEdge(port, svc, "runs", "recon_assessment", 0.7)
		if strings.TrimSpace(s.Version) != "" {
			ver := b.addNode("version", s.Version, "likely", 0.6,
				map[string]any{"port": s.Port}, "recon_assessment")
			b.addEdge(svc, ver, "depends_on", "recon_assessment", 0.6)
		}
	}
	for _, c := range a.CVEFindings {
		if c.CVEID == "" {
			continue
		}
		cand := b.addNode("vulnerability_candidate", c.CVEID, "suspected", 0.5,
			map[string]any{"service": c.Service, "version": c.Version}, "recon_assessment")
		b.addEdge(cand, asset, "affected_by", "recon_assessment", 0.5)
	}
}

type rawFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Service  string `json:"service"`
	Port     int    `json:"port"`
	Summary  string `json:"summary"`
	Evidence string `json:"evidence"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
}

func findingStatus(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "verified", "approved":
		return "confirmed"
	case "still_open":
		return "likely"
	case "rejected", "refuted":
		return "refuted"
	default:
		return "suspected"
	}
}

func (b *builder) addFinding(f rawFinding, asset, source string, confidence float64) {
	title := f.Title
	if title == "" {
		title = f.Summary
	}
	if title == "" {
		title = f.ID
	}
	props := map[string]any{"status": f.Status, "evidence": f.Evidence, "summary": f.Summary}
	if f.Service != "" {
		props["service"] = f.Service
	}
	if f.Port != 0 {
		props["port"] = f.Port
	}
	if f.Severity != "" {
		props["severity"] = f.Severity
	}
	fn := b.addNode("finding", f.ID, findingStatus(f.Status), confidence, props, source)
	b.addEdge(fn, asset, "affected_by", source, confidence)
	if strings.TrimSpace(f.Evidence) != "" {
		ex := f.Evidence
		if len(ex) > 120 {
			ex = ex[:120]
		}
		ev := b.addNode("evidence", slug(f.ID+"-"+ex, 60), "likely", confidence,
			map[string]any{"excerpt": ex}, source)
		b.addEdge(fn, ev, "supported_by", source, confidence)
	}
}

func (b *builder) fromProposed(runDir string) {
	raw, err := os.ReadFile(filepath.Join(runDir, "proposed.json"))
	if err != nil {
		return
	}
	var items []rawFinding
	if json.Unmarshal(raw, &items) != nil {
		return
	}
	asset := b.assetRef(runDir)
	for _, f := range items {
		if f.ID == "" {
			continue
		}
		b.addFinding(f, asset, "proposed", 0.4)
	}
}

func (b *builder) fromEnhanced(runDir string) {
	raw, err := os.ReadFile(filepath.Join(runDir, "enhanced_report.json"))
	if err != nil {
		return
	}
	var rep struct {
		Technical []rawFinding `json:"technical_findings"`
	}
	if json.Unmarshal(raw, &rep) != nil {
		return
	}
	asset := b.assetRef(runDir)
	for _, f := range rep.Technical {
		if f.ID == "" {
			continue
		}
		b.addFinding(f, asset, "enhanced_report", 0.9)
	}
}

func (b *builder) assetRef(runDir string) string {
	if raw, err := os.ReadFile(filepath.Join(runDir, "recon_assessment.json")); err == nil {
		var a struct {
			TargetIP string `json:"target_ip"`
		}
		if json.Unmarshal(raw, &a) == nil && a.TargetIP != "" {
			typ := "ip"
			if net.ParseIP(strings.TrimSpace(a.TargetIP)) == nil {
				typ = "domain"
			}
			return nodeID(b.scope, typ, a.TargetIP)
		}
	}
	return b.addNode("asset", "unknown", "unknown", 0.1, nil, "graph")
}

// Summarize returns the totals + per-type stats the WebUI summary card needs.
func Summarize(g Graph) Summary {
	byType := map[string]int{}
	byEdge := map[string]int{}
	stats := map[string]any{
		"hosts": 0, "domains": 0, "ips": 0, "services": 0, "findings": 0,
		"hypotheses": 0, "evidence": 0, "observations": 0,
		"vulnerability_candidates": 0, "confirmed": 0, "likely": 0, "refuted": 0,
	}
	degree := map[string]int{}
	for _, n := range g.Nodes {
		byType[n.NodeType]++
		switch n.Status {
		case "confirmed":
			stats["confirmed"] = stats["confirmed"].(int) + 1
		case "likely", "suspected":
			stats["likely"] = stats["likely"].(int) + 1
		case "refuted":
			stats["refuted"] = stats["refuted"].(int) + 1
		}
	}
	for _, e := range g.Edges {
		byEdge[e.EdgeType]++
		degree[e.SourceNodeID]++
		degree[e.TargetNodeID]++
	}
	stats["hosts"] = byType["host"] + byType["asset"]
	stats["domains"] = byType["domain"]
	stats["ips"] = byType["ip"]
	stats["services"] = byType["service"] + byType["port"]
	stats["findings"] = byType["finding"]
	stats["hypotheses"] = byType["hypothesis"]
	stats["evidence"] = byType["evidence"]
	stats["observations"] = byType["observation"]
	stats["vulnerability_candidates"] = byType["vulnerability_candidate"]
	var top map[string]any
	best := ""
	bestDeg := 0
	for id, d := range degree {
		if d > bestDeg {
			bestDeg, best = d, id
		}
	}
	if best != "" {
		top = map[string]any{"node_id": best, "value": best, "node_type": "", "degree": bestDeg}
		for _, n := range g.Nodes {
			if n.NodeID == best {
				top["value"], top["node_type"] = n.Value, n.NodeType
				break
			}
		}
	}
	stats["highest_degree_node"] = top
	stats["conflict_count"] = 0
	return Summary{
		RunID: g.RunID,
		Summary: map[string]any{
			"nodes": byType, "edges": byEdge,
			"total_nodes": len(g.Nodes), "total_edges": len(g.Edges),
		},
		Stats: stats,
	}
}
