// Package recon implements native reconnaissance: target validation,
// bounded DNS resolution, parallel TCP connect scanning with banner grabs,
// assessment building (recon_assessment.json shape), and heuristic goal
// suggestions. Mirrors tools/recon/service.py fast/assessment paths and
// tools/run_service/prepare.py target handling.
package recon

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultFastPorts mirrors DEFAULT_FAST_PORTS (24 ports).
var DefaultFastPorts = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 9000, 27017, 6379}

var fqdnLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// ParseTarget validates syntax only (IP or FQDN), never authorization.
// Returns the normalized host and whether it is an IP literal.
func ParseTarget(host string) (string, bool, error) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "", false, fmt.Errorf("empty target")
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return ip.String(), true, nil
	}
	if !IsFQDN(h) {
		return "", false, fmt.Errorf("invalid target %q: not an IP or FQDN", host)
	}
	return strings.ToLower(h), false, nil
}

// IsFQDN reports dot-separated labels (1-63 chars), total <= 253, alpha TLD.
func IsFQDN(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !fqdnLabel.MatchString(l) {
			return false
		}
	}
	tld := labels[len(labels)-1]
	for _, r := range tld {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

// Resolve bounded: IP literals skip DNS; domains resolve with a 5s cap.
// Returns (ip, domain); domain is always echoed back for valid FQDNs.
func Resolve(ctx context.Context, host string) (string, string, error) {
	h, isIP, err := ParseTarget(host)
	if err != nil {
		return "", "", err
	}
	if isIP {
		return h, "", nil
	}
	r := &net.Resolver{}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := r.LookupIPAddr(ctx, h)
	if err != nil || len(ips) == 0 {
		return "", "", fmt.Errorf("DNS resolution failed for %s", h)
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			return ip.IP.String(), h, nil
		}
	}
	return ips[0].IP.String(), h, nil
}

// Service describes one open port.
type Service struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Banner   string `json:"banner"`
}

// ScanResult is one port outcome.
type ScanResult struct {
	Port int
	Open bool
	Banner string
}

// ScanPorts performs a bounded parallel TCP connect scan with banner grabs.
// ctx cancels the whole scan (run cancellation). Per-port timeout 1.5s.
func ScanPorts(ctx context.Context, ip string, ports []int) []ScanResult {
	const perPort = 1500 * time.Millisecond
	const maxParallel = 32
	out := make([]ScanResult, len(ports))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for i, port := range ports {
		i, port := i, port
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			out[i] = probePort(ctx, ip, port, perPort)
		}()
	}
	wg.Wait()
	return out
}

func probePort(ctx context.Context, ip string, port int, timeout time.Duration) ScanResult {
	res := ScanResult{Port: port}
	d := &net.Dialer{Timeout: timeout}
	ctx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return res
	}
	defer conn.Close()
	res.Open = true
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	if n, err := conn.Read(buf); err == nil && n > 0 {
		res.Banner = strings.TrimSpace(sanitizeBanner(string(buf[:n])))
	}
	return res
}

func sanitizeBanner(b string) string {
	var sb strings.Builder
	for _, r := range b {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			sb.WriteRune(r)
		}
		if sb.Len() > 512 {
			break
		}
	}
	return sb.String()
}

var portServiceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
	143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
	1723: "pptp", 3306: "mysql", 3389: "rdp", 5900: "vnc",
	8080: "http-alt", 8443: "https-alt", 9000: "http-alt", 27017: "mongodb", 6379: "redis",
}

// Assessment mirrors ReconAssessment.to_dict (subset the native backend
// produces: no CVE intel yet — cve_findings is honestly empty).
type Assessment struct {
	TargetIP         string    `json:"target_ip"`
	OSVerdict        string    `json:"os_verdict"`
	OSHints          []string  `json:"os_hints"`
	OpenPorts        []int     `json:"open_ports"`
	Services         []Service `json:"services"`
	CVEFindings      []any     `json:"cve_findings"`
	OverallRiskScore int       `json:"overall_risk_score"`
	ChosenGoal       string    `json:"chosen_goal,omitempty"`
}

// BuildAssessment converts scan results to an Assessment.
func BuildAssessment(targetIP string, results []ScanResult) Assessment {
	a := Assessment{TargetIP: targetIP, OSVerdict: "UNKNOWN", OSHints: []string{},
		CVEFindings: []any{}, Services: []Service{}, OpenPorts: []int{}}
	for _, r := range results {
		if !r.Open {
			continue
		}
		a.OpenPorts = append(a.OpenPorts, r.Port)
		name := portServiceNames[r.Port]
		if name == "" {
			name = "unknown"
		}
		a.Services = append(a.Services, Service{Port: r.Port, Protocol: "tcp", Service: name, Banner: r.Banner})
	}
	sort.Ints(a.OpenPorts)
	a.OverallRiskScore = riskScore(a.OpenPorts)
	return a
}

func riskScore(open []int) int {
	score := 0
	high := map[int]bool{21: true, 23: true, 135: true, 139: true, 445: true, 3389: true, 5900: true}
	for _, p := range open {
		if high[p] {
			score += 20
		} else {
			score += 5
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

// GoalSuggestion mirrors one goal_suggestions.json entry.
type GoalSuggestion struct {
	Name              string `json:"name"`
	Description       string `json:"description"`
	ExploitLikelihood string `json:"exploit_likelihood"`
	SuccessRating     int    `json:"success_rating"`
	Rationale         string `json:"rationale"`
	Compatible        bool   `json:"compatible"`
	BlockedReason     string `json:"blocked_reason"`
	RiskRequirement   string `json:"risk_requirement"`
}

// SuggestGoals builds heuristic suggestions from open ports. Ratings are
// heuristics (labelled as such in rationale), never fabricated CVE claims.
func SuggestGoals(openPorts []int, mode string) []GoalSuggestion {
	has := map[int]bool{}
	for _, p := range openPorts {
		has[p] = true
	}
	var out []GoalSuggestion
	add := func(name, desc, likelihood string, rating int, rationale string, req string, compat bool, blocked string) {
		out = append(out, GoalSuggestion{Name: name, Description: desc, ExploitLikelihood: likelihood,
			SuccessRating: rating, Rationale: rationale, Compatible: compat, BlockedReason: blocked, RiskRequirement: req})
	}
	web := has[80] || has[443] || has[8080] || has[8443] || has[9000]
	if web {
		add("service_mapping", "Map exposed web services and technology stack.", "Very Likely", 85,
			"heuristic: HTTP(S) ports open; mapping is non-destructive", "safe", true, "")
	}
	if has[22] {
		add("verify_cves", "Verify SSH service version against known CVEs with safe checks only.", "Likely", 60,
			"heuristic: SSH banner available for version-based CVE matching", "gated", mode != "recon", "")
	}
	if len(openPorts) > 0 {
		add("recon_and_document", "Document all observed services and attack surface.", "Very Likely", 95,
			"heuristic: open ports observed; documentation always applicable", "safe", true, "")
	} else {
		add("recon_only", "No TCP ports responded; recommend UDP/secondary enumeration.", "Unlikely", 20,
			"heuristic: empty connect-scan result on fast port list", "safe", true, "")
	}
	if has[445] || has[3389] || has[21] {
		add("initial_access", "High-risk services exposed; gated exploitation may apply with authorization.", "Possible", 40,
			"heuristic: historically high-risk ports open; requires standard authorization", "gated", mode == "attack", "")
	}
	return out
}
