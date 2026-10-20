// Package recon implements native reconnaissance: target validation,
// bounded DNS resolution, parallel TCP connect scanning with banner grabs,
// service version extraction, OS fingerprinting, unprivileged scanner flag
// downgrading, NVD/EPSS/KEV vulnerability enrichment, assessment building
// (recon_assessment.json shape), and heuristic goal suggestions.
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

	"github.com/braydos-h/BreachPilot/internal/intel"
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
	Port   int
	Open   bool
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
	_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 1024)
	if n, err := conn.Read(buf); err == nil && n > 0 {
		res.Banner = strings.TrimSpace(sanitizeBanner(string(buf[:n])))
		return res
	}
	// Active HTTP HEAD probe for common HTTP ports that wait for client request.
	if port == 80 || port == 8080 || port == 8000 || port == 8888 || port == 9000 {
		_ = conn.SetWriteDeadline(time.Now().Add(400 * time.Millisecond))
		_, _ = fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
		_ = conn.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
		if n, err := conn.Read(buf); err == nil && n > 0 {
			res.Banner = strings.TrimSpace(sanitizeBanner(string(buf[:n])))
		}
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

var versionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(OpenSSH)[_/\s-]([0-9]+\.[0-9]+[a-z0-9p.-]*)`),
	regexp.MustCompile(`(?i)\b(Apache)[/\s]([0-9]+\.[0-9]+\.[0-9]+)`),
	regexp.MustCompile(`(?i)\b(nginx)[/\s]([0-9]+\.[0-9]+\.[0-9]+)`),
	regexp.MustCompile(`(?i)\b(Microsoft-IIS)[/\s]([0-9]+\.[0-9]+)`),
	regexp.MustCompile(`(?i)\b(vsFTPd)[/\s]([0-9]+\.[0-9]+\.[0-9]+)`),
	regexp.MustCompile(`(?i)\b(ProFTPD)[/\s]([0-9]+\.[0-9]+\.[0-9a-z]+)`),
	regexp.MustCompile(`(?i)\b(Redis)[_/\s:v]+([0-9]+\.[0-9]+\.[0-9]+)`),
	regexp.MustCompile(`(?i)\b(MySQL|MariaDB)[_/\s-]+([0-9]+\.[0-9]+\.[0-9]+)`),
	regexp.MustCompile(`(?i)\b(OpenSSL)[_/\s]+([0-9]+\.[0-9]+\.[0-9]+[a-z]*)`),
}

// ExtractServiceVersion extracts a normalized product + version string from a banner.
func ExtractServiceVersion(banner string) string {
	for _, re := range versionPatterns {
		if m := re.FindStringSubmatch(banner); len(m) == 3 {
			return m[1] + " " + m[2]
		}
	}
	return ""
}

// InferOS derives an OS verdict and supporting hints from open ports and banners.
func InferOS(openPorts []int, services []Service) (string, []string) {
	var hints []string
	linuxScore := 0
	windowsScore := 0
	freebsdScore := 0

	addHint := func(h string) {
		for _, existing := range hints {
			if existing == h {
				return
			}
		}
		hints = append(hints, h)
	}

	for _, s := range services {
		low := strings.ToLower(s.Banner)
		switch {
		case strings.Contains(low, "ubuntu"):
			linuxScore += 3
			addHint("banner: Ubuntu")
		case strings.Contains(low, "debian"):
			linuxScore += 3
			addHint("banner: Debian")
		case strings.Contains(low, "centos") || strings.Contains(low, "red hat") || strings.Contains(low, "fedora") || strings.Contains(low, "alpine"):
			linuxScore += 3
			addHint("banner: Linux distribution")
		case strings.Contains(low, "(unix)"):
			linuxScore += 2
			addHint("banner: Unix")
		}
		if strings.Contains(low, "freebsd") {
			freebsdScore += 3
			addHint("banner: FreeBSD")
		}
		if strings.Contains(low, "microsoft") || strings.Contains(low, "windows") || strings.Contains(low, "win32") || strings.Contains(low, "iis") {
			windowsScore += 3
			addHint("banner: Microsoft/Windows")
		}
	}

	hasPort := map[int]bool{}
	for _, p := range openPorts {
		hasPort[p] = true
	}
	if hasPort[135] || hasPort[3389] {
		windowsScore += 2
		addHint("ports: MSRPC/RDP")
	}
	if hasPort[445] && hasPort[139] && !hasPort[22] {
		windowsScore++
		addHint("ports: SMB/NetBIOS without SSH")
	}
	if hasPort[22] && hasPort[111] {
		linuxScore++
		addHint("ports: SSH + rpcbind")
	}

	if hints == nil {
		hints = []string{}
	}
	switch {
	case windowsScore > linuxScore && windowsScore > freebsdScore && windowsScore >= 2:
		return "Windows", hints
	case linuxScore > windowsScore && linuxScore >= freebsdScore && linuxScore >= 2:
		return "Linux", hints
	case freebsdScore > linuxScore && freebsdScore > windowsScore && freebsdScore >= 2:
		return "FreeBSD", hints
	default:
		return "UNKNOWN", hints
	}
}

// Assessment mirrors ReconAssessment.to_dict.
type Assessment struct {
	TargetIP              string         `json:"target_ip"`
	OSVerdict             string         `json:"os_verdict"`
	OSHints               []string       `json:"os_hints"`
	OSFingerprint         *OSFingerprint `json:"os_fingerprint,omitempty"`
	OpenPorts             []int          `json:"open_ports"`
	UDPPorts              []int          `json:"udp_ports"`
	Services              []Service      `json:"services"`
	CVEFindings           []any          `json:"cve_findings"`
	OverallRiskScore      int            `json:"overall_risk_score"`
	ChosenGoal            string         `json:"chosen_goal,omitempty"`
	ChosenGoalDescription string         `json:"chosen_goal_description,omitempty"`
}

// BuildAssessment converts scan results to an Assessment, extracting service
// versions and OS hints from banners.
func BuildAssessment(targetIP string, results []ScanResult) Assessment {
	a := Assessment{TargetIP: targetIP, OSVerdict: "UNKNOWN", OSHints: []string{},
		CVEFindings: []any{}, Services: []Service{}, OpenPorts: []int{}, UDPPorts: []int{}}
	for _, r := range results {
		if !r.Open {
			continue
		}
		a.OpenPorts = append(a.OpenPorts, r.Port)
		name := portServiceNames[r.Port]
		if name == "" {
			name = "unknown"
		}
		ver := ExtractServiceVersion(r.Banner)
		a.Services = append(a.Services, Service{
			Port:     r.Port,
			Protocol: "tcp",
			Service:  name,
			Version:  ver,
			Banner:   r.Banner,
		})
	}
	sort.Ints(a.OpenPorts)
	fp := FingerprintOS(context.Background(), targetIP, a.OpenPorts, a.Services, OSFingerprintOptions{})
	a.OSVerdict = fp.Family
	a.OSHints = fp.Signals
	a.OSFingerprint = &fp
	a.OverallRiskScore = riskScore(a.OpenPorts, len(a.CVEFindings))
	return a
}

// EnrichAssessmentCVEs queries NVD/EPSS/KEV for services that yielded a version
// string and appends structured CVE findings to the Assessment.
func EnrichAssessmentCVEs(ctx context.Context, a *Assessment, nvd *intel.NVDClient) {
	if a == nil || nvd == nil || !nvd.Settings.Enabled {
		return
	}
	seen := map[string]bool{}
	for _, svc := range a.Services {
		q := strings.TrimSpace(svc.Version)
		if q == "" || seen[strings.ToLower(q)] {
			continue
		}
		seen[strings.ToLower(q)] = true
		entries, err := nvd.Search(ctx, q)
		if err != nil {
			continue
		}
		for _, e := range entries {
			a.CVEFindings = append(a.CVEFindings, map[string]any{
				"port":            svc.Port,
				"service":         svc.Service,
				"version":         svc.Version,
				"cve_id":          e.CVEID,
				"severity":        e.Severity,
				"cvss_score":      e.CVSSScore,
				"cwe":             e.CWE,
				"published":       e.Published,
				"description":     e.Description,
				"references":      e.References,
				"epss":            e.EPSS,
				"epss_percentile": e.EPSSPercentile,
				"kev":             e.KEV,
			})
		}
	}
	a.OverallRiskScore = riskScore(a.OpenPorts, len(a.CVEFindings))
}

func riskScore(open []int, cveCount int) int {
	score := 0
	high := map[int]bool{21: true, 23: true, 135: true, 139: true, 445: true, 3389: true, 5900: true}
	for _, p := range open {
		if high[p] {
			score += 20
		} else {
			score += 5
		}
	}
	score += cveCount * 15
	if score > 100 {
		score = 100
	}
	return score
}

// ApplyNmapPrivilege ports tools/nmap_priv.py: when unprivileged, either prepends
// `sudo -n` (when useSudo is true) or downgrades root-only flags (`-sS` -> `-sT`,
// strips `-O`, `--osscan-limit`, `--osscan-guess`, `--traceroute`) when privFallback is true.
func ApplyNmapPrivilege(argv []string, isRoot, useSudo, privFallback bool) ([]string, string) {
	if isRoot || len(argv) == 0 {
		return append([]string{}, argv...), ""
	}
	if useSudo {
		out := make([]string, 0, len(argv)+2)
		out = append(out, "sudo", "-n")
		out = append(out, argv...)
		return out, ""
	}
	if !privFallback {
		return append([]string{}, argv...), ""
	}
	out := make([]string, 0, len(argv))
	var notes []string
	hasConnect := false
	for _, a := range argv {
		if a == "-sT" {
			hasConnect = true
		}
	}
	for _, a := range argv {
		switch a {
		case "-sS", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX":
			if !hasConnect {
				out = append(out, "-sT")
				hasConnect = true
			}
			notes = append(notes, a+"->-sT")
		case "-O", "--osscan-limit", "--osscan-guess", "--traceroute":
			notes = append(notes, "stripped "+a)
		default:
			out = append(out, a)
		}
	}
	if len(notes) == 0 {
		return out, ""
	}
	return out, "nmap unprivileged downgrade: " + strings.Join(notes, ", ")
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

// SuggestGoals builds heuristic suggestions from open ports.
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
