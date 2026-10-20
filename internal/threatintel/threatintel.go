// Package threatintel is the native OSV/GHSA/KEV threat-intel client.
// Mirrors tools/threat_intel.py: query validation (SSRF guard), wire-output
// sanitization (prompt-injection hardening: strip controls, cap 200 chars),
// file cache, token-missing GHSA degradation, and KEV membership checks.
// exploitdb_rss stays off by default, mirroring the Python settings.
package threatintel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/intel"
)

const (
	osvEndpoint  = "https://api.osv.dev/v1/query"
	ghsaEndpoint = "https://api.github.com/graphql"
	// MaxStr caps every wire string, mirroring _MAX_STR.
	MaxStr = 200
)

var (
	cveRe = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)
	pkgRe = regexp.MustCompile(`^[A-Za-z0-9._/+-]{1,128}$`)
)

// Settings configures the threat-intel client. Mirrors ThreatIntelSettings.
type Settings struct {
	Enabled         bool
	CacheDir        string
	CacheTTLSeconds float64
	Sources         map[string]bool
	MaxResults      int
	GitHubTokenEnv  string
	TimeoutSeconds  float64
	OSVEndpoint     string
	GHSAEndpoint    string
}

// SettingsFor translates Config.ThreatIntel into Settings.
func SettingsFor(cfg config.Config) Settings {
	t := cfg.ThreatIntel
	src := map[string]bool{"osv": true, "ghsa": true, "kev": true, "exploitdb_rss": false}
	for k, v := range t.Sources {
		src[k] = v
	}
	return Settings{
		Enabled:         t.Enabled,
		CacheDir:        t.CacheDir,
		CacheTTLSeconds: t.CacheTTLSeconds,
		Sources:         src,
		MaxResults:      t.MaxResults,
		GitHubTokenEnv:  t.GitHubTokenEnv,
		TimeoutSeconds:  t.TimeoutSeconds,
		OSVEndpoint:     osvEndpoint,
		GHSAEndpoint:    ghsaEndpoint,
	}
}

// SourceEnabled reports whether a feed is on.
func (s Settings) SourceEnabled(name string) bool { return s.Sources[name] }

// ValidateQuery rejects anything that is not a package name or CVE ID.
// The query is interpolated into fixed-endpoint request bodies, never used
// as a URL — but shell-metachar/URL-shaped input is still rejected so a
// prompt-injected agent cannot smuggle metadata endpoints through.
func ValidateQuery(query string) (string, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		return "", fmt.Errorf("empty query")
	}
	if len(q) > 128 {
		return "", fmt.Errorf("query too long")
	}
	if cveRe.MatchString(q) {
		return strings.ToUpper(q), nil
	}
	if !pkgRe.MatchString(q) {
		return "", fmt.Errorf("query must be a package name or CVE ID")
	}
	return q, nil
}

// Clean recursively strips control chars and caps string length on feed
// data. Every string off the wire passes through it.
func Clean(v any) any {
	switch x := v.(type) {
	case string:
		var b strings.Builder
		for _, r := range x {
			if r >= ' ' {
				b.WriteRune(r)
			}
		}
		s := b.String()
		if len(s) > MaxStr {
			s = s[:MaxStr]
		}
		return s
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			out = append(out, Clean(e))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			ck := k
			if len(ck) > MaxStr {
				ck = ck[:MaxStr]
			}
			out[ck] = Clean(e)
		}
		return out
	default:
		return v
	}
}

// FetchFunc performs an HTTP call, returning parsed JSON. It overrides the
// real network path so tests never touch the network.
type FetchFunc func(url, method, body string, headers map[string]string) (any, error)

// Client queries OSV/GHSA/KEV with cache and injectable fetch.
type Client struct {
	Settings Settings
	KEV      *intel.KEVCatalog
	Fetch    FetchFunc
	HTTP     *http.Client
}

// NewClient builds a threat-intel client. A nil KEV catalog disables the
// kev source with an explicit note instead of failing.
func NewClient(s Settings, kev *intel.KEVCatalog, fetch FetchFunc) *Client {
	timeout := time.Duration(s.TimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{Settings: s, KEV: kev, Fetch: fetch, HTTP: &http.Client{Timeout: timeout}}
}

func (c *Client) timeout() time.Duration {
	d := time.Duration(c.Settings.TimeoutSeconds * float64(time.Second))
	if d <= 0 {
		return 30 * time.Second
	}
	return d
}

func (c *Client) cacheDir() string {
	if c.Settings.CacheDir != "" {
		return c.Settings.CacheDir
	}
	return "exploit_workspace/.threat_intel"
}

func cacheFile(dir, query, source string) string {
	safe := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, query)
	return filepath.Join(dir, source+"_"+safe+".json")
}

func cacheGet(dir, query, source string, ttl time.Duration) (any, bool) {
	raw, err := os.ReadFile(cacheFile(dir, query, source))
	if err != nil {
		return nil, false
	}
	fi, err := os.Stat(cacheFile(dir, query, source))
	if err != nil || time.Since(fi.ModTime()) >= ttl {
		return nil, false
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil, false
	}
	return v, true
}

func cachePut(dir, query, source string, v any) {
	_ = os.MkdirAll(dir, 0o755)
	raw, _ := json.Marshal(v)
	_ = os.WriteFile(cacheFile(dir, query, source), raw, 0o644)
}

func (c *Client) fetchJSON(url, method string, body any, headers map[string]string) (any, error) {
	h := map[string]string{"User-Agent": "breachpilot-threat-intel/1.0"}
	for k, v := range headers {
		h[k] = v
	}
	var bodyStr string
	if body != nil {
		raw, _ := json.Marshal(body)
		bodyStr = string(raw)
	}
	if c.Fetch != nil {
		return c.Fetch(url, method, bodyStr, h)
	}
	var reqBody *bytes.Reader
	if body != nil {
		reqBody = bytes.NewReader([]byte(bodyStr))
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var v any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func (c *Client) maxResults() int {
	if c.Settings.MaxResults > 0 {
		return c.Settings.MaxResults
	}
	return 20
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// SearchOSV queries OSV.dev for a package or CVE. Mirrors search_osv.
func (c *Client) SearchOSV(ctx context.Context, query string) map[string]any {
	ttl := time.Duration(c.Settings.CacheTTLSeconds * float64(time.Second))
	if cached, ok := cacheGet(c.cacheDir(), query, "osv", ttl); ok {
		if m, ok := cached.(map[string]any); ok {
			return m
		}
	}
	var body any
	if cveRe.MatchString(query) {
		body = map[string]any{"version": query}
	} else {
		body = map[string]any{"package": map[string]any{"name": query}}
	}
	payload, err := c.fetchJSON(c.endpoint(c.Settings.OSVEndpoint, osvEndpoint), "POST",
		body, map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return map[string]any{"error": fmt.Sprintf("osv fetch failed: %v", err)}
	}
	var vulns []any
	for _, v := range asSlice(asMap(payload)["vulns"]) {
		m := asMap(v)
		var severity string
		if sev := asSlice(m["severity"]); len(sev) > 0 {
			severity = asString(asMap(sev[0])["score"])
		}
		var refs []any
		for _, r := range asSlice(m["references"]) {
			if u := asString(asMap(r)["url"]); u != "" {
				refs = append(refs, u)
			}
		}
		vulns = append(vulns, map[string]any{
			"id": m["id"], "summary": m["summary"], "severity": severity,
			"aliases": m["aliases"], "published": m["published"], "references": refs,
		})
		if len(vulns) >= c.maxResults() {
			break
		}
	}
	if vulns == nil {
		vulns = []any{}
	}
	out := map[string]any{"vulns": Clean(vulns)}
	cachePut(c.cacheDir(), query, "osv", out)
	return out
}

// SearchGHSA queries GitHub Security Advisories. Without a token it
// degrades to a skipped marker so OSV+KEV still answer.
func (c *Client) SearchGHSA(ctx context.Context, query string) map[string]any {
	token := strings.TrimSpace(os.Getenv(c.Settings.GitHubTokenEnv))
	if c.Settings.GitHubTokenEnv == "" {
		token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	if token == "" {
		return map[string]any{"skipped": "token missing"}
	}
	ttl := time.Duration(c.Settings.CacheTTLSeconds * float64(time.Second))
	if cached, ok := cacheGet(c.cacheDir(), query, "ghsa", ttl); ok {
		if m, ok := cached.(map[string]any); ok {
			return m
		}
	}
	var gql string
	if cveRe.MatchString(query) {
		gql = `query { securityAdvisories(first: 20, identifier: { type: CVE, value: "` + query + `" }) { nodes { ghsaId summary severity publishedAt references { url } } } }`
	} else {
		// Package names are restricted to [A-Za-z0-9._/+-] by
		// ValidateQuery, so no quote-injection risk here.
		gql = `query { securityVulnerabilities(first: 20, package: { type: NPM, name: "` + query + `" }) { nodes { advisory { ghsaId summary severity publishedAt references { url } } } } }`
	}
	payload, err := c.fetchJSON(c.endpoint(c.Settings.GHSAEndpoint, ghsaEndpoint), "POST",
		map[string]any{"query": gql},
		map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + token})
	if err != nil {
		return map[string]any{"error": fmt.Sprintf("ghsa fetch failed: %v", err)}
	}
	data := asMap(asMap(payload)["data"])
	nodes := asSlice(asMap(data["securityAdvisories"])["nodes"])
	if len(nodes) == 0 {
		var advisories []any
		for _, n := range asSlice(asMap(data["securityVulnerabilities"])["nodes"]) {
			if a := asMap(n)["advisory"]; a != nil {
				advisories = append(advisories, a)
			}
		}
		nodes = advisories
	}
	var out []any
	for _, n := range nodes {
		a := asMap(n)
		var refs []any
		for _, r := range asSlice(a["references"]) {
			if u := asString(asMap(r)["url"]); u != "" {
				refs = append(refs, u)
			}
		}
		out = append(out, map[string]any{
			"ghsa_id": a["ghsaId"], "summary": a["summary"], "severity": a["severity"],
			"published": a["publishedAt"], "references": refs,
		})
		if len(out) >= c.maxResults() {
			break
		}
	}
	if out == nil {
		out = []any{}
	}
	res := map[string]any{"advisories": Clean(out)}
	cachePut(c.cacheDir(), query, "ghsa", res)
	return res
}

// SearchKEV checks CISA KEV membership. Non-CVE queries are always false:
// KEV is a CVE catalog, not a package database.
func (c *Client) SearchKEV(ctx context.Context, query string) map[string]any {
	if c.KEV == nil {
		return map[string]any{"known_exploited": false, "note": "kev disabled"}
	}
	if !cveRe.MatchString(query) {
		return map[string]any{"known_exploited": false}
	}
	return map[string]any{"known_exploited": c.KEV.IsKnownExploited(ctx, query)}
}

func (c *Client) endpoint(setting, def string) string {
	if setting != "" {
		return setting
	}
	return def
}

// Search runs the requested sources (default "osv,ghsa,kev") and returns
// {"query", "sources"}. Disabled config fails closed with an error marker.
func (c *Client) Search(ctx context.Context, query, sources string) (map[string]any, error) {
	q, err := ValidateQuery(query)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"query": q, "sources": map[string]any{}}
	src := out["sources"].(map[string]any)
	if !c.Settings.Enabled {
		out["error"] = "threat_intel disabled"
		return Clean(out).(map[string]any), nil
	}
	if sources == "" {
		sources = "osv,ghsa,kev"
	}
	for _, name := range strings.Split(sources, ",") {
		switch strings.TrimSpace(name) {
		case "osv":
			if c.Settings.SourceEnabled("osv") {
				src["osv"] = c.SearchOSV(ctx, q)
			}
		case "ghsa":
			if c.Settings.SourceEnabled("ghsa") {
				src["ghsa"] = c.SearchGHSA(ctx, q)
			}
		case "kev":
			if c.Settings.SourceEnabled("kev") {
				src["kev"] = c.SearchKEV(ctx, q)
			}
		}
	}
	return Clean(out).(map[string]any), nil
}
