// Package intel implements native vulnerability intelligence: NVD CVE API 2.0
// lookup with query sanitization, LRU caching, rate limiting, and circuit
// breaker, plus EPSS exploit-prediction scoring and CISA KEV catalog enrichment.
// Mirrors tools/cve_lookup.py without any Python runtime dependency.
package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/braydos-h/BreachPilot/internal/config"
)

const (
	DefaultNVDBaseURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultEPSSBaseURL = "https://api.first.org/data/v1/epss"
	DefaultKEVURL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

var shellMetaRe = regexp.MustCompile(`[&;|<>` + "`" + `$\\\n\r]`)

// NVDHTTPError carries the HTTP status code so 4xx soft misses do not trip the
// circuit breaker while 5xx errors count as hard failures.
type NVDHTTPError struct {
	Code    int
	Message string
}

func (e *NVDHTTPError) Error() string {
	return fmt.Sprintf("NVD HTTP %d: %s", e.Code, e.Message)
}

// SanitizeQuery validates and normalizes a CVE search query.
func SanitizeQuery(query string) (string, error) {
	if shellMetaRe.MatchString(query) {
		return "", errors.New("shell metacharacters in query.")
	}
	text := strings.Join(strings.Fields(strings.TrimSpace(query)), " ")
	if text == "" {
		return "", errors.New("empty query.")
	}
	if len(text) > 180 {
		return "", errors.New("query too long.")
	}
	return text, nil
}

// Settings configures NVD, EPSS, and KEV lookup behavior.
type Settings struct {
	Enabled                 bool
	Timeout                 time.Duration
	MaxResults              int
	CacheTTL                time.Duration
	CacheMaxEntries         int
	RateLimit               time.Duration
	APIKey                  string
	CircuitFailureThreshold int
	CircuitRecoveryTimeout  time.Duration
	EPSSEnabled             bool
	KEVEnabled              bool
	KEVCacheTTL             time.Duration
	KEVCachePath            string
	NVDBaseURL              string
	EPSSBaseURL             string
	KEVURL                  string
}

// DefaultSettings returns the standard vulnerability-intelligence settings.
func DefaultSettings() Settings {
	return Settings{
		Enabled:                 true,
		Timeout:                 15 * time.Second,
		MaxResults:              5,
		CacheTTL:                time.Hour,
		CacheMaxEntries:         100,
		RateLimit:               0, // 0 in default native settings unless rate-limited
		CircuitFailureThreshold: 5,
		CircuitRecoveryTimeout:  60 * time.Second,
		EPSSEnabled:             false,
		KEVEnabled:              false,
		KEVCacheTTL:             24 * time.Hour,
		NVDBaseURL:              DefaultNVDBaseURL,
		EPSSBaseURL:             DefaultEPSSBaseURL,
		KEVURL:                  DefaultKEVURL,
	}
}

// SettingsFor translates Config.Intel (the cve_lookup block) into client
// settings, resolving the API key from its configured env var. Mirrors the
// Python cve_lookup defaults so EPSS/KEV enrichment runs when configured.
func SettingsFor(cfg config.Config) Settings {
	s := DefaultSettings()
	i := cfg.Intel
	s.Enabled = i.Enabled
	if i.MaxResults > 0 {
		s.MaxResults = i.MaxResults
	}
	if i.RateLimitSeconds > 0 {
		s.RateLimit = time.Duration(i.RateLimitSeconds * float64(time.Second))
	}
	if i.TimeoutSeconds > 0 {
		s.Timeout = time.Duration(i.TimeoutSeconds * float64(time.Second))
	}
	if i.CacheTTLSeconds > 0 {
		s.CacheTTL = time.Duration(i.CacheTTLSeconds * float64(time.Second))
	}
	if i.CacheMaxEntries > 0 {
		s.CacheMaxEntries = i.CacheMaxEntries
	}
	if i.CircuitFailureThreshold > 0 {
		s.CircuitFailureThreshold = i.CircuitFailureThreshold
	}
	if i.CircuitRecoveryTimeoutSec > 0 {
		s.CircuitRecoveryTimeout = time.Duration(i.CircuitRecoveryTimeoutSec * float64(time.Second))
	}
	s.EPSSEnabled = i.EPSSEnabled
	s.KEVEnabled = i.KEVEnabled
	if i.KEVCacheTTLSeconds > 0 {
		s.KEVCacheTTL = time.Duration(i.KEVCacheTTLSeconds * float64(time.Second))
	}
	if i.KEVCachePath != "" {
		s.KEVCachePath = i.KEVCachePath
	}
	envName := i.APIKeyEnv
	if envName == "" {
		envName = "NVD_API_KEY"
	}
	s.APIKey = os.Getenv(envName)
	return s
}

// CVEEntry represents one enriched CVE record.
type CVEEntry struct {
	CVEID          string   `json:"cve_id"`
	Description    string   `json:"description"`
	CVSSScore      *float64 `json:"cvss_score"`
	Severity       string   `json:"severity"`
	CWE            string   `json:"cwe"`
	Published      string   `json:"published"`
	References     []string `json:"references"`
	EPSS           *float64 `json:"epss,omitempty"`
	EPSSPercentile *float64 `json:"epss_percentile,omitempty"`
	KEV            bool     `json:"kev"`
}

// Summary formats a single CVEEntry identically to CVEEntry.summary() in Python.
func (c CVEEntry) Summary() string {
	sev := c.Severity
	if sev == "" {
		sev = "unknown severity"
	}
	lines := []string{fmt.Sprintf("- %s (%s)", c.CVEID, sev)}
	if c.CVSSScore != nil {
		lines = append(lines, fmt.Sprintf("  CVSS: %.1f", *c.CVSSScore))
	}
	if c.EPSS != nil {
		pct := 0.0
		if c.EPSSPercentile != nil {
			pct = *c.EPSSPercentile
		}
		lines = append(lines, fmt.Sprintf("  EPSS: %.4f (percentile %.4f)", *c.EPSS, pct))
	}
	if c.KEV {
		lines = append(lines, "  KEV: yes (CISA Known Exploited Vulnerability)")
	}
	if c.CWE != "" {
		lines = append(lines, "  CWE: "+c.CWE)
	}
	if c.Published != "" {
		lines = append(lines, "  Published: "+c.Published)
	}
	if c.Description != "" {
		desc := c.Description
		if len(desc) > 300 {
			desc = desc[:300]
		}
		lines = append(lines, "  Description: "+desc)
	}
	if len(c.References) > 0 {
		refs := c.References
		if len(refs) > 3 {
			refs = refs[:3]
		}
		lines = append(lines, "  References: "+strings.Join(refs, ", "))
	}
	return strings.Join(lines, "\n")
}

// FormatCVEResults formats a slice of CVEEntries for MCP and CLI output.
func FormatCVEResults(entries []CVEEntry, query string) string {
	if len(entries) == 0 {
		return fmt.Sprintf("No CVEs found for %q.", query)
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d CVE(s) for %q:\n", len(entries), query))
	for _, e := range entries {
		sb.WriteString(e.Summary())
		sb.WriteString("\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

// ParseNVDResponse parses NVD API 2.0 JSON into CVEEntries.
func ParseNVDResponse(raw []byte, maxResults int) ([]CVEEntry, error) {
	var payload struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string][]struct {
					CVSSData struct {
						BaseScore    *float64 `json:"baseScore"`
						BaseSeverity string   `json:"baseSeverity"`
					} `json:"cvssData"`
					BaseSeverity string `json:"baseSeverity"`
				} `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("parse NVD JSON: %w", err)
	}
	if maxResults <= 0 {
		maxResults = 5
	}
	out := make([]CVEEntry, 0, len(payload.Vulnerabilities))
	for _, item := range payload.Vulnerabilities {
		if len(out) >= maxResults {
			break
		}
		cve := item.CVE
		if strings.TrimSpace(cve.ID) == "" {
			continue
		}
		var desc string
		for _, d := range cve.Descriptions {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		if desc == "" && len(cve.Descriptions) > 0 {
			desc = cve.Descriptions[0].Value
		}

		var score *float64
		var severity string
		for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			if list, ok := cve.Metrics[key]; ok && len(list) > 0 {
				m := list[0]
				score = m.CVSSData.BaseScore
				severity = m.CVSSData.BaseSeverity
				if severity == "" {
					severity = m.BaseSeverity
				}
				break
			}
		}

		var cwe string
		for _, w := range cve.Weaknesses {
			for _, d := range w.Description {
				if strings.HasPrefix(d.Value, "CWE-") {
					cwe = d.Value
					break
				}
			}
			if cwe != "" {
				break
			}
		}

		pub := cve.Published
		if len(pub) >= 10 {
			pub = pub[:10]
		}

		refs := make([]string, 0, 5)
		for _, r := range cve.References {
			if r.URL != "" && len(refs) < 5 {
				refs = append(refs, r.URL)
			}
		}

		out = append(out, CVEEntry{
			CVEID:       cve.ID,
			Description: desc,
			CVSSScore:   score,
			Severity:    strings.ToUpper(severity),
			CWE:         cwe,
			Published:   pub,
			References:  refs,
		})
	}
	return out, nil
}

// EPSSScore holds EPSS probability and percentile.
type EPSSScore struct {
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}

// EPSSClient queries FIRST.org EPSS scores with caching.
type EPSSClient struct {
	Settings Settings
	Client   *http.Client

	mu    sync.Mutex
	cache map[string]EPSSScore
}

// NewEPSSClient builds an EPSSClient.
func NewEPSSClient(s Settings) *EPSSClient {
	if s.EPSSBaseURL == "" {
		s.EPSSBaseURL = DefaultEPSSBaseURL
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &EPSSClient{
		Settings: s,
		Client:   &http.Client{Timeout: timeout},
		cache:    map[string]EPSSScore{},
	}
}

// GetBatch returns EPSS scores for the requested CVE IDs. Advisory: errors return cached subset.
func (e *EPSSClient) GetBatch(ctx context.Context, cveIDs []string) map[string]EPSSScore {
	out := map[string]EPSSScore{}
	var missing []string
	e.mu.Lock()
	for _, id := range cveIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if sc, ok := e.cache[id]; ok {
			out[id] = sc
		} else {
			missing = append(missing, id)
		}
	}
	e.mu.Unlock()
	if len(missing) == 0 {
		return out
	}
	if len(missing) > 100 {
		missing = missing[:100]
	}
	u := e.Settings.EPSSBaseURL + "?cve=" + url.QueryEscape(strings.Join(missing, ","))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return out
	}
	req.Header.Set("User-Agent", "breachpilot-epss/1.0")
	resp, err := e.Client.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}
	var payload struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       any    `json:"epss"`
			Percentile any    `json:"percentile"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return out
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, row := range payload.Data {
		if row.CVE == "" {
			continue
		}
		ev, ok1 := parseFloatAny(row.EPSS)
		pv, ok2 := parseFloatAny(row.Percentile)
		if ok1 && ok2 {
			sc := EPSSScore{EPSS: ev, Percentile: pv}
			e.cache[row.CVE] = sc
			out[row.CVE] = sc
		}
	}
	return out
}

func parseFloatAny(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// KEVCatalog manages CISA Known Exploited Vulnerabilities membership with file cache.
type KEVCatalog struct {
	Settings Settings
	Client   *http.Client

	mu   sync.Mutex
	cves map[string]bool
}

// NewKEVCatalog creates a KEVCatalog.
func NewKEVCatalog(s Settings) *KEVCatalog {
	if s.KEVURL == "" {
		s.KEVURL = DefaultKEVURL
	}
	if s.KEVCacheTTL <= 0 {
		s.KEVCacheTTL = 24 * time.Hour
	}
	if s.KEVCachePath == "" {
		ws := os.Getenv("EXPLOIT_WORKSPACE")
		if ws == "" {
			ws = "exploit_workspace"
		}
		s.KEVCachePath = filepath.Join(ws, ".kev_catalog.json")
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &KEVCatalog{
		Settings: s,
		Client:   &http.Client{Timeout: timeout},
	}
}

func (k *KEVCatalog) load(ctx context.Context) map[string]bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cves != nil {
		return k.cves
	}
	k.cves = map[string]bool{}
	var raw []byte
	if fi, err := os.Stat(k.Settings.KEVCachePath); err == nil && time.Since(fi.ModTime()) < k.Settings.KEVCacheTTL {
		raw, _ = os.ReadFile(filepath.Clean(k.Settings.KEVCachePath))
	}
	if len(raw) == 0 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.Settings.KEVURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "breachpilot-kev/1.0")
			if resp, err := k.Client.Do(req); err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					raw, _ = io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
					if len(raw) > 0 && k.Settings.KEVCachePath != "" {
						_ = os.MkdirAll(filepath.Dir(k.Settings.KEVCachePath), 0o755)
						_ = os.WriteFile(k.Settings.KEVCachePath, raw, 0o644)
					}
				}
			}
		}
	}
	if len(raw) > 0 {
		var payload struct {
			Vulnerabilities []struct {
				CVEID string `json:"cveID"`
			} `json:"vulnerabilities"`
		}
		if json.Unmarshal(raw, &payload) == nil {
			for _, v := range payload.Vulnerabilities {
				id := strings.TrimSpace(v.CVEID)
				if id != "" {
					k.cves[id] = true
				}
			}
		}
	}
	return k.cves
}

// IsKnownExploited reports whether cveID is in the CISA KEV catalog.
func (k *KEVCatalog) IsKnownExploited(ctx context.Context, cveID string) bool {
	return k.load(ctx)[strings.TrimSpace(cveID)]
}

type cacheEntry struct {
	key     string
	at      time.Time
	entries []CVEEntry
}

// NVDClient queries NVD CVE API 2.0 with caching, rate limiting, circuit breaker,
// and optional EPSS/KEV enrichment.
type NVDClient struct {
	Settings Settings
	HTTP     *http.Client
	EPSS     *EPSSClient
	KEV      *KEVCatalog

	mu          sync.Mutex
	cache       []cacheEntry
	failures    int
	openedAt    time.Time
	lastRequest time.Time
}

// NewNVDClient constructs an NVDClient.
func NewNVDClient(s Settings) *NVDClient {
	if s.NVDBaseURL == "" {
		s.NVDBaseURL = DefaultNVDBaseURL
	}
	if s.MaxResults <= 0 {
		s.MaxResults = 5
	}
	if s.CacheTTL <= 0 {
		s.CacheTTL = time.Hour
	}
	if s.CacheMaxEntries <= 0 {
		s.CacheMaxEntries = 100
	}
	if s.CircuitFailureThreshold <= 0 {
		s.CircuitFailureThreshold = 5
	}
	if s.CircuitRecoveryTimeout <= 0 {
		s.CircuitRecoveryTimeout = 60 * time.Second
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &NVDClient{
		Settings: s,
		HTTP:     &http.Client{Timeout: timeout},
		EPSS:     NewEPSSClient(s),
		KEV:      NewKEVCatalog(s),
	}
}

func (n *NVDClient) getCached(key string) ([]CVEEntry, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, ce := range n.cache {
		if ce.key == key {
			if time.Since(ce.at) > n.Settings.CacheTTL {
				n.cache = append(n.cache[:i], n.cache[i+1:]...)
				return nil, false
			}
			// Move to end (MRU)
			n.cache = append(n.cache[:i], n.cache[i+1:]...)
			n.cache = append(n.cache, ce)
			cp := make([]CVEEntry, len(ce.entries))
			copy(cp, ce.entries)
			return cp, true
		}
	}
	return nil, false
}

func (n *NVDClient) putCached(key string, entries []CVEEntry) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, ce := range n.cache {
		if ce.key == key {
			n.cache = append(n.cache[:i], n.cache[i+1:]...)
			break
		}
	}
	cp := make([]CVEEntry, len(entries))
	copy(cp, entries)
	n.cache = append(n.cache, cacheEntry{key: key, at: time.Now(), entries: cp})
	for len(n.cache) > n.Settings.CacheMaxEntries {
		n.cache = n.cache[1:]
	}
}

func (n *NVDClient) breakerOpen() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failures < n.Settings.CircuitFailureThreshold {
		return false
	}
	if time.Since(n.openedAt) >= n.Settings.CircuitRecoveryTimeout {
		return false // half-open probe allowed
	}
	return true
}

func (n *NVDClient) recordSuccess() {
	n.mu.Lock()
	n.failures = 0
	n.mu.Unlock()
}

func (n *NVDClient) recordFailure() {
	n.mu.Lock()
	n.failures++
	if n.failures >= n.Settings.CircuitFailureThreshold {
		n.openedAt = time.Now()
	}
	n.mu.Unlock()
}

// Search queries NVD by keyword and optionally enriches results with EPSS and KEV.
func (n *NVDClient) Search(ctx context.Context, query string) ([]CVEEntry, error) {
	if !n.Settings.Enabled {
		return []CVEEntry{}, nil
	}
	clean, err := SanitizeQuery(query)
	if err != nil {
		return nil, err
	}
	cacheKey := strings.ToLower(clean)
	if cached, ok := n.getCached(cacheKey); ok {
		return cached, nil
	}
	if n.breakerOpen() {
		return []CVEEntry{}, nil
	}

	if n.Settings.RateLimit > 0 {
		n.mu.Lock()
		elapsed := time.Since(n.lastRequest)
		wait := n.Settings.RateLimit - elapsed
		n.lastRequest = time.Now()
		n.mu.Unlock()
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	u := fmt.Sprintf("%s?keywordSearch=%s&resultsPerPage=%d",
		n.Settings.NVDBaseURL, url.QueryEscape(clean), n.Settings.MaxResults)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "breachpilot-nvd/1.0")
	if n.Settings.APIKey != "" {
		req.Header.Set("apiKey", n.Settings.APIKey)
	}
	resp, err := n.HTTP.Do(req)
	if err != nil {
		n.recordFailure()
		return nil, fmt.Errorf("NVD request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		// 4xx is a soft miss (e.g. 404): do not trip circuit breaker
		return []CVEEntry{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		n.recordFailure()
		return nil, &NVDHTTPError{Code: resp.StatusCode, Message: resp.Status}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		n.recordFailure()
		return nil, err
	}
	entries, err := ParseNVDResponse(raw, n.Settings.MaxResults)
	if err != nil {
		n.recordFailure()
		return nil, err
	}
	n.recordSuccess()
	n.enrich(ctx, entries)
	n.putCached(cacheKey, entries)
	return entries, nil
}

func (n *NVDClient) enrich(ctx context.Context, entries []CVEEntry) {
	if len(entries) == 0 {
		return
	}
	if n.Settings.EPSSEnabled && n.EPSS != nil {
		ids := make([]string, 0, len(entries))
		for _, e := range entries {
			ids = append(ids, e.CVEID)
		}
		scores := n.EPSS.GetBatch(ctx, ids)
		for i := range entries {
			if sc, ok := scores[entries[i].CVEID]; ok {
				ev := sc.EPSS
				pv := sc.Percentile
				entries[i].EPSS = &ev
				entries[i].EPSSPercentile = &pv
			}
		}
	}
	if n.Settings.KEVEnabled && n.KEV != nil {
		for i := range entries {
			entries[i].KEV = n.KEV.IsKnownExploited(ctx, entries[i].CVEID)
		}
	}
}
