// Package modules is the native tool registry: real assessment tools with
// capability metadata, dispatched by the agent loop and the manual
// POST /runs/{id}/tools/{name}/calls route. Mirrors the execution contract
// of tools/mcp_tools + tools/attack_modules (registry + capability checks)
// without Python reflection: registration is compile-time.
package modules

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/recon"
)

// Env carries call context: allowlist entries and timeouts.
type Env struct {
	Entries []string
	Timeout time.Duration
}

// Tool is one native capability.
type Tool struct {
	Name           string
	Description    string
	Family         string
	TargetServices []string
	TargetPorts    []int
	RequiredCVEs   []string
	DestructiveICS bool
	Run            func(ctx context.Context, args map[string]any, env Env) (map[string]any, error)
}

// Registry maps name -> tool.
var Registry = map[string]Tool{}

func register(t Tool) { Registry[t.Name] = t }

// List returns tools sorted by name.
func List() []Tool {
	out := make([]Tool, 0, len(Registry))
	for _, t := range Registry {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func strArg(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func targetIP(ctx context.Context, args map[string]any, key string) (string, error) {
	host := strArg(args, key)
	if host == "" {
		return "", fmt.Errorf("missing %q", key)
	}
	if _, _, err := recon.ParseTarget(host); err != nil {
		return "", err
	}
	ip, _, err := recon.Resolve(ctx, host)
	if err != nil {
		return "", err
	}
	return ip, nil
}

func intArg(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func init() {
	register(Tool{Name: "resolve", Description: "Resolve a target to its IP (bounded DNS, IP literals skip DNS).", Family: "network",
		Run: func(ctx context.Context, args map[string]any, env Env) (map[string]any, error) {
			host := strArg(args, "target")
			ip, domain, err := recon.Resolve(ctx, host)
			if err != nil {
				return nil, err
			}
			return map[string]any{"target": host, "ip": ip, "domain": domain}, nil
		}})
	register(Tool{Name: "tcp_scan", Description: "TCP connect scan of target ports with banner grabs.", Family: "network",
		Run: func(ctx context.Context, args map[string]any, env Env) (map[string]any, error) {
			ip, err := targetIP(ctx, args, "target")
			if err != nil {
				return nil, err
			}
			ports := recon.DefaultFastPorts
			if p, ok := args["ports"]; ok {
				var custom []int
				switch v := p.(type) {
				case string:
					for _, s := range strings.Split(v, ",") {
						if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 && n < 65536 {
							custom = append(custom, n)
						}
					}
				case []any:
					for _, e := range v {
						custom = append(custom, intArg(map[string]any{"x": e}, "x", 0))
					}
				}
				if len(custom) > 0 {
					if len(custom) > 256 {
						custom = custom[:256]
					}
					ports = custom
				}
			}
			results := recon.ScanPorts(ctx, ip, ports)
			open := []map[string]any{}
			for _, r := range results {
				if r.Open {
					open = append(open, map[string]any{"port": r.Port, "banner": r.Banner})
				}
			}
			return map[string]any{"target": ip, "open": open, "scanned": len(ports)}, nil
		}})
	register(Tool{Name: "http_probe", Description: "HTTP(S) probe: status, server header, title sniff.", Family: "network",
		Run: func(ctx context.Context, args map[string]any, env Env) (map[string]any, error) {
			ip, err := targetIP(ctx, args, "target")
			if err != nil {
				return nil, err
			}
			port := intArg(args, "port", 80)
			path := strArg(args, "path")
			if path == "" {
				path = "/"
			}
			if !strings.HasPrefix(path, "/") {
				return nil, fmt.Errorf("path must start with /")
			}
			scheme := "http"
			if port == 443 || port == 8443 {
				scheme = "https"
			}
			if s, ok := args["scheme"].(string); ok && (s == "http" || s == "https") {
				scheme = s
			}
			client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			}}
			url := fmt.Sprintf("%s://%s:%d%s", scheme, ip, port, path)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("User-Agent", "BreachPilot-native-probe")
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			body := string(buf[:n])
			title := ""
			if i := strings.Index(strings.ToLower(body), "<title>"); i >= 0 {
				rest := body[i+7:]
				if j := strings.Index(strings.ToLower(rest), "</title>"); j >= 0 && j < 256 {
					title = strings.TrimSpace(rest[:j])
				}
			}
			return map[string]any{"url": url, "status": resp.StatusCode,
				"server": resp.Header.Get("Server"), "title": title}, nil
		}})
	register(Tool{Name: "tls_probe", Description: "TLS handshake probe: cert subject/issuer/expiry, negotiated version.", Family: "network",
		Run: func(ctx context.Context, args map[string]any, env Env) (map[string]any, error) {
			ip, err := targetIP(ctx, args, "target")
			if err != nil {
				return nil, err
			}
			port := intArg(args, "port", 443)
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // assessment probe records presented cert; no trust decision made
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
			if err != nil {
				return nil, err
			}
			defer conn.Close()
			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				return nil, fmt.Errorf("not a TLS connection")
			}
			st := tlsConn.ConnectionState()
			out := map[string]any{"version": tls.VersionName(st.Version), "certs": []any{}}
			var certs []any
			for _, c := range st.PeerCertificates {
				certs = append(certs, map[string]any{"subject": c.Subject.String(), "issuer": c.Issuer.String(),
					"not_after": c.NotAfter.Format(time.RFC3339), "dns_names": c.DNSNames})
			}
			out["certs"] = certs
			return out, nil
		}})
}
