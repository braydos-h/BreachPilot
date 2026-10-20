// Native dns_enum tool: DNS record enumeration via the Go resolver.

package modules

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/recon"
)

func init() {
	register(Tool{Name: "dns_enum", Description: "DNS enumeration: A/AAAA/CNAME/MX/NS/TXT records for a target (bounded resolver, capped output).", Family: "network",
		Run: func(ctx context.Context, args map[string]any, env Env) (map[string]any, error) {
			host := strArg(args, "target")
			if host == "" {
				return nil, fmt.Errorf("missing %q", "target")
			}
			if _, _, err := recon.ParseTarget(host); err != nil {
				return nil, err
			}
			timeout := env.Timeout
			if timeout <= 0 {
				timeout = 10 * time.Second
			}
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			r := &net.Resolver{}
			out := map[string]any{"target": host}
			if addrs, err := r.LookupHost(ctx, host); err == nil {
				out["a"] = cappedStrings(addrs, 16)
			} else {
				out["a"] = []string{}
			}
			if cname, err := r.LookupCNAME(ctx, host); err == nil && !strings.EqualFold(strings.TrimSuffix(cname, "."), strings.TrimSuffix(host, ".")) {
				out["cname"] = strings.TrimSuffix(cname, ".")
			}
			if mxs, err := r.LookupMX(ctx, host); err == nil {
				var hosts []string
				for _, m := range mxs {
					hosts = append(hosts, strings.TrimSuffix(m.Host, "."))
					if len(hosts) >= 16 {
						break
					}
				}
				if hosts == nil {
					hosts = []string{}
				}
				out["mx"] = hosts
			}
			if nss, err := r.LookupNS(ctx, host); err == nil {
				var hosts []string
				for _, n := range nss {
					hosts = append(hosts, strings.TrimSuffix(n.Host, "."))
					if len(hosts) >= 16 {
						break
					}
				}
				if hosts == nil {
					hosts = []string{}
				}
				out["ns"] = hosts
			}
			if txts, err := r.LookupTXT(ctx, host); err == nil {
				out["txt"] = cappedStrings(txts, 16)
			}
			return out, nil
		}})
}

func cappedStrings(in []string, n int) []string {
	if len(in) > n {
		in = in[:n]
	}
	if in == nil {
		return []string{}
	}
	return in
}
