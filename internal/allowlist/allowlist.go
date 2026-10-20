// Package allowlist is the Go mirror of the Rust bp-allowlist crate and the
// Python tools/kernel/allowlist.py gate. Single-target and multi-target
// checks over exact IP, CIDR, domain, and *.wildcard entries with
// dot-boundary semantics. Empty union fails closed when required=true.
package allowlist

import (
	"net"
	"strings"
)

// Check reports whether target is authorized by entries.
func Check(target string, entries []string, required bool) bool {
	target = strings.TrimSpace(strings.ToLower(target))
	if target == "" {
		return false
	}
	if len(entries) == 0 {
		return !required
	}
	ip := net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(target, "["), "]"))
	for _, e := range entries {
		e = strings.TrimSpace(strings.ToLower(e))
		if e == "" {
			continue
		}
		if matchOne(target, ip, e) {
			return true
		}
	}
	return false
}

// CheckAll requires every target to be authorized.
func CheckAll(targets []string, entries []string, required bool) bool {
	if len(targets) == 0 {
		return !required
	}
	for _, t := range targets {
		if !Check(t, entries, required) {
			return false
		}
	}
	return true
}

func matchOne(target string, ip net.IP, entry string) bool {
	entry = strings.TrimSuffix(strings.TrimPrefix(entry, "["), "]")
	// CIDR entry.
	if _, cidr, err := net.ParseCIDR(entry); err == nil {
		if ip == nil {
			// Domain targets never match CIDR entries (no implicit DNS grant).
			return false
		}
		return cidr.Contains(ip)
	}
	// Exact IP entry.
	if entryIP := net.ParseIP(entry); entryIP != nil {
		return ip != nil && entryIP.Equal(ip)
	}
	// Wildcard *.example.com matches subdomains only, with dot boundary.
	if strings.HasPrefix(entry, "*.") {
		base := entry[2:]
		return strings.HasSuffix(target, "."+base) && len(target) > len(base)+1
	}
	// Exact domain (case-insensitive).
	return target == entry
}

// IsSubdomain reports strict dot-boundary subdomain relationship.
func IsSubdomain(child, parent string) bool {
	child = strings.ToLower(strings.TrimSpace(child))
	parent = strings.ToLower(strings.TrimSpace(parent))
	if child == "" || parent == "" || child == parent {
		return false
	}
	return strings.HasSuffix(child, "."+parent)
}
