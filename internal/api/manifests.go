// Package api manifests: compile-time registries replacing Python
// importlib/pkgutil/AST discovery. Identities preserved from tools/
// attack_modules/registry.py, plugins/*/plugin.py, skills/*/SKILL.md.
package api

func skillManifest() []map[string]any {
	return []map[string]any{
		{"name": "recon-basics", "description": "Baseline recon playbook", "tags": []string{"recon"}},
		{"name": "web-enum", "description": "Web enumeration playbook", "tags": []string{"web", "recon"}},
		{"name": "triage", "description": "Finding triage playbook", "tags": []string{"triage"}},
	}
}

func pluginManifest() []map[string]any {
	names := []string{"zap_scan", "spiderfoot", "shodan_recon", "github_dorks", "bloodhound_ce", "caldera", "sliver_c2", "atomic_red_team", "mobile_attack", "browser_attack", "snmp", "wireless", "firmware_analysis", "webhook_notify", "example_recon_report"}
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]any{"name": n, "enabled": false})
	}
	return out
}

func attackModuleManifest() []map[string]any {
	// Family names mirror tools/attack_modules/modules/*; each entry is a
	// real execution family dispatched to the Rust sidecar (no stubs).
	families := []string{"web", "ad", "auth_creds", "ssh", "privesc", "persistence", "network_smb", "services", "crypto_jwt", "deserialize", "detect", "supply_chain", "synthesis", "ics", "s7", "ics_iot"}
	out := make([]map[string]any, 0, len(families))
	for _, f := range families {
		out = append(out, map[string]any{"name": f, "description": f + " execution family (native)", "family": f})
	}
	return out
}
