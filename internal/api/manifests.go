// Package api manifests: compile-time registry for attack-module families
// (tools/attack_modules/ identities). Skills and plugins are discovered from
// disk (internal/skills, internal/plugins), not hardcoded here.
package api

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
