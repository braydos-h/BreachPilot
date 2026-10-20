// Package api manifests: serves the full registered native attack-module
// catalog from internal/modules. Skills and plugins are discovered from disk
// (internal/skills, internal/plugins).
package api

import "github.com/braydos-h/BreachPilot/internal/modules"

func attackModuleManifest() []map[string]any {
	tools := modules.List()
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		svcs := t.TargetServices
		if svcs == nil {
			svcs = []string{}
		}
		ports := t.TargetPorts
		if ports == nil {
			ports = []int{}
		}
		cves := t.RequiredCVEs
		if cves == nil {
			cves = []string{}
		}
		out = append(out, map[string]any{
			"name":            t.Name,
			"description":     t.Description,
			"family":          t.Family,
			"target_services": svcs,
			"target_ports":    ports,
			"required_cves":   cves,
			"destructive_ics": t.DestructiveICS,
		})
	}
	return out
}
