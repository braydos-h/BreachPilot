// Package goals ports tools/goal_engine.py PRESET_GOALS with risk
// requirements (safe/gated/high) and standard_authorized compatibility.
package goals

// Preset is one static goal.
type Preset struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
	Compatible  bool   `json:"compatible"`
	Source      string `json:"source"`
}

// Presets in engine order.
var Presets = []Preset{
	{"recon_only", "Perform thorough reconnaissance of the target. Identify OS, open services, versions, banners, and potential attack surface. Do NOT exploit anything without explicit user confirmation.", "safe", true, "preset"},
	{"identify_vulnerabilities", "Identify potential vulnerabilities on the target based on service versions, banner information, and known CVEs. Document each finding with evidence but do not actively exploit or validate without explicit confirmation.", "safe", true, "preset"},
	{"service_mapping", "Map all exposed services on the target. Document ports, protocols, service versions, and banners. Identify the technology stack and potential attack surface.", "safe", true, "preset"},
	{"recon_and_document", "Perform comprehensive reconnaissance and document everything. Build a complete map of the target's attack surface including subdomains, endpoints, parameters, and technologies. No exploitation.", "safe", true, "preset"},
	{"initial_access", "Gain initial access to the target server by identifying and exploiting a vulnerability. This could be remote code execution, credential compromise, or service exploitation. Report the vulnerability exploited and the type of access obtained. Do NOT establish persistence or exfiltrate data.", "gated", true, "preset"},
	{"verify_cves", "Verify whether identified CVEs are actually exploitable on the target. For each CVE found: (1) confirm version evidence, (2) attempt safe validation, (3) document whether it is exploitable, (4) do NOT cause damage or establish persistence. This is verification, not full exploitation.", "gated", true, "preset"},
	{"backdoor", "Establish a persistent backdoor on the target server. Gain a stable shell, maintain access, and report the method used. Prefer stealthy persistence methods (e.g., scheduled tasks, service installs, web shells). This requires explicit high-authorization testing mode.", "high", false, "preset"},
	{"privilege_escalation", "Escalate privileges on an already compromised host. Move from standard user to SYSTEM/root. Report the privilege escalation vector and confirm elevated access.", "high", false, "preset"},
	{"full_compromise", "Achieve complete compromise of the target. Gain root/SYSTEM access, establish persistence, and demonstrate full control. Report all access vectors and persistence mechanisms. This requires explicit high-authorization testing mode.", "high", false, "preset"},
	{"credential_dumping", "Obtain credentials from the target system. Attempt to dump hashes, retrieve plaintext passwords, or extract key material. Report what credentials were recovered and from where.", "high", false, "preset"},
	{"pivot_and_discovery", "Use the target as a pivot point to discover and map internal network segments. Scan nearby subnets, identify additional targets, and report network topology.", "high", false, "preset"},
	{"lateral_movement", "Move laterally from the compromised target to other hosts on the network. Use stolen credentials, pass-the-hash, or trusted relationship abuse. Report new hosts accessed.", "high", false, "preset"},
	{"data_exfiltration", "Search for and attempt to exfiltrate sensitive data from the target. Look for credentials, config files, databases, or interesting documents. Report what data is accessible and how it could be extracted.", "high", false, "preset"},
	{"whatever_it_takes", "Use any and every technique available to compromise the target. Attempt reconnaissance, service enumeration, default credential attacks, known CVE exploitation, brute force, web vulnerability scanning, payload delivery, and creative custom exploits. Do not stop at the first failure—pivot, adapt, and try alternative angles until access is achieved or all reasonable avenues are exhausted. WARNING: This goal requires HIGH authorization. Only use on infrastructure you own or have explicit full authorization for.", "high", false, "preset"},
}

// Names returns preset names for collision checks.
func Names() []string {
	out := make([]string, 0, len(Presets))
	for _, p := range Presets {
		out = append(out, p.Name)
	}
	return out
}

// IsPreset reports whether name is a preset (case-insensitive).
func IsPreset(name string) bool {
	for _, p := range Presets {
		if equalFold(p.Name, name) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
