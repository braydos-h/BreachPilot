package skills

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/braydos-h/BreachPilot/internal/modules"
)

var slaDaysBySeverity = map[string]int{
	"critical": 14,
	"high":     30,
	"medium":   60,
	"low":      90,
}

func mapSkillToModules(sk *Skill) []string {
	hay := strings.ToLower(sk.Name + " " + sk.Description + " " + strings.Join(sk.Tags, " "))
	var out []string
	add := func(m string) {
		for _, x := range out {
			if x == m {
				return
			}
		}
		if _, ok := modules.Registry[m]; ok {
			out = append(out, m)
		}
	}
	switch {
	case strings.Contains(hay, "active-directory") || strings.Contains(hay, "acl") || strings.Contains(hay, "ldap"):
		add("ADCSEnum")
		add("ADLDAPEnum")
		add("BloodHoundCollect")
	case strings.Contains(hay, "kerberos"):
		add("Kerberoasting")
		add("ASREPRoast")
	case strings.Contains(hay, "xss"):
		add("XSSScanner")
	case strings.Contains(hay, "sql") || strings.Contains(hay, "sqli"):
		add("SQLInjection")
	case strings.Contains(hay, "ssrf"):
		add("SSRFProbe")
	case strings.Contains(hay, "jwt") || strings.Contains(hay, "oauth"):
		add("JWTTamper")
	case strings.Contains(hay, "graphql"):
		add("GraphQLIntrospect")
	case strings.Contains(hay, "api"):
		add("APIFuzzer")
	case strings.Contains(hay, "tls") || strings.Contains(hay, "certificate"):
		add("tls_probe")
	case strings.Contains(hay, "dns") || strings.Contains(hay, "typosquatting") || strings.Contains(hay, "subdomain"):
		add("dns_enum")
	case strings.Contains(hay, "smb"):
		add("SMBSigningCheck")
		add("SMBNullSession")
	case strings.Contains(hay, "ssh"):
		add("OpenSSHCVECheck")
	case strings.Contains(hay, "sbom") || strings.Contains(hay, "supply-chain") || strings.Contains(hay, "cicd"):
		add("SupplyChainRecon")
		add("CICDMisconfig")
	case strings.Contains(hay, "k8s") || strings.Contains(hay, "kubernetes") || strings.Contains(hay, "container") || strings.Contains(hay, "docker"):
		add("K8sPrivesc")
		add("ContainerBreakout")
	case strings.Contains(hay, "modbus") || strings.Contains(hay, "s7") || strings.Contains(hay, "ics") || strings.Contains(hay, "scada"):
		add("ModbusEnum")
		add("S7Enum")
	case strings.Contains(hay, "detection") || strings.Contains(hay, "siem") || strings.Contains(hay, "kill-chain") || strings.Contains(hay, "log"):
		add("detection_coverage_probe")
		add("opsec_posture_report")
	default:
		add("http_probe")
	}
	return out
}

func computeSLAMetrics(rawVulns any) map[string]any {
	var rows []map[string]any
	switch v := rawVulns.(type) {
	case []map[string]any:
		rows = v
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				rows = append(rows, m)
			}
		}
	}
	total := len(rows)
	openCount := 0
	closedCount := 0
	overdueCount := 0
	var escalations []map[string]any
	for _, r := range rows {
		sev, _ := r["severity"].(string)
		sla := slaDaysBySeverity[strings.ToLower(strings.TrimSpace(sev))]
		if sla == 0 {
			sla = 90
		}
		age := 0
		switch a := r["age_days"].(type) {
		case int:
			age = a
		case float64:
			age = int(a)
		}
		isOpen, ok := r["open"].(bool)
		if !ok {
			isOpen = true
		}
		if isOpen {
			openCount++
			if age > sla {
				overdueCount++
				pct := float64(age) / float64(sla) * 100.0
				level := "Manager Escalation"
				if pct >= 120 {
					level = "VP/CTO Escalation"
				} else if pct >= 100 {
					level = "CISO Notification"
				}
				escalations = append(escalations, map[string]any{
					"cve_id":           r["cve_id"],
					"severity":         sev,
					"age_days":         age,
					"sla_days":         sla,
					"days_overdue":     age - sla,
					"escalation_level": level,
				})
			}
		} else {
			closedCount++
		}
	}
	if escalations == nil {
		escalations = []map[string]any{}
	}
	return map[string]any{
		"total_vulnerabilities": total,
		"open_count":            openCount,
		"closed_count":          closedCount,
		"overdue_count":         overdueCount,
		"escalations":           escalations,
	}
}

// Execute runs a runtime skill natively in Go without invoking Python.
// Target-touching execution enforces the allowlist lock; analytical/SLA/KPI
// skills compute metrics directly in Go.
func (st *Store) Execute(ctx context.Context, name string, args map[string]any, allowedTargets []string, requireAllowlist bool) (map[string]any, error) {
	sk, err := st.Get(name)
	if err != nil || sk == nil {
		return nil, fmt.Errorf("skill %q not found", name)
	}
	if args == nil {
		args = map[string]any{}
	}
	target, _ := args["target"].(string)
	if target == "" {
		target, _ = args["target_ip"].(string)
	}
	target = strings.TrimSpace(target)
	if target != "" {
		if !allowlist.Check(target, allowedTargets, requireAllowlist) {
			return nil, fmt.Errorf("SANDBOX_SCOPE_DENIED: target %q is not in allowlist", target)
		}
	}

	mapped := mapSkillToModules(sk)
	var moduleResults []map[string]any
	if target != "" {
		menv := modules.Env{Entries: allowedTargets, Timeout: 3 * time.Second}
		for _, mname := range mapped {
			if tool, ok := modules.Registry[mname]; ok {
				res, merr := tool.Run(ctx, map[string]any{"target": target}, menv)
				if merr == nil && res != nil {
					moduleResults = append(moduleResults, res)
				}
			}
		}
	}
	if moduleResults == nil {
		moduleResults = []map[string]any{}
	}

	out := map[string]any{
		"status":         "completed",
		"skill":          sk.Name,
		"description":    sk.Description,
		"domain":         sk.Domain,
		"subdomain":      sk.Subdomain,
		"tags":           sk.Tags,
		"nist_csf":       sk.NistCsf,
		"mitre_attack":   sk.MitreAttack,
		"sections":       sk.Sections,
		"mapped_modules": mapped,
		"module_results": moduleResults,
	}
	if rawVulns, ok := args["vulnerabilities"]; ok {
		out["sla_metrics"] = computeSLAMetrics(rawVulns)
	} else if strings.Contains(sk.Name, "sla") || strings.Contains(sk.Name, "aging") || strings.Contains(sk.Name, "vulnerability") {
		out["sla_metrics"] = computeSLAMetrics(nil)
	}
	return out, nil
}
