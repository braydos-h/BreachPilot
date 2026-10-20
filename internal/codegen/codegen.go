// Package codegen implements native Go replacements for the repository's
// catalog generators, capability counters, and release gate checks (formerly
// scripts/*.py).
package codegen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/braydos-h/BreachPilot/internal/mcp"
	"github.com/braydos-h/BreachPilot/internal/modules"
	"github.com/braydos-h/BreachPilot/internal/plugins"
	"github.com/braydos-h/BreachPilot/internal/skills"
	"github.com/braydos-h/BreachPilot/internal/zeropython"
)

// Counts holds live repository capability counts.
type Counts struct {
	Skills        int `json:"skills"`
	Plugins       int `json:"plugins"`
	AttackModules int `json:"attack_modules"`
	MCPTools      int `json:"mcp_tools"`
}

// CapabilityCounts computes live counts of skills, plugins, attack modules, and MCP tools.
func CapabilityCounts(root string) (Counts, error) {
	if root == "" {
		root = "."
	}
	skStore := skills.NewStore([]string{filepath.Join(root, "skills")})
	skList, err := skStore.List()
	if err != nil {
		return Counts{}, err
	}
	plList := plugins.Discover(filepath.Join(root, "plugins"))
	modList := modules.List()

	eng := mcp.NewEngineServer(nil, skStore, nil)
	def := mcp.NewDefensiveServer([]string{"127.0.0.1"}, nil, skStore, nil)
	ass := mcp.NewAssessmentServer(mcp.AssessmentConfig{AllowedTargets: []string{"127.0.0.1"}, SkillStore: skStore})
	mcpTotal := len(eng.Tools()) + len(def.Tools()) + len(ass.Tools())

	return Counts{
		Skills:        len(skList),
		Plugins:       len(plList),
		AttackModules: len(modList),
		MCPTools:      mcpTotal,
	}, nil
}

// SkillCatalogMarkdown generates docs/skills/catalog.md from skills/*/SKILL.md.
func SkillCatalogMarkdown(skillsRoot string) (string, error) {
	st := skills.NewStore([]string{skillsRoot})
	list, err := st.List()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Skill Catalog (%d skills)\n\n", len(list))
	b.WriteString("| Skill | Domain | Description | Tags |\n|---|---|---|---|\n")
	for _, sk := range list {
		desc := strings.ReplaceAll(sk.Description, "|", "\\|")
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", sk.Name, sk.Domain, desc, strings.Join(sk.Tags, ", "))
	}
	return b.String(), nil
}

// MCPCatalogMarkdown generates docs/mcp/tool-catalog-generated.md from the
// native Engine, Defensive, and Assessment MCP servers.
func MCPCatalogMarkdown() string {
	eng := mcp.NewEngineServer(nil, nil, nil)
	def := mcp.NewDefensiveServer([]string{"127.0.0.1"}, nil, nil, nil)
	ass := mcp.NewAssessmentServer(mcp.AssessmentConfig{AllowedTargets: []string{"127.0.0.1"}})

	var b strings.Builder
	b.WriteString("# Native MCP Tool Catalog\n\n")
	writeServer := func(title string, srv *mcp.Server) {
		tools := srv.Tools()
		fmt.Fprintf(&b, "## %s (%d tools)\n\n", title, len(tools))
		b.WriteString("| Tool | Description |\n|---|---|\n")
		for _, t := range tools {
			fmt.Fprintf(&b, "| `%s` | %s |\n", t.Name, strings.ReplaceAll(t.Description, "|", "\\|"))
		}
		b.WriteString("\n")
	}
	writeServer("Engine MCP Server", eng)
	writeServer("Defensive MCP Server", def)
	writeServer("Assessment MCP Server", ass)
	return b.String()
}

// ReleaseGateResult summarizes the native release gate check.
type ReleaseGateResult struct {
	Verdict        string            `json:"verdict"`
	GoVersion      string            `json:"go_version"`
	WebUIVersion   string            `json:"webui_version"`
	VersionsMatch  bool              `json:"versions_match"`
	ZeroPython     zeropython.Report `json:"zero_python"`
	ZeroPythonPass bool              `json:"zero_python_pass"`
}

var bpVersionRe = regexp.MustCompile(`const version = "([^"]+)"`)

// RunReleaseGate verifies version synchronization and runs the zero-python scanner.
func RunReleaseGate(root string, strictZeroPython bool) ReleaseGateResult {
	if root == "" {
		root = "."
	}
	var res ReleaseGateResult
	if raw, err := os.ReadFile(filepath.Join(root, "cmd", "bp", "main.go")); err == nil {
		if m := bpVersionRe.FindStringSubmatch(string(raw)); len(m) == 2 {
			res.GoVersion = strings.TrimSuffix(m[1], "-native")
		}
	}
	if raw, err := os.ReadFile(filepath.Join(root, "webui", "package.json")); err == nil {
		var pkg struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(raw, &pkg) == nil {
			res.WebUIVersion = pkg.Version
		}
	}
	res.VersionsMatch = res.GoVersion != "" && res.GoVersion == res.WebUIVersion
	zp, _ := zeropython.Scan(root)
	res.ZeroPython = zp
	res.ZeroPythonPass = !zp.Strict()
	if res.VersionsMatch && (!strictZeroPython || res.ZeroPythonPass) {
		res.Verdict = "GO"
	} else {
		res.Verdict = "NO-GO"
	}
	// Ensure deterministic slice sorting on report
	sort.Strings(res.ZeroPython.PyFiles)
	return res
}
