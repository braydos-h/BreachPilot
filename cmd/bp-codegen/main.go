// Command bp-codegen is the native Go replacement for scripts/*.py:
// generates skill/MCP catalogs, prints capability counts, and runs the
// release gate without Python.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/braydos-h/BreachPilot/internal/codegen"
)

func main() {
	mode := flag.String("mode", "counts", "counts|skill-catalog|mcp-catalog|release-gate")
	root := flag.String("root", ".", "Repository root directory")
	strict := flag.Bool("strict", false, "Enforce strict zero-Python release gate")
	flag.Parse()

	switch *mode {
	case "counts":
		c, err := codegen.CapabilityCounts(*root)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		raw, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(raw))
	case "skill-catalog":
		md, err := codegen.SkillCatalogMarkdown(*root + "/skills")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Print(md)
	case "mcp-catalog":
		fmt.Print(codegen.MCPCatalogMarkdown())
	case "release-gate":
		res := codegen.RunReleaseGate(*root, *strict)
		raw, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(raw))
		if res.Verdict != "GO" {
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(2)
	}
}
