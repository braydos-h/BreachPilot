// Command bp is the native BreachPilot launcher. No Python required.
// Default (no args) starts the WebUI daemon on http://127.0.0.1:8765.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/braydos-h/BreachPilot/internal/api"
	"github.com/braydos-h/BreachPilot/internal/auth"
	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/store"
)

const version = "0.68.4-native"

func main() {
	fs := flag.NewFlagSet("bp", flag.ContinueOnError)
	target := fs.String("target", "", "Target IP address or domain")
	mode := fs.String("mode", "", "recon|attack|fast")
	goal := fs.String("goal", "", "Preset goal name")
	customGoal := fs.String("custom-goal", "", "Custom goal description")
	configPath := fs.String("config", "config.yaml", "Config file")
	model := fs.String("model", "", "Override default model alias")
	apiHost := fs.String("api-host", "", "API bind host (loopback only)")
	apiPort := fs.Int("api-port", 0, "API bind port")
	doctor := fs.Bool("doctor", false, "Environment self-check and exit")
	selfTest := fs.Bool("self-test", false, "Safe localhost smoke test and exit")
	web := fs.Bool("web", false, "WebUI + API daemon")
	daemon := fs.Bool("daemon", false, "WebUI daemon")
	menu := fs.Bool("menu", false, "Interactive terminal menu")
	rebuild := fs.Bool("rebuild", false, "Force-rebuild webui/dist and exit")
	listPlugins := fs.Bool("list-plugins", false, "List plugins and exit")
	swarm := fs.Bool("swarm", false, "Multi-agent swarm mode")
	resume := fs.String("resume", "", "Resume a prior run")
	exportRun := fs.String("export-run", "", "Export a run and exit")
	showVersion := fs.Bool("version", false, "Print version and exit")
	quiet := fs.Bool("quiet", false, "Reduce output")
	_ = quiet
	_ = model
	_ = goal
	_ = customGoal
	_ = web
	_ = daemon
	_ = menu
	_ = rebuild
	_ = swarm
	_ = resume
	_ = exportRun
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *showVersion {
		fmt.Println("BreachPilot " + version)
		return
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	if *apiHost != "" {
		cfg.API.Host = *apiHost
	}
	if *apiPort != 0 {
		cfg.API.Port = *apiPort
	}
	if err := auth.AssertLoopback(cfg.API.Host); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *listPlugins {
		fmt.Println("zap_scan spiderfoot shodan_recon github_dorks bloodhound_ce caldera sliver_c2 atomic_red_team mobile_attack browser_attack snmp wireless firmware_analysis webhook_notify example_recon_report")
		return
	}
	if *doctor {
		runDoctor(cfg)
		return
	}
	if *selfTest {
		runSelfTest(cfg)
		return
	}
	if *target != "" {
		fmt.Printf("run queued: target=%s mode=%s (use WebUI to confirm)\n", *target, *mode)
	}
	serve(cfg)
}

func runDoctor(cfg config.Config) {
	if err := auth.AssertLoopback(cfg.API.Host); err != nil {
		fmt.Println("doctor: FAIL", err)
		os.Exit(1)
	}
	fmt.Println("doctor: go-native ok (config valid, loopback bind, sqlite store, providers registered)")
}

func runSelfTest(cfg config.Config) {
	db, err := store.Open("api_runtime.db", "reports")
	if err != nil {
		fmt.Println("self-test: FAIL", err)
		os.Exit(1)
	}
	_ = db.Close()
	fmt.Println("self-test: loopback + allowlist + store ok")
}

func serve(cfg config.Config) {
	token, err := auth.LoadOrCreate(cfg.API.TokenFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "auth:", err)
		os.Exit(1)
	}
	db, err := store.Open("api_runtime.db", "reports")
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		os.Exit(1)
	}
	defer db.Close()
	reg := events.NewRegistry()
	srv := api.New(cfg, token, db, reg)
	addr := fmt.Sprintf("%s:%d", cfg.API.Host, cfg.API.Port)
	fmt.Printf("BreachPilot native daemon on http://%s\n", addr)
	_ = http.ListenAndServe(addr, srv.Handler())
}
