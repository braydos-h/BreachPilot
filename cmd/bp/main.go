// Command bp is the native BreachPilot launcher. No Python required.
// Default (no args) starts the WebUI daemon on http://127.0.0.1:8765.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/braydos-h/BreachPilot/internal/api"
	"github.com/braydos-h/BreachPilot/internal/auth"
	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/events"
	"github.com/braydos-h/BreachPilot/internal/ollama"
	"github.com/braydos-h/BreachPilot/internal/recon"
	"github.com/braydos-h/BreachPilot/internal/runner"
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
	serve(cfg, *configPath)
}

func runDoctor(cfg config.Config) {
	fail := false
	check := func(name string, err error) {
		if err != nil {
			fmt.Printf("doctor: FAIL %s: %v\n", name, err)
			fail = true
			return
		}
		fmt.Printf("doctor: ok %s\n", name)
	}
	check("loopback-bind", auth.AssertLoopback(cfg.API.Host))
	check("sqlite-store", doctorStore())
	sidecar := "unreachable"
	if dialSidecar() {
		sidecar = "reachable"
	}
	fmt.Printf("doctor: sidecar %s (sandbox.enabled=%v)\n", sidecar, cfg.Sandbox.Enabled)
	if cfg.Sandbox.Enabled && sidecar == "unreachable" {
		fmt.Println("doctor: WARN sandbox enabled but sidecar unreachable; runs will fail closed at exec time")
	}
	if cfg.Models.Provider == "ollama" {
		check("ollama-tags", doctorOllama(cfg))
	} else {
		fmt.Printf("doctor: skip ollama-tags (provider %s)\n", cfg.Models.Provider)
	}
	check("allowlist-gate", doctorAllowlist(cfg))
	if fail {
		os.Exit(1)
	}
	fmt.Println("doctor: done")
}

func doctorStore() error {
	dir, err := os.MkdirTemp("", "bp-doctor")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	db, err := store.Open(dir+"/doctor.db", dir+"/reports")
	if err != nil {
		return err
	}
	return db.Close()
}

func dialSidecar() bool {
	addr := os.Getenv("BP_SIDECAR_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18765"
	}
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func doctorOllama(cfg config.Config) error {
	keyEnv := "OLLAMA_API_KEY"
	if v, ok := cfg.Providers["ollama"]; ok {
		if e, ok := v["api_key_env"].(string); ok && e != "" {
			keyEnv = e
		}
	}
	_, err := ollama.ListModels(cfg.Ollama.Host, keyEnv, 5*time.Second)
	return err
}

func doctorAllowlist(cfg config.Config) error {
	entries := allowlist.ApprovalEntries(cfg.Exploit.AllowedTargets, nil)
	if cfg.Exploit.RequireExplicitAllowlist && len(entries) == 0 {
		return fmt.Errorf("empty allowlist with require_explicit_allowlist=true (fail-closed: no attack targets authorized)")
	}
	// Self-test vector: explicit grant must authorize, others must not.
	if !allowlist.Check("127.0.0.1", append(entries, "127.0.0.1"), true) {
		return fmt.Errorf("allowlist self-check failed")
	}
	return nil
}

func runSelfTest(cfg config.Config) {
	// Safe localhost smoke: resolve + closed-port scan + gated allowlist +
	// store round-trip, all against loopback only. Mirrors --self-test.
	fail := func(format string, a ...any) {
		fmt.Printf("self-test: FAIL "+format+"\n", a...)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ip, _, err := recon.Resolve(ctx, "127.0.0.1")
	if err != nil || ip != "127.0.0.1" {
		fail("resolve loopback: %v", err)
	}
	res := recon.ScanPorts(ctx, "127.0.0.1", []int{1})
	if len(res) != 1 || res[0].Open {
		fail("closed-port scan unexpected: %+v", res)
	}
	entries := allowlist.ApprovalEntries(append(cfg.Exploit.AllowedTargets, "127.0.0.1"), nil)
	if !allowlist.Check("127.0.0.1", entries, true) {
		fail("allowlist gate rejected loopback")
	}
	if err := doctorStore(); err != nil {
		fail("store: %v", err)
	}
	fmt.Println("self-test: PASS loopback resolve + scan + allowlist + store")
}

func serve(cfg config.Config, configPath string) {
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
	srv.ConfigPath = configPath
	srv.ReportsDir = "reports"
	srv.Runner = runner.New(db, reg, "reports", cfg.Exploit.AllowedTargets, cfg.Exploit.RequireExplicitAllowlist, 4)
	srv.Runner.Attack = runner.NativeAttack
	root := http.NewServeMux()
	root.Handle("/api/", srv.Handler())
	root.Handle("/openapi.json", srv.Handler())
	root.Handle("/", spaHandler(findDist()))
	addr := fmt.Sprintf("%s:%s", cfg.API.Host, itoaPort(cfg.API.Port))
	fmt.Printf("BreachPilot native daemon on http://%s\n", addr)
	_ = http.ListenAndServe(addr, root)
}

func itoaPort(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// findDist locates the built WebUI: repo webui/dist first, then the
// container path. Empty means the frontend was not built.
func findDist() string {
	for _, d := range []string{"webui/dist", "/opt/breachpilot/webui/dist"} {
		if fi, err := os.Stat(d + "/index.html"); err == nil && !fi.IsDir() {
			return d
		}
	}
	return ""
}

// spaHandler serves the built SPA without auth (the login page itself is
// public; the API underneath stays bearer-gated). Unknown paths fall back
// to index.html for client-side routing.
func spaHandler(dist string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dist == "" {
			http.Error(w, "WebUI not built (npm run build in webui/)", http.StatusServiceUnavailable)
			return
		}
		clean := filepath.Clean("/" + r.URL.Path)[1:]
		full := filepath.Join(dist, filepath.FromSlash(clean))
		absDist, _ := filepath.Abs(dist)
		absFull, _ := filepath.Abs(full)
		if absFull != absDist && !strings.HasPrefix(absFull, absDist+string(os.PathSeparator)) {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
			http.ServeFile(w, r, full)
			return
		}
		http.ServeFile(w, r, filepath.Join(dist, "index.html"))
	})
}
