// Package diag implements the native doctor and self-test checks, shared by
// the bp CLI and the /api/v1/diagnostics/* endpoints. Every check performs
// real work; nothing returns canned success.
package diag

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/braydos-h/BreachPilot/internal/config"
	"github.com/braydos-h/BreachPilot/internal/ollama"
	"github.com/braydos-h/BreachPilot/internal/recon"
	"github.com/braydos-h/BreachPilot/internal/store"
)

// Doctor runs environment checks, returning exit code + log.
func Doctor(cfg config.Config) (int, string) {
	var sb strings.Builder
	fail := false
	line := func(format string, a ...any) { fmt.Fprintf(&sb, format+"\n", a...) }
	if err := assertLoopback(cfg.API.Host); err != nil {
		line("FAIL loopback-bind: %v", err)
		fail = true
	} else {
		line("ok loopback-bind %s:%d", cfg.API.Host, cfg.API.Port)
	}
	if err := storeCheck(); err != nil {
		line("FAIL sqlite-store: %v", err)
		fail = true
	} else {
		line("ok sqlite-store")
	}
	entries := allowlist.ApprovalEntries(cfg.Exploit.AllowedTargets, nil)
	if cfg.Exploit.RequireExplicitAllowlist && len(entries) == 0 {
		line("FAIL allowlist: empty with require_explicit_allowlist=true (fail-closed)")
		fail = true
	} else {
		line("ok allowlist (%d entries, required=%v)", len(entries), cfg.Exploit.RequireExplicitAllowlist)
	}
	if SidecarReachable() {
		line("ok sidecar reachable")
	} else {
		line("WARN sidecar unreachable (sandbox.enabled=%v)", cfg.Sandbox.Enabled)
	}
	if cfg.Models.Provider == "ollama" {
		if _, err := ollama.ListModels(cfg.Ollama.Host, ollamaKeyEnv(cfg), 5*time.Second); err != nil {
			line("FAIL ollama-tags: %v", err)
			fail = true
		} else {
			line("ok ollama-tags")
		}
	} else {
		line("skip ollama-tags (provider %s)", cfg.Models.Provider)
	}
	if fail {
		return 1, sb.String()
	}
	return 0, sb.String()
}

// SelfTest runs the safe localhost smoke: resolve + closed-port scan +
// allowlist gate + store round-trip.
func SelfTest(cfg config.Config) (int, string) {
	var sb strings.Builder
	fail := func(format string, a ...any) (int, string) {
		fmt.Fprintf(&sb, "FAIL "+format+"\n", a...)
		return 1, sb.String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ip, _, err := recon.Resolve(ctx, "127.0.0.1")
	if err != nil || ip != "127.0.0.1" {
		return fail("resolve loopback: %v", err)
	}
	fmt.Fprintln(&sb, "ok resolve loopback")
	res := recon.ScanPorts(ctx, "127.0.0.1", []int{1})
	if len(res) != 1 || res[0].Open {
		return fail("closed-port scan unexpected: %+v", res)
	}
	fmt.Fprintln(&sb, "ok closed-port scan")
	entries := allowlist.ApprovalEntries(append(cfg.Exploit.AllowedTargets, "127.0.0.1"), nil)
	if !allowlist.Check("127.0.0.1", entries, true) {
		return fail("allowlist gate rejected loopback")
	}
	fmt.Fprintln(&sb, "ok allowlist gate")
	if err := storeCheck(); err != nil {
		return fail("store: %v", err)
	}
	fmt.Fprintln(&sb, "ok store")
	return 0, sb.String()
}

func assertLoopback(host string) error {
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return nil
	}
	return fmt.Errorf("API host must be loopback, got %q", host)
}

func storeCheck() error {
	dir, err := os.MkdirTemp("", "bp-diag")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	db, err := store.Open(dir+"/diag.db", dir+"/reports")
	if err != nil {
		return err
	}
	return db.Close()
}

// SidecarReachable dials the Rust execution sidecar briefly.
func SidecarReachable() bool {
	addr := os.Getenv("BP_SIDECAR_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18765"
	}
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func ollamaKeyEnv(cfg config.Config) string {
	if v, ok := cfg.Providers["ollama"]; ok {
		if e, ok := v["api_key_env"].(string); ok && e != "" {
			return e
		}
	}
	return "OLLAMA_API_KEY"
}
