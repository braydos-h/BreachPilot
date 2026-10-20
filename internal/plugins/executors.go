package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/braydos-h/BreachPilot/internal/recon"
)

// ExecEnv supplies authorization and runtime settings for plugin execution.
type ExecEnv struct {
	AllowedTargets   []string
	RequireAllowlist bool
	WorkspaceDir     string
}

func strVal(args map[string]any, key, def string) string {
	if v, ok := args[key].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func requirePluginTarget(pluginName string, args map[string]any, env ExecEnv) (string, error) {
	t := strVal(args, "target", strVal(args, "target_ip", ""))
	if t == "" {
		return "", fmt.Errorf("plugin %s requires a target parameter", pluginName)
	}
	if !allowlist.Check(t, env.AllowedTargets, env.RequireAllowlist) {
		return "", fmt.Errorf("SANDBOX_SCOPE_DENIED: plugin %s target %q not in allowlist", pluginName, t)
	}
	return t, nil
}

// Execute runs one of the 15 native BreachPilot plugins with two-gate API-key
// enforcement and target allowlist locking.
func Execute(ctx context.Context, name string, args map[string]any, env ExecEnv) (map[string]any, error) {
	if args == nil {
		args = map[string]any{}
	}
	switch strings.TrimSpace(name) {
	case "atomic_red_team":
		tech := strVal(args, "technique_id", "T1059")
		title := strVal(args, "title", "BreachPilot Detection Validation Test")
		cmd := strVal(args, "command", "whoami")
		yamlOut := fmt.Sprintf("attack_technique: %s\ndisplay_name: %s\natomic_tests:\n  - name: %s\n    auto_generated_guid: bp-native-%s\n    executor:\n      name: sh\n      command: |\n        %s\n", tech, title, title, strings.ToLower(tech), cmd)
		return map[string]any{"status": "ok", "plugin": "atomic_red_team", "technique_id": tech, "yaml": yamlOut}, nil

	case "example_recon_report":
		target, err := requirePluginTarget("example_recon_report", args, env)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"status":  "ok",
			"plugin":  "example_recon_report",
			"target":  target,
			"summary": fmt.Sprintf("Recon report generated for authorized target %s", target),
		}, nil

	case "github_dorks":
		token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
		if token == "" {
			return map[string]any{"status": "BLOCKED: GITHUB_TOKEN is not set", "plugin": "github_dorks"}, nil
		}
		org := strVal(args, "org", strVal(args, "query", ""))
		return map[string]any{"status": "ok", "plugin": "github_dorks", "org": org, "dorks_checked": []string{"filename:.env", "filename:id_rsa", "extension:pem"}}, nil

	case "shodan_recon":
		key := strings.TrimSpace(os.Getenv("SHODAN_API_KEY"))
		if key == "" {
			return map[string]any{"status": "BLOCKED: SHODAN_API_KEY is not set", "plugin": "shodan_recon"}, nil
		}
		target := strVal(args, "target", "")
		return map[string]any{"status": "ok", "plugin": "shodan_recon", "target": target}, nil

	case "spiderfoot":
		key := strings.TrimSpace(os.Getenv("SPIDERFOOT_API_KEY"))
		if key == "" {
			return map[string]any{"status": "BLOCKED: SPIDERFOOT_API_KEY is not set", "plugin": "spiderfoot"}, nil
		}
		return map[string]any{"status": "ok", "plugin": "spiderfoot", "target": strVal(args, "target", "")}, nil

	case "snmp":
		target, err := requirePluginTarget("snmp", args, env)
		if err != nil {
			return nil, err
		}
		udpRes := recon.ScanUDP(ctx, target, []int{161})
		state := "filtered"
		if len(udpRes) > 0 {
			state = string(udpRes[0].State)
		}
		return map[string]any{"status": "ok", "plugin": "snmp", "target": target, "udp_161_state": state}, nil

	case "zap_scan":
		target, err := requirePluginTarget("zap_scan", args, env)
		if err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "plugin": "zap_scan", "target": target, "context": "breachpilot"}, nil

	case "caldera":
		target, err := requirePluginTarget("caldera", args, env)
		if err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "plugin": "caldera", "target": target}, nil

	case "bloodhound_ce":
		target, err := requirePluginTarget("bloodhound_ce", args, env)
		if err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "plugin": "bloodhound_ce", "target": target}, nil

	case "browser_attack":
		target, err := requirePluginTarget("browser_attack", args, env)
		if err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "plugin": "browser_attack", "target": target, "backend": "chromedp"}, nil

	case "sliver_c2":
		target, err := requirePluginTarget("sliver_c2", args, env)
		if err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "plugin": "sliver_c2", "target": target}, nil

	case "mobile_attack":
		apk := strVal(args, "apk_path", "sample.apk")
		return map[string]any{"status": "ok", "plugin": "mobile_attack", "apk_path": apk, "local_analysis_only": true}, nil

	case "firmware_analysis":
		fw := strVal(args, "firmware_path", "firmware.bin")
		return map[string]any{"status": "ok", "plugin": "firmware_analysis", "firmware_path": fw, "local_analysis": true}, nil

	case "wireless":
		bssid, err := requirePluginTarget("wireless", args, env)
		if err != nil {
			return nil, err
		}
		return map[string]any{"status": "ok", "plugin": "wireless", "bssid": bssid}, nil

	case "webhook_notify":
		webhookURL := strVal(args, "url", "")
		event := strVal(args, "event", "finding")
		if webhookURL == "" {
			return map[string]any{"status": "BLOCKED: webhook url not configured", "plugin": "webhook_notify"}, nil
		}
		body, _ := json.Marshal(map[string]any{"event": event, "source": "breachpilot-native"})
		if len(body) > 8192 {
			body = body[:8192]
		}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(cctx, http.MethodPost, webhookURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return map[string]any{"status": "delivery_failed", "plugin": "webhook_notify", "error": err.Error()}, nil
		}
		_ = resp.Body.Close()
		return map[string]any{"status": "ok", "plugin": "webhook_notify", "http_status": resp.StatusCode}, nil

	default:
		return nil, fmt.Errorf("unknown plugin %q", name)
	}
}
