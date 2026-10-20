package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/braydos-h/BreachPilot/internal/ipc"
	"github.com/braydos-h/BreachPilot/internal/memory"
)

var (
	sandboxJobsMu sync.Mutex
	sandboxJobs   = map[string]map[string]any{}
	hexJobRe      = regexp.MustCompile(`^[0-9a-fA-F]{6,32}$`)
	sandboxCodeRe = regexp.MustCompile(`SANDBOX_[A-Z_]+`)
)

func contentTypeForExt(ext string) string {
	switch strings.ToLower(ext) {
	case ".md":
		return "text/markdown; charset=utf-8"
	case ".json":
		return "application/json"
	case ".jsonl":
		return "application/x-ndjson"
	case ".html":
		return "text/html; charset=utf-8"
	case ".log", ".txt":
		return "text/plain; charset=utf-8"
	case ".csv":
		return "text/csv; charset=utf-8"
	case ".pdf":
		return "application/pdf"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".svg":
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}

func (s *Server) memoryExt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	mem := memory.New(s.DB, "")
	rawLessons, _ := mem.ListLessons(100)
	lessons := make([]map[string]any, 0, len(rawLessons))
	byPhase := map[string]int{}
	lastSeen := map[string]string{}
	for _, l := range rawLessons {
		lessons = append(lessons, map[string]any{
			"id":               l.ID,
			"target_signature": l.Target,
			"action_type":      l.Phase,
			"outcome":          "success",
			"confidence":       0.8,
			"created_at":       l.CreatedAt,
			"metadata":         map[string]any{"summary": l.Summary, "tags": l.Tags},
		})
		byPhase[l.Phase]++
		if l.CreatedAt > lastSeen[l.Phase] {
			lastSeen[l.Phase] = l.CreatedAt
		}
	}
	confidence := make([]map[string]any, 0, len(byPhase))
	for phase, count := range byPhase {
		confidence = append(confidence, map[string]any{
			"action_type":  phase,
			"observations": count,
			"successes":    count,
			"failures":     0,
			"partials":     0,
			"confidence":   float64(1+count) / float64(2+count),
			"last_seen":    lastSeen[phase],
		})
	}
	episodes, _ := mem.ListAllEpisodes(200)
	attackMem := make([]map[string]any, 0, len(episodes))
	for _, ep := range episodes {
		attackMem = append(attackMem, map[string]any{
			"id":            ep.ID,
			"session_id":    ep.MissionID,
			"target_ip":     ep.Target,
			"category":      ep.MemoryType,
			"item_key":      ep.MemoryType,
			"item_value":    ep.Fact,
			"source_tool":   "native",
			"success":       true,
			"metadata":      ep.Metadata,
			"first_seen_at": ep.CreatedAt,
			"last_seen_at":  ep.CreatedAt,
			"seen_count":    1,
		})
	}
	writeJSON(w, 200, map[string]any{
		"lessons":       lessons,
		"confidence":    confidence,
		"attack_memory": attackMem,
		"episodes":      attackMem,
		"semantic":      lessons,
	})
}

func probeDockerAndImage(image string) (cliPresent, daemonUp, imagePresent bool, dockerErr string) {
	if image == "" {
		image = "breachpilot-sandbox:latest"
	}
	// First check sidecar if reachable.
	addr := os.Getenv("BP_SIDECAR_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18765"
	}
	sc := &ipc.Client{Addr: addr, Timeout: 2 * time.Second}
	if st, err := sc.SandboxStatus(); err == nil && st != nil {
		dAvail, _ := st["docker_available"].(bool)
		iPres, _ := st["image_present"].(bool)
		info, _ := st["docker_info"].(string)
		if dAvail {
			return true, true, iPres, ""
		}
		return true, false, false, info
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return false, false, false, "docker CLI not found in PATH"
	}
	cliPresent = true
	cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return true, false, false, strings.TrimSpace(string(out))
	}
	daemonUp = true
	icmd := exec.Command("docker", "image", "inspect", image)
	if err := icmd.Run(); err == nil {
		imagePresent = true
	}
	return cliPresent, daemonUp, imagePresent, ""
}

func (s *Server) sandboxExt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	img := s.Cfg.Sandbox.Image
	if img == "" {
		img = "breachpilot-sandbox:latest"
	}
	backend := s.Cfg.Sandbox.Backend
	if backend == "" {
		backend = "docker"
	}
	_, daemonUp, imgPresent, dErr := probeDockerAndImage(img)
	mode := "disabled"
	fallbackReason := ""
	var imgPtr any
	if s.Cfg.Sandbox.Enabled {
		if daemonUp {
			imgPtr = imgPresent
			if imgPresent {
				mode = "contained"
			} else {
				mode = "blocked"
				fallbackReason = "sandbox image " + img + " not built"
			}
		} else {
			mode = "blocked"
			if dErr != "" {
				fallbackReason = dErr
			} else {
				fallbackReason = "Docker daemon unreachable"
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"enabled":           s.Cfg.Sandbox.Enabled,
		"backend":           backend,
		"image":             img,
		"user":              "sandbox",
		"read_only_rootfs":  true,
		"mode":              mode,
		"fallback_native":   false,
		"fallback_reason":   fallbackReason,
		"docker_available":  daemonUp,
		"docker_error":      dErr,
		"image_present":     imgPtr,
		"sidecar_reachable": sidecarReachable(),
		"network": map[string]any{
			"enforce":           true,
			"fail_closed":       true,
			"allow_dns":         "controlled",
			"map_host_loopback": false,
			"extra_allow_cidrs": []string{},
		},
		"resources": map[string]any{
			"memory_mb":        4096,
			"cpus":             2.0,
			"pids":             512,
			"timeout_seconds":  300,
			"output_max_bytes": 2000000,
		},
		"cleanup": map[string]any{
			"remove_on_exit":          true,
			"remove_stale_on_startup": true,
		},
	})
}

func (s *Server) sandboxSub(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/system/sandbox/"), "/")
	img := s.Cfg.Sandbox.Image
	if img == "" {
		img = "breachpilot-sandbox:latest"
	}
	cliPresent, daemonUp, imgPresent, dErr := probeDockerAndImage(img)
	plat := runtime.GOOS
	var imgPtr any
	if daemonUp {
		imgPtr = imgPresent
	}
	steps := []map[string]any{}
	if !cliPresent {
		steps = append(steps, map[string]any{
			"id":              "install_docker",
			"title":           "Install Docker",
			"description":     "Install Docker Engine or Docker Desktop on this host.",
			"command_preview": "docker --version",
			"requires_admin":  true,
			"manual":          true,
		})
	}
	if !daemonUp {
		steps = append(steps, map[string]any{
			"id":              "start_daemon",
			"title":           "Start Docker daemon",
			"description":     "Ensure the Docker service is running.",
			"command_preview": "docker info",
			"requires_admin":  false,
			"manual":          plat != "linux",
		})
	}
	if !imgPresent {
		steps = append(steps, map[string]any{
			"id":              "build_image",
			"title":           "Build sandbox worker image",
			"description":     "Build " + img + " from docker/sandbox.",
			"command_preview": "docker build -t " + img + " docker/sandbox",
			"requires_admin":  false,
			"manual":          false,
		})
	}

	switch {
	case rest == "fix/plan" && r.Method == http.MethodGet:
		reason := "ready"
		if !daemonUp {
			reason = "docker_daemon_unreachable"
		} else if !imgPresent {
			reason = "sandbox_image_missing"
		}
		writeJSON(w, 200, map[string]any{
			"platform":              plat,
			"reason":                reason,
			"docker_cli_present":    cliPresent,
			"docker_daemon_running": daemonUp,
			"image_present":         imgPtr,
			"requires_admin":        !cliPresent,
			"steps":                 steps,
			"image":                 img,
			"docker_error":          dErr,
		})
	case rest == "fix" && r.Method == http.MethodPost:
		if !s.Cfg.Sandbox.Enabled {
			writeErr(w, 400, "sandbox_disabled", "Sandbox is intentionally disabled (sandbox.enabled: false).")
			return
		}
		var b [6]byte
		_, _ = rand.Read(b[:])
		jobID := hex.EncodeToString(b[:])
		status := "succeeded"
		errStr := ""
		if !daemonUp {
			status = "failed"
			errStr = "Docker daemon is not running on this host"
		}
		jobSteps := make([]map[string]any, 0, len(steps))
		for _, st := range steps {
			cp := map[string]any{}
			for k, v := range st {
				cp[k] = v
			}
			cp["status"] = status
			jobSteps = append(jobSteps, cp)
		}
		job := map[string]any{
			"job_id":                jobID,
			"status":                status,
			"platform":              plat,
			"reason":                "remediation",
			"steps":                 jobSteps,
			"error":                 errStr,
			"docker_ready":          daemonUp && imgPresent,
			"docker_cli_present":    cliPresent,
			"docker_daemon_running": daemonUp,
			"image_present":         imgPtr,
		}
		sandboxJobsMu.Lock()
		sandboxJobs[jobID] = job
		sandboxJobsMu.Unlock()
		writeJSON(w, 200, job)
	case strings.HasPrefix(rest, "fix/") && r.Method == http.MethodGet:
		jobID := strings.TrimPrefix(rest, "fix/")
		if !hexJobRe.MatchString(jobID) {
			writeErr(w, 404, "not_found", "Fix job not found")
			return
		}
		sandboxJobsMu.Lock()
		job, ok := sandboxJobs[jobID]
		sandboxJobsMu.Unlock()
		if !ok {
			writeErr(w, 404, "not_found", "Fix job not found")
			return
		}
		writeJSON(w, 200, job)
	default:
		writeErr(w, 404, "not_found", "Not found")
	}
}

func (s *Server) resetSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	runs, _, _ := s.DB.ListRuns(200, 0, "", "", "")
	for _, rn := range runs {
		st, _ := rn["state"].(string)
		if st == "running" || st == "queued" || st == "preparing" || st == "awaiting_input" {
			writeErr(w, 409, "conflict", "Cannot reset while a run is active.")
			return
		}
	}
	deleted := 0
	for _, rn := range runs {
		if id, ok := rn["id"].(string); ok && id != "" {
			_ = s.DB.SetRunState(id, "deleted")
			deleted++
		}
	}
	writeJSON(w, 200, map[string]any{"status": "ok", "runs_deleted": deleted})
}

func isArtifactWhitelisted(name string) bool {
	whitelist := map[string]bool{
		"session_summary.md":    true,
		"run.json":              true,
		"recon_assessment.json": true,
		"fast_recon.json":       true,
		"goal_suggestions.json": true,
		"activity.jsonl":        true,
		"exploit_audit.jsonl":   true,
		"events.jsonl":          true,
		"errors.jsonl":          true,
		"session_error.log":     true,
		"recon_first_error.log": true,
		"proposed.json":         true,
		"enhanced_report.json":  true,
		"enhanced_report.md":    true,
		"enhanced_report.html":  true,
		"enhanced_report.pdf":   true,
	}
	if whitelist[name] {
		return true
	}
	if strings.HasPrefix(name, "enhanced/") {
		sub := strings.TrimPrefix(name, "enhanced/")
		return sub != "" && !strings.Contains(sub, "/") && !strings.Contains(sub, "..")
	}
	return false
}

func safeSubpath(root, rel string) (string, bool) {
	clean := filepath.ToSlash(strings.TrimSpace(rel))
	if clean == "" || clean == "." || clean == ".." || strings.HasPrefix(clean, "/") {
		return "", false
	}
	for _, p := range strings.Split(clean, "/") {
		if p == "" || p == "." || p == ".." {
			return "", false
		}
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	full, err := filepath.Abs(filepath.Join(absRoot, filepath.FromSlash(clean)))
	if err != nil {
		return "", false
	}
	if !strings.HasPrefix(full, absRoot+string(os.PathSeparator)) {
		return "", false
	}
	return full, true
}

func (s *Server) serveArtifact(w http.ResponseWriter, r *http.Request, runID, name string) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	if !isArtifactWhitelisted(name) {
		writeErr(w, 404, "not_found", "Artifact not found")
		return
	}
	full, ok := safeSubpath(s.runDir(runID), name)
	if !ok {
		writeErr(w, 400, "invalid_request", "Invalid artifact name")
		return
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		writeErr(w, 404, "not_found", "Artifact not found")
		return
	}
	w.Header().Set("Content-Type", contentTypeForExt(filepath.Ext(full)))
	w.Header().Set("X-Request-ID", "go-native")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}

func (s *Server) serveStateJSON(w http.ResponseWriter, runID, filename string) {
	rdir := s.runDir(runID)
	candidates := []string{
		filepath.Join(rdir, "swarm_workspace", "autonomous", filename),
		filepath.Join(rdir, "swarm_workspace", filename),
		filepath.Join(rdir, filename),
	}
	for _, p := range candidates {
		if raw, err := os.ReadFile(p); err == nil && len(raw) > 0 {
			var v map[string]any
			if json.Unmarshal(raw, &v) == nil {
				writeJSON(w, 200, map[string]any{"state": v})
				return
			}
		}
	}
	writeJSON(w, 200, map[string]any{"state": map[string]any{}})
}

func (s *Server) serveLog(w http.ResponseWriter, r *http.Request, runID, sub string) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	name := strings.TrimPrefix(sub, "logs/")
	if name == "" || name == "logs" {
		writeJSON(w, 200, map[string]any{"name": "tail", "lines": []string{}, "total_lines_returned": 0, "total_lines_in_file": 0})
		return
	}
	tail := graphClamp(atoiOr(r.URL.Query().Get("tail"), 200), 200, 1, 2000)
	rdir := s.runDir(runID)
	var candidates []string
	if full, ok := safeSubpath(rdir, name); ok {
		candidates = append(candidates, full)
	}
	if full, ok := safeSubpath(filepath.Join(rdir, "exploit_workspace"), name); ok {
		candidates = append(candidates, full)
	}
	for _, p := range candidates {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		text := strings.ReplaceAll(string(raw), "\r\n", "\n")
		text = strings.TrimSuffix(text, "\n")
		var all []string
		if text != "" {
			all = strings.Split(text, "\n")
		}
		ret := all
		if len(ret) > tail {
			ret = ret[len(ret)-tail:]
		}
		if ret == nil {
			ret = []string{}
		}
		writeJSON(w, 200, map[string]any{
			"name":                 name,
			"lines":                ret,
			"total_lines_returned": len(ret),
			"total_lines_in_file":  len(all),
		})
		return
	}
	writeErr(w, 404, "not_found", "Log not found")
}

func (s *Server) serveWorkspace(w http.ResponseWriter, r *http.Request, runID, sub string) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	wsDir := filepath.Join(s.runDir(runID), "exploit_workspace")
	if sub == "workspace" {
		files := []map[string]any{}
		if fi, err := os.Stat(wsDir); err == nil && fi.IsDir() {
			absWS, _ := filepath.Abs(wsDir)
			_ = filepath.WalkDir(absWS, func(p string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				rel, rerr := filepath.Rel(absWS, p)
				if rerr != nil {
					return nil
				}
				info, ierr := d.Info()
				var sz int64
				if ierr == nil {
					sz = info.Size()
				}
				files = append(files, map[string]any{"path": filepath.ToSlash(rel), "bytes": sz})
				return nil
			})
		}
		sort.Slice(files, func(i, j int) bool { return files[i]["path"].(string) < files[j]["path"].(string) })
		writeJSON(w, 200, map[string]any{"files": files})
		return
	}
	rel := strings.TrimPrefix(sub, "workspace/")
	full, ok := safeSubpath(wsDir, rel)
	if !ok {
		writeErr(w, 400, "invalid_request", "Invalid workspace path")
		return
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		writeErr(w, 404, "not_found", "File not found")
		return
	}
	w.Header().Set("Content-Type", contentTypeForExt(filepath.Ext(full)))
	w.Header().Set("X-Request-ID", "go-native")
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}

func readJSONL(path string) []map[string]any {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m != nil {
			out = append(out, m)
		}
	}
	return out
}

func (s *Server) serveLoot(w http.ResponseWriter, runID string) {
	ws := filepath.Join(s.runDir(runID), "exploit_workspace")
	for _, p := range []string{filepath.Join(ws, "loot", "loot.jsonl"), filepath.Join(ws, "loot.jsonl")} {
		if items := readJSONL(p); len(items) > 0 {
			writeJSON(w, 200, map[string]any{"loot": items})
			return
		}
	}
	writeJSON(w, 200, map[string]any{"loot": []any{}})
}

func findCredFiles(ws string) []string {
	var out []string
	credRoot := filepath.Join(ws, "credentials")
	if entries, err := os.ReadDir(credRoot); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				p := filepath.Join(credRoot, e.Name(), "credentials.jsonl")
				if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
					out = append(out, p)
				}
			}
		}
	}
	legacy := filepath.Join(ws, "credentials.jsonl")
	if fi, err := os.Stat(legacy); err == nil && !fi.IsDir() {
		out = append(out, legacy)
	}
	return out
}

func (s *Server) serveCredentials(w http.ResponseWriter, r *http.Request, runID, sub string) {
	ws := filepath.Join(s.runDir(runID), "exploit_workspace")
	files := findCredFiles(ws)
	type credRef struct {
		file string
		line int
		rec  map[string]any
	}
	var all []credRef
	for _, f := range files {
		for i, m := range readJSONL(f) {
			all = append(all, credRef{file: f, line: i, rec: m})
		}
	}
	if sub == "credentials" && r.Method == http.MethodGet {
		out := make([]map[string]any, 0, len(all))
		for idx, c := range all {
			cp := map[string]any{}
			for k, v := range c.rec {
				cp[k] = v
			}
			cp["password"] = "[REDACTED]"
			cp["index"] = idx
			out = append(out, cp)
		}
		writeJSON(w, 200, map[string]any{"credentials": out})
		return
	}
	rest := strings.TrimPrefix(sub, "credentials/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || r.Method != http.MethodPost {
		writeErr(w, 404, "not_found", "Not found")
		return
	}
	idx, err := strconv.Atoi(parts[0])
	if err != nil || idx < 0 || idx >= len(all) {
		writeErr(w, 404, "not_found", "Credential index out of range")
		return
	}
	target := all[idx]
	username, _ := target.rec["username"].(string)
	host, _ := target.rec["target_host"].(string)
	password, _ := target.rec["password"].(string)
	switch parts[1] {
	case "reveal":
		writeJSON(w, 200, map[string]any{
			"index":       idx,
			"username":    username,
			"target_host": host,
			"password":    password,
		})
	case "confirm":
		rows := readJSONL(target.file)
		if target.line < len(rows) {
			rows[target.line]["confirmed"] = true
			var b strings.Builder
			for _, row := range rows {
				raw, _ := json.Marshal(row)
				b.Write(raw)
				b.WriteByte('\n')
			}
			_ = os.WriteFile(target.file, []byte(b.String()), 0o600)
		}
		writeJSON(w, 200, map[string]any{
			"index":       idx,
			"username":    username,
			"target_host": host,
			"confirmed":   true,
		})
	default:
		writeErr(w, 404, "not_found", "Not found")
	}
}

func (s *Server) serveErrors(w http.ResponseWriter, r *http.Request, runID string) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method_not_allowed", "Method not allowed")
		return
	}
	q := r.URL.Query()
	wantKind := strings.TrimSpace(q.Get("kind"))
	tail := graphClamp(atoiOr(q.Get("tail"), 200), 200, 1, 2000)
	rows := readJSONL(filepath.Join(s.runDir(runID), "errors.jsonl"))
	kindSet := map[string]bool{}
	var filtered []map[string]any
	for _, row := range rows {
		k, _ := row["kind"].(string)
		if k != "" {
			kindSet[k] = true
		}
		if wantKind == "" || k == wantKind {
			filtered = append(filtered, row)
		}
	}
	kinds := make([]string, 0, len(kindSet))
	for k := range kindSet {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	total := len(filtered)
	if len(filtered) > tail {
		filtered = filtered[len(filtered)-tail:]
	}
	if filtered == nil {
		filtered = []map[string]any{}
	}
	writeJSON(w, 200, map[string]any{
		"run_id":        runID,
		"records":       filtered,
		"total_records": total,
		"kinds":         kinds,
	})
}

func (s *Server) serveWitness(w http.ResponseWriter, runID string) {
	for _, p := range []string{
		filepath.Join(s.runDir(runID), "witness.jsonl"),
		filepath.Join(s.ReportsDir, "witness.jsonl"),
	} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			flags := readJSONL(p)
			if flags == nil {
				flags = []map[string]any{}
			}
			writeJSON(w, 200, map[string]any{"flags": flags})
			return
		}
	}
	writeErr(w, 404, "not_found", "No witness log")
}

func (s *Server) serveRunSandbox(w http.ResponseWriter, runID string) {
	rdir := s.runDir(runID)
	summary := map[string]any{
		"run_id":        runID,
		"found":         false,
		"config":        map[string]any{"enabled": s.Cfg.Sandbox.Enabled, "backend": s.Cfg.Sandbox.Backend, "image": s.Cfg.Sandbox.Image},
		"container":     map[string]any{},
		"network":       map[string]any{},
		"executions":    map[string]any{"attempts": 0, "completed": 0, "failed": 0, "timed_out": 0, "total": 0},
		"blocked":       map[string]any{"total": 0, "recent": []any{}},
		"last_activity": "",
	}
	completed, failed, timedOut, blockedTotal := 0, 0, 0, 0
	var recentBlocks []map[string]any
	for _, p := range []string{filepath.Join(rdir, "exploit_audit.jsonl"), filepath.Join(rdir, "exploit_workspace", "exploit_audit.jsonl")} {
		rows := readJSONL(p)
		if len(rows) == 0 {
			continue
		}
		summary["found"] = true
		for _, row := range rows {
			if ts, ok := row["timestamp"].(string); ok && ts != "" {
				summary["last_activity"] = ts
			}
			st, _ := row["status"].(string)
			switch st {
			case "completed":
				completed++
			case "failed":
				failed++
			case "timed_out":
				timedOut++
			case "blocked":
				blockedTotal++
				tool, _ := row["tool_name"].(string)
				cmd, _ := row["command"].(string)
				recentBlocks = append(recentBlocks, map[string]any{
					"timestamp": row["timestamp"],
					"tool":      tool,
					"code":      "SANDBOX_SCOPE_DENIED",
					"message":   cmd,
				})
			}
			if cid, ok := row["container_id"].(string); ok && cid != "" {
				summary["container"] = map[string]any{"id": cid, "sandbox_run_id": runID}
			}
		}
		break
	}
	for _, ev := range readJSONL(filepath.Join(rdir, "events.jsonl")) {
		if ev["type"] != "tool_result" {
			continue
		}
		pl, _ := ev["payload"].(map[string]any)
		resTxt, _ := pl["result"].(string)
		if code := sandboxCodeRe.FindString(resTxt); code != "" {
			summary["found"] = true
			blockedTotal++
			recentBlocks = append(recentBlocks, map[string]any{
				"timestamp": ev["timestamp"],
				"tool":      pl["name"],
				"code":      code,
				"message":   resTxt,
			})
		}
	}
	if len(recentBlocks) > 5 {
		recentBlocks = recentBlocks[len(recentBlocks)-5:]
	}
	if recentBlocks == nil {
		recentBlocks = []map[string]any{}
	}
	total := completed + failed + timedOut
	summary["executions"] = map[string]any{
		"attempts":  total,
		"completed": completed,
		"failed":    failed,
		"timed_out": timedOut,
		"total":     total,
	}
	summary["blocked"] = map[string]any{
		"total":  blockedTotal,
		"recent": recentBlocks,
	}
	writeJSON(w, 200, summary)
}
