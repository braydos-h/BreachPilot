// Package browser implements the non-Python browser backend: real Chrome
// control over the DevTools protocol via chromedp. Sessions are headless by
// default, bounded in count and time, and every navigation is gated by the
// target allowlist before the browser ever loads the URL. Mirrors
// tools/browser/ (manager + sandbox_launcher) at the native subset.
package browser

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/braydos-h/BreachPilot/internal/allowlist"
	"github.com/chromedp/chromedp"
)

var osStat = os.Stat

// Session is one controlled browser tab-set.
type Session struct {
	ID      string
	Target  string
	Created time.Time
	ctx     context.Context
	cancel  context.CancelFunc
	alloc   context.CancelFunc
	Closed  bool
}

// Manager owns sessions with a cap and allowlist gate.
type Manager struct {
	Entries []string
	Require bool
	Max     int

	mu       sync.Mutex
	sessions map[string]*Session
	next     int
}

// New builds a manager (max <= 0 defaults to 2).
func New(entries []string, require bool, max int) *Manager {
	if max <= 0 {
		max = 2
	}
	return &Manager{Entries: entries, Require: require, Max: max, sessions: map[string]*Session{}}
}

// Available reports whether a Chrome binary can be launched, with version.
func Available() (bool, string) {
	path, err := LookPath()
	if err != nil {
		return false, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return false, path
	}
	return true, string(bytesTrim(out))
}

// LookPath finds a Chrome/Chromium/Edge binary.
func LookPath() (string, error) {
	for _, name := range []string{"chrome", "google-chrome", "chromium", "chromium-browser", "msedge"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, p := range []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		"/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	} {
		if fi, err := osStat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("no chrome binary found")
}

// Create opens a headless session for target after the allowlist gate.
func (m *Manager) Create(ctx context.Context, target string) (*Session, error) {
	if !allowlist.Check(target, allowlist.ApprovalEntries(m.Entries, nil), m.Require) {
		return nil, fmt.Errorf("target %s not in allowlist", target)
	}
	m.mu.Lock()
	if len(m.sessions) >= m.Max {
		m.mu.Unlock()
		return nil, fmt.Errorf("too many browser sessions (max %d)", m.Max)
	}
	m.next++
	id := fmt.Sprintf("browser-%d", m.next)
	m.mu.Unlock()

	bin, err := LookPath()
	if err != nil {
		return nil, err
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx,
		append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ExecPath(bin),
			chromedp.Flag("headless", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-first-run", true),
		)...,
	)
	sctx, cancel := chromedp.NewContext(allocCtx)
	s := &Session{ID: id, Target: target, Created: time.Now().UTC(), ctx: sctx, cancel: cancel, alloc: allocCancel}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

// Navigate loads url (must be http/https) with a deadline.
func (m *Manager) Navigate(s *Session, url string, timeout time.Duration) error {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if len(url) < 8 || !(hasPrefix(url, "http://") || hasPrefix(url, "https://")) {
		return fmt.Errorf("browser only loads http(s) URLs")
	}
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()
	return chromedp.Run(ctx, chromedp.Navigate(url))
}

// Text returns the visible body text.
func (m *Manager) Text(s *Session, timeout time.Duration) (string, error) {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()
	var text string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`document.body ? document.body.innerText : ""`, &text)); err != nil {
		return "", err
	}
	return text, nil
}

// Screenshot captures a PNG of the viewport.
func (m *Manager) Screenshot(s *Session, timeout time.Duration) ([]byte, error) {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()
	var shot []byte
	if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&shot)); err != nil {
		return nil, err
	}
	return shot, nil
}

// Close shuts the session down and frees the slot.
func (m *Manager) Close(s *Session) {
	m.mu.Lock()
	delete(m.sessions, s.ID)
	m.mu.Unlock()
	if !s.Closed {
		s.Closed = true
		s.cancel()
		s.alloc()
	}
}

// Count returns live sessions.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
