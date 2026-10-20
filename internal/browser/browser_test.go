package browser_test

import (
	"context"
	"testing"
	"time"

	"github.com/braydos-h/BreachPilot/internal/browser"
)

func TestAvailabilityProbe(t *testing.T) {
	ok, ver := browser.Available()
	t.Logf("chrome available=%v version=%q", ok, ver)
	if _, err := browser.LookPath(); (err == nil) != ok {
		t.Fatal("probe inconsistent")
	}
}

func TestCreateGateDenies(t *testing.T) {
	m := browser.New(nil, true, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := m.Create(ctx, "10.9.9.9"); err == nil {
		t.Fatal("out-of-scope target must be denied before launch")
	}
}

func TestNavigateSchemeGate(t *testing.T) {
	m := browser.New([]string{"127.0.0.1"}, true, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := m.Create(ctx, "127.0.0.1")
	if err != nil {
		t.Skipf("chrome unavailable: %v", err)
	}
	defer m.Close(s)
	if err := m.Navigate(s, "file:///etc/passwd", 5*time.Second); err == nil {
		t.Fatal("non-http(s) URL must be rejected")
	}
	if got := m.Count(); got != 1 {
		t.Fatalf("count=%d", got)
	}
	m.Close(s)
	if got := m.Count(); got != 0 {
		t.Fatalf("count after close=%d", got)
	}
}
