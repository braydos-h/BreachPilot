package events_test

import (
	"testing"

	"github.com/braydos-h/BreachPilot/internal/events"
)

func TestReplayCursor(t *testing.T) {
	b := events.NewBroker()
	b.Append("r1", "a", nil)
	b.Append("r1", "b", nil)
	all := b.Replay(0)
	if len(all) != 2 || all[0].Sequence != 1 || all[1].Sequence != 2 {
		t.Fatalf("replay: %+v", all)
	}
	tail := b.Replay(1)
	if len(tail) != 1 || tail[0].Type != "b" {
		t.Fatalf("cursor: %+v", tail)
	}
}

func TestSubscribeReplays(t *testing.T) {
	b := events.NewBroker()
	b.Append("r1", "a", map[string]any{"n": 1})
	sub := b.Subscribe(0)
	defer sub.Close()
	ev := <-sub.Chan()
	if ev.Type != "a" || ev.Sequence != 1 {
		t.Fatalf("sub: %+v", ev)
	}
}
