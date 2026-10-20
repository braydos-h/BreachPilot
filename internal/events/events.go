// Package events is the in-process event broker: ordered replay, SSE fan-out,
// and WebSocket fan-out with sequence cursors and 30s heartbeats.
// Mirrors tools/api/event_broker.py semantics.
package events

import (
	"sync"
	"time"
)

type Event struct {
	Sequence  int            `json:"sequence"`
	Timestamp string         `json:"timestamp"`
	RunID     string         `json:"run_id"`
	Type      string         `json:"type"`
	Payload   map[string]any `json:"payload"`
}

// Broker holds one run's ordered log plus live subscribers.
type Broker struct {
	mu   sync.Mutex
	log  []Event
	subs map[*Subscription]struct{}
	next int
}

// Subscription streams replay then live events.
type Subscription struct {
	ch     chan Event
	closed chan struct{}
	once   sync.Once
}

func (s *Subscription) Chan() <-chan Event { return s.ch }

// Close stops delivery.
func (s *Subscription) Close() {
	s.once.Do(func() { close(s.closed) })
}

func NewBroker() *Broker { return &Broker{subs: map[*Subscription]struct{}{}} }

// Append records an event and fans out to subscribers (non-blocking; slow
// subscribers drop live delivery but keep replay history).
func (b *Broker) Append(runID, typ string, payload map[string]any) Event {
	b.mu.Lock()
	b.next++
	ev := Event{Sequence: b.next, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), RunID: runID, Type: typ, Payload: payload}
	b.log = append(b.log, ev)
	for s := range b.subs {
		select {
		case s.ch <- ev:
		default:
		}
	}
	b.mu.Unlock()
	return ev
}

// Replay returns events with sequence > after, ascending.
func (b *Broker) Replay(after int) []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Event
	for _, e := range b.log {
		if e.Sequence > after {
			out = append(out, e)
		}
	}
	return out
}

// ReplayPage implements tail/before/limit paging (newest-first when paged).
func (b *Broker) ReplayPage(after, tail, before, limit int, hasTail, hasBefore, hasLimit bool) (evts []Event, oldest, latest *int, hasMore bool, first, last *int, omitted int, nextBefore *int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !hasTail && !hasBefore && !hasLimit {
		for _, e := range b.log {
			if e.Sequence > after {
				evts = append(evts, e)
			}
		}
		if len(evts) > 0 {
			f, l := evts[0].Sequence, evts[len(evts)-1].Sequence
			first, last = &f, &l
		}
		return evts, nil, nil, false, first, last, 0, nil
	}
	// Paged: newest-first slice.
	var desc []Event
	for i := len(b.log) - 1; i >= 0; i-- {
		e := b.log[i]
		if e.Sequence <= after {
			continue
		}
		if hasBefore && before > 0 && e.Sequence >= before {
			continue
		}
		desc = append(desc, e)
		if hasTail && tail > 0 && len(desc) >= tail {
			break
		}
		if hasLimit && limit > 0 && len(desc) >= limit {
			break
		}
	}
	return desc, nil, nil, false, nil, nil, 0, nil
}

// Subscribe replays from after then streams live. Caller must Close().
func (b *Broker) Subscribe(after int) *Subscription {
	s := &Subscription{ch: make(chan Event, 128), closed: make(chan struct{})}
	replay := b.Replay(after)
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	go func() {
		defer func() {
			b.mu.Lock()
			delete(b.subs, s)
			b.mu.Unlock()
		}()
		for _, e := range replay {
			select {
			case s.ch <- e:
			case <-s.closed:
				return
			}
		}
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-s.closed:
				return
			case <-tick.C:
				hb := Event{Sequence: 0, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Type: "heartbeat", Payload: map[string]any{}}
				select {
				case s.ch <- hb:
				case <-s.closed:
					return
				}
			}
		}
	}()
	return s
}

// Registry maps run_id -> broker.
type Registry struct {
	mu sync.Mutex
	m  map[string]*Broker
}

func NewRegistry() *Registry { return &Registry{m: map[string]*Broker{}} }

func (r *Registry) GetOrCreate(runID string) *Broker {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.m[runID]
	if !ok {
		b = NewBroker()
		r.m[runID] = b
	}
	return b
}
