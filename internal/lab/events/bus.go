// Package events is a lightweight in-process event bus for the lab API/UI.
package events

import (
	"sync"
	"time"
)

// Event is a lab domain event.
type Event struct {
	Type       string    `json:"type"`
	At         time.Time `json:"at"`
	ArtifactID string    `json:"artifact_id,omitempty"`
	RunID      string    `json:"run_id,omitempty"`
	ScenarioID string    `json:"scenario_id,omitempty"`
	Message    string    `json:"message,omitempty"`
	Level      string    `json:"level,omitempty"` // info|warn|error
	Data       any       `json:"data,omitempty"`
}

// Bus fans events to subscribers.
type Bus struct {
	mu   sync.RWMutex
	subs map[chan Event]struct{}
	log  []Event
	max  int
}

// NewBus creates a bus that retains a ring of recent events.
func NewBus(retain int) *Bus {
	if retain <= 0 {
		retain = 2000
	}
	return &Bus{subs: map[chan Event]struct{}{}, max: retain}
}

// Publish broadcasts an event.
func (b *Bus) Publish(e Event) {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if e.Level == "" {
		e.Level = "info"
	}
	b.mu.Lock()
	b.log = append(b.log, e)
	if len(b.log) > b.max {
		b.log = b.log[len(b.log)-b.max:]
	}
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
			// drop if slow consumer
		}
	}
	b.mu.Unlock()
}

// Subscribe returns a channel; call Unsubscribe when done.
func (b *Bus) Subscribe(buf int) chan Event {
	if buf <= 0 {
		buf = 64
	}
	ch := make(chan Event, buf)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber.
func (b *Bus) Unsubscribe(ch chan Event) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
	// do not close(ch): publishers may still be selecting; GC after unsubscribe
}

// Recent returns a copy of retained events.
func (b *Bus) Recent() []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Event, len(b.log))
	copy(out, b.log)
	return out
}
