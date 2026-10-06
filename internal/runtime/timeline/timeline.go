// Package timeline builds a unified runtime event timeline.
package timeline

import (
	"fmt"
	"sort"
	"time"
)

// Event is one timed runtime observation.
type Event struct {
	At      time.Time `json:"at"`
	Offset  string    `json:"offset"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
	Class   string    `json:"evidence_class"` // RUNTIME_OBSERVATION | INFERENCE
}

// Builder accumulates events from session start.
type Builder struct {
	Start  time.Time
	Events []Event
}

// New creates a builder.
func New(start time.Time) *Builder {
	return &Builder{Start: start}
}

// Add appends an event.
func (b *Builder) Add(kind, message, class string) {
	now := time.Now().UTC()
	if class == "" {
		class = "RUNTIME_OBSERVATION"
	}
	b.Events = append(b.Events, Event{
		At: now, Offset: formatOffset(now.Sub(b.Start)),
		Kind: kind, Message: message, Class: class,
	})
}

// AddAt appends with explicit timestamp.
func (b *Builder) AddAt(at time.Time, kind, message, class string) {
	if class == "" {
		class = "RUNTIME_OBSERVATION"
	}
	b.Events = append(b.Events, Event{
		At: at, Offset: formatOffset(at.Sub(b.Start)),
		Kind: kind, Message: message, Class: class,
	})
}

// Sorted returns events ordered by time.
func (b *Builder) Sorted() []Event {
	out := append([]Event(nil), b.Events...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// FormatText renders a human timeline.
func FormatText(events []Event) string {
	var s string
	for _, e := range events {
		s += fmt.Sprintf("%s  %-14s %s\n", e.Offset, e.Kind, e.Message)
	}
	return s
}

func formatOffset(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	sec := int(d.Seconds())
	h := sec / 3600
	m := (sec % 3600) / 60
	s := sec % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}
