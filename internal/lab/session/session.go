// Package session is the Lab test-run observability envelope.
//
// Every automated interaction (validate, security, scenario, MCP-driven)
// should bind to a Run so recording, timeline events, logs, and network
// share one identity and clock reference (§35).
package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/events"
)

// Kind classifies how the run was started.
type Kind string

const (
	KindValidate Kind = "validate"
	KindSecurity Kind = "security"
	KindScenario Kind = "scenario"
	KindManual   Kind = "manual"
	KindMCP      Kind = "mcp"
)

// Status is the run lifecycle state.
type Status string

const (
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusPartial   Status = "partial" // crashed mid-run; partial recording may exist
	StatusCanceled  Status = "canceled"
)

// Run is one test execution with linked evidence artifacts.
type Run struct {
	ID            string            `json:"id"`
	Kind          Kind              `json:"kind"`
	Status        Status            `json:"status"`
	ArtifactID    string            `json:"artifact_id,omitempty"`
	APKPath       string            `json:"apk_path,omitempty"`
	Package       string            `json:"package,omitempty"`
	RuntimeSerial string            `json:"runtime_serial,omitempty"`
	RuntimeAVD    string            `json:"runtime_avd,omitempty"`
	ScenarioID    string            `json:"scenario_id,omitempty"`
	RecordingID   string            `json:"recording_id,omitempty"`
	MCPSession    string            `json:"mcp_session,omitempty"`
	NetworkID     string            `json:"network_id,omitempty"`
	LogsPath      string            `json:"logs_path,omitempty"`
	Result        string            `json:"result,omitempty"` // PASSED|FAILED|…
	FailureAtMS   int64             `json:"failure_at_ms,omitempty"`
	FailureNote   string            `json:"failure_note,omitempty"`
	RecordEnabled bool              `json:"record_enabled"`
	Profile       string            `json:"profile,omitempty"` // low|balanced|high
	Meta          map[string]string `json:"meta,omitempty"`
	StartedAt     time.Time         `json:"started_at"`
	EndedAt       time.Time         `json:"ended_at,omitempty"`
	Dir           string            `json:"dir,omitempty"`
}

// Event is a unified timeline marker on the run clock.
type Event struct {
	ID       string         `json:"event_id"`
	RunID    string         `json:"run_id"`
	At       time.Time      `json:"timestamp"`
	OffsetMS int64          `json:"offset_ms"`
	Type     string         `json:"event_type"`
	Source   string         `json:"source"` // ai-agent|mcp|scenario|runtime|network|system|user
	Category string         `json:"category"`
	Message  string         `json:"message,omitempty"`
	Level    string         `json:"level,omitempty"` // info|warn|error
	Bookmark bool           `json:"bookmark,omitempty"`
	Tags     []string       `json:"tags,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Manager persists runs + timeline under the lab workspace.
type Manager struct {
	Root string
	Bus  *events.Bus

	mu   sync.Mutex
	live map[string]*liveRun
}

type liveRun struct {
	run       *Run
	t0        time.Time
	events    []Event
	recording any // set by higher layer (*recording.Session)
}

// NewManager creates a session manager rooted at the lab workspace.
func NewManager(root string, bus *events.Bus) *Manager {
	_ = os.MkdirAll(filepath.Join(root, "sessions"), 0o750)
	return &Manager{Root: root, Bus: bus, live: map[string]*liveRun{}}
}

func (m *Manager) runDir(id string) string {
	return filepath.Join(m.Root, "sessions", id)
}

// StartOptions configures a new test run.
type StartOptions struct {
	Kind          Kind
	ArtifactID    string
	APKPath       string
	Package       string
	RuntimeSerial string
	RuntimeAVD    string
	ScenarioID    string
	MCPSession    string
	Record        bool
	Profile       string // low|balanced|high
	Meta          map[string]string
}

// Start creates a running test session.
func (m *Manager) Start(opt StartOptions) (*Run, error) {
	if opt.Kind == "" {
		opt.Kind = KindManual
	}
	if opt.Profile == "" {
		opt.Profile = "balanced"
	}
	id := lab.NewID("run")
	dir := m.runDir(id)
	if err := os.MkdirAll(filepath.Join(dir, "timeline"), 0o750); err != nil {
		return nil, err
	}
	_ = os.MkdirAll(filepath.Join(dir, "screenshots"), 0o750)
	r := &Run{
		ID: id, Kind: opt.Kind, Status: StatusRunning,
		ArtifactID: opt.ArtifactID, APKPath: opt.APKPath, Package: opt.Package,
		RuntimeSerial: opt.RuntimeSerial, RuntimeAVD: opt.RuntimeAVD,
		ScenarioID: opt.ScenarioID, MCPSession: opt.MCPSession,
		RecordEnabled: opt.Record, Profile: opt.Profile,
		Meta: opt.Meta, StartedAt: time.Now().UTC(), Dir: dir,
	}
	m.mu.Lock()
	m.live[id] = &liveRun{run: r, t0: r.StartedAt, events: nil}
	m.mu.Unlock()
	if err := m.save(r); err != nil {
		return nil, err
	}
	m.emit("SESSION_STARTED", r, "test run started", "info")
	_, _ = m.AddEvent(id, Event{
		Type: "SESSION_STARTED", Source: "system", Category: "runtime",
		Message: fmt.Sprintf("kind=%s record=%v", r.Kind, r.RecordEnabled),
	})
	return r, nil
}

// Get loads a run (live or disk).
func (m *Manager) Get(id string) (*Run, error) {
	m.mu.Lock()
	if lr, ok := m.live[id]; ok {
		cp := *lr.run
		m.mu.Unlock()
		return &cp, nil
	}
	m.mu.Unlock()
	data, err := os.ReadFile(filepath.Join(m.runDir(id), "run.json"))
	if err != nil {
		return nil, err
	}
	var r Run
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// List returns runs newest-first.
func (m *Manager) List() ([]*Run, error) {
	dir := filepath.Join(m.Root, "sessions")
	_ = os.MkdirAll(dir, 0o750)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]*Run, 0)
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		r, err := m.Get(e.Name())
		if err == nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

// AddEvent appends a timeline event using the run clock.
func (m *Manager) AddEvent(runID string, ev Event) (*Event, error) {
	m.mu.Lock()
	lr, ok := m.live[runID]
	var t0 time.Time
	if ok {
		t0 = lr.t0
	}
	m.mu.Unlock()
	if !ok {
		r, err := m.Get(runID)
		if err != nil {
			return nil, err
		}
		t0 = r.StartedAt
	}
	if ev.ID == "" {
		ev.ID = lab.NewID("event")
	}
	ev.RunID = runID
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	if ev.OffsetMS == 0 {
		preserve := false
		if ev.Metadata != nil {
			if _, ok := ev.Metadata["url"]; ok {
				preserve = true
			}
			if v, ok := ev.Metadata["preserve_offset"].(bool); ok && v {
				preserve = true
			}
		}
		if !preserve {
			ev.OffsetMS = ev.At.Sub(t0).Milliseconds()
			if ev.OffsetMS < 0 {
				ev.OffsetMS = 0
			}
		}
	}
	if ev.Category == "" {
		ev.Category = categoryFor(ev.Type, ev.Source)
	}
	if ev.Level == "" {
		switch {
		case ev.Category == "error" ||
			strings.Contains(ev.Type, "FAIL") ||
			strings.Contains(ev.Type, "ASSERT") ||
			ev.Type == "CRASH" ||
			ev.Type == "RUNTIME_FATAL":
			ev.Level = "error"
		case ev.Type == "SESSION_PARTIAL" || strings.Contains(ev.Type, "EXPIRED"):
			ev.Level = "warn"
		default:
			ev.Level = "info"
		}
	}

	m.mu.Lock()
	if lr, ok := m.live[runID]; ok {
		lr.events = append(lr.events, ev)
	}
	m.mu.Unlock()

	path := filepath.Join(m.runDir(runID), "timeline", ev.ID+".json")
	data, _ := json.MarshalIndent(ev, "", "  ")
	_ = os.WriteFile(path, data, 0o640)

	if m.Bus != nil {
		m.Bus.Publish(events.Event{
			Type: ev.Type, At: ev.At, RunID: runID, Message: ev.Message, Level: ev.Level,
			Data: map[string]any{"event_id": ev.ID, "offset_ms": ev.OffsetMS, "category": ev.Category, "source": ev.Source},
		})
	}
	return &ev, nil
}

// RecentFeed returns bus-shaped events from recent run timelines on disk.
// Used by Live Log so CLI/MCP runs (separate process bus) still appear in the UI.
func (m *Manager) RecentFeed(maxRuns, maxEvents int) []events.Event {
	if maxRuns <= 0 {
		maxRuns = 8
	}
	if maxEvents <= 0 {
		maxEvents = 500
	}
	runs, err := m.List()
	if err != nil || len(runs) == 0 {
		return nil
	}
	out := make([]events.Event, 0, maxEvents)
	newestID := runs[0].ID
	for i, run := range runs {
		if i >= maxRuns {
			break
		}
		evs, err := m.ListEvents(run.ID)
		if err != nil {
			continue
		}
		for _, ev := range evs {
			// Keep Live Log focused: stale FAIL/ASSERT from older runs pollute the err count
			// after a successful retry (e.g. two prior phone-digit failures).
			if run.ID != newestID &&
				(ev.Type == "ASSERTION_FAILED" || ev.Type == "SCENARIO_FAILED" || ev.Level == "error") {
				continue
			}
			out = append(out, events.Event{
				Type:       ev.Type,
				At:         ev.At,
				RunID:      run.ID,
				ArtifactID: run.ArtifactID,
				ScenarioID: run.ScenarioID,
				Message:    ev.Message,
				Level:      ev.Level,
				Data: map[string]any{
					"event_id":  ev.ID,
					"offset_ms": ev.OffsetMS,
					"category":  ev.Category,
					"source":    ev.Source,
					"from":      "session_timeline",
				},
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	if len(out) > maxEvents {
		out = out[len(out)-maxEvents:]
	}
	return out
}

// ListEvents returns timeline events sorted by offset.
func (m *Manager) ListEvents(runID string) ([]Event, error) {
	m.mu.Lock()
	if lr, ok := m.live[runID]; ok && len(lr.events) > 0 {
		out := append([]Event(nil), lr.events...)
		m.mu.Unlock()
		sort.Slice(out, func(i, j int) bool { return out[i].OffsetMS < out[j].OffsetMS })
		return out, nil
	}
	m.mu.Unlock()

	dir := filepath.Join(m.runDir(runID), "timeline")
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []Event{}, nil
		}
		return nil, err
	}
	out := make([]Event, 0)
	for _, e := range ents {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var ev Event
		if json.Unmarshal(data, &ev) == nil {
			out = append(out, ev)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OffsetMS < out[j].OffsetMS })
	return out, nil
}

// Bookmark creates a user/system bookmark on the timeline.
func (m *Manager) Bookmark(runID, title, description string, tags []string) (*Event, error) {
	return m.AddEvent(runID, Event{
		Type: "BOOKMARK", Source: "user", Category: "bookmark", Bookmark: true,
		Message: title, Tags: tags,
		Metadata: map[string]any{"description": description, "title": title},
	})
}

// Complete finishes a run.
func (m *Manager) Complete(runID string, ok bool, result, failureNote string, failureAtMS int64) (*Run, error) {
	m.mu.Lock()
	var r *Run
	if lr, okLive := m.live[runID]; okLive {
		cp := *lr.run
		r = &cp
	}
	m.mu.Unlock()
	if r == nil {
		got, err := m.Get(runID)
		if err != nil {
			return nil, err
		}
		r = got
	}
	r.EndedAt = time.Now().UTC()
	if ok {
		r.Status = StatusCompleted
		if result == "" {
			result = "PASSED"
		}
	} else {
		r.Status = StatusFailed
		if result == "" {
			result = "FAILED"
		}
		r.FailureNote = failureNote
		r.FailureAtMS = failureAtMS
		failEv := Event{
			Type: "ASSERTION_FAILED", Source: "system", Category: "assertion", Level: "error",
			Message: failureNote, Bookmark: true, Tags: []string{"failure"},
		}
		// Only pin OffsetMS when caller provided a concrete failure time.
		// OffsetMS==0 means "use now" inside AddEvent.
		if failureAtMS > 0 {
			failEv.OffsetMS = failureAtMS
		}
		_, _ = m.AddEvent(runID, failEv)
	}
	r.Result = result
	// Keep live RecordingID if Complete's copy somehow lagged (shouldn't, but safe).
	m.mu.Lock()
	if lr, okLive := m.live[runID]; okLive && lr.run.RecordingID != "" {
		r.RecordingID = lr.run.RecordingID
	}
	m.mu.Unlock()
	if err := m.save(r); err != nil {
		return nil, err
	}
	m.mu.Lock()
	delete(m.live, runID)
	m.mu.Unlock()
	level := "info"
	if !ok {
		level = "error"
	}
	m.emit("SESSION_COMPLETED", r, result+" "+failureNote, level)
	return r, nil
}

// MarkPartial marks a crashed/disconnected run that still has usable media.
func (m *Manager) MarkPartial(runID, note string) (*Run, error) {
	r, err := m.Get(runID)
	if err != nil {
		return nil, err
	}
	r.Status = StatusPartial
	r.EndedAt = time.Now().UTC()
	r.FailureNote = note
	r.Result = "PARTIAL"
	_ = m.save(r)
	m.mu.Lock()
	delete(m.live, runID)
	m.mu.Unlock()
	_, _ = m.AddEvent(runID, Event{
		Type: "SESSION_PARTIAL", Source: "system", Category: "runtime", Level: "warn",
		Message: note, Bookmark: true, Tags: []string{"partial"},
	})
	return r, nil
}

// SetRecording links a recording artifact to the run.
func (m *Manager) SetRecording(runID, recordingID string) error {
	m.mu.Lock()
	if lr, ok := m.live[runID]; ok {
		lr.run.RecordingID = recordingID
		r := *lr.run
		m.mu.Unlock()
		return m.save(&r)
	}
	m.mu.Unlock()
	r, err := m.Get(runID)
	if err != nil {
		return err
	}
	r.RecordingID = recordingID
	return m.save(r)
}

func (m *Manager) save(r *Run) error {
	if r.Dir == "" {
		r.Dir = m.runDir(r.ID)
	}
	_ = os.MkdirAll(r.Dir, 0o750)
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.Dir, "run.json"), data, 0o640)
}

func (m *Manager) emit(typ string, r *Run, msg, level string) {
	if m.Bus == nil || r == nil {
		return
	}
	m.Bus.Publish(events.Event{
		Type: typ, ArtifactID: r.ArtifactID, RunID: r.ID, ScenarioID: r.ScenarioID,
		Message: msg, Level: level,
		Data: map[string]any{"recording_id": r.RecordingID, "kind": r.Kind},
	})
}

func categoryFor(typ, source string) string {
	switch {
	case typ == "BOOKMARK":
		return "bookmark"
	case typ == "AUTH_PROMPT" || typ == "AUTH_FILLED" || typ == "AUTH_TYPED" || typ == "AUTH_EXPIRED" ||
		typ == "AUTH_CHOICE" || typ == "AUTH_CHOICE_SOFT" || typ == "AUTH_PREPARE" || typ == "AUTH_TYPE_RETRY" ||
		typ == "AUTH_TYPED_ALT":
		return "auth"
	case typ == "PROCESS_EVIDENCE" || typ == "HARNESS_LOG":
		return "process"
	case source == "ai-agent" || source == "mcp":
		return "mcp"
	case source == "network" || typ == "MITM_HTTP":
		return "network"
	case source == "logcat" && (typ == "KERNEL_LOG" || typ == "RUNTIME_FATAL"):
		return "kernel"
	case source == "logcat" && (typ == "APP_LOG" || typ == "APP_LIFECYCLE"):
		return "app"
	case typ == "CRASH" || typ == "ASSERTION_FAILED":
		return "error"
	case source == "scenario":
		return "scenario"
	default:
		return "runtime"
	}
}
