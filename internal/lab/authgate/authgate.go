// Package authgate collects interactive login fields (phone / SMS OTP / text)
// from the Lab UI, API, CLI prefill, or MCP — reusable for any package.
//
// Pending prompts are stored under workspace/auth/ so UI/MCP/CLI share state
// across process boundaries.
package authgate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/events"
)

// Kind of interactive field.
type Kind string

const (
	KindPhone  Kind = "phone"
	KindOTP    Kind = "otp"
	KindText   Kind = "text"
	KindPIN    Kind = "pin"
	KindChoice Kind = "choice" // Accept / Deny / Allow notifications, etc.
)

// Prompt is a pending or recently filled interactive request.
type Prompt struct {
	ID        string    `json:"id"`
	RunID     string    `json:"run_id"`
	Kind      Kind      `json:"kind"`
	Label     string    `json:"label"`
	Package   string    `json:"package,omitempty"`
	Choices   []string  `json:"choices,omitempty"` // for KindChoice button labels
	Status    string    `json:"status"`             // pending|filled|canceled|expired
	CreatedAt time.Time `json:"created_at"`
	FilledAt  time.Time `json:"filled_at,omitempty"`
	Value     string    `json:"value,omitempty"`
}

// Manager coordinates blocking Wait calls with async Submit from UI/MCP.
type Manager struct {
	Root string
	Bus  *events.Bus

	mu      sync.Mutex
	prefill map[string]string // in-memory one-shot (same process)
}

// New creates an auth gate rooted at the lab workspace.
func New(root string, bus *events.Bus) *Manager {
	_ = os.MkdirAll(filepath.Join(root, "auth"), 0o750)
	return &Manager{Root: root, Bus: bus, prefill: map[string]string{}}
}

func key(runID string, kind Kind) string {
	return runID + "|" + string(kind)
}

func (m *Manager) dir() string {
	return filepath.Join(m.Root, "auth")
}

func (m *Manager) pathFor(runID string, kind Kind) string {
	safe := strings.ReplaceAll(runID, "/", "_")
	return filepath.Join(m.dir(), safe+"-"+string(kind)+".json")
}

// Prefill stores a value so the next Wait for that kind returns immediately.
// Pass runID="" for a one-shot global default (any run).
func (m *Manager) Prefill(runID string, kind Kind, value string) {
	if m == nil {
		return
	}
	kind = NormalizeKind(string(kind))
	value = normalize(kind, value)
	if value == "" || kind == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if runID == "" {
		m.prefill["*|"+string(kind)] = value
	} else {
		m.prefill[key(runID, kind)] = value
	}
}

// Pending returns open prompts (values redacted).
func (m *Manager) Pending() []Prompt {
	if m == nil {
		return nil
	}
	_ = os.MkdirAll(m.dir(), 0o750)
	entries, err := os.ReadDir(m.dir())
	if err != nil {
		return nil
	}
	out := make([]Prompt, 0)
	for _, ent := range entries {
		if ent.IsDir() || filepath.Ext(ent.Name()) != ".json" {
			continue
		}
		p, err := m.readFile(filepath.Join(m.dir(), ent.Name()))
		if err != nil || p.Status != "pending" {
			continue
		}
		p.Value = ""
		out = append(out, p)
	}
	return out
}

// PendingFor filters by run id.
func (m *Manager) PendingFor(runID string) []Prompt {
	all := m.Pending()
	if runID == "" {
		return all
	}
	out := make([]Prompt, 0)
	for _, p := range all {
		if p.RunID == runID {
			out = append(out, p)
		}
	}
	return out
}

// Wait blocks until Submit fills the prompt, a prefill exists, or ctx/timeout ends.
// Optional choices (for KindChoice) are shown as buttons in the Lab UI.
func (m *Manager) Wait(ctx context.Context, runID string, kind Kind, label, pkg string, timeout time.Duration, choices ...string) (string, error) {
	if m == nil {
		return "", fmt.Errorf("auth gate not configured")
	}
	if runID == "" {
		return "", fmt.Errorf("run_id required for auth prompt")
	}
	kind = NormalizeKind(string(kind))
	if kind == "" {
		return "", fmt.Errorf("prompt kind required (phone|otp|pin|text|choice)")
	}
	if label == "" {
		label = defaultLabel(kind)
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	if kind == KindChoice && len(choices) == 0 {
		choices = []string{"Allow", "Don't allow", "Accept", "Deny"}
	}

	m.mu.Lock()
	if v := m.prefill[key(runID, kind)]; v != "" {
		delete(m.prefill, key(runID, kind))
		m.mu.Unlock()
		return v, nil
	}
	if v := m.prefill["*|"+string(kind)]; v != "" {
		delete(m.prefill, "*|"+string(kind))
		m.mu.Unlock()
		return v, nil
	}
	m.mu.Unlock()

	// Disk prefill from earlier Submit (other process).
	if p, err := m.readFile(m.pathFor(runID, kind)); err == nil && p.Status == "filled" && p.Value != "" {
		_ = os.Remove(m.pathFor(runID, kind))
		return normalize(kind, p.Value), nil
	}

	prompt := Prompt{
		ID: lab.NewID("auth"), RunID: runID, Kind: kind, Label: label, Package: pkg,
		Choices: append([]string(nil), choices...),
		Status:  "pending", CreatedAt: time.Now().UTC(),
	}
	if err := m.writeFile(m.pathFor(runID, kind), prompt); err != nil {
		return "", err
	}
	m.publish("AUTH_PROMPT", runID, kind, label, pkg, "pending")

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = m.expire(runID, kind)
			m.publish("AUTH_EXPIRED", runID, kind, label, pkg, "expired")
			return "", fmt.Errorf("auth prompt %s expired/canceled: %w", kind, ctx.Err())
		case <-tick.C:
			p, err := m.readFile(m.pathFor(runID, kind))
			if err != nil {
				continue
			}
			if p.Status == "filled" && p.Value != "" {
				val := normalize(kind, p.Value)
				_ = os.Remove(m.pathFor(runID, kind))
				m.publish("AUTH_FILLED", runID, kind, redactMsg(kind, val), pkg, "filled")
				return val, nil
			}
			if p.Status == "canceled" || p.Status == "expired" {
				_ = os.Remove(m.pathFor(runID, kind))
				return "", fmt.Errorf("auth prompt %s %s", kind, p.Status)
			}
		}
	}
}

// Submit fills a pending prompt for the run (works across UI/MCP/CLI processes).
func (m *Manager) Submit(runID string, kind Kind, value string) (*Prompt, error) {
	if m == nil {
		return nil, fmt.Errorf("auth gate not configured")
	}
	kind = NormalizeKind(string(kind))
	value = normalize(kind, value)
	if runID == "" || kind == "" || value == "" {
		return nil, fmt.Errorf("run_id, kind, and value required")
	}
	path := m.pathFor(runID, kind)
	p, err := m.readFile(path)
	if err != nil {
		p = Prompt{
			ID: lab.NewID("auth"), RunID: runID, Kind: kind,
			CreatedAt: time.Now().UTC(),
		}
	}
	p.Status = "filled"
	p.Value = value
	p.FilledAt = time.Now().UTC()
	p.Kind = kind
	p.RunID = runID
	if err := m.writeFile(path, p); err != nil {
		return nil, err
	}
	out := p
	out.Value = ""
	return &out, nil
}

// Cancel expires a pending prompt.
func (m *Manager) Cancel(runID string, kind Kind) bool {
	if m == nil {
		return false
	}
	kind = NormalizeKind(string(kind))
	path := m.pathFor(runID, kind)
	p, err := m.readFile(path)
	if err != nil {
		return false
	}
	p.Status = "canceled"
	p.Value = ""
	_ = m.writeFile(path, p)
	return true
}

func (m *Manager) expire(runID string, kind Kind) error {
	path := m.pathFor(runID, kind)
	p, err := m.readFile(path)
	if err != nil {
		return err
	}
	p.Status = "expired"
	p.Value = ""
	return m.writeFile(path, p)
}

func (m *Manager) readFile(path string) (Prompt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Prompt{}, err
	}
	var p Prompt
	if err := json.Unmarshal(data, &p); err != nil {
		return Prompt{}, err
	}
	return p, nil
}

func (m *Manager) writeFile(path string, p Prompt) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// NormalizeKind maps aliases to canonical kinds.
func NormalizeKind(s string) Kind {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "phone", "mobile", "msisdn", "tel":
		return KindPhone
	case "otp", "sms", "code", "sms_code", "verification":
		return KindOTP
	case "pin":
		return KindPIN
	case "text", "input", "field":
		return KindText
	case "choice", "confirm", "notification", "permission", "dialog", "allow_deny":
		return KindChoice
	default:
		return Kind(strings.ToLower(strings.TrimSpace(s)))
	}
}

// IsChoice reports whether the kind is decided via UI buttons (not free text).
func IsChoice(kind Kind) bool {
	return NormalizeKind(string(kind)) == KindChoice
}

func normalize(kind Kind, v string) string {
	v = strings.TrimSpace(v)
	switch kind {
	case KindPhone:
		var b strings.Builder
		for i, r := range v {
			if r >= '0' && r <= '9' {
				b.WriteRune(r)
			} else if r == '+' && i == 0 {
				b.WriteRune(r)
			}
		}
		return b.String()
	case KindOTP, KindPIN:
		var b strings.Builder
		for _, r := range v {
			if r >= '0' && r <= '9' {
				b.WriteRune(r)
			}
		}
		return b.String()
	default:
		return v
	}
}

func defaultLabel(k Kind) string {
	switch k {
	case KindPhone:
		return "Phone number (SMS login)"
	case KindOTP:
		return "SMS verification code"
	case KindPIN:
		return "PIN code"
	case KindChoice:
		return "Choose an option on the device dialog (Allow / Don't allow)"
	default:
		return "Text input"
	}
}

func redactMsg(kind Kind, v string) string {
	if v == "" {
		return "(empty)"
	}
	switch kind {
	case KindPhone:
		if len(v) <= 4 {
			return "****"
		}
		return strings.Repeat("*", len(v)-4) + v[len(v)-4:]
	case KindOTP, KindPIN:
		return fmt.Sprintf("(%d digits)", len(v))
	default:
		if len(v) <= 2 {
			return "**"
		}
		return v[:1] + strings.Repeat("*", len(v)-2) + v[len(v)-1:]
	}
}

func (m *Manager) publish(typ, runID string, kind Kind, msg, pkg, status string) {
	if m == nil || m.Bus == nil {
		return
	}
	m.Bus.Publish(events.Event{
		Type: typ, RunID: runID, Message: msg,
		Data: map[string]any{
			"kind": kind, "package": pkg, "status": status, "auth": true,
		},
	})
}
