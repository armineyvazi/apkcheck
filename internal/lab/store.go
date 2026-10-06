// Package lab is the APK Laboratory workbench: artifacts, rebuild pipeline,
// validation, events, and HTTP API — extending apkcheck without replacing
// Smali-backed static analysis.
package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/armin/apkcheck/internal/lab/events"
)

// Kind classifies a tracked artifact.
type Kind string

const (
	KindOriginalAPK Kind = "original_apk"
	KindProject     Kind = "project" // apktool decode dir
	KindUnsignedAPK Kind = "unsigned_apk"
	KindSignedAPK   Kind = "signed_apk"
)

// Artifact is one lineage node.
type Artifact struct {
	ID        string            `json:"id"`
	Kind      Kind              `json:"kind"`
	Path      string            `json:"path"`
	ParentID  string            `json:"parent_id,omitempty"`
	Package   string            `json:"package,omitempty"`
	Label     string            `json:"label,omitempty"`
	SHA256    string            `json:"sha256,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	Meta      map[string]string `json:"meta,omitempty"`
}

// ValidateStage is one step in rebuild validation.
type ValidateStage struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
	LogPath string `json:"log_path,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ValidateResult is the full rebuild smoke pipeline.
type ValidateResult struct {
	ArtifactID  string          `json:"artifact_id"`
	OK          bool            `json:"ok"`
	Stages      []ValidateStage `json:"stages"`
	SessionID   string          `json:"session_id,omitempty"`   // runtime evidence session
	LabRunID    string          `json:"lab_run_id,omitempty"`   // Lab test-run / observability id
	RecordingID string          `json:"recording_id,omitempty"` // device recording artifact
	StartedAt   time.Time       `json:"started_at"`
	EndedAt     time.Time       `json:"ended_at"`
}

// Store persists lab state under a workspace directory.
type Store struct {
	Root string
	Bus  *events.Bus

	mu        sync.RWMutex
	artifacts map[string]*Artifact
}

// OpenStore creates or loads a lab workspace.
func OpenStore(root string, bus *events.Bus) (*Store, error) {
	if root == "" {
		root = "./lab-data"
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	root = abs
	for _, sub := range []string{"apks", "projects", "builds", "certs", "runs", "logs", "scenarios", "proxy", "sessions", "recordings"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o750); err != nil {
			return nil, err
		}
	}
	s := &Store{
		Root:      root,
		Bus:       bus,
		artifacts: map[string]*Artifact{},
	}
	_ = s.loadIndex()
	return s, nil
}

func (s *Store) indexPath() string {
	return filepath.Join(s.Root, "index.json")
}

func (s *Store) loadIndex() error {
	data, err := os.ReadFile(s.indexPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []*Artifact
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range list {
		s.artifacts[a.ID] = a
	}
	return nil
}

func (s *Store) saveIndex() error {
	s.mu.RLock()
	list := make([]*Artifact, 0, len(s.artifacts))
	for _, a := range s.artifacts {
		list = append(list, a)
	}
	s.mu.RUnlock()
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.indexPath(), data, 0o640)
}

// Put registers an artifact.
func (s *Store) Put(a *Artifact) error {
	if a == nil || a.ID == "" {
		return fmt.Errorf("artifact id required")
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	s.artifacts[a.ID] = a
	s.mu.Unlock()
	if s.Bus != nil {
		s.Bus.Publish(events.Event{
			Type: "ARTIFACT_SAVED", ArtifactID: a.ID,
			Message: fmt.Sprintf("%s %s", a.Kind, a.Label),
		})
	}
	return s.saveIndex()
}

// Get returns an artifact by id.
func (s *Store) Get(id string) (*Artifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.artifacts[id]
	if !ok {
		return nil, fmt.Errorf("artifact not found: %s", id)
	}
	cp := *a
	return &cp, nil
}

// List returns all artifacts.
func (s *Store) List() []*Artifact {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Artifact, 0, len(s.artifacts))
	for _, a := range s.artifacts {
		cp := *a
		out = append(out, &cp)
	}
	return out
}

// NewID returns a short unique id.
func NewID(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UTC().UnixNano(), idSeq.Add(1)%100000)
}

var idSeq atomic.Uint64
