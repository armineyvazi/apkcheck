package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/events"
)

// Store persists observations and run reports under the lab workspace.
type Store struct {
	Root string
	Bus  *events.Bus
	mu   sync.Mutex
}

func (s *Store) obsDir() string  { return filepath.Join(s.Root, "observations") }
func (s *Store) runsDir() string { return filepath.Join(s.Root, "security-runs") }
func (s *Store) evidRoot() string {
	return filepath.Join(s.Root, "evidence")
}

// SaveObservation writes an observation JSON.
func (s *Store) SaveObservation(o *Observation) error {
	if o == nil {
		return fmt.Errorf("nil observation")
	}
	if o.ID == "" {
		o.ID = lab.NewID("obs")
	}
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now().UTC()
	}
	if err := os.MkdirAll(s.obsDir(), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.obsDir(), o.ID+".json"), data, 0o640); err != nil {
		return err
	}
	if s.Bus != nil {
		s.Bus.Publish(events.Event{
			Type: "OBSERVATION_RECORDED", ArtifactID: o.ArtifactID,
			Message: o.Title, Level: "info",
			Data: map[string]any{"id": o.ID, "severity": o.Severity},
		})
	}
	return nil
}

// ListObservations returns all observations.
func (s *Store) ListObservations() ([]*Observation, error) {
	_ = os.MkdirAll(s.obsDir(), 0o750)
	entries, err := os.ReadDir(s.obsDir())
	if err != nil {
		return nil, err
	}
	out := make([]*Observation, 0)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.obsDir(), e.Name()))
		if err != nil {
			continue
		}
		var o Observation
		if json.Unmarshal(data, &o) == nil {
			out = append(out, &o)
		}
	}
	return out, nil
}

// GetObservation loads one observation.
func (s *Store) GetObservation(id string) (*Observation, error) {
	data, err := os.ReadFile(filepath.Join(s.obsDir(), id+".json"))
	if err != nil {
		return nil, err
	}
	var o Observation
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// SaveRun persists a security run report.
func (s *Store) SaveRun(r *RunReport) error {
	if r == nil {
		return fmt.Errorf("nil run")
	}
	if r.ID == "" {
		r.ID = lab.NewID("secrun")
	}
	if err := os.MkdirAll(s.runsDir(), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.runsDir(), r.ID+".json"), data, 0o640)
}

// ListRuns returns security run reports.
func (s *Store) ListRuns() ([]*RunReport, error) {
	_ = os.MkdirAll(s.runsDir(), 0o750)
	entries, err := os.ReadDir(s.runsDir())
	if err != nil {
		return nil, err
	}
	out := make([]*RunReport, 0)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.runsDir(), e.Name()))
		if err != nil {
			continue
		}
		var r RunReport
		if json.Unmarshal(data, &r) == nil {
			out = append(out, &r)
		}
	}
	return out, nil
}
