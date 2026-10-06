package proxy

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FlowEvent is one HTTP exchange exported for Lab timeline filtering.
type FlowEvent struct {
	OffsetMS int64    `json:"offset_ms"`
	Method   string   `json:"method"`
	Host     string   `json:"host"`
	URL      string   `json:"url"`
	Path     string   `json:"path"`
	Status   int      `json:"status"`
	Tags     []string `json:"tags"`
	TS       float64  `json:"ts,omitempty"`
}

// ReadFlowJSONL loads flows.jsonl written by configs/mitm_jsonl_addon.py.
func ReadFlowJSONL(proxyDir string) ([]FlowEvent, error) {
	path := filepath.Join(proxyDir, "flows.jsonl")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []FlowEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev FlowEvent
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, sc.Err()
}

// AlignOffsets shifts flow offsets so t0 aligns with a Lab run start.
// When flows were captured with their own epoch, recompute from absolute ts.
func AlignOffsets(flows []FlowEvent, runStarted time.Time) []FlowEvent {
	if runStarted.IsZero() {
		return flows
	}
	out := make([]FlowEvent, 0, len(flows))
	for _, f := range flows {
		ev := f
		if f.TS > 0 {
			at := time.Unix(int64(f.TS), int64((f.TS-float64(int64(f.TS)))*1e9))
			ev.OffsetMS = at.Sub(runStarted).Milliseconds()
			if ev.OffsetMS < 0 {
				ev.OffsetMS = 0
			}
		}
		out = append(out, ev)
	}
	return out
}
