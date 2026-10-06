package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"

	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/iocscan"
)

// iocCache holds scan results for the server lifetime, keyed by artifact ID.
var (
	iocMu    sync.Mutex
	iocCache = map[string]*iocscan.Result{}
)

func (s *Server) registerIOCRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/scan/ioc", s.handleIOCScan)
}

// handleIOCScan handles both GET (return cached result) and POST (run / re-run scan).
//
// POST /api/scan/ioc  {"artifact_id": "abc123"}
// GET  /api/scan/ioc?artifact_id=abc123
func (s *Server) handleIOCScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		id := r.URL.Query().Get("artifact_id")
		iocMu.Lock()
		res, ok := iocCache[id]
		iocMu.Unlock()
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "no scan result for artifact — POST first"})
			return
		}
		writeJSON(w, 200, res)

	case http.MethodPost:
		var req struct {
			ArtifactID string `json:"artifact_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ArtifactID == "" {
			writeJSON(w, 400, map[string]string{"error": "artifact_id required"})
			return
		}
		root, err := s.iocScanRoot(req.ArtifactID)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		if s.Bus != nil {
			s.Bus.Publish(events.Event{Type: "IOC_SCAN_START",
				Message: "starting IOC scan for " + req.ArtifactID, Level: "info"})
		}
		res := iocscan.Scan(req.ArtifactID, root)
		iocMu.Lock()
		iocCache[req.ArtifactID] = res
		iocMu.Unlock()
		if s.Bus != nil {
			if res.Error != "" {
				s.Bus.Publish(events.Event{Type: "IOC_SCAN_ERROR", Message: res.Error, Level: "warn"})
			} else {
				s.Bus.Publish(events.Event{
					Type:    "IOC_SCAN_DONE",
					Message: fmt.Sprintf("IOC scan done: %d finding(s) in %d file(s)", len(res.Findings), res.FilesScanned),
					Level:   "info",
				})
			}
		}
		writeJSON(w, 200, res)

	default:
		writeJSON(w, 405, map[string]string{"error": "GET or POST"})
	}
}

// iocScanRoot returns the directory to scan for an artifact.
// Prefers a companion "project" artifact (JADX/apktool output), falls back to artifact dir.
func (s *Server) iocScanRoot(artifactID string) (string, error) {
	if s.Store == nil {
		return "", errors.New("store not initialised")
	}
	arts := s.Store.List()
	for _, a := range arts {
		if a.ID != artifactID {
			continue
		}
		// Prefer a project artifact whose parent is this artifact.
		for _, b := range arts {
			if b.Kind == "project" && b.ParentID == a.ID {
				return b.Path, nil
			}
		}
		return filepath.Dir(a.Path), nil
	}
	return "", fmt.Errorf("artifact %s not found", artifactID)
}
