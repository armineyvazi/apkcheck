package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/armin/apkcheck/internal/lab/logsync"
	"github.com/armin/apkcheck/internal/lab/recording"
	"github.com/armin/apkcheck/internal/lab/session"
	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/adb"
)

func (s *Server) registerSessionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/sessions", s.handleSessions)
	mux.HandleFunc("/api/sessions/", s.handleSessionByID)
	mux.HandleFunc("/api/recordings", s.handleRecordings)
	mux.HandleFunc("/api/recordings/", s.handleRecordingByID)
}

func (s *Server) sessions() *session.Manager {
	if s.Sessions == nil {
		root := "./lab-data"
		if s.Store != nil {
			root = s.Store.Root
		}
		s.Sessions = session.NewManager(root, s.Bus)
	}
	return s.Sessions
}

func (s *Server) recordings() *recording.Manager {
	if s.Recordings == nil {
		root := "./lab-data"
		if s.Store != nil {
			root = s.Store.Root
		}
		s.Recordings = recording.NewManager(root, s.Bus, s.sessions())
	}
	return s.Recordings
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.sessions().List()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if list == nil {
			list = []*session.Run{}
		}
		writeJSON(w, 200, list)
	case http.MethodPost:
		var req struct {
			Kind       string `json:"kind"`
			ArtifactID string `json:"artifact_id"`
			Serial     string `json:"serial"`
			AVD        string `json:"avd"`
			ScenarioID string `json:"scenario_id"`
			Record     bool   `json:"record"`
			Profile    string `json:"profile"`
			Package    string `json:"package"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "json required"})
			return
		}
		run, err := s.sessions().Start(session.StartOptions{
			Kind: session.Kind(req.Kind), ArtifactID: req.ArtifactID,
			RuntimeSerial: req.Serial, RuntimeAVD: req.AVD, ScenarioID: req.ScenarioID,
			Record: req.Record, Profile: req.Profile, Package: req.Package,
		})
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if req.Record && req.Serial != "" {
			art, rerr := s.recordings().Start(r.Context(), run, req.Serial, recording.ParseProfile(req.Profile))
			if rerr != nil {
				writeJSON(w, 200, map[string]any{"run": run, "recording_error": rerr.Error()})
				return
			}
			run.RecordingID = art.ID
			writeJSON(w, 200, map[string]any{"run": run, "recording": art})
			return
		}
		writeJSON(w, 200, run)
	default:
		writeJSON(w, 405, map[string]string{"error": "method"})
	}
}

func (s *Server) handleSessionByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, 400, map[string]string{"error": "id required"})
		return
	}
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		run, err := s.sessions().Get(id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		ev, _ := s.sessions().ListEvents(id)
		var rec any
		playable := false
		root := "./lab-data"
		if s.Store != nil {
			root = s.Store.Root
		}
		if run.RecordingID != "" {
			if art, gerr := s.recordings().Get(run.RecordingID); gerr == nil {
				mediaPath := recording.ResolvePlayablePath(art, root)
				playable = mediaPath != ""
				rec = map[string]any{
					"recording_id":     art.ID,
					"run_id":           art.RunID,
					"status":           art.Status,
					"profile":          art.Profile,
					"duration_ms":      art.DurationMS,
					"size_bytes":       art.SizeBytes,
					"storage_location": art.Path,
					"title":            art.Title,
					"file_name":        art.FileName,
					"scenario_id":      art.ScenarioID,
					"note":             art.Note,
					"playable":         playable,
					"media_url":        recording.FileURLPath(art.ID),
				}
				if !playable && art.Note == "" {
					rec.(map[string]any)["note"] = "no usable video (missing moov / truncated / path not visible to Lab)"
				}
			} else {
				rec = map[string]any{
					"recording_id": run.RecordingID,
					"status":       "missing",
					"note":         gerr.Error(),
					"playable":     false,
				}
			}
		}
		writeJSON(w, 200, map[string]any{"run": run, "events": ev, "recording": rec, "playable": playable})
		return
	}
	if len(parts) >= 2 {
		switch parts[1] {
		case "events":
			ev, err := s.sessions().ListEvents(id)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, ev)
			return
		case "complete":
			if r.Method != http.MethodPost {
				writeJSON(w, 405, map[string]string{"error": "POST"})
				return
			}
			var req struct {
				OK          bool   `json:"ok"`
				Result      string `json:"result"`
				FailureNote string `json:"failure_note"`
				FailureAtMS int64  `json:"failure_at_ms"`
				StopRecord  bool   `json:"stop_recording"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.StopRecord {
				_, _ = s.recordings().Stop(r.Context(), id)
			}
			run, err := s.sessions().Complete(id, req.OK, req.Result, req.FailureNote, req.FailureAtMS)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, run)
			return
		case "bookmark":
			if r.Method != http.MethodPost {
				writeJSON(w, 405, map[string]string{"error": "POST"})
				return
			}
			var req struct {
				Title       string   `json:"title"`
				Description string   `json:"description"`
				Tags        []string `json:"tags"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			ev, err := s.sessions().Bookmark(id, req.Title, req.Description, req.Tags)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, ev)
			return
		case "import-proxy":
			if r.Method != http.MethodPost {
				writeJSON(w, 405, map[string]string{"error": "POST"})
				return
			}
			n := s.syncProxyFlowsToSession(id)
			writeJSON(w, 200, map[string]any{"ok": true, "imported": n, "run_id": id})
			return
		case "import-logcat":
			if r.Method != http.MethodPost {
				writeJSON(w, 405, map[string]string{"error": "POST"})
				return
			}
			run, err := s.sessions().Get(id)
			if err != nil {
				writeJSON(w, 404, map[string]string{"error": err.Error()})
				return
			}
			var req struct {
				Serial  string `json:"serial"`
				Package string `json:"package"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			serial := req.Serial
			if serial == "" {
				serial = run.RuntimeSerial
			}
			pkg := req.Package
			if pkg == "" {
				pkg = run.Package
			}
			adbPath, _ := runner.LookPath("", "adb")
			client := &adb.Client{Path: adbPath}
			n, err := logsync.Import(r.Context(), client, serial, s.sessions(), run, logsync.ImportOptions{Package: pkg})
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]any{"ok": true, "imported": n, "run_id": id, "package": pkg})
			return
		case "screenshot":
			if r.Method != http.MethodPost {
				writeJSON(w, 405, map[string]string{"error": "POST"})
				return
			}
			run, err := s.sessions().Get(id)
			if err != nil {
				writeJSON(w, 404, map[string]string{"error": err.Error()})
				return
			}
			var req struct {
				Serial string `json:"serial"`
				Name   string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			serial := req.Serial
			if serial == "" {
				serial = run.RuntimeSerial
			}
			path, err := s.recordings().CaptureScreenshot(r.Context(), run, serial, req.Name)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]any{"path": path})
			return
		case "recording", "record":
			if r.Method == http.MethodPost {
				var req struct {
					Action  string `json:"action"` // start|stop
					Serial  string `json:"serial"`
					Profile string `json:"profile"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				run, err := s.sessions().Get(id)
				if err != nil {
					writeJSON(w, 404, map[string]string{"error": err.Error()})
					return
				}
				switch req.Action {
				case "stop":
					art, err := s.recordings().Stop(r.Context(), id)
					if err != nil {
						writeJSON(w, 500, map[string]string{"error": err.Error()})
						return
					}
					writeJSON(w, 200, art)
				default:
					serial := req.Serial
					if serial == "" {
						serial = run.RuntimeSerial
					}
					art, err := s.recordings().Start(r.Context(), run, serial, recording.ParseProfile(req.Profile))
					if err != nil {
						writeJSON(w, 500, map[string]any{"error": err.Error(), "recording": art})
						return
					}
					writeJSON(w, 200, art)
				}
				return
			}
			writeJSON(w, 200, s.recordings().Status(id))
			return
		case "event":
			if r.Method != http.MethodPost {
				writeJSON(w, 405, map[string]string{"error": "POST"})
				return
			}
			var ev session.Event
			if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
				writeJSON(w, 400, map[string]string{"error": "json required"})
				return
			}
			out, err := s.sessions().AddEvent(id, ev)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, out)
			return
		}
	}
	writeJSON(w, 404, map[string]string{"error": "not found", "path": r.URL.Path})
}

func (s *Server) handleRecordings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]string{"error": "GET"})
		return
	}
	list, err := s.recordings().List()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if list == nil {
		list = []*recording.Artifact{}
	}
	writeJSON(w, 200, list)
}

func (s *Server) handleRecordingRetention(w http.ResponseWriter, r *http.Request) {
	root := "./lab-data"
	if s.Store != nil {
		root = s.Store.Root
	}
	switch r.Method {
	case http.MethodGet:
		cfg := recording.LoadRetention(root)
		writeJSON(w, 200, map[string]any{
			"policy":      cfg.Policy,
			"description": recording.DescribeRetention(cfg.Policy),
		})
	case http.MethodPost:
		var req struct {
			Policy  string `json:"policy"`
			Cleanup bool   `json:"cleanup"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "json required"})
			return
		}
		cfg := recording.RetentionConfig{Policy: recording.ParseRetention(req.Policy)}
		if err := recording.SaveRetention(root, cfg); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		out := map[string]any{"policy": cfg.Policy, "description": recording.DescribeRetention(cfg.Policy)}
		if req.Cleanup {
			res, err := s.recordings().Cleanup(s.sessions())
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			out["cleanup"] = res
		}
		writeJSON(w, 200, out)
	default:
		writeJSON(w, 405, map[string]string{"error": "GET|POST"})
	}
}

func (s *Server) handleRecordingByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/recordings/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, 400, map[string]string{"error": "id required"})
		return
	}
	if parts[0] == "retention" {
		s.handleRecordingRetention(w, r)
		return
	}
	id := parts[0]
	if len(parts) >= 2 && parts[1] == "media" {
		art, err := s.recordings().Get(id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()})
			return
		}
		root := "./lab-data"
		if s.Store != nil {
			root = s.Store.Root
		}
		media := art.Path
		candidates := []string{media, filepath.Join(root, "recordings", id, "recording.mp4")}
		segDirs := []string{}
		if art.SegmentsDir != "" {
			segDirs = append(segDirs, art.SegmentsDir)
		}
		segDirs = append(segDirs, filepath.Join(root, "recordings", id, "segments"))
		for _, sd := range segDirs {
			if segs, _ := filepath.Glob(filepath.Join(sd, "segment-*.mp4")); len(segs) > 0 {
				sort.Strings(segs)
				candidates = append(candidates, segs...)
			}
		}
		found := recording.ResolvePlayablePath(art, root)
		if found == "" {
			// Fall back to walking candidates (Resolve already covers them when root set).
			for _, c := range candidates {
				if recording.MP4Playable(c) {
					found = c
					break
				}
			}
		}
		if found == "" {
			msg := "no usable video (file missing, truncated, or missing moov atom)"
			if art.Note != "" {
				msg = art.Note
			}
			writeJSON(w, 404, map[string]string{"error": msg, "status": art.Status, "playable": "false"})
			return
		}
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Accept-Ranges", "bytes")
		http.ServeFile(w, r, found)
		return
	}
	if len(parts) >= 2 && parts[1] == "segment" && len(parts) >= 3 {
		root := "./lab-data"
		if s.Store != nil {
			root = s.Store.Root
		}
		seg := filepath.Join(root, "recordings", id, "segments", filepath.Base(parts[2]))
		if _, err := os.Stat(seg); err != nil {
			writeJSON(w, 404, map[string]string{"error": "segment missing"})
			return
		}
		w.Header().Set("Content-Type", "video/mp4")
		http.ServeFile(w, r, seg)
		return
	}
	art, err := s.recordings().Get(id)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, art)
}
