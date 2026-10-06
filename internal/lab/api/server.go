// Package api serves the APK Lab HTTP + WebSocket API.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/authgate"
	"github.com/armin/apkcheck/internal/lab/certs"
	"github.com/armin/apkcheck/internal/lab/compare"
	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/logsync"
	"github.com/armin/apkcheck/internal/lab/pipeline"
	"github.com/armin/apkcheck/internal/lab/proxy"
	"github.com/armin/apkcheck/internal/lab/proxysync"
	"github.com/armin/apkcheck/internal/lab/recording"
	"github.com/armin/apkcheck/internal/lab/scenarios"
	"github.com/armin/apkcheck/internal/lab/security"
	"github.com/armin/apkcheck/internal/lab/session"
	"github.com/armin/apkcheck/internal/lab/workspace"
	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/adb"
)

// Server is the lab API.
type Server struct {
	Store      *lab.Store
	Pipe       *pipeline.Pipeline
	Bus        *events.Bus
	Proxy      *proxy.Manager
	Scenarios  *scenarios.Engine
	Certs      *certs.Manager
	Security   *security.Engine
	Sessions   *session.Manager
	Recordings *recording.Manager
	Auth       *authgate.Manager
	UIDir      string

	mu           sync.Mutex
	lastValidate map[string]*lab.ValidateResult
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	if s.lastValidate == nil {
		s.lastValidate = map[string]*lab.ValidateResult{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/artifacts", s.handleArtifacts)
	mux.HandleFunc("/api/artifacts/", s.handleArtifactByID)
	mux.HandleFunc("/api/import", s.handleImport)
	mux.HandleFunc("/api/decompile", s.handleDecompile)
	mux.HandleFunc("/api/build", s.handleBuild)
	mux.HandleFunc("/api/sign", s.handleSign)
	mux.HandleFunc("/api/rebuild", s.handleRebuild)
	mux.HandleFunc("/api/validate", s.handleValidate)
	mux.HandleFunc("/api/compare", s.handleCompare)
	mux.HandleFunc("/api/certs", s.handleCerts)
	mux.HandleFunc("/api/scenarios", s.handleScenarios)
	mux.HandleFunc("/api/scenarios/run", s.handleScenarioRun)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/events/stream", s.handleEventStream)
	mux.HandleFunc("/api/proxy/status", s.handleProxyStatus)
	mux.HandleFunc("/api/proxy/start", s.handleProxyStart)
	mux.HandleFunc("/api/proxy/stop", s.handleProxyStop)
	mux.HandleFunc("/api/workspace/reset", s.handleWorkspaceReset)
	s.registerSecurityRoutes(mux)
	s.registerRuntimeRoutes(mux)
	s.registerSessionRoutes(mux)
	s.registerAuthRoutes(mux)
	s.registerIOCRoutes(mux)
	s.registerFridaRoutes(mux)
	// Catch-all: unknown /api/* must return JSON (never Go FileServer plain-text "404 page not found").
	mux.HandleFunc("/", s.handleRoot)
	return withCORS(mux)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, 404, map[string]string{
			"error": "api endpoint not found",
			"path":  r.URL.Path,
			"hint":  "rebuild/restart lab server if this endpoint should exist (apkcheck lab ui)",
		})
		return
	}
	if s.UIDir != "" {
		http.FileServer(http.Dir(s.UIDir)).ServeHTTP(w, r)
		return
	}
	s.handleIndex(w, r)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// writeJSONList always encodes a JSON array (never bare null).
func writeJSONList(w http.ResponseWriter, code int, v any) {
	if v == nil {
		writeJSON(w, code, []any{})
		return
	}
	writeJSON(w, code, v)
}

// detachedTimeout is independent of the HTTP request context so browser
// disconnect / refresh does not cancel long emulator boots or rebuilds.
func detachedTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = 30 * time.Minute
	}
	return context.WithTimeout(context.Background(), d)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "service": "apkcheck-lab"})
}

func (s *Server) handleArtifacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]string{"error": "method"})
		return
	}
	writeJSON(w, 200, s.Store.List())
}

func (s *Server) handleArtifactByID(w http.ResponseWriter, r *http.Request) {
	id := stringsTrimPrefix(r.URL.Path, "/api/artifacts/")
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "id required"})
		return
	}
	a, err := s.Store.Get(id)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, a)
}

type pathReq struct {
	Path        string `json:"path"`
	Label       string `json:"label"`
	ID          string `json:"id"`
	Emulator    string `json:"emulator"`
	Device      string `json:"device"`
	DurationSec int    `json:"duration_sec"`
	Record      bool   `json:"record"`
	Profile     string `json:"profile"`
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req pathReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		writeJSON(w, 400, map[string]string{"error": "path required"})
		return
	}
	a, err := s.Pipe.ImportAPK(req.Path, req.Label)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, a)
}

func (s *Server) handleDecompile(w http.ResponseWriter, r *http.Request) {
	s.runID(w, r, func(ctx context.Context, id string) (any, error) {
		return s.Pipe.Decompile(ctx, id)
	})
}

func (s *Server) handleBuild(w http.ResponseWriter, r *http.Request) {
	s.runID(w, r, func(ctx context.Context, id string) (any, error) {
		return s.Pipe.Build(ctx, id)
	})
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	s.runID(w, r, func(ctx context.Context, id string) (any, error) {
		return s.Pipe.Sign(ctx, id)
	})
}

func (s *Server) handleRebuild(w http.ResponseWriter, r *http.Request) {
	s.runID(w, r, func(ctx context.Context, id string) (any, error) {
		return s.Pipe.RebuildFull(ctx, id)
	})
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req pathReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeJSON(w, 400, map[string]string{"error": "id required"})
		return
	}
	opt := pipeline.ValidateOptions{EmulatorAVD: req.Emulator, DeviceSerial: req.Device}
	if req.DurationSec > 0 {
		opt.Duration = time.Duration(req.DurationSec) * time.Second
	}

	var labRun *session.Run
	var recArt *recording.Artifact
	if req.Record {
		serial := req.Device
		if serial == "" {
			serial = security.DiscoverDefaultSerial(r.Context())
		}
		if serial == "" && req.Emulator != "" {
			// boot AVD then record
			avd := req.Emulator
			if avd == "" {
				avd = "Pixel_8_API_34"
			}
			ctxBoot, cancel := detachedTimeout(12 * time.Minute)
			ser, err := s.runtimeMgr().Start(ctxBoot, avd, false, 10*time.Minute)
			cancel()
			if err == nil {
				serial = ser
				opt.DeviceSerial = ser
				opt.EmulatorAVD = ""
			}
		}
		run, err := s.sessions().Start(session.StartOptions{
			Kind: session.KindValidate, ArtifactID: req.ID,
			RuntimeSerial: serial, RuntimeAVD: req.Emulator,
			Record: true, Profile: req.Profile,
		})
		if err == nil {
			labRun = run
			if serial != "" {
				art, rerr := s.recordings().Start(r.Context(), run, serial, recording.ParseProfile(req.Profile))
				if rerr != nil {
					_, _ = s.sessions().AddEvent(run.ID, session.Event{
						Type: "RECORDING_FAILED", Source: "system", Category: "runtime", Level: "warn",
						Message: rerr.Error(), Bookmark: true, Tags: []string{"recording"},
					})
				} else {
					recArt = art
					labRun.RecordingID = art.ID
					// SAFETY: only set DeviceSerial on the pipeline when there is no
					// EmulatorAVD; if both are present the pipeline picks mode="device"
					// and SelectPhysical rejects emulator serials.
					if req.Emulator == "" {
						opt.DeviceSerial = serial
					}
				}
			}
			_, _ = s.sessions().AddEvent(run.ID, session.Event{
				Type: "VALIDATE_STARTED", Source: "system", Category: "runtime",
				Message: "validate with recording=" + fmt.Sprintf("%v", recArt != nil),
			})
		}
	}

	ctx, cancel := detachedTimeout(30 * time.Minute)
	defer cancel()
	res, err := s.Pipe.Validate(ctx, req.ID, opt)
	if res != nil && labRun != nil {
		res.LabRunID = labRun.ID
		if recArt != nil {
			res.RecordingID = recArt.ID
		}
	}
	if labRun != nil {
		if res != nil {
			for _, st := range res.Stages {
				level := "info"
				if !st.OK {
					level = "error"
				}
				_, _ = s.sessions().AddEvent(labRun.ID, session.Event{
					Type: "VALIDATE_STAGE", Source: "system", Category: "runtime", Level: level,
					Message:  st.Name + ": " + st.Detail + st.Error,
					Metadata: map[string]any{"stage": st.Name, "ok": st.OK},
					Bookmark: !st.OK,
					Tags:     []string{"validate", st.Name},
				})
			}
		}
		if recArt != nil {
			stopped, _ := s.recordings().Stop(ctx, labRun.ID)
			if stopped != nil && res != nil {
				res.RecordingID = stopped.ID
			}
		}
		ok := err == nil && res != nil && res.OK
		note := ""
		var failAt int64
		if res != nil && !res.OK {
			note = "validation stages failed"
			if ev, _ := s.sessions().ListEvents(labRun.ID); ev != nil {
				for _, e := range ev {
					if e.Level == "error" {
						failAt = e.OffsetMS
						break
					}
				}
				if failAt == 0 {
					for _, e := range ev {
						if e.Bookmark && e.Type != "RECORDING_FAILED" {
							failAt = e.OffsetMS
							break
						}
					}
				}
			}
		}
		if err != nil {
			note = err.Error()
		}
		_, _ = s.sessions().Complete(labRun.ID, ok, "", note, failAt)
	}
	if res != nil {
		s.mu.Lock()
		if s.lastValidate == nil {
			s.lastValidate = map[string]*lab.ValidateResult{}
		}
		s.lastValidate[req.ID] = res
		s.mu.Unlock()
	}
	if err != nil {
		payload := map[string]any{"error": err.Error(), "result": res}
		if labRun != nil {
			payload["lab_run_id"] = labRun.ID
			if res != nil {
				payload["recording_id"] = res.RecordingID
			}
		}
		writeJSON(w, 500, payload)
		return
	}
	payload := map[string]any{"result": res}
	if labRun != nil {
		payload["lab_run_id"] = labRun.ID
		if res != nil && res.RecordingID != "" {
			payload["recording_id"] = res.RecordingID
		} else if labRun.RecordingID != "" {
			payload["recording_id"] = labRun.RecordingID
		}
	}
	writeJSON(w, 200, payload)
}

func (s *Server) handleCompare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		Left  string `json:"left"`
		Right string `json:"right"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Left == "" || req.Right == "" {
		writeJSON(w, 400, map[string]string{"error": "left and right artifact ids required"})
		return
	}
	left, err := s.Store.Get(req.Left)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	right, err := s.Store.Get(req.Right)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	s.mu.Lock()
	lv, rv := s.lastValidate[req.Left], s.lastValidate[req.Right]
	s.mu.Unlock()
	writeJSON(w, 200, compare.ValidateResults(left, right, lv, rv))
}

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	if s.Certs == nil {
		writeJSON(w, 200, map[string]any{"note": "certs not configured"})
		return
	}
	writeJSON(w, 200, s.Certs.Status())
}

func (s *Server) handleScenarios(w http.ResponseWriter, r *http.Request) {
	if s.Scenarios == nil {
		writeJSON(w, 500, map[string]string{"error": "scenarios not configured"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		list, err := s.Scenarios.List()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, list)
	case http.MethodPost:
		var d scenarios.Definition
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json"})
			return
		}
		if err := s.Scenarios.Save(&d); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, d)
	default:
		writeJSON(w, 405, map[string]string{"error": "method"})
	}
}

func (s *Server) handleScenarioRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	if s.Scenarios == nil {
		writeJSON(w, 500, map[string]string{"error": "scenarios not configured"})
		return
	}
	var req struct {
		ScenarioID     string `json:"scenario_id"`
		ArtifactID     string `json:"artifact_id"`
		Serial         string `json:"serial"`
		Package        string `json:"package"`
		Activity       string `json:"activity"`
		Record         bool   `json:"record"`
		Profile        string `json:"profile"`
		Phone          string `json:"phone"`
		OTP            string `json:"otp"`
		AVD            string `json:"avd"`
		FreshEmulator  *bool  `json:"fresh_emulator"` // default true when record=true
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ScenarioID == "" {
		writeJSON(w, 400, map[string]string{"error": "scenario_id required"})
		return
	}
	// Fill package from selected artifact when UI only picked an APK.
	if req.Package == "" && req.ArtifactID != "" && s.Store != nil {
		if art, gerr := s.Store.Get(req.ArtifactID); gerr == nil && art != nil && art.Package != "" {
			req.Package = art.Package
		}
	}
	if req.Package == "" {
		writeJSON(w, 400, map[string]string{"error": "package required (set package field or select an artifact with package name)"})
		return
	}
	ctx, cancel := detachedTimeout(10 * time.Minute)
	defer cancel()

	var labRun *session.Run
	var recArt *recording.Artifact
	scenName := req.ScenarioID
	if def, gerr := s.Scenarios.Get(req.ScenarioID); gerr == nil && def != nil && def.Name != "" {
		scenName = def.Name
	}
	// Always create a Lab session when serial is known so timeline (scenario/logcat/mitm) is available.
	if req.Serial != "" && s.Sessions != nil {
		run, err := s.sessions().Start(session.StartOptions{
			Kind: session.KindScenario, ArtifactID: req.ArtifactID, ScenarioID: req.ScenarioID,
			RuntimeSerial: req.Serial, Package: req.Package, Record: req.Record, Profile: req.Profile,
			Meta: map[string]string{"scenario_name": scenName, "title": scenName},
		})
		if err == nil {
			labRun = run
			adbPath, _ := runner.LookPath("", "adb")
			client := &adb.Client{Path: adbPath}
			_ = logsync.Clear(ctx, client, req.Serial)
			if req.Record {
				recArt, _ = s.recordings().Start(ctx, run, req.Serial, recording.ParseProfile(req.Profile))
				// Warm-up so video includes the first scenario moment (not mid-launch).
				logsync.WarmRecording(2 * time.Second)
				_, _ = s.sessions().AddEvent(run.ID, session.Event{
					Type: "RECORDING_READY", Source: "system", Category: "runtime",
					Message: "screenrecord warm — scenario actions start now",
					Tags:    []string{"recording"},
				})
			}
			_, _ = s.sessions().AddEvent(run.ID, session.Event{
				Type: "SCENARIO_STARTED", Source: "scenario", Category: "scenario",
				Message: scenName, Tags: []string{"app", "scenario"},
			})
		}
	}

	runOpt := scenarios.RunOptions{
		Serial: req.Serial, Package: req.Package, Activity: req.Activity,
		Auth: s.auth(), Phone: req.Phone, OTP: req.OTP,
	}
	if labRun != nil {
		runOpt.LabRunID = labRun.ID
		runOpt.Sessions = s.sessions()
	}
	res, err := s.Scenarios.Run(ctx, req.ScenarioID, req.ArtifactID, runOpt)
	var logN, mitmN int
	var freshSerial string
	var freshErr error
	if labRun != nil {
		adbPath, _ := runner.LookPath("", "adb")
		client := &adb.Client{Path: adbPath}
		logN, _ = logsync.Import(ctx, client, req.Serial, s.sessions(), labRun, logsync.ImportOptions{Package: req.Package})
		mitmN = s.syncProxyFlowsToSession(labRun.ID)
		if recArt != nil {
			_, _ = s.recordings().Stop(ctx, labRun.ID)
		}
		ok := err == nil && res != nil && res.OK
		note := ""
		if !ok && err != nil {
			note = err.Error()
		} else if !ok {
			note = "scenario steps failed"
		}
		_, _ = s.sessions().Complete(labRun.ID, ok, "", note, 0)

		// After scenario: wipe + cold-boot the emulator so the next run starts clean.
		// Default true for any emulator serial (KVM host), regardless of recording.
		wantFresh := strings.HasPrefix(req.Serial, "emulator-")
		if req.FreshEmulator != nil {
			wantFresh = *req.FreshEmulator
		}
		if wantFresh && strings.HasPrefix(req.Serial, "emulator-") {
			avd := req.AVD
			if avd == "" {
				avd = "Pixel_8_API_34"
			}
			fctx, fcancel := detachedTimeout(14 * time.Minute)
			freshSerial, freshErr = s.runtimeMgr().FreshAfterRecording(fctx, avd, req.Serial, 12*time.Minute)
			fcancel()
			if freshErr == nil {
				_, _ = s.sessions().AddEvent(labRun.ID, session.Event{
					Type: "RUNTIME_FRESH", Source: "system", Category: "runtime",
					Message: "fresh emulator ready · " + freshSerial,
					Tags:    []string{"emulator", "fresh"},
				})
			}
		}
	}
	payload := map[string]any{"result": res}
	if labRun != nil {
		payload["lab_run_id"] = labRun.ID
		payload["timeline_logcat"] = logN
		payload["timeline_mitm"] = mitmN
		if labRun.RecordingID != "" {
			payload["recording_id"] = labRun.RecordingID
		} else if recArt != nil {
			payload["recording_id"] = recArt.ID
		}
		if freshSerial != "" {
			payload["fresh_serial"] = freshSerial
		}
		if freshErr != nil {
			payload["fresh_emulator_error"] = freshErr.Error()
		}
	}
	if err != nil {
		payload["error"] = err.Error()
		writeJSON(w, 500, payload)
		return
	}
	writeJSON(w, 200, payload)
}

func (s *Server) runID(w http.ResponseWriter, r *http.Request, fn func(context.Context, string) (any, error)) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req pathReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		writeJSON(w, 400, map[string]string{"error": "id required"})
		return
	}
	ctx, cancel := detachedTimeout(45 * time.Minute)
	defer cancel()
	out, err := fn(ctx, req.ID)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleEvents(w http.ResponseWriter, _ *http.Request) {
	writeJSONList(w, 200, s.liveEventFeed())
}

func (s *Server) liveEventFeed() []events.Event {
	var busEv []events.Event
	if s.Bus != nil {
		busEv = s.Bus.Recent()
	}
	diskEv := s.sessions().RecentFeed(10, 600)
	return mergeEventFeed(busEv, diskEv)
}

func eventFeedKey(e events.Event) string {
	id := ""
	if m, ok := e.Data.(map[string]any); ok {
		if v, ok := m["event_id"].(string); ok {
			id = v
		}
	}
	if id != "" {
		return id
	}
	return fmt.Sprintf("%s|%s|%s|%s", e.RunID, e.Type, e.At.UTC().Format(time.RFC3339Nano), e.Message)
}

func mergeEventFeed(parts ...[]events.Event) []events.Event {
	const max = 800
	seen := make(map[string]struct{}, 256)
	out := make([]events.Event, 0, 256)
	for _, list := range parts {
		for _, e := range list {
			k := eventFeedKey(e)
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	if len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	var ch chan events.Event
	if s.Bus != nil {
		ch = s.Bus.Subscribe(128)
		defer s.Bus.Unsubscribe(ch)
	} else {
		ch = make(chan events.Event) // never receives; ticker still drives disk feed
	}

	seen := make(map[string]struct{}, 256)
	send := func(e events.Event) {
		k := eventFeedKey(e)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		b, err := json.Marshal(e)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", b)
	}

	for _, e := range s.liveEventFeed() {
		send(e)
	}
	// Always write a comment so clients/proxies see an immediate body (keeps EventSource healthy).
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()
	pingEvery := 0
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			send(e)
			flusher.Flush()
		case <-tick.C:
			for _, e := range s.sessions().RecentFeed(6, 300) {
				send(e)
			}
			pingEvery++
			if pingEvery%15 == 0 {
				fmt.Fprintf(w, ": ping\n\n")
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleProxyStatus(w http.ResponseWriter, _ *http.Request) {
	if s.Proxy == nil {
		writeJSON(w, 200, map[string]any{"enabled": false, "available": false})
		return
	}
	writeJSON(w, 200, s.Proxy.Status())
}

func (s *Server) handleProxyStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	if s.Proxy == nil {
		writeJSON(w, 500, map[string]string{"error": "proxy not configured"})
		return
	}
	if err := s.Proxy.Start(r.Context()); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, s.Proxy.Status())
}

func (s *Server) handleProxyStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	if s.Proxy != nil {
		_ = s.Proxy.Stop()
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleWorkspaceReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req workspace.ResetOptions
	_ = json.NewDecoder(r.Body).Decode(&req)
	if !req.Sessions && !req.Recordings && !req.Logs && !req.Runs && !req.SecurityRuns && !req.Observations && !req.ProxyFlows && !req.Exports {
		req = workspace.FreshRunReset()
	}
	root := "./lab-data"
	if s.Store != nil {
		root = s.Store.Root
	}
	removed, err := workspace.Reset(root, req)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if s.Scenarios != nil {
		s.Scenarios.EnsureBuiltins()
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "removed": removed, "workspace": root,
		"note": "APKs/projects kept. Scenarios re-seeded. Next scenario run starts fresh.",
	})
}

// syncProxyFlowsToSession imports mitm JSONL into the run timeline (category=network).
func (s *Server) syncProxyFlowsToSession(runID string) int {
	if s.Sessions == nil || runID == "" || s.Proxy == nil {
		return 0
	}
	run, err := s.Sessions.Get(runID)
	if err != nil || run == nil {
		return 0
	}
	return proxysync.Import(s.Proxy.WorkDir, s.Sessions, run)
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(fallbackHTML))
}

func stringsTrimPrefix(s, pref string) string {
	if len(s) >= len(pref) && s[:len(pref)] == pref {
		return s[len(pref):]
	}
	return s
}

const fallbackHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>APKCheck Lab</title>
<style>
:root{--bg:#0b1220;--panel:#141c2b;--text:#e8eef7;--muted:#8b9bb4;--accent:#3d9cf0;--ok:#3dd68c;--bad:#f31260;--border:#243044}
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,system-ui;background:var(--bg);color:var(--text)}
header{padding:1rem 1.5rem;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.layout{display:grid;grid-template-columns:220px 1fr;min-height:calc(100vh - 56px)}
nav{background:var(--panel);border-right:1px solid var(--border);padding:1rem}
nav button{display:block;width:100%;text-align:left;margin:.25rem 0;background:transparent;border:1px solid var(--border);color:var(--text);padding:.5rem;border-radius:8px;cursor:pointer}
main{padding:1.25rem 1.5rem} .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1rem;margin-bottom:1rem}
input,button.primary{background:#0b1017;border:1px solid var(--border);color:var(--text);padding:.5rem .75rem;border-radius:8px}
button.primary{background:var(--accent);border:none;color:#041018;font-weight:600;cursor:pointer}
pre{background:#070b12;border:1px solid var(--border);border-radius:8px;padding:.75rem;max-height:280px;overflow:auto;font-size:.8rem}
.badge{font-size:.7rem;padding:.15rem .4rem;border-radius:4px;background:#222} .ok{color:var(--ok)} .bad{color:var(--bad)}
</style></head><body>
<header><strong>APKCheck Lab</strong><span id="health" class="badge">…</span></header>
<div class="layout"><nav>
<button onclick="loadArtifacts()">Artifacts</button>
<button onclick="showImport()">Import APK</button>
<button onclick="loadEvents()">Events</button>
<button onclick="proxyStatus()">Proxy</button>
</nav><main id="main"><div class="card"><h2>APK Laboratory</h2>
<p style="color:var(--muted)">Smali-backed rebuild · sign · validate · live observe. DEX/Smali remains ground truth.</p>
<p>Use CLI: <code>apkcheck lab import|rebuild|validate|serve</code></p>
</div></main></div>
<script>
const api=p=>fetch(p).then(r=>r.json());
const post=(p,b)=>fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json());
api('/api/health').then(h=>document.getElementById('health').textContent=h.ok?'connected':'down');
function loadArtifacts(){api('/api/artifacts').then(list=>{
  document.getElementById('main').innerHTML='<div class="card"><h2>Artifacts</h2><pre>'+JSON.stringify(list,null,2)+'</pre></div>';
})}
function showImport(){
  document.getElementById('main').innerHTML='<div class="card"><h2>Import APK</h2>'+
  '<input id="path" style="width:70%" placeholder="/absolute/path/app.apk"/> '+
  '<button class="primary" onclick="doImport()">Import</button><pre id="out"></pre></div>';
}
async function doImport(){const path=document.getElementById('path').value;const r=await post('/api/import',{path});document.getElementById('out').textContent=JSON.stringify(r,null,2)}
function loadEvents(){api('/api/events').then(e=>{document.getElementById('main').innerHTML='<div class="card"><h2>Events</h2><pre>'+JSON.stringify(e.slice(-50),null,2)+'</pre></div>'})}
function proxyStatus(){api('/api/proxy/status').then(s=>{document.getElementById('main').innerHTML='<div class="card"><h2>Proxy</h2><pre>'+JSON.stringify(s,null,2)+'</pre><button class="primary" onclick="post(\'/api/proxy/start\',{}).then(proxyStatus)">Start mitmproxy</button></div>'})}
const es=new EventSource('/api/events/stream');
es.onmessage=ev=>{/* live events available */};
</script></body></html>`
