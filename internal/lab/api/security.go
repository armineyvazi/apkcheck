package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/armin/apkcheck/internal/lab/security"
)

func (s *Server) registerSecurityRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/security/catalog", s.handleSecCatalog)
	mux.HandleFunc("/api/security/presets", s.handleSecPresets)
	mux.HandleFunc("/api/security/categories", s.handleSecCategories)
	mux.HandleFunc("/api/security/run", s.handleSecRun)
	mux.HandleFunc("/api/security/preset", s.handleSecPresetRun)
	mux.HandleFunc("/api/security/matrix", s.handleSecMatrix)
	mux.HandleFunc("/api/security/observations", s.handleSecObservations)
	mux.HandleFunc("/api/security/runs", s.handleSecRuns)
	mux.HandleFunc("/api/security/manifest", s.handleSecManifest)
	mux.HandleFunc("/api/security/export", s.handleSecExport)
	mux.HandleFunc("/api/security/harness", s.handleSecHarness)
	mux.HandleFunc("/api/commands", s.handleCommands)
}

func (s *Server) secEngine() *security.Engine {
	if s.Security == nil {
		root := "./lab-data"
		if s.Store != nil {
			root = s.Store.Root
		}
		s.Security = &security.Engine{
			Store: s.Store,
			Sec:   &security.Store{Root: root, Bus: s.Bus},
			Bus:   s.Bus,
		}
	}
	return s.Security
}

func (s *Server) handleSecCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, security.Catalog())
}

func (s *Server) handleSecPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, security.Presets())
}

func (s *Server) handleSecCategories(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, security.Categories())
}

func (s *Server) handleSecRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		ArtifactID string `json:"artifact_id"`
		TemplateID string `json:"template_id"`
		Serial     string `json:"serial"`
		Emulator   string `json:"emulator"`
		Package    string `json:"package"`
		DurationSec int   `json:"duration_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ArtifactID == "" || req.TemplateID == "" {
		writeJSON(w, 400, map[string]string{"error": "artifact_id and template_id required"})
		return
	}
	req.Serial = security.ResolveDeviceSerial(r.Context(), req.Serial, req.Emulator)
	opt := security.RunOptions{
		ArtifactID: req.ArtifactID, TemplateID: req.TemplateID,
		Serial: req.Serial, Package: req.Package,
	}
	if req.DurationSec > 0 {
		opt.Duration = time.Duration(req.DurationSec) * time.Second
	}
	ctx, cancel := detachedTimeout(30 * time.Minute)
	defer cancel()
	rep, err := s.secEngine().Run(ctx, opt)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error(), "report": rep})
		return
	}
	writeJSON(w, 200, rep)
}

func (s *Server) handleSecPresetRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		ArtifactID string `json:"artifact_id"`
		PresetID   string `json:"preset_id"`
		Serial     string `json:"serial"`
		Emulator   string `json:"emulator"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ArtifactID == "" || req.PresetID == "" {
		writeJSON(w, 400, map[string]string{"error": "artifact_id and preset_id required"})
		return
	}
	req.Serial = security.ResolveDeviceSerial(r.Context(), req.Serial, req.Emulator)
	ctx, cancel := detachedTimeout(60 * time.Minute)
	defer cancel()
	reps, err := s.secEngine().RunPreset(ctx, req.PresetID, security.RunOptions{
		ArtifactID: req.ArtifactID, Serial: req.Serial,
	})
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error(), "reports": reps})
		return
	}
	writeJSON(w, 200, reps)
}

func (s *Server) handleSecMatrix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		ArtifactIDs []string `json:"artifact_ids"`
		TemplateIDs []string `json:"template_ids"`
		Serial      string   `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.ArtifactIDs) == 0 || len(req.TemplateIDs) == 0 {
		writeJSON(w, 400, map[string]string{"error": "artifact_ids and template_ids required"})
		return
	}
	if req.Serial == "" {
		req.Serial = security.DiscoverDefaultSerial(r.Context())
	}
	ctx, cancel := detachedTimeout(90 * time.Minute)
	defer cancel()
	m, err := s.secEngine().BuildMatrix(ctx, req.ArtifactIDs, req.TemplateIDs, req.Serial)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, m)
}

func (s *Server) handleSecObservations(w http.ResponseWriter, r *http.Request) {
	list, err := s.secEngine().Sec.ListObservations()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if list == nil {
		list = []*security.Observation{}
	}
	writeJSON(w, 200, list)
}

func (s *Server) handleSecRuns(w http.ResponseWriter, r *http.Request) {
	list, err := s.secEngine().Sec.ListRuns()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if list == nil {
		list = []*security.RunReport{}
	}
	writeJSON(w, 200, list)
}

func (s *Server) handleSecManifest(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("artifact_id")
	if id == "" && r.Method == http.MethodPost {
		var req struct {
			ArtifactID string `json:"artifact_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		id = req.ArtifactID
	}
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "artifact_id required"})
		return
	}
	art, err := s.Store.Get(id)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	rev, err := security.ReviewManifest(art)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, rev)
}

func (s *Server) handleSecExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		ObservationID string `json:"observation_id"`
		Format        string `json:"format"` // json|markdown|html|zip
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ObservationID == "" {
		writeJSON(w, 400, map[string]string{"error": "observation_id required"})
		return
	}
	o, err := s.secEngine().Sec.GetObservation(req.ObservationID)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	format := security.ExportFormat(req.Format)
	if format == "" {
		format = security.ExportMD
	}
	ext := map[security.ExportFormat]string{
		security.ExportJSON: ".json", security.ExportMD: ".md",
		security.ExportHTML: ".html", security.ExportZIP: ".zip",
	}[format]
	outDir := filepath.Join(s.Store.Root, "exports")
	_ = os.MkdirAll(outDir, 0o750)
	out := filepath.Join(outDir, req.ObservationID+ext)
	if err := security.ExportObservation(o, format, out); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"path": out, "format": format})
}

func (s *Server) handleSecHarness(w http.ResponseWriter, r *http.Request) {
	root := s.Store.Root
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, security.HarnessStatus(root))
	case http.MethodPost:
		var req struct {
			Action string `json:"action"` // seed|build|status
			Serial string `json:"serial"`
			Source string `json:"source"` // path to testdata harness
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Action {
		case "seed":
			src := req.Source
			if src == "" {
				for _, cand := range []string{"testdata/lab/harness", filepath.Join("..", "testdata", "lab", "harness")} {
					if st, err := os.Stat(cand); err == nil && st.IsDir() {
						src = cand
						break
					}
				}
			}
			if err := security.SeedHarnessProject(root, src); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, security.HarnessStatus(root))
		case "build":
			// seed then ensure
			_ = security.SeedHarnessProject(root, "testdata/lab/harness")
			note, err := security.EnsureHarness(r.Context(), root, nil, "")
			if err != nil {
				writeJSON(w, 500, map[string]any{"error": err.Error(), "note": note})
				return
			}
			writeJSON(w, 200, map[string]any{"note": note, "status": security.HarnessStatus(root)})
		default:
			writeJSON(w, 200, security.HarnessStatus(root))
		}
	default:
		writeJSON(w, 405, map[string]string{"error": "method"})
	}
}

// handleCommands powers the UI command palette (CLI↔UI parity map).
func (s *Server) handleCommands(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, []map[string]string{
		{"id": "import", "title": "Import APK", "cli": "apkcheck lab import <apk>", "api": "POST /api/import"},
		{"id": "decompile", "title": "Decompile APK", "cli": "apkcheck lab decompile <id>", "api": "POST /api/decompile"},
		{"id": "build", "title": "Build Project", "cli": "apkcheck lab build <id>", "api": "POST /api/build"},
		{"id": "sign", "title": "Sign APK", "cli": "apkcheck lab sign <id>", "api": "POST /api/sign"},
		{"id": "rebuild", "title": "Full Rebuild", "cli": "apkcheck lab rebuild <id>", "api": "POST /api/rebuild"},
		{"id": "validate", "title": "Validate Run", "cli": "apkcheck lab validate <id>", "api": "POST /api/validate"},
		{"id": "compare", "title": "Compare APKs", "cli": "apkcheck lab compare <a> <b>", "api": "POST /api/compare"},
		{"id": "proxy-start", "title": "Start Proxy", "cli": "POST /api/proxy/start", "api": "POST /api/proxy/start"},
		{"id": "proxy-stop", "title": "Stop Proxy", "cli": "POST /api/proxy/stop", "api": "POST /api/proxy/stop"},
		{"id": "certs", "title": "Certificate Status", "cli": "GET /api/certs", "api": "GET /api/certs"},
		{"id": "sec-exported", "title": "Run Exported Components Audit", "cli": "apkcheck lab security run exported-components", "api": "POST /api/security/run"},
		{"id": "sec-background", "title": "Run Background Behavior Audit", "cli": "apkcheck lab security run background-behavior", "api": "POST /api/security/run"},
		{"id": "sec-deeplink", "title": "Run Deep Link Audit", "cli": "apkcheck lab security run deep-link-audit", "api": "POST /api/security/run"},
		{"id": "sec-network", "title": "Run Network Audit", "cli": "apkcheck lab security run network-audit", "api": "POST /api/security/run"},
		{"id": "sec-quick", "title": "Quick Android Security Audit", "cli": "apkcheck lab security preset quick-android-security", "api": "POST /api/security/preset"},
		{"id": "manifest", "title": "Manifest Security Panel", "cli": "apkcheck lab security manifest", "api": "GET /api/security/manifest"},
		{"id": "observations", "title": "Open Observations", "cli": "apkcheck lab security observations", "api": "GET /api/security/observations"},
		{"id": "export-evidence", "title": "Export Evidence", "cli": "apkcheck lab security export", "api": "POST /api/security/export"},
		{"id": "harness", "title": "Test Harness Status", "cli": "apkcheck lab security harness", "api": "GET /api/security/harness"},
		{"id": "runtime-list", "title": "List Runtimes / Devices", "cli": "apkcheck lab runtime list", "api": "GET /api/runtimes"},
		{"id": "runtime-start", "title": "Start Emulator", "cli": "apkcheck lab runtime start --avd Pixel_8_API_34", "api": "POST /api/runtimes/start"},
		{"id": "runtime-stop", "title": "Stop Emulator", "cli": "apkcheck lab runtime stop --avd Pixel_8_API_34", "api": "POST /api/runtimes/stop"},
		{"id": "runtime-stop-all", "title": "Stop All Emulators", "cli": "apkcheck lab runtime stop --all", "api": "POST /api/runtimes/stop-all"},
		{"id": "runtime-restart", "title": "Restart Emulator", "cli": "apkcheck lab runtime restart --avd Pixel_8_API_34", "api": "POST /api/runtimes/restart"},
		{"id": "runs", "title": "Open Test Runs / Recordings", "cli": "GET /api/sessions", "api": "GET /api/sessions"},
		{"id": "events", "title": "Open Live Events", "cli": "GET /api/events", "api": "GET /api/events"},
	})
}
