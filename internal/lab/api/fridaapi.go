package api

import (
	"encoding/json"
	"net/http"

	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/frida"
)

func (s *Server) registerFridaRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/frida/status", s.handleFridaStatus)
	mux.HandleFunc("/api/frida/push", s.handleFridaPush)
	mux.HandleFunc("/api/frida/start-server", s.handleFridaStartServer)
	mux.HandleFunc("/api/frida/stop-server", s.handleFridaStopServer)
	mux.HandleFunc("/api/frida/ssl-unpin", s.handleFridaSSLUnpin)
	mux.HandleFunc("/api/frida/method-trace", s.handleFridaMethodTrace)
	mux.HandleFunc("/api/frida/dex-loader", s.handleFridaDexLoader)
	mux.HandleFunc("/api/frida/network-trace", s.handleFridaNetworkTrace)
}

func (s *Server) fridaMgr() *frida.Manager {
	return &frida.Manager{Bus: s.Bus}
}

// handleFridaStatus returns host Frida CLI + device frida-server status.
func (s *Server) handleFridaStatus(w http.ResponseWriter, r *http.Request) {
	serial := r.URL.Query().Get("serial")
	st := s.fridaMgr().Status(r.Context(), serial)
	writeJSON(w, 200, st)
}

// handleFridaPush pushes a frida-server binary from the workspace to the device.
//
// POST /api/frida/push  {"serial":"...", "host_path":"/data/lab/frida-server"}
func (s *Server) handleFridaPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		Serial   string `json:"serial"`
		HostPath string `json:"host_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.HostPath == "" {
		writeJSON(w, 400, map[string]string{"error": "host_path required"})
		return
	}
	if err := s.fridaMgr().PushServer(r.Context(), req.Serial, req.HostPath); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "pushed"})
}

// handleFridaStartServer starts frida-server on the device.
//
// POST /api/frida/start-server  {"serial":"..."}
func (s *Server) handleFridaStartServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	if err := s.fridaMgr().StartServer(r.Context(), req.Serial); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "started"})
}

// handleFridaStopServer kills frida-server on the device.
//
// POST /api/frida/stop-server  {"serial":"..."}
func (s *Server) handleFridaStopServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	if err := s.fridaMgr().StopServer(r.Context(), req.Serial); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "stopped"})
}

// hookRequest is the common shape for hook run requests.
type hookRequest struct {
	Serial        string `json:"serial"`
	Package       string `json:"package"`
	MethodPattern string `json:"method_pattern,omitempty"` // for method_trace
	TimeoutSec    int    `json:"timeout_sec,omitempty"`
}

func (s *Server) runFridaHook(w http.ResponseWriter, r *http.Request, hook frida.Hook) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req hookRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Package == "" {
		writeJSON(w, 400, map[string]string{"error": "package required"})
		return
	}
	if s.Bus != nil {
		s.Bus.Publish(events.Event{
			Type:    "FRIDA_HOOK_START",
			Message: "frida hook=" + string(hook) + " pkg=" + req.Package,
			Level:   "info",
		})
	}
	evs, err := s.fridaMgr().RunHook(r.Context(), frida.RunOptions{
		Serial:        req.Serial,
		Package:       req.Package,
		Hook:          hook,
		MethodPattern: req.MethodPattern,
		TimeoutSec:    req.TimeoutSec,
	})
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"hook": hook, "events": evs, "count": len(evs)})
}

func (s *Server) handleFridaSSLUnpin(w http.ResponseWriter, r *http.Request) {
	s.runFridaHook(w, r, frida.HookSSLUnpin)
}

func (s *Server) handleFridaMethodTrace(w http.ResponseWriter, r *http.Request) {
	s.runFridaHook(w, r, frida.HookMethodTrace)
}

func (s *Server) handleFridaDexLoader(w http.ResponseWriter, r *http.Request) {
	s.runFridaHook(w, r, frida.HookDexLoader)
}

func (s *Server) handleFridaNetworkTrace(w http.ResponseWriter, r *http.Request) {
	s.runFridaHook(w, r, frida.HookNetworkTrace)
}
