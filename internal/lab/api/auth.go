package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/armin/apkcheck/internal/lab/authgate"
)

func (s *Server) auth() *authgate.Manager {
	if s.Auth == nil {
		root := "./lab-data"
		if s.Store != nil {
			root = s.Store.Root
		}
		s.Auth = authgate.New(root, s.Bus)
	}
	return s.Auth
}

func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/auth/pending", s.handleAuthPending)
	mux.HandleFunc("/api/auth/submit", s.handleAuthSubmit)
	mux.HandleFunc("/api/auth/cancel", s.handleAuthCancel)
}

func (s *Server) handleAuthPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]string{"error": "GET"})
		return
	}
	runID := r.URL.Query().Get("run_id")
	list := s.auth().Pending()
	if runID != "" {
		list = s.auth().PendingFor(runID)
	}
	if list == nil {
		list = []authgate.Prompt{}
	}
	writeJSON(w, 200, map[string]any{"pending": list, "count": len(list)})
}

func (s *Server) handleAuthSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		RunID string `json:"run_id"`
		Kind  string `json:"kind"`
		Value string `json:"value"`
		Phone string `json:"phone"`
		OTP   string `json:"otp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if req.RunID == "" {
		writeJSON(w, 400, map[string]string{"error": "run_id required"})
		return
	}
	// Convenience: phone/otp fields without kind.
	if req.Kind == "" {
		switch {
		case strings.TrimSpace(req.Phone) != "":
			req.Kind = "phone"
			req.Value = req.Phone
		case strings.TrimSpace(req.OTP) != "":
			req.Kind = "otp"
			req.Value = req.OTP
		}
	}
	p, err := s.auth().Submit(req.RunID, authgate.NormalizeKind(req.Kind), req.Value)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	// Never echo the secret back.
	p.Value = ""
	writeJSON(w, 200, map[string]any{"ok": true, "prompt": p})
}

func (s *Server) handleAuthCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		RunID string `json:"run_id"`
		Kind  string `json:"kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	if req.RunID == "" || req.Kind == "" {
		writeJSON(w, 400, map[string]string{"error": "run_id and kind required"})
		return
	}
	ok := s.auth().Cancel(req.RunID, authgate.NormalizeKind(req.Kind))
	writeJSON(w, 200, map[string]any{"ok": ok, "run_id": req.RunID, "kind": req.Kind})
}
