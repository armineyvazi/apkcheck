package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/lab/runtimes"
	"github.com/armin/apkcheck/internal/runtime/adb"
	"github.com/armin/apkcheck/internal/runtime/env"
)

func (s *Server) registerRuntimeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/runtimes", s.handleRuntimes)
	mux.HandleFunc("/api/runtimes/start", s.handleRuntimeStart)
	mux.HandleFunc("/api/runtimes/stop", s.handleRuntimeStop)
	mux.HandleFunc("/api/runtimes/stop-all", s.handleRuntimeStopAll)
	mux.HandleFunc("/api/runtimes/restart", s.handleRuntimeRestart)
	mux.HandleFunc("/api/runtimes/screen", s.handleRuntimeScreen)
	mux.HandleFunc("/api/runtimes/screen/stream", s.handleRuntimeScreenStream)
}

func (s *Server) runtimeMgr() *runtimes.Manager {
	return &runtimes.Manager{Bus: s.Bus}
}

func (s *Server) handleRuntimes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := detachedTimeout(30 * time.Second)
	defer cancel()
	st, err := s.runtimeMgr().Snapshot(ctx)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) handleRuntimeStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		AVD        string `json:"avd"`
		ColdBoot   bool   `json:"cold_boot"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	to := time.Duration(req.TimeoutSec) * time.Second
	if to <= 0 {
		to = 10 * time.Minute
	}
	// Detached from request: browser refresh must not kill emulator boot.
	ctx, cancel := detachedTimeout(to + time.Minute)
	defer cancel()
	serial, err := s.runtimeMgr().Start(ctx, req.AVD, req.ColdBoot, to)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	avd := req.AVD
	if avd == "" {
		avd = "Pixel_8_API_34"
	}
	writeJSON(w, 200, map[string]any{"ok": true, "serial": serial, "avd": avd})
}

func (s *Server) handleRuntimeStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		Serial string `json:"serial"`
		AVD    string `json:"avd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "json required"})
		return
	}
	if req.AVD == "(unknown AVD)" {
		req.AVD = ""
	}
	if req.Serial == "" && req.AVD == "" {
		writeJSON(w, 400, map[string]string{"error": "serial or avd required"})
		return
	}
	ctx, cancel := detachedTimeout(2 * time.Minute)
	defer cancel()
	if err := s.runtimeMgr().Stop(ctx, req.Serial, req.AVD); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleRuntimeStopAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	ctx, cancel := detachedTimeout(2 * time.Minute)
	defer cancel()
	stopped, err := s.runtimeMgr().StopAll(ctx)
	if stopped == nil {
		stopped = []string{}
	}
	if err != nil && len(stopped) == 0 {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "stopped": stopped})
}

func (s *Server) handleRuntimeRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST"})
		return
	}
	var req struct {
		AVD        string `json:"avd"`
		ColdBoot   bool   `json:"cold_boot"`
		TimeoutSec int    `json:"timeout_sec"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.AVD == "" || req.AVD == "(unknown AVD)" {
		writeJSON(w, 400, map[string]string{"error": "valid avd name required (unknown AVD rows: stop by serial)"})
		return
	}
	to := time.Duration(req.TimeoutSec) * time.Second
	if to <= 0 {
		to = 10 * time.Minute
	}
	ctx, cancel := detachedTimeout(to + time.Minute)
	defer cancel()
	serial, err := s.runtimeMgr().Restart(ctx, req.AVD, req.ColdBoot, to)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "serial": serial, "avd": req.AVD})
}

func (s *Server) resolveScreenSerial(r *http.Request) (string, error) {
	serial := strings.TrimSpace(r.URL.Query().Get("serial"))
	if serial != "" {
		return serial, nil
	}
	ctx, cancel := detachedTimeout(15 * time.Second)
	defer cancel()
	st, err := s.runtimeMgr().Snapshot(ctx)
	if err != nil {
		return "", err
	}
	for _, inst := range st.Instances {
		if inst.Serial == "" {
			continue
		}
		if inst.Kind == "emulator" && (inst.Status == "running" || inst.Status == "device") {
			return inst.Serial, nil
		}
		if inst.Kind == "device" && inst.Status == "device" {
			return inst.Serial, nil
		}
	}
	return "", fmt.Errorf("no running emulator/device — start AVD or pass ?serial=")
}

func adbPath() (string, error) {
	if client, err := adb.New(env.Discover()); err == nil && client.Path != "" {
		return client.Path, nil
	}
	p, err := exec.LookPath("adb")
	if err != nil {
		return "", fmt.Errorf("adb not found")
	}
	return p, nil
}

// adbRemoteArgs returns the base ADB flags for remote-host routing.
// Set APKCHECK_ADB_HOST=<host>[:<port>] to proxy all screencap / shell calls
// through a remote ADB server (e.g. the Linux Lab laptop running KVM).
// If the env var is unset, plain local ADB is used.
func adbRemoteArgs() []string {
	host := strings.TrimSpace(os.Getenv("APKCHECK_ADB_HOST"))
	if host == "" {
		return nil
	}
	if strings.Contains(host, ":") {
		parts := strings.SplitN(host, ":", 2)
		return []string{"-H", parts[0], "-P", parts[1]}
	}
	return []string{"-H", host}
}

func captureScreenPNG(ctx context.Context, serial string) ([]byte, error) {
	path, err := adbPath()
	if err != nil {
		return nil, err
	}
	args := append(adbRemoteArgs(), "-s", serial, "exec-out", "screencap", "-p")
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("screencap: %w", err)
	}
	if len(out) < 8 || out[0] != 0x89 || string(out[1:4]) != "PNG" {
		return nil, fmt.Errorf("screencap: not a PNG (%d bytes)", len(out))
	}
	return out, nil
}

// GET /api/runtimes/screen?serial=emulator-5554 — single PNG frame for Lab UI live preview.
func (s *Server) handleRuntimeScreen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]string{"error": "GET"})
		return
	}
	serial, err := s.resolveScreenSerial(r)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := detachedTimeout(8 * time.Second)
	defer cancel()
	png, err := captureScreenPNG(ctx, serial)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error(), "serial": serial})
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("X-Device-Serial", serial)
	_, _ = w.Write(png)
}

// GET /api/runtimes/screen/stream?serial=… — multipart MJPEG-like PNG stream for live UI.
func (s *Server) handleRuntimeScreenStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]string{"error": "GET"})
		return
	}
	serial, err := s.resolveScreenSerial(r)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 500, map[string]string{"error": "stream unsupported"})
		return
	}
	const boundary = "apkcheckframe"
	w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary="+boundary)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Device-Serial", serial)
	w.WriteHeader(200)
	flusher.Flush()

	ticker := time.NewTicker(450 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
			png, err := captureScreenPNG(ctx, serial)
			cancel()
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "--%s\r\nContent-Type: image/png\r\nContent-Length: %d\r\n\r\n", boundary, len(png))
			if _, err := w.Write(png); err != nil {
				return
			}
			_, _ = w.Write([]byte("\r\n"))
			flusher.Flush()
		}
	}
}
