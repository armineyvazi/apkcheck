package proxy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Manager controls a local mitmdump process.
type Manager struct {
	WorkDir string
	Listen  string // e.g. :8080
	mu      sync.Mutex
	cmd     *exec.Cmd
	started time.Time
	logFile *os.File
}

// Status describes proxy state.
type Status struct {
	Available bool   `json:"available"`
	Running   bool   `json:"running"`
	Listen    string `json:"listen,omitempty"`
	CAPath    string `json:"ca_path,omitempty"`
	FlowPath  string `json:"flow_path,omitempty"`
	Note      string `json:"note,omitempty"`
	PID       int    `json:"pid,omitempty"`
}

// New creates a proxy manager.
func New(workDir, listen string) *Manager {
	if listen == "" {
		listen = ":8080"
	}
	return &Manager{WorkDir: workDir, Listen: listen}
}

func (m *Manager) mitmAvailable() bool {
	_, err := exec.LookPath("mitmdump")
	return err == nil
}

func (m *Manager) pidPath() string {
	return filepath.Join(m.WorkDir, "mitmdump.pid")
}

func (m *Manager) writePID(pid int) {
	if m.WorkDir == "" || pid <= 0 {
		return
	}
	_ = os.MkdirAll(m.WorkDir, 0o750)
	_ = os.WriteFile(m.pidPath(), []byte(strconv.Itoa(pid)+"\n"), 0o640)
}

func (m *Manager) clearPID() {
	_ = os.Remove(m.pidPath())
}

func (m *Manager) alivePID() int {
	m.mu.Lock()
	if m.cmd != nil && m.cmd.Process != nil && (m.cmd.ProcessState == nil || !m.cmd.ProcessState.Exited()) {
		pid := m.cmd.Process.Pid
		m.mu.Unlock()
		return pid
	}
	m.mu.Unlock()
	data, err := os.ReadFile(m.pidPath())
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return 0
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		m.clearPID()
		return 0
	}
	return pid
}

// Status returns current proxy status (works across processes via pid file).
func (m *Manager) Status() Status {
	st := Status{
		Available: m.mitmAvailable(),
		Listen:    m.Listen,
		Note:      "MITM is OFF by default. Enable only for APKs you are authorized to analyze. Android 7+ may require user CA / test image for HTTPS.",
	}
	if m.WorkDir != "" {
		st.CAPath = filepath.Join(m.WorkDir, "mitmproxy-ca-cert.pem")
		st.FlowPath = filepath.Join(m.WorkDir, "flows.mitm")
	}
	if pid := m.alivePID(); pid > 0 {
		st.Running = true
		st.PID = pid
	}
	return st
}

// Start launches mitmdump writing flows to WorkDir.
// Uses an independent process lifetime (not tied to the HTTP request context).
func (m *Manager) Start(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.mitmAvailable() {
		return fmt.Errorf("mitmdump not on PATH — brew install mitmproxy")
	}
	if m.cmd != nil && m.cmd.Process != nil && (m.cmd.ProcessState == nil || !m.cmd.ProcessState.Exited()) {
		return nil
	}
	// Already running from another process?
	if pid := func() int {
		data, err := os.ReadFile(m.pidPath())
		if err != nil {
			return 0
		}
		p, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		if p <= 0 {
			return 0
		}
		proc, err := os.FindProcess(p)
		if err != nil {
			return 0
		}
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return 0
		}
		return p
	}(); pid > 0 {
		return nil
	}
	if err := os.MkdirAll(m.WorkDir, 0o750); err != nil {
		return err
	}
	flow := filepath.Join(m.WorkDir, "flows.mitm")
	logf := filepath.Join(m.WorkDir, "mitm.log")
	jsonl := filepath.Join(m.WorkDir, "flows.jsonl")
	_ = os.Remove(jsonl) // fresh capture for this proxy session
	if m.logFile != nil {
		_ = m.logFile.Close()
		m.logFile = nil
	}
	logFile, err := os.OpenFile(logf, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	m.logFile = logFile
	args := []string{
		"-p", trimColon(m.Listen),
		"-w", flow,
		"--set", "confdir=" + m.WorkDir,
	}
	// Optional JSONL addon for Lab timeline (app / mitm filters).
	addonCandidates := []string{
		filepath.Join("configs", "mitm_jsonl_addon.py"),
		"/opt/apkcheck/configs/mitm_jsonl_addon.py",
	}
	for _, a := range addonCandidates {
		if st, err := os.Stat(a); err == nil && !st.IsDir() {
			args = append(args, "-s", a)
			break
		}
	}
	cmd := exec.Command("mitmdump", args...)
	cmd.Env = append(os.Environ(),
		"APKCHECK_FLOW_JSONL="+jsonl,
		"APKCHECK_PROXY_DIR="+m.WorkDir,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		m.logFile = nil
		return err
	}
	m.cmd = cmd
	m.started = time.Now().UTC()
	m.writePID(cmd.Process.Pid)
	go func() {
		_ = cmd.Wait()
		m.mu.Lock()
		if m.cmd == cmd {
			m.cmd = nil
			m.clearPID()
		}
		m.mu.Unlock()
	}()
	return nil
}

// Stop terminates mitmdump (in-process or via pid file).
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var err error
	if m.cmd != nil && m.cmd.Process != nil {
		err = m.cmd.Process.Kill()
		m.cmd = nil
	} else if data, rerr := os.ReadFile(m.pidPath()); rerr == nil {
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil && pid > 0 {
			if proc, ferr := os.FindProcess(pid); ferr == nil {
				err = proc.Kill()
			}
		}
	}
	if m.logFile != nil {
		_ = m.logFile.Close()
		m.logFile = nil
	}
	m.clearPID()
	return err
}

func trimColon(listen string) string {
	if len(listen) > 0 && listen[0] == ':' {
		return listen[1:]
	}
	return listen
}
