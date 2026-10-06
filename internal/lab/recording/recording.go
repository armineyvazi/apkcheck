// Package recording captures synchronized device screen video for Lab test runs (§35).
//
// Recording is a session component — not a standalone utility. Videos are stored
// with metadata and linked to a session.Run via recording_id.
package recording

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/session"
	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/adb"
	"github.com/armin/apkcheck/internal/runtime/screenshots"
)

// Profile presets control overhead vs fidelity.
type Profile string

const (
	ProfileLow      Profile = "low"
	ProfileBalanced Profile = "balanced"
	ProfileHigh     Profile = "high"
)

// DefaultMinCapture is how long screenrecord must run before Stop signals it.
// Short captures routinely produce stub MP4s (ftyp+free, no moov) that no player can open.
const DefaultMinCapture = 5 * time.Second

// MinPlayableBytes is a soft lower bound; real Android screenrecord output is far larger.
// Combined with moov-atom detection to reject 3KB "finalized" stubs.
const MinPlayableBytes int64 = 8 * 1024

// Options configures an Android recording.
type Options struct {
	Profile    Profile
	FPS        int
	BitRate    int           // bits/sec; 0 = profile default
	TimeLimit  int           // seconds per segment (adb max ~180)
	RemotePath string        // device path prefix (unused; segments use indexed names)
	MinCapture time.Duration // minimum wall time before Stop sends SIGINT; 0 = DefaultMinCapture
	ADBPath    string        // optional override (tests); empty = discover adb
}

func (o Options) resolved() Options {
	if o.Profile == "" {
		o.Profile = ProfileBalanced
	}
	switch o.Profile {
	case ProfileLow:
		if o.FPS == 0 {
			o.FPS = 10
		}
		if o.BitRate == 0 {
			o.BitRate = 1_000_000
		}
	case ProfileHigh:
		if o.FPS == 0 {
			o.FPS = 30
		}
		if o.BitRate == 0 {
			o.BitRate = 8_000_000
		}
	default:
		o.Profile = ProfileBalanced
		if o.FPS == 0 {
			o.FPS = 15
		}
		if o.BitRate == 0 {
			o.BitRate = 4_000_000
		}
	}
	if o.TimeLimit <= 0 {
		// Shorter segments finalize reliably on SIGINT-broken emulators (natural --time-limit).
		o.TimeLimit = 60
	}
	if o.TimeLimit > 180 {
		o.TimeLimit = 180
	}
	if o.RemotePath == "" {
		o.RemotePath = "/sdcard/apkcheck-rec.mp4"
	}
	if o.MinCapture <= 0 {
		o.MinCapture = DefaultMinCapture
	}
	return o
}

// Artifact is a finalized recording with metadata (never a bare orphan mp4).
type Artifact struct {
	ID            string    `json:"recording_id"`
	RunID         string    `json:"run_id"`
	RuntimeSerial string    `json:"runtime_id,omitempty"`
	ArtifactID    string    `json:"apk_id,omitempty"`
	ScenarioID    string    `json:"scenario_id,omitempty"`
	Title         string    `json:"title,omitempty"`     // human name (usually scenario name)
	FileName      string    `json:"file_name,omitempty"` // e.g. app-sc12-bg-attack.mp4
	Status        string    `json:"status"`              // recording|finalized|partial|failed
	Profile       Profile   `json:"profile"`
	FPS           int       `json:"fps"`
	BitRate       int       `json:"bitrate"`
	Codec         string    `json:"codec"`
	DurationMS    int64     `json:"duration_ms,omitempty"`
	SizeBytes     int64     `json:"size_bytes,omitempty"`
	Path          string    `json:"storage_location,omitempty"` // primary playable file
	SegmentsDir   string    `json:"segments_dir,omitempty"`
	SegmentCount  int       `json:"segment_count,omitempty"`
	ManifestPath  string    `json:"manifest_path,omitempty"`
	StartedAt     time.Time `json:"created_at"`
	EndedAt       time.Time `json:"ended_at,omitempty"`
	Note          string    `json:"note,omitempty"`
}

// Provider abstracts platform recording (§35.27).
type Provider interface {
	Start(ctx context.Context, serial string, opt Options) error
	Stop(ctx context.Context) (*Artifact, error)
	Status() Status
	CaptureScreenshot(ctx context.Context, name string) (string, error)
}

// Status is live recorder state.
type Status struct {
	Running bool   `json:"running"`
	Serial  string `json:"serial,omitempty"`
	Profile string `json:"profile,omitempty"`
	Note    string `json:"note,omitempty"`
}

// Manager owns recording artifacts under the lab workspace and binds them to sessions.
type Manager struct {
	Root     string
	Bus      *events.Bus
	Sessions *session.Manager

	mu   sync.Mutex
	live map[string]*androidRecorder // runID → recorder

	// testOpt merges into Start options (tests only; zero = defaults).
	testOpt Options
}

// NewManager creates a recording manager.
func NewManager(root string, bus *events.Bus, sessions *session.Manager) *Manager {
	_ = os.MkdirAll(filepath.Join(root, "recordings"), 0o750)
	return &Manager{Root: root, Bus: bus, Sessions: sessions, live: map[string]*androidRecorder{}}
}

// SetTestOptions overrides Start options (ADBPath, MinCapture, …) for tests.
func (m *Manager) SetTestOptions(opt Options) {
	m.mu.Lock()
	m.testOpt = opt
	m.mu.Unlock()
}

// Start begins device recording for a test run.
func (m *Manager) Start(ctx context.Context, run *session.Run, serial string, profile Profile) (*Artifact, error) {
	if run == nil {
		return nil, fmt.Errorf("run required")
	}
	if serial == "" {
		return nil, fmt.Errorf("device serial required to record")
	}
	m.mu.Lock()
	testOpt := m.testOpt
	m.mu.Unlock()

	opt := Options{Profile: profile}.resolved()
	if testOpt.ADBPath != "" {
		opt.ADBPath = testOpt.ADBPath
	}
	if testOpt.MinCapture > 0 {
		opt.MinCapture = testOpt.MinCapture
	}
	if testOpt.BitRate > 0 {
		opt.BitRate = testOpt.BitRate
	}
	if testOpt.TimeLimit > 0 {
		opt.TimeLimit = testOpt.TimeLimit
	}

	recID := lab.NewID("rec")
	dir := filepath.Join(m.Root, "recordings", recID)
	if err := os.MkdirAll(filepath.Join(dir, "segments"), 0o750); err != nil {
		return nil, err
	}
	art := &Artifact{
		ID: recID, RunID: run.ID, RuntimeSerial: serial,
		ArtifactID: run.ArtifactID, ScenarioID: run.ScenarioID,
		Status: "recording", Profile: opt.Profile, FPS: opt.FPS, BitRate: opt.BitRate,
		Codec: "H.264", SegmentsDir: filepath.Join(dir, "segments"),
		StartedAt: time.Now().UTC(), ManifestPath: filepath.Join(dir, "metadata.json"),
		Note: "adb screenrecord; segment time-limit ≤180s",
	}
	art.Title, art.FileName = recordingTitle(run)
	adbPath := opt.ADBPath
	if adbPath == "" {
		var err error
		adbPath, err = runner.LookPath("", "adb")
		if err != nil {
			return nil, err
		}
	}
	client := &adb.Client{Path: adbPath}
	linkRecording := func() {
		if m.Sessions != nil {
			_ = m.Sessions.SetRecording(run.ID, recID)
		}
	}
	if err := ensureScreenrecord(ctx, client, serial); err != nil {
		art.Status = "failed"
		art.Note = err.Error()
		_ = writeMeta(art)
		linkRecording() // still bind failed artifact so MCP/UI can show the note
		return art, err
	}
	rec := &androidRecorder{
		client: client, serial: serial, opt: opt, art: art, dir: dir,
		bus: m.Bus, sessions: m.Sessions,
	}
	if err := rec.start(ctx); err != nil {
		art.Status = "failed"
		art.Note = err.Error()
		_ = writeMeta(art)
		linkRecording()
		return art, err
	}
	m.mu.Lock()
	m.live[run.ID] = rec
	m.mu.Unlock()
	linkRecording()
	if m.Sessions != nil {
		_, _ = m.Sessions.AddEvent(run.ID, session.Event{
			Type: "RECORDING_STARTED", Source: "system", Category: "runtime",
			Message:  fmt.Sprintf("recording %s profile=%s", recID, opt.Profile),
			Metadata: map[string]any{"recording_id": recID, "fps": opt.FPS, "bitrate": opt.BitRate},
		})
	}
	_ = writeMeta(art)
	return art, nil
}

// Stop finalizes recording for a run (pulls segments, builds playlist metadata).
func (m *Manager) Stop(ctx context.Context, runID string) (*Artifact, error) {
	m.mu.Lock()
	rec, ok := m.live[runID]
	if ok {
		delete(m.live, runID)
	}
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no live recording for run %s", runID)
	}
	art, err := rec.stop(ctx)
	if art != nil {
		_ = writeMeta(art)
		if m.Sessions != nil {
			_, _ = m.Sessions.AddEvent(runID, session.Event{
				Type: "RECORDING_STOPPED", Source: "system", Category: "runtime",
				Message:  fmt.Sprintf("status=%s duration_ms=%d size=%d", art.Status, art.DurationMS, art.SizeBytes),
				Metadata: map[string]any{"recording_id": art.ID, "path": art.Path, "status": art.Status},
			})
		}
	}
	return art, err
}

// Status returns live recorder status for a run.
func (m *Manager) Status(runID string) Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.live[runID]
	if !ok {
		return Status{Running: false, Note: "not recording"}
	}
	return Status{Running: true, Serial: rec.serial, Profile: string(rec.opt.Profile)}
}

// Get loads recording metadata.
func (m *Manager) Get(id string) (*Artifact, error) {
	data, err := os.ReadFile(filepath.Join(m.Root, "recordings", id, "metadata.json"))
	if err != nil {
		return nil, err
	}
	var a Artifact
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// List returns recordings newest-first.
func (m *Manager) List() ([]*Artifact, error) {
	dir := filepath.Join(m.Root, "recordings")
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*Artifact{}, nil
		}
		return nil, err
	}
	out := make([]*Artifact, 0)
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		a, err := m.Get(e.Name())
		if err == nil {
			out = append(out, a)
		}
	}
	// newest first
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].StartedAt.After(out[i].StartedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// CaptureScreenshot stores a still under the run and timeline.
func (m *Manager) CaptureScreenshot(ctx context.Context, run *session.Run, serial, name string) (string, error) {
	if run == nil {
		return "", fmt.Errorf("run required")
	}
	if serial == "" {
		return "", fmt.Errorf("device serial required for screenshot")
	}
	adbPath, err := runner.LookPath("", "adb")
	if err != nil {
		return "", err
	}
	client := &adb.Client{Path: adbPath}
	dir := run.Dir
	if dir == "" {
		dir = filepath.Join(m.Root, "sessions", run.ID)
	}
	dir = filepath.Join(dir, "screenshots")
	if name == "" {
		name = fmt.Sprintf("shot-%d.png", time.Now().UnixNano())
	}
	path, err := screenshots.Capture(ctx, client, serial, dir, name)
	if err != nil {
		return "", err
	}
	if m.Sessions != nil {
		_, _ = m.Sessions.AddEvent(run.ID, session.Event{
			Type: "SCREENSHOT", Source: "system", Category: "screenshot",
			Message: path, Metadata: map[string]any{"path": path},
		})
	}
	return path, nil
}

func writeMeta(a *Artifact) error {
	if a == nil || a.ManifestPath == "" {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(a.ManifestPath), 0o750)
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.ManifestPath, data, 0o640)
}

func ensureScreenrecord(ctx context.Context, client *adb.Client, serial string) error {
	if err := waitDeviceReady(ctx, client, serial, 45*time.Second); err != nil {
		return err
	}
	// Prefer simple, separate probes — complex `sh -c` scripts are flaky across
	// adb/shell quoting and were reporting "missing binary" on working emulators.
	candidates := []struct {
		args []string
		ok   func(string) bool
	}{
		{[]string{"ls", "/system/bin/screenrecord"}, func(s string) bool {
			return strings.Contains(s, "screenrecord") && !strings.Contains(s, "No such")
		}},
		{[]string{"ls", "/system/xbin/screenrecord"}, func(s string) bool {
			return strings.Contains(s, "screenrecord") && !strings.Contains(s, "No such")
		}},
		{[]string{"command", "-v", "screenrecord"}, func(s string) bool {
			s = strings.TrimSpace(s)
			return s != "" && !strings.Contains(s, "not found")
		}},
		{[]string{"which", "screenrecord"}, func(s string) bool {
			s = strings.TrimSpace(s)
			return s != "" && !strings.Contains(s, "not found")
		}},
	}
	var lastErr error
	for _, c := range candidates {
		out, err := client.Shell(ctx, serial, c.args...)
		if err != nil {
			lastErr = err
			// Device may still be settling after boot.
			if strings.Contains(err.Error(), "offline") || strings.Contains(err.Error(), "not found") {
				_ = waitDeviceReady(ctx, client, serial, 15*time.Second)
			}
			continue
		}
		if c.ok(out) {
			return nil
		}
	}
	if lastErr != nil {
		return fmt.Errorf("screenrecord not available on device: %w", lastErr)
	}
	return fmt.Errorf("screenrecord not available on device (missing binary)")
}

// waitDeviceReady waits until adb reports the serial as online and boot_completed=1.
func waitDeviceReady(ctx context.Context, client *adb.Client, serial string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		boot, err := client.GetProp(ctx, serial, "sys.boot_completed")
		boot = strings.TrimSpace(boot)
		if err == nil && boot == "1" {
			return nil
		}
		if err != nil {
			last = err.Error()
		} else {
			last = "boot_completed=" + boot
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if last == "" {
		last = "device not ready"
	}
	return fmt.Errorf("device %s not ready for recording: %s", serial, last)
}

// androidRecorder uses adb shell screenrecord (segmented for long runs).
type androidRecorder struct {
	client   *adb.Client
	serial   string
	opt      Options
	art      *Artifact
	dir      string
	bus      *events.Bus
	sessions *session.Manager

	mu      sync.Mutex
	cmd     *exec.Cmd
	segIdx  int
	cancel  context.CancelFunc
	stopped bool
	done    chan struct{}
}

func (r *androidRecorder) start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done != nil {
		return fmt.Errorf("recorder already started")
	}
	ctx2, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		r.loop(ctx2)
	}()
	// Brief settle so the first screenrecord process is actually running.
	time.Sleep(150 * time.Millisecond)
	_ = ctx
	return nil
}

func (r *androidRecorder) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		r.mu.Lock()
		if r.stopped {
			r.mu.Unlock()
			return
		}
		r.segIdx++
		idx := r.segIdx
		r.mu.Unlock()

		remote := fmt.Sprintf("/sdcard/apkcheck-rec-%03d.mp4", idx)
		args := []string{
			"-s", r.serial,
			"shell", "screenrecord",
			"--time-limit", strconv.Itoa(r.opt.TimeLimit),
			"--bit-rate", strconv.Itoa(r.opt.BitRate),
			remote,
		}
		// Do NOT use CommandContext here: canceling the host adb process SIGKILLs
		// the shell and truncates the on-device MP4 before screenrecord can finalize.
		cmd := exec.Command(r.client.Path, args...)
		r.mu.Lock()
		r.cmd = cmd
		r.mu.Unlock()

		startErr := cmd.Start()
		if startErr != nil {
			r.mu.Lock()
			r.cmd = nil
			r.mu.Unlock()
			return
		}
		waitDone := make(chan error, 1)
		go func() { waitDone <- cmd.Wait() }()

		select {
		case <-waitDone:
		case <-ctx.Done():
			// Last resort: only kill host adb after Stop already tried SIGINT.
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			<-waitDone
		}

		r.mu.Lock()
		r.cmd = nil
		stopped := r.stopped
		r.mu.Unlock()

		if stopped {
			// stop() owns the final pull — avoid racing an empty pull + remote rm.
			return
		}

		// Natural segment rollover (time-limit): pull then remove remote only if usable.
		local := filepath.Join(r.art.SegmentsDir, fmt.Sprintf("segment-%03d.mp4", idx))
		if pullUsable(context.Background(), r.client, r.serial, remote, local) {
			_, _ = r.client.Shell(context.Background(), r.serial, "rm", "-f", remote)
		}

		if ctx.Err() != nil {
			return
		}
	}
}

func (r *androidRecorder) stop(ctx context.Context) (*Artifact, error) {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return r.art, nil
	}
	r.stopped = true
	cancel := r.cancel
	done := r.done
	started := r.art.StartedAt
	minCapture := r.opt.MinCapture
	timeLimit := r.opt.TimeLimit
	if timeLimit <= 0 {
		timeLimit = 60
	}
	r.mu.Unlock()

	// Android screenrecord needs a short window to emit a valid container.
	if wait := minCapture - time.Since(started); wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
		}
	}

	// Soft-stop: let the current --time-limit segment finish naturally.
	// SIGINT on many API 34 emulators yields truncated mdat with no moov.
	softWait := time.Duration(timeLimit)*time.Second + 15*time.Second
	if done != nil {
		select {
		case <-done:
		case <-time.After(softWait):
			// Last resort: SIGINT + kill host adb (may still be unplayable).
			sigCtx, sigCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, _ = r.client.Shell(sigCtx, r.serial, "pkill", "-2", "screenrecord")
			_, _ = r.client.Shell(sigCtx, r.serial, "killall", "-2", "screenrecord")
			sigCancel()
			if cancel != nil {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				r.mu.Lock()
				cmd := r.cmd
				r.mu.Unlock()
				if cmd != nil && cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
				select {
				case <-done:
				case <-time.After(2 * time.Second):
				}
			}
		}
	}

	r.mu.Lock()
	idx := r.segIdx
	r.mu.Unlock()
	if idx > 0 {
		remote := fmt.Sprintf("/sdcard/apkcheck-rec-%03d.mp4", idx)
		local := filepath.Join(r.art.SegmentsDir, fmt.Sprintf("segment-%03d.mp4", idx))
		waitRemoteStable(context.Background(), r.client, r.serial, remote, 15*time.Second)
		if pullPlayable(context.Background(), r.client, r.serial, remote, local) {
			_, _ = r.client.Shell(context.Background(), r.serial, "rm", "-f", remote)
		} else if pullUsable(context.Background(), r.client, r.serial, remote, local) {
			_, _ = r.client.Shell(context.Background(), r.serial, "rm", "-f", remote)
		}
	}
	if cancel != nil {
		cancel()
	}

	return r.finalizeArtifact(), nil
}

func (r *androidRecorder) finalizeArtifact() *Artifact {
	art := r.art
	art.EndedAt = time.Now().UTC()
	art.DurationMS = art.EndedAt.Sub(art.StartedAt).Milliseconds()

	segs, _ := filepath.Glob(filepath.Join(art.SegmentsDir, "segment-*.mp4"))
	sort.Strings(segs)
	var usable []string
	var total int64
	for _, s := range segs {
		st, err := os.Stat(s)
		if err != nil || st.Size() == 0 {
			_ = os.Remove(s)
			continue
		}
		usable = append(usable, s)
		total += st.Size()
	}
	// Prefer playable segments only for the published primary.
	var playableSegs []string
	for _, s := range usable {
		if MP4Playable(s) {
			playableSegs = append(playableSegs, s)
		}
	}
	art.SegmentCount = len(usable)
	art.SizeBytes = total
	if len(playableSegs) > 0 {
		primary := playableSegs[0]
		dest := filepath.Join(r.dir, "recording.mp4")
		if len(playableSegs) > 1 {
			_ = writePlaylist(r.dir, playableSegs)
			if concatErr := concatMP4(playableSegs, dest); concatErr == nil && MP4Playable(dest) {
				primary = dest
				art.Note = fmt.Sprintf("adb screenrecord · %d segments concatenated", len(playableSegs))
			} else {
				// Fall back to longest playable segment (usually covers later attack window).
				primary = longestFile(playableSegs)
				_ = copyFile(primary, dest)
				art.Note = fmt.Sprintf("adb screenrecord · %d playable segments (concat unavailable; using longest)", len(playableSegs))
			}
		} else {
			_ = copyFile(primary, dest)
			primary = dest
			art.Note = "adb screenrecord"
		}
		art.Path = dest
		if art.FileName != "" && art.FileName != "recording.mp4" {
			named := filepath.Join(r.dir, art.FileName)
			if err := copyFile(art.Path, named); err == nil {
				art.Path = named
			}
		}
		if art.Title != "" {
			if art.Note == "adb screenrecord" || strings.HasPrefix(art.Note, "adb screenrecord ·") {
				art.Note = strings.TrimSpace(art.Note + " · " + art.Title)
			}
		}
		if MP4Playable(art.Path) || MP4Playable(dest) {
			if !MP4Playable(art.Path) {
				art.Path = dest
			}
			art.Status = "finalized"
			if st, err := os.Stat(art.Path); err == nil {
				art.SizeBytes = st.Size()
			}
		} else {
			art.Status = "partial"
			art.Note = "recording pulled but not playable (missing moov atom / truncated MP4) — keep recorder on ≥60s and stop gracefully"
		}
	} else if len(usable) > 0 {
		art.Status = "partial"
		art.Note = "recording pulled but not playable (missing moov atom / truncated MP4) — keep recorder on ≥60s and stop gracefully"
		art.Path = usable[0]
	} else {
		art.Status = "partial"
		switch {
		case art.DurationMS < int64(DefaultMinCapture/time.Millisecond):
			art.Note = "recording stopped without usable video — capture window too short for screenrecord to finalize"
		default:
			art.Note = "recording stopped without usable video — finalize/pull failed (device offline, permission, or screenrecord interrupted)"
		}
	}
	return art
}

// waitRemoteStable polls remote size until it stops changing (or timeout).
func waitRemoteStable(ctx context.Context, client *adb.Client, serial, remote string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	var last int64 = -1
	stable := 0
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return
		}
		sz := remoteSize(ctx, client, serial, remote)
		if sz > 0 && sz == last {
			stable++
			if stable >= 3 {
				return
			}
		} else {
			stable = 0
			last = sz
		}
		time.Sleep(400 * time.Millisecond)
	}
}

// pullPlayable pulls until local MP4 has a moov atom (or timeout).
func pullPlayable(ctx context.Context, client *adb.Client, serial, remote, local string) bool {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if pullUsable(ctx, client, serial, remote, local) && MP4Playable(local) {
			return true
		}
		_ = os.Remove(local)
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// pullUsable pulls remote→local and returns true only when local is non-empty.
// Retries briefly because screenrecord may still be flushing after SIGINT.
func pullUsable(ctx context.Context, client *adb.Client, serial, remote, local string) bool {
	deadline := time.Now().Add(12 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		// Prefer pulling only when remote looks non-empty.
		if sz := remoteSize(ctx, client, serial, remote); sz == 0 && attempt < 3 {
			time.Sleep(250 * time.Millisecond)
			continue
		}
		pullCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		_, _ = client.SerialRun(pullCtx, serial, "pull", remote, local)
		cancel()
		if st, err := os.Stat(local); err == nil && st.Size() > 0 {
			return true
		}
		_ = os.Remove(local)
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func remoteSize(ctx context.Context, client *adb.Client, serial, remote string) int64 {
	out, err := client.Shell(ctx, serial, "sh", "-c", fmt.Sprintf("stat -c %%s %q 2>/dev/null || wc -c < %q", remote, remote))
	if err != nil {
		return 0
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return 0
	}
	// wc may include trailing junk; take first field.
	if i := strings.IndexAny(out, " \n\t"); i >= 0 {
		out = out[:i]
	}
	n, err := strconv.ParseInt(out, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func writePlaylist(dir string, segs []string) error {
	names := make([]string, 0, len(segs))
	for _, s := range segs {
		names = append(names, filepath.Base(s))
	}
	data, _ := json.MarshalIndent(map[string]any{"segments": names}, "", "  ")
	return os.WriteFile(filepath.Join(dir, "playlist.json"), data, 0o640)
}

func copyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0o640)
}

func longestFile(paths []string) string {
	var best string
	var bestSize int64
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st.Size() >= bestSize {
			bestSize = st.Size()
			best = p
		}
	}
	if best == "" && len(paths) > 0 {
		return paths[0]
	}
	return best
}

// concatMP4 joins playable segments with ffmpeg stream-copy when available.
func concatMP4(segs []string, dest string) error {
	if len(segs) == 0 {
		return fmt.Errorf("no segments")
	}
	if len(segs) == 1 {
		return copyFile(segs[0], dest)
	}
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		return err
	}
	list := dest + ".ffconcat.txt"
	var b strings.Builder
	b.WriteString("ffconcat version 1.0\n")
	for _, s := range segs {
		abs, _ := filepath.Abs(s)
		b.WriteString("file '" + strings.ReplaceAll(abs, "'", "'\\''") + "'\n")
	}
	if err := os.WriteFile(list, []byte(b.String()), 0o640); err != nil {
		return err
	}
	defer os.Remove(list)
	cmd := exec.Command(ffmpeg, "-y", "-f", "concat", "-safe", "0", "-i", list, "-c", "copy", dest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ffmpeg concat: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// FileURLPath returns a lab-relative path suitable for /api/recordings/<id>/media.
func FileURLPath(recID string) string {
	return "/api/recordings/" + recID + "/media"
}

func recordingTitle(run *session.Run) (title, fileName string) {
	if run == nil {
		return "", "recording.mp4"
	}
	title = strings.TrimSpace(run.ScenarioID)
	if run.Meta != nil {
		if n := strings.TrimSpace(run.Meta["scenario_name"]); n != "" {
			title = n
		} else if n := strings.TrimSpace(run.Meta["title"]); n != "" {
			title = n
		}
	}
	if title == "" {
		title = string(run.Kind)
		if title == "" {
			title = run.ID
		}
	}
	slug := slugifyName(title)
	if slug == "" {
		slug = "recording"
	}
	return title, slug + ".mp4"
}

func slugifyName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == ' ' || r == '_' || r == '-' || r == '.' || r == '·':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

// ParseProfile maps string to Profile.
func ParseProfile(s string) Profile {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return ProfileLow
	case "high":
		return ProfileHigh
	default:
		return ProfileBalanced
	}
}

// HasPlayableMedia reports whether an artifact has a browser-playable primary MP4
// (non-empty, has a moov atom — not an Android screenrecord stub).
func HasPlayableMedia(art *Artifact) bool {
	return ResolvePlayablePath(art, "") != ""
}

// ResolvePlayablePath returns the first browser-playable MP4 path for art.
// workspaceRoot is optional; when set, also checks recordings/<id>/ under the
// workspace (needed when metadata stores a host absolute path that differs
// inside Docker).
func ResolvePlayablePath(art *Artifact, workspaceRoot string) string {
	if art == nil {
		return ""
	}
	candidates := []string{art.Path}
	if workspaceRoot != "" && art.ID != "" {
		candidates = append(candidates,
			filepath.Join(workspaceRoot, "recordings", art.ID, "recording.mp4"),
		)
		segDirs := []string{}
		if art.SegmentsDir != "" {
			segDirs = append(segDirs, art.SegmentsDir)
		}
		segDirs = append(segDirs, filepath.Join(workspaceRoot, "recordings", art.ID, "segments"))
		for _, sd := range segDirs {
			if segs, _ := filepath.Glob(filepath.Join(sd, "segment-*.mp4")); len(segs) > 0 {
				sort.Strings(segs)
				candidates = append(candidates, segs...)
			}
		}
	}
	for _, c := range candidates {
		if MP4Playable(c) {
			return c
		}
	}
	return ""
}

// MP4Playable reports whether path looks like a finalized ISO-BMFF file with a moov box.
func MP4Playable(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() < MinPlayableBytes {
		return false
	}
	return mp4HasMoov(path)
}

// mp4HasMoov walks top-level boxes until it finds moov (or EOF / corrupt size).
func mp4HasMoov(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(f, hdr[:]); err != nil {
			return false
		}
		size := uint64(binary.BigEndian.Uint32(hdr[0:4]))
		typ := string(hdr[4:8])
		headerLen := uint64(8)
		if size == 1 {
			var ext [8]byte
			if _, err := io.ReadFull(f, ext[:]); err != nil {
				return false
			}
			size = binary.BigEndian.Uint64(ext[:])
			headerLen = 16
		}
		if size != 0 && size < headerLen {
			return false
		}
		if typ == "moov" {
			return true
		}
		if size == 0 {
			// extends to EOF — not moov
			return false
		}
		skip := int64(size - headerLen)
		if skip > 0 {
			if _, err := f.Seek(skip, io.SeekCurrent); err != nil {
				return false
			}
		}
	}
}
