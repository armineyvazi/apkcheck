package recording_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/recording"
	"github.com/armin/apkcheck/internal/lab/session"
)

func emulatorSerial(t *testing.T) string {
	t.Helper()
	if os.Getenv("APKCHECK_EMU_RECORD") == "0" {
		t.Skip("APKCHECK_EMU_RECORD=0")
	}
	out, err := exec.Command("adb", "devices").CombinedOutput()
	if err != nil {
		t.Skipf("adb unavailable: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.HasPrefix(fields[0], "emulator-") && fields[1] == "device" {
			return fields[0]
		}
	}
	t.Skip("no booted emulator (adb devices)")
	return ""
}

// TestEmulatorRecordingE2E exercises the real adb screenrecord path end-to-end.
// Requires a running emulator with /system/bin/screenrecord.
func TestEmulatorRecordingE2E(t *testing.T) {
	serial := emulatorSerial(t)

	// Confirm binary exists with a simple probe (complex sh -c if/then breaks on toybox).
	probe := exec.Command("adb", "-s", serial, "shell", "ls", "/system/bin/screenrecord")
	pout, err := probe.CombinedOutput()
	if err != nil || !strings.Contains(string(pout), "screenrecord") {
		t.Fatalf("screenrecord missing on %s: %v out=%q", serial, err, pout)
	}

	root := t.TempDir()
	bus := events.NewBus(64)
	sess := session.NewManager(root, bus)
	mgr := recording.NewManager(root, bus, sess)
	mgr.SetTestOptions(recording.Options{
		MinCapture: 3 * time.Second,
		// Short time-limit: Stop waits for natural finalize (SIGINT is unreliable on API 34).
		TimeLimit: 20,
		BitRate:   2_000_000,
	})

	run, err := sess.Start(session.StartOptions{
		Kind: session.KindValidate, ArtifactID: "apk-e2e", Record: true, Profile: "balanced",
		RuntimeSerial: serial,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	art, err := mgr.Start(ctx, run, serial, recording.ProfileBalanced)
	if err != nil {
		t.Fatalf("Start: %v note=%v", err, art)
	}
	if art.Status != "recording" {
		t.Fatalf("status=%s note=%s", art.Status, art.Note)
	}

	// Start segment, then Stop (soft-stop waits for --time-limit natural moov).
	time.Sleep(5 * time.Second)

	stopped, err := mgr.Stop(ctx, run.ID)
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if stopped.Status != "finalized" {
		t.Fatalf("want finalized, got status=%s note=%s size=%d duration_ms=%d",
			stopped.Status, stopped.Note, stopped.SizeBytes, stopped.DurationMS)
	}
	if stopped.Path == "" || !recording.HasPlayableMedia(stopped) {
		t.Fatalf("unplayable: %#v", stopped)
	}
	st, err := os.Stat(stopped.Path)
	if err != nil || st.Size() < recording.MinPlayableBytes {
		t.Fatalf("primary too small: %v size=%v path=%s", err, st, stopped.Path)
	}
	// Segments must not include empty decoys.
	segs, _ := filepath.Glob(filepath.Join(stopped.SegmentsDir, "segment-*.mp4"))
	if len(segs) == 0 {
		t.Fatal("expected at least one segment")
	}
	for _, s := range segs {
		info, err := os.Stat(s)
		if err != nil || info.Size() == 0 {
			t.Fatalf("bad segment %s: %v", s, err)
		}
	}
}
