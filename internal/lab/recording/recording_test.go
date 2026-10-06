package recording_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/recording"
	"github.com/armin/apkcheck/internal/lab/session"
)

func TestRecordingProfilesAndMeta(t *testing.T) {
	if recording.ParseProfile("high") != recording.ProfileHigh {
		t.Fatal("profile")
	}
	root := t.TempDir()
	bus := events.NewBus(20)
	sess := session.NewManager(root, bus)
	mgr := recording.NewManager(root, bus, sess)
	list, err := mgr.List()
	if err != nil || list == nil {
		t.Fatalf("%v %#v", err, list)
	}
	st := mgr.Status("missing")
	if st.Running {
		t.Fatal("expected idle")
	}
}

func TestFileURLPath(t *testing.T) {
	if recording.FileURLPath("rec-1") != "/api/recordings/rec-1/media" {
		t.Fatal(recording.FileURLPath("rec-1"))
	}
}

func TestHasPlayableMedia(t *testing.T) {
	if recording.HasPlayableMedia(nil) {
		t.Fatal("nil")
	}
	dir := t.TempDir()
	stub := filepath.Join(dir, "stub.mp4")
	// Classic Android stub: ftyp + free, no moov — must NOT count as playable.
	if err := os.WriteFile(stub, append([]byte{
		0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'm', 'p', '4', '2', 0, 0, 0, 0,
		'i', 's', 'o', 'm', 'm', 'p', '4', '2',
	}, make([]byte, 3200)...), 0o640); err != nil {
		t.Fatal(err)
	}
	if recording.HasPlayableMedia(&recording.Artifact{Path: stub, Status: "finalized", SizeBytes: 3224}) {
		t.Fatal("stub without moov must not count as playable")
	}
	path := filepath.Join(dir, "recording.mp4")
	if err := os.WriteFile(path, minimalPlayableMP4(), 0o640); err != nil {
		t.Fatal(err)
	}
	art := &recording.Artifact{Path: path, Status: "finalized", SizeBytes: int64(len(minimalPlayableMP4()))}
	if !recording.HasPlayableMedia(art) {
		t.Fatal("expected playable")
	}
	empty := filepath.Join(dir, "empty.mp4")
	if err := os.WriteFile(empty, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if recording.HasPlayableMedia(&recording.Artifact{Path: empty, Status: "partial"}) {
		t.Fatal("empty must not count as playable")
	}
}

// minimalPlayableMP4 is ftyp + moov + mdat, padded past MinPlayableBytes.
func minimalPlayableMP4() []byte {
	ftyp := []byte{
		0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 0, 0,
		'i', 's', 'o', 'm', 'm', 'p', '4', '2',
	}
	moov := []byte{0, 0, 0, 8, 'm', 'o', 'o', 'v'}
	pad := make([]byte, int(recording.MinPlayableBytes)+64)
	copy(pad, ftyp)
	copy(pad[len(ftyp):], moov)
	// rest zeros act as free/mdat filler for size gate
	return pad
}

// TestStartStopProducesUsableVideo catches the historic bug where Stop canceled
// the host `adb shell` immediately after SIGINT, yielding 0-byte segments and
// "Could not load recording media".
func TestStartStopProducesUsableVideo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake adb shell script")
	}
	fakeADB, deviceFS := writeFakeADB(t)

	root := t.TempDir()
	bus := events.NewBus(32)
	sess := session.NewManager(root, bus)
	mgr := recording.NewManager(root, bus, sess)
	mgr.SetTestOptions(recording.Options{
		ADBPath:    fakeADB,
		MinCapture: 300 * time.Millisecond,
		TimeLimit:  30,
		BitRate:    1_000_000,
	})

	run, err := sess.Start(session.StartOptions{Kind: session.KindValidate, Record: true, Profile: "balanced"})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	art, err := mgr.Start(ctx, run, "emulator-fake", recording.ProfileBalanced)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if art.Status != "recording" {
		t.Fatalf("status=%s note=%s", art.Status, art.Note)
	}

	// Stop almost immediately — previously this produced empty media.
	// MinCapture forces a short wait; fake screenrecord still finalizes on SIGINT.
	stopped, err := mgr.Stop(ctx, run.ID)
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if stopped.Status != "finalized" {
		t.Fatalf("want finalized, got status=%s note=%s size=%d deviceFS=%s",
			stopped.Status, stopped.Note, stopped.SizeBytes, deviceFS)
	}
	if stopped.Path == "" {
		t.Fatal("storage_location empty")
	}
	st, err := os.Stat(stopped.Path)
	if err != nil || st.Size() == 0 {
		t.Fatalf("primary media missing/empty: %v size=%v", err, st)
	}
	if !recording.HasPlayableMedia(stopped) {
		t.Fatal("HasPlayableMedia false")
	}

	// No 0-byte decoy segments.
	segs, _ := filepath.Glob(filepath.Join(stopped.SegmentsDir, "segment-*.mp4"))
	for _, s := range segs {
		info, err := os.Stat(s)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() == 0 {
			t.Fatalf("empty segment left behind: %s", s)
		}
	}
}

// TestImmediateCancelRaceStillFinalizes ensures SIGINT-before-cancel ordering:
// even when Stop is invoked right away, we wait for screenrecord to exit before
// tearing down the host adb process.
func TestImmediateCancelRaceStillFinalizes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake adb shell script")
	}
	fakeADB, _ := writeFakeADB(t)

	root := t.TempDir()
	bus := events.NewBus(8)
	sess := session.NewManager(root, bus)
	mgr := recording.NewManager(root, bus, sess)
	mgr.SetTestOptions(recording.Options{
		ADBPath:    fakeADB,
		MinCapture: 50 * time.Millisecond,
		TimeLimit:  60,
	})

	run, err := sess.Start(session.StartOptions{Kind: session.KindValidate, Record: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Start(context.Background(), run, "serial-1", recording.ProfileLow); err != nil {
		t.Fatal(err)
	}
	art, err := mgr.Stop(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if art.Status != "finalized" || art.SizeBytes == 0 {
		t.Fatalf("race left unusable media: status=%s size=%d note=%s", art.Status, art.SizeBytes, art.Note)
	}
}

func TestStartFailsWhenScreenrecordMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake adb shell script")
	}
	fake := writeFakeADBMode(t, false) // no screenrecord binary
	root := t.TempDir()
	bus := events.NewBus(8)
	sess := session.NewManager(root, bus)
	mgr := recording.NewManager(root, bus, sess)
	mgr.SetTestOptions(recording.Options{ADBPath: fake, MinCapture: time.Millisecond})
	run, err := sess.Start(session.StartOptions{Kind: session.KindValidate, Record: true})
	if err != nil {
		t.Fatal(err)
	}
	art, err := mgr.Start(context.Background(), run, "serial", recording.ProfileBalanced)
	if err == nil {
		t.Fatal("expected start error when screenrecord missing")
	}
	if art == nil || art.Status != "failed" {
		t.Fatalf("%#v", art)
	}
	if !strings.Contains(art.Note, "screenrecord") {
		t.Fatalf("note=%q", art.Note)
	}
}

func TestStopWithoutStartErrors(t *testing.T) {
	root := t.TempDir()
	mgr := recording.NewManager(root, events.NewBus(4), session.NewManager(root, nil))
	if _, err := mgr.Stop(context.Background(), "run-missing"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDoubleStopIsIdempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake adb shell script")
	}
	fake, _ := writeFakeADB(t)
	root := t.TempDir()
	bus := events.NewBus(8)
	sess := session.NewManager(root, bus)
	mgr := recording.NewManager(root, bus, sess)
	mgr.SetTestOptions(recording.Options{ADBPath: fake, MinCapture: 80 * time.Millisecond})
	run, err := sess.Start(session.StartOptions{Kind: session.KindValidate, Record: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Start(context.Background(), run, "s1", recording.ProfileBalanced); err != nil {
		t.Fatal(err)
	}
	a1, err := mgr.Stop(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a1.Status != "finalized" {
		t.Fatalf("%s", a1.Status)
	}
	// Second Stop must fail (no live recorder) — not panic.
	if _, err := mgr.Stop(context.Background(), run.ID); err == nil {
		t.Fatal("second stop should error")
	}
	// Metadata on disk remains playable.
	got, err := mgr.Get(a1.ID)
	if err != nil || !recording.HasPlayableMedia(got) {
		t.Fatalf("get: %v %#v", err, got)
	}
}

func TestScreenrecordProbeFindsBinaryWithoutWhich(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake adb shell script")
	}
	// Probe path: command -v/which fail, but /system/bin/screenrecord is executable.
	fake := writeFakeADBMode(t, true)
	root := t.TempDir()
	bus := events.NewBus(8)
	sess := session.NewManager(root, bus)
	mgr := recording.NewManager(root, bus, sess)
	mgr.SetTestOptions(recording.Options{ADBPath: fake, MinCapture: 80 * time.Millisecond})
	run, err := sess.Start(session.StartOptions{Kind: session.KindValidate, Record: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Start(context.Background(), run, "emu", recording.ProfileHigh); err != nil {
		t.Fatalf("probe should accept /system/bin/screenrecord: %v", err)
	}
	art, err := mgr.Stop(context.Background(), run.ID)
	if err != nil || art.Status != "finalized" {
		t.Fatalf("err=%v status=%v note=%v", err, art.Status, art.Note)
	}
}

func writeFakeADB(t *testing.T) (adbPath, deviceFS string) {
	t.Helper()
	return writeFakeADBFull(t, true, true)
}

func writeFakeADBMode(t *testing.T, haveScreenrecord bool) string {
	t.Helper()
	p, _ := writeFakeADBFull(t, haveScreenrecord, false)
	return p
}

func writeFakeADBFull(t *testing.T, haveScreenrecord, whichWorks bool) (adbPath, deviceFS string) {
	t.Helper()
	dir := t.TempDir()
	deviceFS = filepath.Join(dir, "fs")
	if err := os.MkdirAll(filepath.Join(deviceFS, "sdcard"), 0o750); err != nil {
		t.Fatal(err)
	}
	if haveScreenrecord {
		bin := filepath.Join(deviceFS, "system", "bin")
		if err := os.MkdirAll(bin, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "screenrecord"), []byte("#!/bin/sh\n"), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	whichFlag := "0"
	if whichWorks {
		whichFlag = "1"
	}
	haveFlag := "0"
	if haveScreenrecord {
		haveFlag = "1"
	}
	adbPath = filepath.Join(dir, "adb")
	script := `#!/bin/sh
set -e
FS="` + deviceFS + `"
HAVE=` + haveFlag + `
WHICH=` + whichFlag + `
PIDFILE="$FS/screenrecord.pid"
if [ "$1" = "-s" ]; then shift 2; fi
cmd="$1"; shift || true
case "$cmd" in
  shell)
    if [ "$1" = "screenrecord" ]; then
      if [ "$HAVE" != "1" ]; then echo "screenrecord: not found" >&2; exit 127; fi
      remote=""
      for a in "$@"; do remote="$a"; done
      dest="$FS$remote"
      mkdir -p "$(dirname "$dest")"
      # Minimal ISO-BMFF with moov (playable gate); pad past MinPlayableBytes.
      {
        printf '\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isommp42'
        printf '\x00\x00\x00\x08moov'
        dd if=/dev/zero bs=9000 count=1 2>/dev/null
      } > "$dest"
      echo $$ > "$PIDFILE"
      trap 'printf "\nfinalized" >> "$dest"; rm -f "$PIDFILE"; exit 0' INT TERM
      i=0
      while [ "$i" -lt 120 ]; do
        printf "\x00frame-%s" "$i" >> "$dest"
        i=$((i+1))
        sleep 0.05
      done
      rm -f "$PIDFILE"
      exit 0
    fi
    if [ "$1" = "pkill" ] || [ "$1" = "killall" ]; then
      if [ -f "$PIDFILE" ]; then kill -2 "$(cat "$PIDFILE")" 2>/dev/null || true; fi
      exit 0
    fi
    if [ "$1" = "rm" ]; then
      shift
      while [ $# -gt 0 ]; do
        case "$1" in -f) shift ;; *) rm -f "$FS$1"; shift ;; esac
      done
      exit 0
    fi
    if [ "$1" = "ls" ]; then
      target="$2"
      if [ "$HAVE" = "1" ] && [ "$target" = "/system/bin/screenrecord" ]; then
        echo "/system/bin/screenrecord"; exit 0
      fi
      echo "ls: $target: No such file or directory" >&2; exit 1
    fi
    if [ "$1" = "command" ] && [ "$2" = "-v" ]; then
      if [ "$HAVE" = "1" ] && [ "$WHICH" = "1" ] && [ "$3" = "screenrecord" ]; then
        echo "/system/bin/screenrecord"; exit 0
      fi
      exit 1
    fi
    if [ "$1" = "which" ]; then
      if [ "$HAVE" = "1" ] && [ "$WHICH" = "1" ] && [ "$2" = "screenrecord" ]; then
        echo "/system/bin/screenrecord"; exit 0
      fi
      exit 1
    fi
    if [ "$1" = "getprop" ]; then
      if [ "$2" = "sys.boot_completed" ]; then echo 1; exit 0; fi
      exit 0
    fi
    if [ "$1" = "sh" ] && [ "$2" = "-c" ]; then
      code="$3"
      remote=$(printf '%s' "$code" | sed -n 's/.*\("\/sdcard\/[^"]*"\).*/\1/p' | tr -d '"')
      if [ -n "$remote" ] && [ -f "$FS$remote" ]; then wc -c < "$FS$remote" | tr -d ' '; exit 0; fi
      echo 0
      exit 0
    fi
    exit 0
    ;;
  pull)
    remote="$1"; local="$2"
    src="$FS$remote"
    if [ ! -f "$src" ]; then echo "missing" >&2; exit 1; fi
    cp "$src" "$local"
    exit 0
    ;;
  *) exit 0 ;;
esac
`
	if err := os.WriteFile(adbPath, []byte(script), 0o750); err != nil {
		t.Fatal(err)
	}
	return adbPath, deviceFS
}

func TestRecordingNamedAfterScenario(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake adb")
	}
	fakeADB, _ := writeFakeADB(t)
	root := t.TempDir()
	bus := events.NewBus(32)
	sess := session.NewManager(root, bus)
	mgr := recording.NewManager(root, bus, sess)
	mgr.SetTestOptions(recording.Options{
		ADBPath: fakeADB, MinCapture: 200 * time.Millisecond, TimeLimit: 30,
	})
	run, err := sess.Start(session.StartOptions{
		Kind: session.KindScenario, ScenarioID: "app-security-rerun", Record: true, Profile: "high",
		Meta: map[string]string{"scenario_name": "App Security Rerun (SC-12)", "title": "App Security Rerun (SC-12)"},
		RuntimeSerial: "emulator-fake",
	})
	if err != nil {
		t.Fatal(err)
	}
	art, err := mgr.Start(context.Background(), run, "emulator-fake", recording.ProfileHigh)
	if err != nil {
		t.Fatal(err)
	}
	if art.Title != "App Security Rerun (SC-12)" {
		t.Fatalf("title=%q", art.Title)
	}
	if art.FileName != "app-security-rerun-sc-12.mp4" {
		t.Fatalf("file_name=%q", art.FileName)
	}
	stopped, err := mgr.Stop(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(stopped.Path) != "app-security-rerun-sc-12.mp4" && !strings.HasSuffix(stopped.Path, "app-security-rerun-sc-12.mp4") {
		// Named copy may sit beside recording.mp4; Path should prefer named file when playable.
		named := filepath.Join(filepath.Dir(stopped.Path), "app-security-rerun-sc-12.mp4")
		if _, err := os.Stat(named); err != nil {
			t.Fatalf("expected named mp4 at %s (path=%s status=%s note=%s)", named, stopped.Path, stopped.Status, stopped.Note)
		}
	}
}
