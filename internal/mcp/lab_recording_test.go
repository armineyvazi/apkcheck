package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/recording"
	"github.com/armin/apkcheck/internal/lab/session"
	"github.com/armin/apkcheck/internal/mcp"
)

func callLabTool(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	in := bytes.NewBuffer(nil)
	writeRPC(in, 1, "tools/call", map[string]any{
		"name": name, "arguments": args,
	})
	var out bytes.Buffer
	_ = mcp.New(in, &out, &bytes.Buffer{}).Run(context.Background())
	var resp map[string]any
	if err := json.NewDecoder(&out).Decode(&resp); err != nil {
		t.Fatalf("decode: %v out=%s", err, out.String())
	}
	result, _ := resp["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("empty content: %#v", resp)
	}
	text := content[0].(map[string]any)["text"].(string)
	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("payload json: %v text=%s", err, text)
	}
	payload["_isError"] = result["isError"] == true
	return payload
}

func TestMCPEventsReadsSessionTimeline(t *testing.T) {
	ws := t.TempDir()
	// Simulate CLI validate writing timeline with a separate bus (MCP call is fresh).
	cli := session.NewManager(ws, nil)
	run, err := cli.Start(session.StartOptions{Kind: session.KindValidate, ArtifactID: "apk-1", Record: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.AddEvent(run.ID, session.Event{
		Type: "VALIDATE_STAGE", Source: "system", Message: "install ok",
	}); err != nil {
		t.Fatal(err)
	}

	payload := callLabTool(t, "apkcheck_lab_events", map[string]any{
		"workspace": ws, "limit": 20,
	})
	if payload["_isError"] == true {
		t.Fatalf("%#v", payload)
	}
	ev, _ := payload["events"].([]any)
	if len(ev) == 0 {
		t.Fatalf("expected timeline events, got empty: %#v", payload)
	}
	blob, _ := json.Marshal(ev)
	if !strings.Contains(string(blob), "VALIDATE_STAGE") || !strings.Contains(string(blob), "install ok") {
		t.Fatalf("missing stage event: %s", blob)
	}
}

func mcpMinimalPlayableMP4() []byte {
	ftyp := []byte{
		0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 0, 0,
		'i', 's', 'o', 'm', 'm', 'p', '4', '2',
	}
	moov := []byte{0, 0, 0, 8, 'm', 'o', 'o', 'v'}
	pad := make([]byte, int(recording.MinPlayableBytes)+64)
	copy(pad, ftyp)
	copy(pad[len(ftyp):], moov)
	return pad
}

func TestMCPRecordingsGetPlayableFlag(t *testing.T) {
	ws := t.TempDir()
	recID := "rec-play-1"
	dir := filepath.Join(ws, "recordings", recID)
	if err := os.MkdirAll(filepath.Join(dir, "segments"), 0o750); err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(dir, "recording.mp4")
	blob := mcpMinimalPlayableMP4()
	if err := os.WriteFile(primary, blob, 0o640); err != nil {
		t.Fatal(err)
	}
	art := &recording.Artifact{
		ID: recID, Status: "finalized", Path: primary, SizeBytes: int64(len(blob)),
		ManifestPath: filepath.Join(dir, "metadata.json"),
		StartedAt:    time.Now().UTC(), Profile: recording.ProfileBalanced, Codec: "H.264",
	}
	data, _ := json.MarshalIndent(art, "", "  ")
	if err := os.WriteFile(art.ManifestPath, data, 0o640); err != nil {
		t.Fatal(err)
	}

	payload := callLabTool(t, "apkcheck_lab_recordings_get", map[string]any{
		"workspace": ws, "recording_id": recID,
	})
	if payload["playable"] != true {
		t.Fatalf("expected playable=true: %#v", payload)
	}
	if payload["media_url"] != "/api/recordings/"+recID+"/media" {
		t.Fatalf("media_url=%v", payload["media_url"])
	}

	// Empty partial
	rec2 := "rec-empty"
	dir2 := filepath.Join(ws, "recordings", rec2)
	_ = os.MkdirAll(filepath.Join(dir2, "segments"), 0o750)
	art2 := &recording.Artifact{
		ID: rec2, Status: "partial", Note: "recording stopped without usable video",
		ManifestPath: filepath.Join(dir2, "metadata.json"),
		StartedAt:    time.Now().UTC(), Profile: recording.ProfileLow,
	}
	data2, _ := json.MarshalIndent(art2, "", "  ")
	_ = os.WriteFile(art2.ManifestPath, data2, 0o640)
	payload2 := callLabTool(t, "apkcheck_lab_recordings_get", map[string]any{
		"workspace": ws, "id": rec2,
	})
	if payload2["playable"] != false {
		t.Fatalf("expected playable=false: %#v", payload2)
	}
	if payload2["warning"] == nil || payload2["warning"] == "" {
		t.Fatalf("expected warning for unplayable: %#v", payload2)
	}
}

func TestMCPBeginRecordingFinishWithFakeADB(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake adb")
	}
	// Unit-level coverage via recording manager + session (same path MCP uses).
	fake := writeMCPFakeADB(t)
	ws := t.TempDir()
	bus := events.NewBus(32)
	sess := session.NewManager(ws, bus)
	recMgr := recording.NewManager(ws, bus, sess)
	recMgr.SetTestOptions(recording.Options{
		ADBPath: fake, MinCapture: 200 * time.Millisecond, TimeLimit: 30,
	})

	run, err := sess.Start(session.StartOptions{
		Kind: session.KindValidate, ArtifactID: "apk-mcp", Record: true, Profile: "balanced",
		RuntimeSerial: "emulator-fake", MCPSession: "mcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	art, err := recMgr.Start(context.Background(), run, "emulator-fake", recording.ProfileBalanced)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if art.Status != "recording" {
		t.Fatalf("%s", art.Status)
	}
	stopped, err := recMgr.Stop(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Status != "finalized" || !recording.HasPlayableMedia(stopped) {
		t.Fatalf("status=%s note=%s", stopped.Status, stopped.Note)
	}
	_, _ = sess.Complete(run.ID, true, "PASSED", "", 0)

	// MCP events + recordings_get must see it after a fresh process-like open.
	evPayload := callLabTool(t, "apkcheck_lab_events", map[string]any{"workspace": ws})
	blob, _ := json.Marshal(evPayload["events"])
	if !strings.Contains(string(blob), "RECORDING_STARTED") && !strings.Contains(string(blob), "SESSION_STARTED") {
		t.Fatalf("events missing session markers: %s", blob)
	}
	get := callLabTool(t, "apkcheck_lab_recordings_get", map[string]any{
		"workspace": ws, "recording_id": stopped.ID,
	})
	if get["playable"] != true {
		t.Fatalf("%#v", get)
	}
}

func TestMCPEventsEmptyWorkspaceOK(t *testing.T) {
	ws := t.TempDir()
	payload := callLabTool(t, "apkcheck_lab_events", map[string]any{"workspace": ws})
	if payload["_isError"] == true {
		t.Fatalf("%#v", payload)
	}
	if int(payload["count"].(float64)) != 0 {
		t.Fatalf("count=%v", payload["count"])
	}
}

func writeMCPFakeADB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	fs := filepath.Join(dir, "fs")
	_ = os.MkdirAll(filepath.Join(fs, "sdcard"), 0o750)
	_ = os.MkdirAll(filepath.Join(fs, "system", "bin"), 0o750)
	_ = os.WriteFile(filepath.Join(fs, "system", "bin", "screenrecord"), []byte("x"), 0o750)
	adbPath := filepath.Join(dir, "adb")
	script := `#!/bin/sh
set -e
FS="` + fs + `"
PIDFILE="$FS/screenrecord.pid"
if [ "$1" = "-s" ]; then shift 2; fi
cmd="$1"; shift || true
case "$cmd" in
  shell)
    if [ "$1" = "screenrecord" ]; then
      remote=""; for a in "$@"; do remote="$a"; done
      dest="$FS$remote"; mkdir -p "$(dirname "$dest")"
      {
        printf '\000\000\000\030ftypisom\000\000\000\000isommp42'
        printf '\000\000\000\010moov'
        dd if=/dev/zero bs=9000 count=1 2>/dev/null
      } > "$dest"
      echo $$ > "$PIDFILE"
      trap 'printf "\nfinal" >> "$dest"; rm -f "$PIDFILE"; exit 0' INT TERM
      i=0; while [ "$i" -lt 80 ]; do printf x >> "$dest"; i=$((i+1)); sleep 0.05; done
      rm -f "$PIDFILE"; exit 0
    fi
    if [ "$1" = "pkill" ] || [ "$1" = "killall" ]; then
      [ -f "$PIDFILE" ] && kill -2 "$(cat "$PIDFILE")" 2>/dev/null || true
      exit 0
    fi
    if [ "$1" = "rm" ]; then shift; while [ $# -gt 0 ]; do case "$1" in -f) shift;; *) rm -f "$FS$1"; shift;; esac; done; exit 0; fi
    if [ "$1" = "ls" ]; then echo "/system/bin/screenrecord"; exit 0; fi
    if [ "$1" = "getprop" ]; then echo 1; exit 0; fi
    if [ "$1" = "command" ] || [ "$1" = "which" ]; then echo "/system/bin/screenrecord"; exit 0; fi
    if [ "$1" = "sh" ] && [ "$2" = "-c" ]; then
      remote=$(printf '%s' "$3" | sed -n 's/.*\("\/sdcard\/[^"]*"\).*/\1/p' | tr -d '"')
      if [ -n "$remote" ] && [ -f "$FS$remote" ]; then wc -c < "$FS$remote" | tr -d ' '; exit 0; fi
      echo 0; exit 0
    fi
    exit 0 ;;
  pull)
    cp "$FS$1" "$2"; exit 0 ;;
  *) exit 0 ;;
esac
`
	if err := os.WriteFile(adbPath, []byte(script), 0o750); err != nil {
		t.Fatal(err)
	}
	return adbPath
}
