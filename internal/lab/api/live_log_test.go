package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/api"
	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/pipeline"
	"github.com/armin/apkcheck/internal/lab/recording"
	"github.com/armin/apkcheck/internal/lab/session"
)

func newTestServer(t *testing.T) (root string, bus *events.Bus, srv *api.Server) {
	t.Helper()
	root = t.TempDir()
	bus = events.NewBus(200)
	store, err := lab.OpenStore(root, bus)
	if err != nil {
		t.Fatal(err)
	}
	sess := session.NewManager(root, bus)
	recs := recording.NewManager(root, bus, sess)
	srv = &api.Server{
		Store:      store,
		Pipe:       &pipeline.Pipeline{Store: store, Bus: bus},
		Bus:        bus,
		Sessions:   sess,
		Recordings: recs,
	}
	return root, bus, srv
}

func TestLiveLogFeedDedupesBusAndDisk(t *testing.T) {
	root, bus, srv := newTestServer(t)
	// UI process bus event
	bus.Publish(events.Event{Type: "VALIDATE", Message: "from-bus", RunID: "run-x"})

	// CLI-like writer (separate manager, nil bus) — same workspace
	cli := session.NewManager(root, nil)
	run, err := cli.Start(session.StartOptions{Kind: session.KindValidate, ArtifactID: "apk-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.AddEvent(run.ID, session.Event{Type: "INSTALL", Message: "from-disk", Source: "system"}); err != nil {
		t.Fatal(err)
	}
	// Duplicate: republish the INSTALL timeline row onto the bus with the same event_id.
	evs, err := cli.ListEvents(run.ID)
	if err != nil || len(evs) == 0 {
		t.Fatalf("list: %v", err)
	}
	installID := ""
	for _, e := range evs {
		if e.Type == "INSTALL" {
			installID = e.ID
			break
		}
	}
	if installID == "" {
		t.Fatal("INSTALL event missing from timeline")
	}
	bus.Publish(events.Event{
		Type: "INSTALL", Message: "from-disk", RunID: run.ID,
		Data: map[string]any{"event_id": installID},
	})

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/events", nil))
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	var list []events.Event
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	installs := 0
	busHits := 0
	for _, e := range list {
		if e.Type == "INSTALL" && e.Message == "from-disk" {
			installs++
		}
		if e.Type == "VALIDATE" && e.Message == "from-bus" {
			busHits++
		}
	}
	if installs != 1 {
		t.Fatalf("dedupe failed: installs=%d body=%s", installs, rr.Body.String())
	}
	if busHits != 1 {
		t.Fatalf("bus event missing: %s", rr.Body.String())
	}
}

func TestLiveLogSSEPicksUpCLITimelineAfterConnect(t *testing.T) {
	root, _, srv := newTestServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/events/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var mu sync.Mutex
	var buf strings.Builder
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		tmp := make([]byte, 512)
		for {
			n, rerr := res.Body.Read(tmp)
			if n > 0 {
				mu.Lock()
				buf.Write(tmp[:n])
				mu.Unlock()
			}
			if rerr != nil {
				return
			}
		}
	}()

	snapshot := func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(snapshot(), ": connected") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(snapshot(), ": connected") {
		cancel()
		<-readDone
		t.Fatalf("no connected comment: %q", snapshot())
	}

	// CLI writes timeline after SSE is live — stream ticker must surface it.
	cli := session.NewManager(root, nil)
	run, err := cli.Start(session.StartOptions{Kind: session.KindSecurity, ArtifactID: "apk-live"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.AddEvent(run.ID, session.Event{
		Type: "SECURITY_STEP", Message: "exported-components", Source: "system", Level: "info",
	}); err != nil {
		t.Fatal(err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		body := snapshot()
		if strings.Contains(body, "SECURITY_STEP") && strings.Contains(body, "exported-components") {
			cancel()
			<-readDone
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-readDone
	t.Fatalf("SSE never received CLI timeline event:\n%s", snapshot())
}

func TestRecordingMediaServesNonEmptyAndRejectsEmpty(t *testing.T) {
	root, _, srv := newTestServer(t)
	recID := "rec-test-1"
	dir := filepath.Join(root, "recordings", recID)
	segDir := filepath.Join(dir, "segments")
	if err := os.MkdirAll(segDir, 0o750); err != nil {
		t.Fatal(err)
	}
	primary := filepath.Join(dir, "recording.mp4")
	playable := minimalAPIPlayableMP4()
	if err := os.WriteFile(primary, playable, 0o640); err != nil {
		t.Fatal(err)
	}
	// Empty decoy must be ignored when primary exists.
	if err := os.WriteFile(filepath.Join(segDir, "segment-001.mp4"), nil, 0o640); err != nil {
		t.Fatal(err)
	}
	art := &recording.Artifact{
		ID: recID, Status: "finalized", Path: primary, SizeBytes: int64(len(playable)),
		SegmentsDir: segDir, ManifestPath: filepath.Join(dir, "metadata.json"),
		StartedAt: time.Now().UTC(), Profile: recording.ProfileBalanced, Codec: "H.264",
	}
	data, _ := json.MarshalIndent(art, "", "  ")
	if err := os.WriteFile(art.ManifestPath, data, 0o640); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/recordings/"+recID+"/media", nil))
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "video/mp4") {
		t.Fatalf("content-type=%q", ct)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("moov")) {
		t.Fatalf("body missing moov: len=%d", rr.Body.Len())
	}

	// Stub without moov must 404 (not served as video/mp4).
	stubID := "rec-stub"
	stubDir := filepath.Join(root, "recordings", stubID)
	if err := os.MkdirAll(stubDir, 0o750); err != nil {
		t.Fatal(err)
	}
	stubPath := filepath.Join(stubDir, "recording.mp4")
	stub := append([]byte{
		0, 0, 0, 0x18, 'f', 't', 'y', 'p', 'm', 'p', '4', '2', 0, 0, 0, 0,
		'i', 's', 'o', 'm', 'm', 'p', '4', '2',
	}, make([]byte, 4000)...)
	_ = os.WriteFile(stubPath, stub, 0o640)
	artStub := &recording.Artifact{
		ID: stubID, Status: "partial", Path: stubPath, SizeBytes: int64(len(stub)),
		Note: "recording pulled but not playable (missing moov atom / truncated MP4)",
		ManifestPath: filepath.Join(stubDir, "metadata.json"),
		StartedAt:    time.Now().UTC(),
	}
	stubMeta, _ := json.MarshalIndent(artStub, "", "  ")
	_ = os.WriteFile(artStub.ManifestPath, stubMeta, 0o640)
	rrStub := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rrStub, httptest.NewRequest(http.MethodGet, "/api/recordings/"+stubID+"/media", nil))
	if rrStub.Code != 404 {
		t.Fatalf("stub want 404, got %d", rrStub.Code)
	}

	// Partial with only empty segments → JSON 404 with note (not opaque empty).
	rec2 := "rec-empty"
	dir2 := filepath.Join(root, "recordings", rec2, "segments")
	if err := os.MkdirAll(dir2, 0o750); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir2, "segment-001.mp4"), nil, 0o640)
	art2 := &recording.Artifact{
		ID: rec2, Status: "partial", Note: "recording stopped without usable video — finalize/pull failed",
		SegmentsDir: dir2, ManifestPath: filepath.Join(root, "recordings", rec2, "metadata.json"),
		StartedAt: time.Now().UTC(), Profile: recording.ProfileLow,
	}
	data2, _ := json.MarshalIndent(art2, "", "  ")
	_ = os.WriteFile(art2.ManifestPath, data2, 0o640)
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/api/recordings/"+rec2+"/media", nil))
	if rr2.Code != 404 {
		t.Fatalf("want 404, got %d", rr2.Code)
	}
	var errBody map[string]string
	if err := json.Unmarshal(rr2.Body.Bytes(), &errBody); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errBody["error"], "usable video") && errBody["error"] != "no media file" {
		t.Fatalf("%#v", errBody)
	}
}

func minimalAPIPlayableMP4() []byte {
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

func TestSessionsListExposesRecordingID(t *testing.T) {
	_, _, srv := newTestServer(t)
	run, err := srv.Sessions.Start(session.StartOptions{Kind: session.KindValidate, Record: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Sessions.SetRecording(run.ID, "rec-abc"); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/sessions", nil))
	if rr.Code != 200 {
		t.Fatalf("%s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "rec-abc") {
		t.Fatalf("recording_id missing: %s", rr.Body.String())
	}
}
