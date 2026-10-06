package session_test

import (
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/session"
)

func TestCategoryForLogcatKernelApp(t *testing.T) {
	root := t.TempDir()
	m := session.NewManager(root, events.NewBus(20))
	run, err := m.Start(session.StartOptions{Kind: session.KindScenario, Package: "com.example.app"})
	if err != nil {
		t.Fatal(err)
	}
	k, err := m.AddEvent(run.ID, session.Event{
		Type: "KERNEL_LOG", Source: "logcat", Category: "kernel",
		Message: "E/Kernel: oops", Tags: []string{"kernel"},
		OffsetMS: 10, Metadata: map[string]any{"preserve_offset": true},
	})
	if err != nil || k.Category != "kernel" {
		t.Fatalf("%#v %v", k, err)
	}
	d, err := m.AddEvent(run.ID, session.Event{
		Type: "APP_LOG", Source: "logcat", Category: "app",
		Message: "I/com.example.app: browse", Tags: []string{"app"},
		OffsetMS: 20, Metadata: map[string]any{"preserve_offset": true},
	})
	if err != nil || d.Category != "app" {
		t.Fatalf("%#v %v", d, err)
	}
	// Empty category → inferred as app for APP_LOG
	inferred, err := m.AddEvent(run.ID, session.Event{
		Type: "APP_LOG", Source: "logcat",
		Message: "I/com.example: hello", Tags: []string{"app"},
		OffsetMS: 25, Metadata: map[string]any{"preserve_offset": true},
	})
	if err != nil || inferred.Category != "app" {
		t.Fatalf("infer app: %#v %v", inferred, err)
	}
	n, err := m.AddEvent(run.ID, session.Event{
		Type: "MITM_HTTP", Source: "network",
		Message: "GET https://api.example.com/v1 → 200", Tags: []string{"mitm"},
		OffsetMS: 30, Metadata: map[string]any{"url": "https://api.example.com/v1", "preserve_offset": true},
	})
	if err != nil || n.Category != "network" {
		t.Fatalf("%#v %v", n, err)
	}
}

func TestSessionLifecycleAndTimeline(t *testing.T) {
	root := t.TempDir()
	bus := events.NewBus(50)
	m := session.NewManager(root, bus)
	run, err := m.Start(session.StartOptions{
		Kind: session.KindValidate, ArtifactID: "apk-1", Record: true, Profile: "balanced",
	})
	if err != nil {
		t.Fatal(err)
	}
	if run.ID == "" || run.Status != session.StatusRunning {
		t.Fatalf("%#v", run)
	}
	ev, err := m.AddEvent(run.ID, session.Event{
		Type: "MCP_TOOL_CALL", Source: "mcp", Message: "tap",
		Metadata: map[string]any{"tool": "tap"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.OffsetMS < 0 || ev.RunID != run.ID {
		t.Fatalf("%#v", ev)
	}
	time.Sleep(5 * time.Millisecond)
	_, _ = m.Bookmark(run.ID, "Interesting", "note", []string{"manual"})
	list, err := m.ListEvents(run.ID)
	if err != nil || len(list) < 3 {
		t.Fatalf("events=%d err=%v", len(list), err)
	}
	done, err := m.Complete(run.ID, false, "FAILED", "assertion", list[len(list)-1].OffsetMS)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != session.StatusFailed || done.RecordingID != "" && done.Result == "" {
		t.Fatalf("%#v", done)
	}
	got, err := m.Get(run.ID)
	if err != nil || got.Status != session.StatusFailed {
		t.Fatalf("%#v %v", got, err)
	}
	all, err := m.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("%d %v", len(all), err)
	}
}

func TestRecentFeedIncludesTimeline(t *testing.T) {
	root := t.TempDir()
	bus := events.NewBus(20)
	m := session.NewManager(root, bus)
	run, err := m.Start(session.StartOptions{Kind: session.KindValidate, ArtifactID: "apk-1", Record: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddEvent(run.ID, session.Event{
		Type: "VALIDATE_STAGE", Source: "system", Message: "install ok",
	}); err != nil {
		t.Fatal(err)
	}
	// New manager (simulates Lab UI process reading CLI-written timelines).
	ui := session.NewManager(root, events.NewBus(20))
	feed := ui.RecentFeed(5, 100)
	if len(feed) == 0 {
		t.Fatal("expected timeline events in RecentFeed")
	}
	found := false
	for _, e := range feed {
		if e.Type == "VALIDATE_STAGE" && e.Message == "install ok" && e.RunID == run.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing stage event: %#v", feed)
	}
}

func TestSetRecordingSurvivesComplete(t *testing.T) {
	root := t.TempDir()
	m := session.NewManager(root, events.NewBus(10))
	run, err := m.Start(session.StartOptions{Kind: session.KindValidate, Record: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetRecording(run.ID, "rec-xyz"); err != nil {
		t.Fatal(err)
	}
	done, err := m.Complete(run.ID, true, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if done.RecordingID != "rec-xyz" || done.Result != "PASSED" {
		t.Fatalf("%#v", done)
	}
	got, err := m.Get(run.ID)
	if err != nil || got.RecordingID != "rec-xyz" {
		t.Fatalf("%#v %v", got, err)
	}
}

func TestCompleteFailureOffsetZeroMeansNow(t *testing.T) {
	root := t.TempDir()
	m := session.NewManager(root, events.NewBus(10))
	run, err := m.Start(session.StartOptions{Kind: session.KindValidate})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(8 * time.Millisecond)
	done, err := m.Complete(run.ID, false, "", "boom", 0)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != session.StatusFailed {
		t.Fatalf("%#v", done)
	}
	ev, err := m.ListEvents(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	var fail *session.Event
	for i := range ev {
		if ev[i].Type == "ASSERTION_FAILED" {
			fail = &ev[i]
			break
		}
	}
	if fail == nil || fail.OffsetMS <= 0 {
		t.Fatalf("expected failure offset > 0, got %#v", fail)
	}
}
