package recording_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/recording"
	"github.com/armin/apkcheck/internal/lab/session"
)

func TestRetentionCleanupProtectsBookmarks(t *testing.T) {
	root := t.TempDir()
	bus := events.NewBus(20)
	sess := session.NewManager(root, bus)
	mgr := recording.NewManager(root, bus, sess)

	run, err := sess.Start(session.StartOptions{Kind: session.KindValidate, Record: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := recording.SaveRetention(root, recording.RetentionConfig{Policy: recording.RetainSavedOnly}); err != nil {
		t.Fatal(err)
	}

	keep := &recording.Artifact{
		ID: "rec-keep", RunID: run.ID, Status: "finalized", Profile: recording.ProfileBalanced,
		StartedAt: time.Now().UTC().Add(-48 * time.Hour),
		ManifestPath: filepath.Join(root, "recordings", "rec-keep", "metadata.json"),
	}
	_ = sess.SetRecording(run.ID, keep.ID)
	_, _ = sess.Bookmark(run.ID, "keep me", "important", []string{"saved"})
	if err := writeArtifactMeta(keep); err != nil {
		t.Fatal(err)
	}

	drop := &recording.Artifact{
		ID: "rec-drop", Status: "finalized", Profile: recording.ProfileLow,
		StartedAt: time.Now().UTC().Add(-48 * time.Hour),
		ManifestPath: filepath.Join(root, "recordings", "rec-drop", "metadata.json"),
	}
	if err := writeArtifactMeta(drop); err != nil {
		t.Fatal(err)
	}

	res, err := mgr.Cleanup(sess)
	if err != nil {
		t.Fatal(err)
	}
	foundDrop := false
	for _, id := range res.Deleted {
		if id == "rec-drop" {
			foundDrop = true
		}
		if id == "rec-keep" {
			t.Fatal("bookmarked recording must not be deleted")
		}
	}
	if !foundDrop {
		t.Fatalf("expected rec-drop deleted, got %#v", res)
	}
	if _, err := mgr.Get("rec-keep"); err != nil {
		t.Fatalf("bookmarked recording should remain: %v", err)
	}
}

func TestParseRetention(t *testing.T) {
	if recording.ParseRetention("7d") != recording.Retain7Days {
		t.Fatal("7d")
	}
	if recording.ParseRetention("failed_only") != recording.RetainFailedOnly {
		t.Fatal("failed")
	}
	if recording.DescribeRetention(recording.RetainEverything) == "" {
		t.Fatal("describe")
	}
}

func writeArtifactMeta(a *recording.Artifact) error {
	if err := os.MkdirAll(filepath.Dir(a.ManifestPath), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.ManifestPath, data, 0o640)
}
