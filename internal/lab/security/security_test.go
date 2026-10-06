package security_test

import (
	"path/filepath"
	"testing"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/security"
)

func TestCatalogAndPresets(t *testing.T) {
	c := security.Catalog()
	if len(c) < 8 {
		t.Fatalf("expected templates, got %d", len(c))
	}
	p := security.Presets()
	if len(p) < 5 {
		t.Fatalf("presets %d", len(p))
	}
	if _, ok := security.TemplateByID("background-behavior"); !ok {
		t.Fatal("missing background-behavior")
	}
	if _, ok := security.PresetByID("quick-android-security"); !ok {
		t.Fatal("missing quick preset")
	}
}

func TestManifestReviewProject(t *testing.T) {
	root := filepath.Join("..", "..", "..", "testdata", "lab", "mini")
	abs, _ := filepath.Abs(root)
	art := &lab.Artifact{ID: "x", Kind: lab.KindProject, Path: abs, Package: "com.apkcheck.lab"}
	rev, err := security.ReviewManifest(art)
	if err != nil {
		t.Fatal(err)
	}
	if rev.Package != "com.apkcheck.lab" {
		t.Fatalf("package %q", rev.Package)
	}
	if len(rev.ReviewNotes) == 0 {
		t.Fatal("expected notes")
	}
}

func TestObservationStoreExport(t *testing.T) {
	dir := t.TempDir()
	st := &security.Store{Root: dir, Bus: events.NewBus(10)}
	o := &security.Observation{
		Title: "test", Severity: security.SeverityNeedsReview,
		Summary: "review me", Package: "com.apkcheck.lab",
	}
	if err := st.SaveObservation(o); err != nil {
		t.Fatal(err)
	}
	list, err := st.ListObservations()
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	out := filepath.Join(dir, "o.md")
	if err := security.ExportObservation(list[0], security.ExportMD, out); err != nil {
		t.Fatal(err)
	}
}
