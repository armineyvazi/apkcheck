package pipeline_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/pipeline"
)

func TestBuildSignMiniProject(t *testing.T) {
	if _, err := exec.LookPath("apktool"); err != nil {
		t.Skip("apktool not installed")
	}
	if _, err := exec.LookPath("keytool"); err != nil {
		t.Skip("keytool not installed")
	}
	root := t.TempDir()
	bus := events.NewBus(50)
	store, err := lab.OpenStore(root, bus)
	if err != nil {
		t.Fatal(err)
	}
	// Copy fixture project into store as registered project
	src := filepath.Join("..", "..", "..", "testdata", "lab", "mini")
	if _, err := os.Stat(src); err != nil {
		src = filepath.Join("testdata", "lab", "mini")
	}
	abs, _ := filepath.Abs(src)
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	projID := "proj-mini"
	projDir := filepath.Join(root, "projects", projID)
	if err := copyDir(abs, projDir); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(&lab.Artifact{
		ID: projID, Kind: lab.KindProject, Path: projDir,
		Package: "com.apkcheck.lab", Label: "mini",
	}); err != nil {
		t.Fatal(err)
	}
	p := &pipeline.Pipeline{Store: store, Bus: bus}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	unsigned, err := p.Build(ctx, projID)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if unsigned.Kind != lab.KindUnsignedAPK {
		t.Fatalf("kind %s", unsigned.Kind)
	}
	if _, err := os.Stat(unsigned.Path); err != nil {
		t.Fatal(err)
	}
	signed, err := p.Sign(ctx, unsigned.ID)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed.Kind != lab.KindSignedAPK {
		t.Fatalf("kind %s", signed.Kind)
	}
	if _, err := os.Stat(signed.Path); err != nil {
		t.Fatal(err)
	}
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o640)
	})
}
