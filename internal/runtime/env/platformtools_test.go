package env_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/armin/apkcheck/internal/runtime/env"
)

func TestEnsurePlatformToolsSymlinks(t *testing.T) {
	root := t.TempDir()
	// Pretend brew platform-tools exists with adb
	src := filepath.Join(t.TempDir(), "platform-tools")
	if err := os.MkdirAll(src, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "adb"), []byte("#!/bin/sh\n"), 0o750); err != nil {
		t.Fatal(err)
	}
	// Point PATH at fake adb
	oldPath := os.Getenv("PATH")
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })
	_ = os.Setenv("PATH", src+string(os.PathListSeparator)+oldPath)

	note, err := env.EnsurePlatformTools(root)
	if err != nil {
		t.Fatal(err)
	}
	if note == "" {
		t.Fatal("expected symlink note")
	}
	dest := filepath.Join(root, "platform-tools", "adb")
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("adb not linked: %v", err)
	}
	// second call is no-op
	note2, err := env.EnsurePlatformTools(root)
	if err != nil || note2 != "" {
		t.Fatalf("second call: note=%q err=%v", note2, err)
	}
}
