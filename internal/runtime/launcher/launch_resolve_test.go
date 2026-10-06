package launcher_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/runtime/adb"
	"github.com/armin/apkcheck/internal/runtime/launcher"
)

// TestLaunchResolvesActivityWhenEmpty covers the Lab UI/MCP bug where only
// package is sent (no activity) and launch used to fail with
// "missing package/activity".
func TestLaunchResolvesActivityWhenEmpty(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fake adb")
	}
	dir := t.TempDir()
	adbPath := filepath.Join(dir, "adb")
	script := `#!/bin/sh
set -e
if [ "$1" = "-s" ]; then shift 2; fi
cmd="$1"; shift || true
case "$cmd" in
  shell)
    if [ "$1" = "cmd" ] && [ "$2" = "package" ] && [ "$3" = "resolve-activity" ]; then
      echo "priority=0"
      echo "com.example.app/.MainActivity"
      exit 0
    fi
    if [ "$1" = "am" ] && [ "$2" = "start" ]; then
      echo "Starting: Intent { cmp=com.example.app/.MainActivity }"
      exit 0
    fi
    if [ "$1" = "monkey" ]; then
      echo "Events injected: 1"
      exit 0
    fi
    if [ "$1" = "dumpsys" ]; then
      exit 0
    fi
    exit 0 ;;
  *) exit 0 ;;
esac
`
	if err := os.WriteFile(adbPath, []byte(script), 0o750); err != nil {
		t.Fatal(err)
	}
	client := &adb.Client{Path: adbPath}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := launcher.Launch(ctx, client, "emulator-fake", launcher.Target{
		Package: "com.example.app",
		// Activity intentionally empty — must resolve.
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	if !res.Success {
		t.Fatalf("not success: %+v", res)
	}
	if res.Target.Activity == "" && res.Target.Source != "monkey" {
		t.Fatalf("expected resolved activity or monkey, got %+v", res.Target)
	}
}

func TestLaunchPackageOnlyFallsBackToMonkey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fake adb")
	}
	dir := t.TempDir()
	adbPath := filepath.Join(dir, "adb")
	script := `#!/bin/sh
if [ "$1" = "-s" ]; then shift 2; fi
cmd="$1"; shift || true
case "$cmd" in
  shell)
    if [ "$1" = "monkey" ]; then
      echo "Events injected: 1"
      exit 0
    fi
    # resolve-activity / dumpsys fail → monkey path
    exit 1 ;;
  *) exit 0 ;;
esac
`
	if err := os.WriteFile(adbPath, []byte(script), 0o750); err != nil {
		t.Fatal(err)
	}
	client := &adb.Client{Path: adbPath}
	res, err := launcher.Launch(context.Background(), client, "emu", launcher.Target{Package: "ir.divar"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success || res.Target.Source != "monkey" {
		t.Fatalf("%+v", res)
	}
}
