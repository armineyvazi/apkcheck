package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReorderArgs(t *testing.T) {
	got := reorderArgs([]string{"app.apk", "--output", "./out", "--workers", "8"})
	want := []string{"--output", "./out", "--workers", "8", "app.apk"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}

	got = reorderArgs([]string{"--verbose", "app.apk", "--focus", "security"})
	want = []string{"--verbose", "--focus", "security", "app.apk"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}

	got = reorderArgs([]string{"app.apk", "--emulator", "Pixel_8_API_34", "--screenshots"})
	want = []string{"--emulator", "Pixel_8_API_34", "--screenshots", "app.apk"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("emulator reorder: got %#v want %#v", got, want)
	}
}

func TestRequireAPKAcceptsSplitsAndAPK(t *testing.T) {
	dir := t.TempDir()
	apks := filepath.Join(dir, "app.apks")
	if err := os.WriteFile(apks, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := requireAPK([]string{apks})
	if err != nil || got != apks {
		t.Fatalf("expected .apks accepted, got %q err=%v", got, err)
	}
	apk := filepath.Join(dir, "app.apk")
	if err := os.WriteFile(apk, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = requireAPK([]string{apk})
	if err != nil || got != apk {
		t.Fatalf("got %q err=%v", got, err)
	}
	xapk := filepath.Join(dir, "app.xapk")
	if err := os.WriteFile(xapk, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := requireAPK([]string{xapk}); err != nil {
		t.Fatalf("xapk: %v", err)
	}
	// Split directory
	if _, err := requireAPK([]string{dir}); err != nil {
		t.Fatalf("dir: %v", err)
	}
}
