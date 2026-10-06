package cli

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

func TestListenURL(t *testing.T) {
	cases := map[string]string{
		":8787":           "http://127.0.0.1:8787",
		"127.0.0.1:9000":  "http://127.0.0.1:9000",
		"0.0.0.0:8787":    "http://127.0.0.1:8787",
	}
	for in, want := range cases {
		if got := listenURL(in); got != want {
			t.Fatalf("%q → %q want %q", in, got, want)
		}
	}
}

func TestParseLabArgsBoolDoesNotSwallow(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "")
	open := fs.Bool("open", false, "")
	pos, err := parseLabArgs(fs, []string{"--open", "--workspace", "/tmp/ws", "artifact-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !*open {
		t.Fatal("expected --open")
	}
	if *ws != "/tmp/ws" {
		t.Fatalf("workspace %q", *ws)
	}
	if len(pos) != 1 || pos[0] != "artifact-1" {
		t.Fatalf("pos %#v", pos)
	}
}

func TestFindWebDist(t *testing.T) {
	d := findWebDist()
	if d == "" {
		t.Skip("web/dist not built in this environment")
	}
	if _, err := os.Stat(filepath.Join(d, "index.html")); err != nil {
		t.Fatal(err)
	}
}

func TestLocateWebDistFromParentSecLayout(t *testing.T) {
	// Mimic: sec/apkcheck/web/dist when cwd is sec/
	sec := t.TempDir()
	dist := filepath.Join(sec, "apkcheck", "web", "dist")
	if err := os.MkdirAll(dist, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "index.html"), []byte("<!doctype html>"), 0o640); err != nil {
		t.Fatal(err)
	}
	got := locateWebDist(sec)
	if got == "" {
		t.Fatal("expected apkcheck/web/dist from parent dir")
	}
	want, _ := filepath.Abs(dist)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLocateWebDistViaSymlinkedBinaryRoot(t *testing.T) {
	// Mimic: ~/.local/bin/apkcheck → repo/bin/apkcheck, UI at repo/web/dist
	repo := t.TempDir()
	dist := filepath.Join(repo, "web", "dist")
	binDir := filepath.Join(repo, "bin")
	if err := os.MkdirAll(dist, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "index.html"), []byte("<!doctype html>"), 0o640); err != nil {
		t.Fatal(err)
	}
	realBin := filepath.Join(binDir, "apkcheck")
	if err := os.WriteFile(realBin, []byte("#!/bin/sh\n"), 0o750); err != nil {
		t.Fatal(err)
	}
	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "apkcheck")
	if err := os.Symlink(realBin, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	// Same roots findWebDist uses after EvalSymlinks.
	got := locateWebDist(filepath.Dir(resolved), filepath.Dir(filepath.Dir(resolved)))
	want, _ := filepath.Abs(dist)
	want, _ = filepath.EvalSymlinks(want) // macOS /var → /private/var
	got, _ = filepath.EvalSymlinks(got)
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
