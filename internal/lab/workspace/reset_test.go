package workspace_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/armin/apkcheck/internal/lab/workspace"
)

func TestFreshRunResetClearsContents(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"sessions", "recordings", "logs", "runs"} {
		p := filepath.Join(root, d, "junk")
		if err := os.MkdirAll(p, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "x.txt"), []byte("x"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	proxy := filepath.Join(root, "proxy")
	_ = os.MkdirAll(proxy, 0o750)
	_ = os.WriteFile(filepath.Join(proxy, "flows.jsonl"), []byte("{}\n"), 0o640)
	_ = os.WriteFile(filepath.Join(proxy, "ca.pem"), []byte("KEEP"), 0o640)

	removed, err := workspace.Reset(root, workspace.FreshRunReset())
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) == 0 {
		t.Fatal("expected removals")
	}
	ents, _ := os.ReadDir(filepath.Join(root, "sessions"))
	if len(ents) != 0 {
		t.Fatalf("sessions not empty: %v", ents)
	}
	if _, err := os.Stat(filepath.Join(root, "proxy", "flows.jsonl")); !os.IsNotExist(err) {
		t.Fatal("flows.jsonl should be gone")
	}
	if _, err := os.Stat(filepath.Join(root, "proxy", "ca.pem")); err != nil {
		t.Fatal("ca.pem must be kept")
	}
}
