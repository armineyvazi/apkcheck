package proxysync_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/proxysync"
	"github.com/armin/apkcheck/internal/lab/session"
)

func TestImportEmpty(t *testing.T) {
	dir := t.TempDir()
	sess := session.NewManager(dir, events.NewBus(10))
	run, err := sess.Start(session.StartOptions{Kind: session.KindScenario, Package: "com.example.app"})
	if err != nil {
		t.Fatal(err)
	}
	if n := proxysync.Import(filepath.Join(dir, "missing"), sess, run); n != 0 {
		t.Fatalf("want 0 got %d", n)
	}
}

func TestImportNilGuards(t *testing.T) {
	dir := t.TempDir()
	sess := session.NewManager(dir, events.NewBus(10))
	run, err := sess.Start(session.StartOptions{Kind: session.KindScenario, Package: "com.example.app"})
	if err != nil {
		t.Fatal(err)
	}
	if n := proxysync.Import("", sess, run); n != 0 {
		t.Fatalf("empty proxyDir: want 0 got %d", n)
	}
	if n := proxysync.Import(dir, nil, run); n != 0 {
		t.Fatalf("nil sess: want 0 got %d", n)
	}
	if n := proxysync.Import(dir, sess, nil); n != 0 {
		t.Fatalf("nil run: want 0 got %d", n)
	}
}

func TestImportFlows(t *testing.T) {
	root := t.TempDir()
	proxyDir := filepath.Join(root, "proxy")
	if err := os.MkdirAll(proxyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ts := float64(time.Now().UTC().Add(2*time.Second).Unix()) + 0.5
	line := fmt.Sprintf(
		`{"ts":%f,"method":"GET","host":"api.example.com","url":"https://api.example.com/v1/data","path":"/v1/data","status":200,"tags":["mitm"]}`+"\n",
		ts,
	)
	if err := os.WriteFile(filepath.Join(proxyDir, "flows.jsonl"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	sess := session.NewManager(root, events.NewBus(10))
	run, err := sess.Start(session.StartOptions{
		Kind: session.KindScenario, Package: "com.example.app",
	})
	if err != nil {
		t.Fatal(err)
	}
	n := proxysync.Import(proxyDir, sess, run)
	if n < 1 {
		t.Fatalf("expected imported flows, got %d", n)
	}
	ev, err := sess.ListEvents(run.ID)
	if err != nil || len(ev) == 0 {
		t.Fatal(err)
	}
	found := false
	for _, e := range ev {
		if e.Type == "MITM_HTTP" && e.Category == "network" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no MITM_HTTP event in %#v", ev)
	}
}
