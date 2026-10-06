package lab_test

import (
	"path/filepath"
	"testing"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/events"
)

func TestStorePutGet(t *testing.T) {
	root := t.TempDir()
	bus := events.NewBus(10)
	st, err := lab.OpenStore(root, bus)
	if err != nil {
		t.Fatal(err)
	}
	a := &lab.Artifact{ID: "apk-1", Kind: lab.KindOriginalAPK, Path: filepath.Join(root, "x.apk"), Label: "x"}
	if err := st.Put(a); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("apk-1")
	if err != nil || got.Label != "x" {
		t.Fatalf("got %+v err=%v", got, err)
	}
	st2, err := lab.OpenStore(root, bus)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st2.Get("apk-1"); err != nil {
		t.Fatal("reload:", err)
	}
}

func TestBusPublishSubscribe(t *testing.T) {
	bus := events.NewBus(5)
	ch := bus.Subscribe(4)
	bus.Publish(events.Event{Type: "TEST", Message: "hi"})
	select {
	case e := <-ch:
		if e.Type != "TEST" {
			t.Fatalf("%+v", e)
		}
	default:
		t.Fatal("no event")
	}
	bus.Unsubscribe(ch)
}
