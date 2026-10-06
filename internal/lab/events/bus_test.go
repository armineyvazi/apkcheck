package events_test

import (
	"sync"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab/events"
)

func TestBusPublishSubscribeRecent(t *testing.T) {
	bus := events.NewBus(10)
	ch := bus.Subscribe(4)
	defer bus.Unsubscribe(ch)

	bus.Publish(events.Event{Type: "A", Message: "one"})
	select {
	case e := <-ch:
		if e.Type != "A" || e.Level != "info" || e.At.IsZero() {
			t.Fatalf("%#v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}

	recent := bus.Recent()
	if len(recent) != 1 || recent[0].Message != "one" {
		t.Fatalf("%#v", recent)
	}
}

func TestBusRetainRing(t *testing.T) {
	bus := events.NewBus(3)
	for i := 0; i < 5; i++ {
		bus.Publish(events.Event{Type: "N", Message: string(rune('a' + i))})
	}
	recent := bus.Recent()
	if len(recent) != 3 {
		t.Fatalf("len=%d", len(recent))
	}
	if recent[0].Message != "c" || recent[2].Message != "e" {
		t.Fatalf("%#v", recent)
	}
}

func TestBusSlowConsumerDoesNotBlock(t *testing.T) {
	bus := events.NewBus(100)
	ch := bus.Subscribe(1) // tiny buffer
	defer bus.Unsubscribe(ch)

	// Fill buffer then publish more — must not deadlock.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			bus.Publish(events.Event{Type: "FLOOD", Message: "x"})
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on slow subscriber")
	}
}

func TestBusConcurrentPublish(t *testing.T) {
	bus := events.NewBus(500)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				bus.Publish(events.Event{Type: "C", Message: "ok"})
			}
		}()
	}
	wg.Wait()
	if n := len(bus.Recent()); n != 320 {
		t.Fatalf("recent=%d", n)
	}
}
