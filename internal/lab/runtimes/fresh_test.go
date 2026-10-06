package runtimes_test

import (
	"strings"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab/runtimes"
)

func TestFreshAfterRecordingDefaultAVD(t *testing.T) {
	mgr := &runtimes.Manager{}
	// Without SDK this returns an error — still exercises the API contract.
	_, err := mgr.FreshAfterRecording(t.Context(), "", "", time.Millisecond)
	if err == nil {
		t.Fatal("expected error without emulator SDK")
	}
	// Empty AVD should still attempt default name path (error mentions SDK/emulator/avd).
	msg := err.Error()
	if !strings.Contains(msg, "emulator") && !strings.Contains(msg, "ANDROID") && !strings.Contains(msg, "AVD") && !strings.Contains(msg, "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFreshAfterRecordingRespectsTimeout(t *testing.T) {
	mgr := &runtimes.Manager{}
	ctx, cancel := t.Context(), func() {}
	_ = cancel
	start := time.Now()
	_, err := mgr.FreshAfterRecording(ctx, "Pixel_8_API_34", "emulator-5554", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected error")
	}
	if time.Since(start) > 30*time.Second {
		t.Fatalf("FreshAfterRecording hung too long: %v", time.Since(start))
	}
}
