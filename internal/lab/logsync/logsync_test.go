package logsync

import (
	"context"
	"testing"
	"time"
)

func TestSplitEpochLine(t *testing.T) {
	ts, rest, ok := splitEpochLine("1728000001.250 I/com.example.app: hello")
	if !ok || ts < 1728000001 || rest == "" {
		t.Fatalf("%v %v %v", ts, rest, ok)
	}
	if _, _, ok = splitEpochLine("not-a-log"); ok {
		t.Fatal("expected fail")
	}
}

func TestClassifyLogLine(t *testing.T) {
	cat, tags, typ := classifyLogLine("I/com.example.app: opened listing", "com.example.app")
	if cat != "app" || typ != "APP_LOG" || len(tags) == 0 {
		t.Fatalf("%s %v %s", cat, tags, typ)
	}
	cat, tags, typ = classifyLogLine("I/com.other.pkg: hi", "com.other.pkg")
	if cat != "app" || typ != "APP_LOG" {
		t.Fatalf("generic app: %s %v %s", cat, tags, typ)
	}
	cat, tags, typ = classifyLogLine("I/ActivityTaskManager: START u0 {cmp=com.example.app/.Main}", "com.example.app")
	if cat != "app" || typ != "APP_LIFECYCLE" {
		t.Fatalf("%s %v %s", cat, tags, typ)
	}
	cat, _, typ = classifyLogLine("E/Kernel: oops", "com.example.app")
	if cat != "kernel" || typ != "KERNEL_LOG" {
		t.Fatalf("%s %s", cat, typ)
	}
	cat, _, typ = classifyLogLine("E/AndroidRuntime: FATAL EXCEPTION: main", "com.example.app")
	if cat != "kernel" || typ != "RUNTIME_FATAL" {
		t.Fatalf("%s %s", cat, typ)
	}
	cat, _, _ = classifyLogLine("I/chatty: ignore", "com.example.app")
	if cat != "" {
		t.Fatalf("want empty got %s", cat)
	}
	cat, _, _ = classifyLogLine("W FrameTracker: Missed SF frame:PREDICTION_ERROR, 36911, 0", "com.example.app")
	if cat != "" {
		t.Fatalf("FrameTracker noise must be dropped, got %s", cat)
	}
}

func TestWarmRecording(t *testing.T) {
	start := time.Now()
	WarmRecording(5 * time.Millisecond)
	if time.Since(start) < 5*time.Millisecond {
		t.Fatal("warm did not wait")
	}
}

func TestClearNilGuard(t *testing.T) {
	if err := Clear(context.Background(), nil, "emulator-5554"); err == nil {
		t.Fatal("want error for nil client")
	}
	if err := Clear(context.Background(), nil, ""); err == nil {
		t.Fatal("want error for empty serial")
	}
}

func TestClassifyLogLineHarness(t *testing.T) {
	cat, tags, typ := classifyLogLine("I/apkcheck-harness: probe_launch ok", "com.example.app")
	if cat != "process" || typ != "HARNESS_LOG" {
		t.Fatalf("harness: cat=%s typ=%s tags=%v", cat, typ, tags)
	}
}

func TestClassifyLogLineRuntimeFatal(t *testing.T) {
	cat, _, typ := classifyLogLine("E/AndroidRuntime: FATAL EXCEPTION: main Process: com.example.app", "com.example.app")
	if cat != "kernel" || typ != "RUNTIME_FATAL" {
		t.Fatalf("fatal: cat=%s typ=%s", cat, typ)
	}
}

func TestClassifyLogLineAppLifecycle(t *testing.T) {
	line := "I/ActivityTaskManager: START u0 {cmp=com.example.app/.MainActivity}"
	cat, tags, typ := classifyLogLine(line, "com.example.app")
	if cat != "app" || typ != "APP_LIFECYCLE" {
		t.Fatalf("lifecycle: cat=%s typ=%s", cat, typ)
	}
	found := false
	for _, tag := range tags {
		if tag == "lifecycle" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing lifecycle tag: %v", tags)
	}
}

func TestSplitEpochLineTooShort(t *testing.T) {
	if _, _, ok := splitEpochLine(""); ok {
		t.Fatal("empty string must fail")
	}
	if _, _, ok := splitEpochLine("123.45"); ok {
		t.Fatal("no space must fail")
	}
	if _, _, ok := splitEpochLine("not-float rest"); ok {
		t.Fatal("non-float ts must fail")
	}
	// Epoch too small (pre-2001) must fail.
	if _, _, ok := splitEpochLine("1000.0 rest"); ok {
		t.Fatal("tiny epoch must fail")
	}
}
