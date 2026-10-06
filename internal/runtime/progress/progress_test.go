package progress_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/runtime/progress"
)

func TestBarLifecycle(t *testing.T) {
	var buf bytes.Buffer
	b := progress.NewBar(&buf, "system-images;android-34;google_apis;arm64-v8a")
	b.Start()
	b.Update(500*1024*1024, 1000*1024*1024, 500*1024*1024, 10*time.Second)
	b.Success("1.00 GB in 10s")
	out := buf.String()
	if !strings.Contains(out, "fetch") {
		t.Fatalf("missing fetch header:\n%s", out)
	}
	if !strings.Contains(out, "system-images;android-34") {
		t.Fatalf("missing package name:\n%s", out)
	}
	if !strings.Contains(out, "ok") {
		t.Fatalf("missing success:\n%s", out)
	}
	if strings.Contains(out, "npm") || strings.Contains(out, "🚀") {
		t.Fatalf("must not use npm/emoji chrome:\n%s", out)
	}
}

func TestBootWaiter(t *testing.T) {
	var buf bytes.Buffer
	b := progress.NewWaiter(&buf, progress.EmulatorLabel("Pixel_8_API_34"), "boot")
	b.Start()
	b.UpdateTimed(5*time.Second, 10*time.Minute, "waiting for sys.boot_completed")
	b.UpdateTimed(10*time.Second, 10*time.Minute, "adb: emulator-5554:device · waiting for boot")
	b.Success("booted emulator-5554 in 34s")
	out := buf.String()
	if !strings.Contains(out, "boot") {
		t.Fatalf("missing boot header:\n%s", out)
	}
	if !strings.Contains(out, "Pixel_8_API_34") {
		t.Fatalf("missing avd:\n%s", out)
	}
	if !strings.Contains(out, "5s") && !strings.Contains(out, "10s") {
		t.Fatalf("missing elapsed times:\n%s", out)
	}
	if strings.Contains(out, "npm") || strings.Contains(out, "🚀") || strings.Contains(out, "emulator;") {
		t.Fatalf("must not look like download/npm:\n%s", out)
	}
}

func TestPackageLabel(t *testing.T) {
	got := progress.PackageLabel("34", "google_apis", "arm64-v8a")
	want := "system-images;android-34;google_apis;arm64-v8a"
	if got != want {
		t.Fatalf("%s != %s", got, want)
	}
}

func TestRenderDoesNotPanicOnFail(t *testing.T) {
	var buf bytes.Buffer
	b := progress.NewBar(&buf, "pkg")
	b.Start()
	b.Fail(assertErr{})
	if !strings.Contains(buf.String(), "fail") {
		t.Fatal(buf.String())
	}
}

type assertErr struct{}

func (assertErr) Error() string { return "boom" }
