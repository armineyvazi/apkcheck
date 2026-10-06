package runtime_test

import (
	"strings"
	"testing"

	appruntime "github.com/armin/apkcheck/internal/runtime"
	"github.com/armin/apkcheck/internal/runtime/device"
	"github.com/armin/apkcheck/internal/runtime/launcher"
	"github.com/armin/apkcheck/internal/runtime/logcat"
)

func TestSanitizeSessionName(t *testing.T) {
	if got := appruntime.SanitizeSessionName("../etc/passwd"); strings.Contains(got, "/") {
		t.Fatalf("unsafe: %q", got)
	}
}

func TestFormatDevices(t *testing.T) {
	s := device.FormatTable([]device.Info{{Serial: "x", State: "device", Model: "Pixel", APILevel: "35", ABI: "arm64-v8a"}})
	if !strings.Contains(s, "Android Devices") || !strings.Contains(s, "Pixel") {
		t.Fatal(s)
	}
}

func TestParseBadging(t *testing.T) {
	in := "package: name='com.example.app' versionCode='1' versionName='1.0'\nlaunchable-activity: name='com.example.app.MainActivity'  label='App' icon=''\n"
	pkg, act := launcher.ParseBadging(in)
	if pkg != "com.example.app" || act != "com.example.app.MainActivity" {
		t.Fatalf("%q %q", pkg, act)
	}
}

func TestDetectCrashes(t *testing.T) {
	raw := `01-01 00:00:00.000  1234  1234 E AndroidRuntime: FATAL EXCEPTION: main
01-01 00:00:00.001  1234  1234 E AndroidRuntime: java.lang.NullPointerException
01-01 00:00:00.002  1234  1234 E AndroidRuntime: 	at com.example.Foo.bar(Foo.kt:10)
01-01 00:00:00.003  1234  1234 E AndroidRuntime: 	at com.example.Foo.onCreate(Foo.kt:5)
`
	crashes := logcat.DetectCrashes(raw)
	if len(crashes) == 0 {
		t.Fatal("expected crash")
	}
	if crashes[0].Kind != "java" {
		t.Fatalf("kind=%s", crashes[0].Kind)
	}
	if len(crashes[0].Frames) == 0 {
		t.Fatal("expected frames")
	}
}
