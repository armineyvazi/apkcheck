package launcher_test

import (
	"testing"

	"github.com/armin/apkcheck/internal/runtime/launcher"
)

func TestNormalizeActivity(t *testing.T) {
	if got := launcher.NormalizeActivity("com.example", ".MainActivity"); got != "com.example.MainActivity" {
		t.Fatal(got)
	}
	if got := launcher.NormalizeActivity("com.example", "com.example.MainActivity"); got != "com.example.MainActivity" {
		t.Fatal(got)
	}
}

func TestComponent(t *testing.T) {
	t0 := launcher.Target{Package: "com.example", Activity: ".Main"}
	if got := t0.Component(); got != "com.example/com.example.Main" {
		t.Fatal(got)
	}
}

func TestParseBadging(t *testing.T) {
	in := "package: name='com.example.app' versionCode='1' versionName='1.0'\nlaunchable-activity: name='com.example.app.MainActivity'  label='App'\n"
	pkg, act := launcher.ParseBadging(in)
	if pkg != "com.example.app" || act != "com.example.app.MainActivity" {
		t.Fatalf("%q %q", pkg, act)
	}
}
