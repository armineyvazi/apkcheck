package security_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/security"
)

func TestHarnessSeedForceAndBuild(t *testing.T) {
	src, err := filepath.Abs(filepath.Join("..", "..", "..", "testdata", "lab", "harness"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(src, "AndroidManifest.xml")); err != nil {
		t.Skip("testdata harness missing")
	}
	ws := t.TempDir()
	if err := security.SeedHarnessProjectOpts(ws, src, false); err != nil {
		t.Fatal(err)
	}
	st := security.HarnessStatus(ws)
	if st["project_present"] != true {
		t.Fatalf("status %#v", st)
	}
	if st["scaffold_current"] != true {
		t.Fatalf("expected current scaffold: %#v", st)
	}
	if err := security.SeedHarnessProjectOpts(ws, src, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(ws, "harness", "project", "AndroidManifest.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "com.apkcheck.testharness") {
		t.Fatal("manifest missing package")
	}
}

func TestManifestReviewExportsNotes(t *testing.T) {
	dir := t.TempDir()
	man := `<?xml version="1.0"?><manifest package="com.example.app" android:versionName="1.2.3">
  <uses-permission android:name="android.permission.CAMERA"/>
  <application android:debuggable="true">
    <activity android:name="com.example.app.MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>
      <intent-filter>
        <data android:scheme="divar" android:host="open"/>
      </intent-filter>
    </activity>
    <activity android:name=".Private" android:exported="false"/>
    <service android:name=".ExportedSvc" android:exported="true"/>
    <receiver android:name=".BootRecv">
      <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter>
    </receiver>
  </application>
</manifest>`
	if err := os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(man), 0o640); err != nil {
		t.Fatal(err)
	}
	rev, err := security.ReviewManifest(&lab.Artifact{Kind: lab.KindProject, Path: dir, Package: "com.example.app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rev.ExportedActivities) == 0 {
		t.Fatalf("expected exported activities: %#v", rev)
	}
	found := false
	for _, n := range rev.ReviewNotes {
		if strings.Contains(n, "EXPORT activity") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected EXPORT notes, got %#v", rev.ReviewNotes)
	}
	if len(rev.DeepLinks) == 0 {
		t.Fatalf("expected deep links: %#v", rev)
	}
}

func TestManifestReviewAPKUsesAAPT(t *testing.T) {
	// Requires a real APK on disk; skip when not present so CI stays green.
	apkPath := filepath.Join("..", "..", "..", "..", "testdata", "sample.apk")
	abs, err := filepath.Abs(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Skip("sample apk not present")
	}
	rev, err := security.ReviewManifest(&lab.Artifact{
		Kind: lab.KindOriginalAPK, Path: abs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rev.ExportedActivities) == 0 && len(rev.ExportedReceivers) == 0 {
		if !strings.Contains(rev.Source, "zip inspect") {
			t.Fatalf("expected exports or zip-only note: source=%s notes=%v", rev.Source, rev.ReviewNotes)
		}
		t.Skip("aapt unavailable — zip-only path")
	}
	joined := strings.Join(rev.ReviewNotes, "\n")
	if strings.Contains(joined, "No high-signal static review notes") {
		t.Fatalf("empty review for sample APK: %s", joined)
	}
}
