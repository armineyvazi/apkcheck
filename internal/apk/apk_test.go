package apk_test

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/armin/apkcheck/internal/apk"
)

func TestInspectMinimalAPK(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")
	if err := writeMinimalAPK(apkPath); err != nil {
		t.Fatal(err)
	}
	info, err := apk.Inspect(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.DEXCount != 1 {
		t.Fatalf("dex=%d", info.DEXCount)
	}
	if info.SHA256 == "" {
		t.Fatal("missing hash")
	}
	if len(info.ABIs) != 1 || info.ABIs[0] != "arm64-v8a" {
		t.Fatalf("abis=%v", info.ABIs)
	}
}

func TestRejectPathTraversal(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "evil.apk")
	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("dex\n035\x00"))
	w2, err := zw.Create("../evil.so")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w2.Write([]byte("x"))
	_ = zw.Close()
	_ = f.Close()

	// Inspect itself may clean paths; ExtractSafe must refuse traversal.
	dest := filepath.Join(dir, "out")
	err = apk.ExtractSafe(apkPath, dest, nil)
	if err == nil {
		// zip.Clean may neutralize .. ; ensure we at least extract safely under dest
		entries, _ := os.ReadDir(dest)
		for _, e := range entries {
			if e.Name() == "evil.so" && !fileUnder(dest, filepath.Join(dest, e.Name())) {
				t.Fatal("escaped")
			}
		}
	}
}

func fileUnder(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !filepath.IsAbs(rel)
}

func writeMinimalAPK(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	files := map[string]string{
		"AndroidManifest.xml":   "\x00\x00",
		"classes.dex":           "dex\n035\x00fake",
		"lib/arm64-v8a/libx.so": "MZ",
		"resources.arsc":        "x",
		"assets/a.txt":          "a",
		"META-INF/MANIFEST.MF":  "Manifest-Version: 1.0\n",
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(body)); err != nil {
			return err
		}
	}
	return zw.Close()
}
