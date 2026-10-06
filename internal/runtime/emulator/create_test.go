package emulator

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemImageReady(t *testing.T) {
	dir := t.TempDir()
	if systemImageReady(dir) {
		t.Fatal("empty dir should not be ready")
	}
	// Incomplete sdkmanager stub
	_ = os.MkdirAll(filepath.Join(dir, ".installer"), 0o755)
	if systemImageReady(dir) {
		t.Fatal(".installer only should not be ready")
	}
	if err := os.WriteFile(filepath.Join(dir, "system.img"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// too small
	if systemImageReady(dir) {
		t.Fatal("tiny system.img should not count")
	}
	big := make([]byte, 2048)
	if err := os.WriteFile(filepath.Join(dir, "system.img"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if !systemImageReady(dir) {
		t.Fatal("expected ready")
	}
}

func TestUnzipRejectsZipSlip(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "evil.zip")
	dest := filepath.Join(t.TempDir(), "out")
	if err := writeZip(zipPath, map[string]string{
		"../evil.txt": "pwned",
	}); err != nil {
		t.Fatal(err)
	}
	err := unzipTo(zipPath, dest)
	if err == nil {
		t.Fatal("expected zip-slip error")
	}
}

func TestUnzipAndFlatten(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "img.zip")
	dest := filepath.Join(t.TempDir(), "sysimg")
	payload := make([]byte, 2048)
	if err := writeZip(zipPath, map[string]string{
		"nested/system.img":  string(payload),
		"nested/ramdisk.img": string(payload),
	}); err != nil {
		t.Fatal(err)
	}
	if err := unzipTo(zipPath, dest); err != nil {
		t.Fatal(err)
	}
	if systemImageReady(dest) {
		// nested still counts via recursive check
	} else {
		t.Fatal("nested system.img should be detected")
	}
	_ = flattenOneLevel(dest)
	if !systemImageReady(dest) {
		t.Fatal("after flatten should be ready at root")
	}
}

func writeZip(path string, files map[string]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := zip.NewWriter(f)
	for name, body := range files {
		fw, err := w.Create(name)
		if err != nil {
			return err
		}
		if _, err := fw.Write([]byte(body)); err != nil {
			return err
		}
	}
	return w.Close()
}
