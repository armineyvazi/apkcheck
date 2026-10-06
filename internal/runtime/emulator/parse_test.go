package emulator

import (
	"os"
	"testing"
)

func TestParseCreateFromName(t *testing.T) {
	opt := ParseCreateFromName("Pixel_8_API_34")
	if opt.API != "34" || opt.Name != "Pixel_8_API_34" {
		t.Fatalf("%+v", opt)
	}
	opt = ParseCreateFromName("My_API_35_Phone")
	if opt.API != "35" {
		t.Fatalf("api=%s", opt.API)
	}
}

func TestProgressBar(t *testing.T) {
	s := progressBar(50, 10)
	if s != "[#####-----]" {
		t.Fatalf("%q", s)
	}
}

func TestZipValidRejectsGarbage(t *testing.T) {
	p := t.TempDir() + "/bad.zip"
	if err := os.WriteFile(p, []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if zipValid(p) {
		t.Fatal("expected invalid")
	}
}
