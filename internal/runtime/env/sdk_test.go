package env

import "testing"

func TestCompatibleWithAVD(t *testing.T) {
	s := SDK{HostArch: "arm64"}
	ok, msg := s.CompatibleWithAVD("x86_64")
	if ok || msg == "" {
		t.Fatalf("expected incompatible: %v %q", ok, msg)
	}
	ok, _ = s.CompatibleWithAVD("arm64-v8a")
	if !ok {
		t.Fatal("arm64 should accept arm64-v8a")
	}
}
