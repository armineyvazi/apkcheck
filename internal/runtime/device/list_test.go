package device_test

import (
	"strings"
	"testing"

	"github.com/armin/apkcheck/internal/runtime/device"
)

func TestSelectPhysicalMultipleRequiresID(t *testing.T) {
	devs := []device.Info{
		{Serial: "A", State: device.StateDevice, Model: "Pixel"},
		{Serial: "B", State: device.StateDevice, Model: "Pixel2"},
	}
	_, err := device.SelectPhysical(devs, "")
	if err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Fatalf("got %v", err)
	}
}

func TestSelectPhysicalUnauthorized(t *testing.T) {
	devs := []device.Info{{Serial: "X", State: device.StateUnauthorized, Model: "Pixel"}}
	_, err := device.SelectPhysical(devs, "X")
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("got %v", err)
	}
}

func TestSelectPhysicalExact(t *testing.T) {
	devs := []device.Info{
		{Serial: "R58", State: device.StateDevice, Model: "Pixel 8", ABI: "arm64-v8a"},
		{Serial: "emulator-5554", State: device.StateDevice, IsEmulator: true},
	}
	got, err := device.SelectPhysical(devs, "R58")
	if err != nil || got.Serial != "R58" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestDiagnoseUnauthorized(t *testing.T) {
	s := device.Diagnose(device.Info{Serial: "R58", Model: "Pixel", State: device.StateUnauthorized})
	if !strings.Contains(s, "USB debugging") {
		t.Fatal(s)
	}
}
