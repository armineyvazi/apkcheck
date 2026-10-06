package runtime

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/armin/apkcheck/internal/runtime/device"
)

// RuntimeInfo records exactly where the APK executed (required for reproducibility).
type RuntimeInfo struct {
	Type         string `json:"type"`                 // physical-device | emulator
	Connection   string `json:"connection,omitempty"` // USB | emulator | tcp
	Host         string `json:"host,omitempty"`       // macOS
	HostArch     string `json:"host_arch,omitempty"`
	Device       string `json:"device,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	AVD          string `json:"avd,omitempty"`
	Android      string `json:"android,omitempty"`
	API          string `json:"api,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Screen       string `json:"screen,omitempty"`
}

// FormatText renders runtime environment for reports/CLI.
func (r RuntimeInfo) FormatText() string {
	var b strings.Builder
	b.WriteString("Runtime:\n")
	b.WriteString(fmt.Sprintf("    type: %s\n", r.Type))
	if r.Connection != "" {
		b.WriteString(fmt.Sprintf("    connection: %s\n", r.Connection))
	}
	if r.Host != "" {
		b.WriteString(fmt.Sprintf("    host: %s\n", r.Host))
	}
	if r.AVD != "" {
		b.WriteString(fmt.Sprintf("    AVD: %s\n", r.AVD))
	}
	if r.Device != "" {
		b.WriteString(fmt.Sprintf("    device: %s\n", r.Device))
	}
	if r.DeviceID != "" {
		b.WriteString(fmt.Sprintf("    device-id: %s\n", r.DeviceID))
	}
	if r.Android != "" {
		b.WriteString(fmt.Sprintf("    Android: %s\n", r.Android))
	}
	if r.API != "" {
		b.WriteString(fmt.Sprintf("    API: %s\n", r.API))
	}
	if r.Architecture != "" {
		b.WriteString(fmt.Sprintf("    architecture: %s\n", r.Architecture))
	}
	if r.Screen != "" {
		b.WriteString(fmt.Sprintf("    screen: %s\n", r.Screen))
	}
	if r.HostArch != "" {
		b.WriteString(fmt.Sprintf("    host-arch: %s\n", r.HostArch))
	}
	return b.String()
}

func runtimeInfoFromDevice(d *device.Info, mode, avd string) RuntimeInfo {
	ri := RuntimeInfo{
		Host:     "macOS",
		HostArch: runtime.GOARCH,
	}
	if d != nil {
		ri.Device = d.Model
		ri.DeviceID = d.Serial
		ri.Android = d.AndroidVersion
		ri.API = d.APILevel
		ri.Architecture = d.ABI
		ri.Screen = d.Screen
		ri.Connection = d.Connection
	}
	switch mode {
	case "emulator":
		ri.Type = "emulator"
		ri.Host = "macOS"
		ri.AVD = avd
		if ri.Connection == "" {
			ri.Connection = "emulator"
		}
	default:
		ri.Type = "physical-device"
		if ri.Connection == "" {
			ri.Connection = "USB"
		}
		if strings.EqualFold(ri.Connection, "usb") {
			ri.Connection = "USB"
		}
	}
	return ri
}
