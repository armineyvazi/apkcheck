// Package device lists physical/authorized Android devices via ADB.
package device

import (
	"context"
	"fmt"
	"strings"

	"github.com/armin/apkcheck/internal/runtime/adb"
)

// Known ADB connection states.
const (
	StateDevice        = "device"
	StateOffline       = "offline"
	StateUnauthorized  = "unauthorized"
	StateNoPermissions = "no permissions"
	StateUnknown       = "unknown"
)

// Info is one connected device/emulator target.
type Info struct {
	Serial         string `json:"serial"`
	State          string `json:"state"`
	Model          string `json:"model,omitempty"`
	Product        string `json:"product,omitempty"`
	AndroidVersion string `json:"android_version,omitempty"`
	APILevel       string `json:"api_level,omitempty"`
	ABI            string `json:"abi,omitempty"`
	IsEmulator     bool   `json:"is_emulator"`
	StorageFree    string `json:"storage_free,omitempty"`
	Screen         string `json:"screen,omitempty"`
	Connection     string `json:"connection,omitempty"` // usb | tcp | emulator
}

// List returns devices from `adb devices -l`, optionally enriching props.
func List(ctx context.Context, client *adb.Client, enrich bool) ([]Info, error) {
	res, err := client.Run(ctx, "devices", "-l")
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		d := Info{Serial: fields[0], State: normalizeState(fields[1])}
		for _, f := range fields[2:] {
			switch {
			case strings.HasPrefix(f, "model:"):
				d.Model = strings.TrimPrefix(f, "model:")
			case strings.HasPrefix(f, "product:"):
				d.Product = strings.TrimPrefix(f, "product:")
			case strings.HasPrefix(f, "usb:"):
				d.Connection = "usb"
			default:
				// ignore transport_id: and other adb -l fields
			}
		}
		d.IsEmulator = strings.HasPrefix(d.Serial, "emulator-") ||
			strings.Contains(strings.ToLower(d.Product), "sdk") ||
			strings.Contains(strings.ToLower(d.Model), "sdk_gphone")
		if d.Connection == "" {
			if d.IsEmulator {
				d.Connection = "emulator"
			} else if strings.Contains(d.Serial, ":") {
				d.Connection = "tcp"
			} else {
				d.Connection = "usb"
			}
		}
		if enrich && d.State == StateDevice {
			enrichDevice(ctx, client, &d)
		}
		out = append(out, d)
	}
	return out, nil
}

func normalizeState(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "device":
		return StateDevice
	case "offline":
		return StateOffline
	case "unauthorized":
		return StateUnauthorized
	case "no", "permissions", "no permissions":
		return StateNoPermissions
	default:
		if s == "" {
			return StateUnknown
		}
		return s
	}
}

func enrichDevice(ctx context.Context, client *adb.Client, d *Info) {
	if v, err := client.GetProp(ctx, d.Serial, "ro.build.version.release"); err == nil {
		d.AndroidVersion = v
	}
	if v, err := client.GetProp(ctx, d.Serial, "ro.build.version.sdk"); err == nil {
		d.APILevel = v
	}
	if v, err := client.GetProp(ctx, d.Serial, "ro.product.cpu.abi"); err == nil {
		d.ABI = v
	}
	if d.Model == "" {
		if v, err := client.GetProp(ctx, d.Serial, "ro.product.model"); err == nil {
			d.Model = v
		}
	}
	if out, err := client.Shell(ctx, d.Serial, "df", "-h", "/data"); err == nil {
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[len(lines)-1])
			if len(fields) >= 4 {
				d.StorageFree = fields[3]
			}
		}
	}
	if out, err := client.Shell(ctx, d.Serial, "wm", "size"); err == nil {
		d.Screen = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "Physical size:"))
	}
}

// FormatTable renders a devices table.
func FormatTable(devices []Info) string {
	var b strings.Builder
	b.WriteString("Android Devices\n\n")
	b.WriteString(fmt.Sprintf("%-18s %-18s %-12s %-6s %-12s %-14s %s\n",
		"ID", "MODEL", "ANDROID", "API", "ARCH", "STATUS", "CONN"))
	if len(devices) == 0 {
		b.WriteString("(none — connect a phone via USB-C with USB debugging, or start an emulator)\n")
		return b.String()
	}
	for _, d := range devices {
		android := d.AndroidVersion
		if android != "" && !strings.HasPrefix(android, "Android") {
			android = "Android " + android
		}
		b.WriteString(fmt.Sprintf("%-18s %-18s %-12s %-6s %-12s %-14s %s\n",
			truncate(d.Serial, 18), truncate(d.Model, 18), truncate(android, 12),
			d.APILevel, d.ABI, d.State, d.Connection))
	}
	b.WriteString("\n")
	for _, d := range devices {
		b.WriteString(Diagnose(d))
		b.WriteString("\n")
	}
	return b.String()
}

// Diagnose returns actionable guidance for a device state.
func Diagnose(d Info) string {
	switch d.State {
	case StateDevice:
		kind := "physical USB device"
		if d.IsEmulator {
			kind = "emulator"
		}
		return fmt.Sprintf("Status: connected / authorized (%s)\n", kind)
	case StateUnauthorized:
		return fmt.Sprintf("Device detected:\n    ID: %s\n    Model: %s\n    Status: unauthorized\n\nAction required:\n    Unlock the phone and accept the USB debugging authorization dialog.\n", d.Serial, d.Model)
	case StateOffline:
		return fmt.Sprintf("Device %s is offline.\nAction: unplug/replug USB-C, toggle USB debugging, or run: adb kill-server && adb start-server\n", d.Serial)
	case StateNoPermissions:
		return fmt.Sprintf("Device %s: no permissions.\nAction: check USB cable/port and macOS privacy prompts.\n", d.Serial)
	default:
		return fmt.Sprintf("Device %s status: %s\n", d.Serial, d.State)
	}
}

// SelectPhysical picks a physical device by serial, or the only ready one.
// Never silently picks when multiple ready devices exist.
func SelectPhysical(devs []Info, serial string) (Info, error) {
	if serial != "" {
		for _, d := range devs {
			if d.Serial != serial {
				continue
			}
			if d.IsEmulator {
				return Info{}, fmt.Errorf("serial %s is an emulator — use --emulator / --runtime-emulator", serial)
			}
			switch d.State {
			case StateDevice:
				return d, nil
			case StateUnauthorized:
				return d, fmt.Errorf("%s", Diagnose(d))
			default:
				return d, fmt.Errorf("device %s is not ready (status=%s)\n%s\n%s", serial, d.State, Diagnose(d), FormatTable(devs))
			}
		}
		return Info{}, fmt.Errorf("device %q not found\n%s", serial, FormatTable(devs))
	}

	var ready []Info
	var blocked []Info
	for _, d := range devs {
		if d.IsEmulator {
			continue
		}
		if d.State == StateDevice {
			ready = append(ready, d)
		} else {
			blocked = append(blocked, d)
		}
	}
	if len(ready) == 1 {
		return ready[0], nil
	}
	if len(ready) > 1 {
		return Info{}, fmt.Errorf("multiple physical devices connected — specify one explicitly:\n  apkcheck runtime app.apk --device-id <ID>\n  apkcheck analyze app.apk --runtime-device <ID>\n\n%s", FormatTable(devs))
	}
	if len(blocked) > 0 {
		return Info{}, fmt.Errorf("no authorized physical device ready\n%s", FormatTable(devs))
	}
	return Info{}, fmt.Errorf("no physical Android device connected via USB-C\nEnable USB debugging, connect the phone, then run: apkcheck devices\n\n%s", FormatTable(devs))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
