// Package emulator discovers and manages Android Virtual Devices.
package emulator

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/adb"
	"github.com/armin/apkcheck/internal/runtime/device"
	"github.com/armin/apkcheck/internal/runtime/env"
	"github.com/armin/apkcheck/internal/runtime/progress"
)

// AVD is one Android Virtual Device.
type AVD struct {
	Name   string `json:"name"`
	API    string `json:"api,omitempty"`
	ABI    string `json:"abi,omitempty"`
	Path   string `json:"path,omitempty"`
	Status string `json:"status"` // running | stopped | unknown
	Serial string `json:"serial,omitempty"`
}

// Manager controls the emulator binary.
type Manager struct {
	SDK      env.SDK
	ADB      *adb.Client
	Emulator string
}

// NewManager constructs an emulator manager (emulator binary may be empty for listing AVDs from disk).
func NewManager(sdk env.SDK, client *adb.Client) *Manager {
	return &Manager{SDK: sdk, ADB: client, Emulator: sdk.Emulator}
}

// ListAVDs returns configured AVDs and marks running ones.
func (m *Manager) ListAVDs(ctx context.Context) ([]AVD, error) {
	names := []string{}
	seen := map[string]bool{}

	if m.Emulator != "" {
		res, err := runner.Run(ctx, m.Emulator, "-list-avds")
		if err == nil {
			for _, line := range strings.Split(res.Stdout, "\n") {
				name := strings.TrimSpace(line)
				if name == "" || seen[name] {
					continue
				}
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	// Fallback / supplement: scan ~/.android/avd/*.ini
	for _, name := range listAVDIniNames() {
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) == 0 && m.Emulator == "" {
		return nil, fmt.Errorf("no AVDs found — install Android SDK emulator, create an AVD, set ANDROID_HOME")
	}

	running := map[string]string{}
	if m.ADB != nil {
		devs, _ := device.List(ctx, m.ADB, false)
		for _, d := range devs {
			if !d.IsEmulator || d.State != "device" {
				continue
			}
			name, _ := m.ADB.Shell(ctx, d.Serial, "getprop", "ro.boot.qemu.avd_name")
			name = strings.TrimSpace(name)
			if name == "" {
				name, _ = m.ADB.Shell(ctx, d.Serial, "getprop", "ro.kernel.qemu.avd_name")
				name = strings.TrimSpace(name)
			}
			if name != "" {
				running[name] = d.Serial
			}
		}
	}

	var avds []AVD
	for _, name := range names {
		a := AVD{Name: name, Status: "stopped"}
		if serial, ok := running[name]; ok {
			a.Status = "running"
			a.Serial = serial
		}
		a.API, a.ABI, a.Path = readAVDConfig(m.SDK.Root, name)
		avds = append(avds, a)
	}
	return avds, nil
}

func listAVDIniNames() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := filepath.Join(home, ".android", "avd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".ini") && !e.IsDir() {
			names = append(names, strings.TrimSuffix(name, ".ini"))
		}
	}
	return names
}

func readAVDConfig(sdkRoot, name string) (api, abi, path string) {
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".android", "avd", name+".avd", "config.ini"),
	}
	if sdkRoot != "" {
		candidates = append(candidates, filepath.Join(sdkRoot, "avd", name+".avd", "config.ini"))
	}
	// Also follow path= from the .ini sidecar.
	if home != "" {
		if data, err := os.ReadFile(filepath.Join(home, ".android", "avd", name+".ini")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "path=") {
					candidates = append([]string{filepath.Join(strings.TrimPrefix(line, "path="), "config.ini")}, candidates...)
				}
			}
		}
	}
	for _, c := range candidates {
		data, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		path = filepath.Dir(c)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "AndroidVersion.ApiLevel="):
				api = strings.TrimPrefix(line, "AndroidVersion.ApiLevel=")
			case strings.HasPrefix(line, "image.sysdir") && strings.Contains(line, "android-"):
				if i := strings.Index(line, "android-"); i >= 0 {
					rest := line[i+len("android-"):]
					j := 0
					for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
						j++
					}
					if j > 0 && api == "" {
						api = rest[:j]
					}
				}
			case strings.HasPrefix(line, "abi.type="):
				abi = strings.TrimPrefix(line, "abi.type=")
			case strings.HasPrefix(line, "hw.cpu.arch=") && abi == "":
				abi = strings.TrimPrefix(line, "hw.cpu.arch=")
			}
		}
		return api, abi, path
	}
	return "", "", ""
}

// Start launches an AVD if not already running. Returns emulator serial.
// progressOut may be nil; when set, boot wait uses plain status lines (not a download bar).
func (m *Manager) Start(ctx context.Context, avd string, coldBoot bool, bootTimeout time.Duration, progressOut io.Writer) (string, error) {
	if m.Emulator == "" {
		return "", fmt.Errorf("emulator binary not found — install Android SDK emulator and set ANDROID_HOME")
	}
	if m.ADB == nil {
		return "", fmt.Errorf("adb required to start emulator")
	}
	if avd == "" {
		return "", fmt.Errorf("avd name required")
	}
	if bootTimeout <= 0 {
		bootTimeout = 180 * time.Second
	}
	if progressOut == nil {
		progressOut = io.Discard
	}
	wait := progress.NewWaiter(progressOut, progress.EmulatorLabel(avd), "boot")

	avds, err := m.ListAVDs(ctx)
	if err != nil {
		return "", err
	}
	found := false
	for _, a := range avds {
		if a.Name == avd {
			found = true
			// coldBoot/wipe must not reuse a live guest — stop first then relaunch.
			if a.Status == "running" && a.Serial != "" && !coldBoot {
				wait.Start()
				wait.Success(fmt.Sprintf("already running (%s)", a.Serial))
				return a.Serial, nil
			}
			if a.Status == "running" && a.Serial != "" && coldBoot {
				wait.Info("cold-boot requested — stopping running emulator first")
				_ = m.Stop(ctx, a.Serial)
				select {
				case <-ctx.Done():
					return "", ctx.Err()
				case <-time.After(2 * time.Second):
				}
			}
		}
	}
	if !found {
		return "", fmt.Errorf("AVD %q not found\nRun: apkcheck emulator-create --name %s", avd, avd)
	}

	wait.Start()
	wait.Info("starting emulator (system image already local; this is not a download)")
	logPath := filepath.Join(os.TempDir(), "apkcheck-emulator-"+sanitizeFile(avd)+".log")
	logFile, logErr := os.Create(logPath)
	args := []string{"-avd", avd, "-no-audio"}
	// Headless on Linux Lab hosts (tool laptop). Set APKCHECK_EMU_WINDOW=1 for a window.
	if os.Getenv("APKCHECK_EMU_WINDOW") != "1" && (runtime.GOOS == "linux" || os.Getenv("APKCHECK_EMU_HEADLESS") == "1") {
		args = append(args, "-no-window")
	}
	if coldBoot {
		// Lab security runs need a clean guest after each recorded scenario.
		args = append(args, "-no-snapshot-load", "-wipe-data")
	}
	cmd := exec.Command(m.Emulator, args...) //nolint:gosec // path from SDK discovery
	// Emulator prints FATAL to stdout sometimes; capture both streams.
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	// Critical: emulator validates ANDROID_SDK_ROOT must contain platform-tools/.
	envVars := os.Environ()
	if m.SDK.Root != "" {
		envVars = append(envVars,
			"ANDROID_HOME="+m.SDK.Root,
			"ANDROID_SDK_ROOT="+m.SDK.Root,
		)
	}
	cmd.Env = envVars

	exited := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		wait.Fail(err)
		return "", fmt.Errorf("start emulator: %w", err)
	}
	go func() {
		err := cmd.Wait()
		if logFile != nil {
			_ = logFile.Close()
		}
		exited <- err
	}()

	deadline := time.Now().Add(bootTimeout)
	t0 := time.Now()
	var lastState string
	nextHint := 5 * time.Second
	for time.Now().Before(deadline) {
		elapsed := time.Since(t0)
		detail := "waiting for sys.boot_completed"
		if lastState != "" {
			detail = "adb: " + lastState + " · waiting for boot"
		} else if elapsed >= 3*time.Second {
			detail = "no emulator in adb yet · starting…"
		}
		wait.UpdateTimed(elapsed, bootTimeout, detail)

		select {
		case <-ctx.Done():
			wait.Fail(ctx.Err())
			return "", ctx.Err()
		case err := <-exited:
			snip := tailFile(logPath, 12)
			wait.Info("emulator process exited early — see %s", logPath)
			if snip != "" {
				wait.Info("log tail:\n%s", snip)
			}
			if err != nil {
				wait.Fail(err)
				return "", fmt.Errorf("emulator exited before boot: %w\n%s\n(log: %s)", err, snip, logPath)
			}
			wait.Fail(fmt.Errorf("emulator process exited before boot completed"))
			return "", fmt.Errorf("emulator process exited before boot\n%s\n(log: %s)", snip, logPath)
		case <-time.After(1500 * time.Millisecond):
		}

		devs, err := device.List(ctx, m.ADB, false)
		if err != nil {
			continue
		}
		lastState = describeEmulators(devs)
		if lastState == "" {
			lastState = "(none)"
		}
		if serial, ok := pickBootedEmulator(ctx, m.ADB, devs, avd); ok {
			wait.Success(fmt.Sprintf("booted %s in %s", serial, elapsed.Truncate(time.Second)))
			return serial, nil
		}
		if elapsed >= nextHint {
			if lastState == "(none)" {
				wait.Info("still no adb device — check Mac Dock for Android Emulator; log: %s", logPath)
			} else {
				wait.Info("adb devices: %s", lastState)
			}
			nextHint += 30 * time.Second
		}
	}
	if logErr == nil {
		wait.Info("emulator log: %s", logPath)
	}
	if lastState != "" {
		wait.Info("adb last saw: %s", lastState)
	}
	if snip := tailFile(logPath, 8); snip != "" {
		wait.Info("log tail:\n%s", snip)
	}
	err = fmt.Errorf("boot timeout after %s", bootTimeout)
	wait.Fail(err)
	return "", fmt.Errorf("emulator boot timeout after %s for AVD %s (log: %s; try --boot-timeout 10m or apkcheck hunt for static-only)", bootTimeout, avd, logPath)
}

func tailFile(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, "    "+l)
	}
	return strings.Join(out, "\n")
}

func pickBootedEmulator(ctx context.Context, client *adb.Client, devs []device.Info, avd string) (string, bool) {
	var booted []struct {
		serial string
		name   string
	}
	for _, d := range devs {
		if !d.IsEmulator {
			continue
		}
		if d.State != "device" {
			continue
		}
		boot, _ := client.GetProp(ctx, d.Serial, "sys.boot_completed")
		if strings.TrimSpace(boot) != "1" {
			continue
		}
		name, _ := client.Shell(ctx, d.Serial, "getprop", "ro.boot.qemu.avd_name")
		name = strings.TrimSpace(name)
		if name == "" {
			name, _ = client.Shell(ctx, d.Serial, "getprop", "ro.kernel.qemu.avd_name")
			name = strings.TrimSpace(name)
		}
		booted = append(booted, struct {
			serial string
			name   string
		}{d.Serial, name})
	}
	for _, b := range booted {
		if b.name == avd {
			return b.serial, true
		}
	}
	// Single booted emulator: use it (AVD name props are often empty on some images).
	if len(booted) == 1 {
		return booted[0].serial, true
	}
	return "", false
}

func describeEmulators(devs []device.Info) string {
	var parts []string
	for _, d := range devs {
		if !d.IsEmulator {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s", d.Serial, d.State))
	}
	return strings.Join(parts, ", ")
}

func sanitizeFile(s string) string {
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
	if s == "" {
		return "avd"
	}
	return s
}

// Stop shuts down an emulator by serial.
func (m *Manager) Stop(ctx context.Context, serial string) error {
	if m.ADB == nil {
		return fmt.Errorf("adb unavailable")
	}
	if serial == "" {
		return fmt.Errorf("serial required")
	}
	_, err := m.ADB.SerialRun(ctx, serial, "emu", "kill")
	return err
}

// StopAVD shuts down a running emulator by AVD name.
func (m *Manager) StopAVD(ctx context.Context, name string) error {
	avds, err := m.ListAVDs(ctx)
	if err != nil {
		return err
	}
	for _, a := range avds {
		if a.Name == name {
			if a.Status != "running" || a.Serial == "" {
				return fmt.Errorf("AVD %q is not running", name)
			}
			return m.Stop(ctx, a.Serial)
		}
	}
	return fmt.Errorf("AVD %q not found", name)
}

// StopAll kills every running emulator instance reported by adb.
func (m *Manager) StopAll(ctx context.Context) (stopped []string, err error) {
	if m.ADB == nil {
		return nil, fmt.Errorf("adb unavailable")
	}
	devs, err := device.List(ctx, m.ADB, false)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, d := range devs {
		if !d.IsEmulator {
			continue
		}
		if err := m.Stop(ctx, d.Serial); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		stopped = append(stopped, d.Serial)
	}
	return stopped, firstErr
}

// Restart stops (if running) then starts an AVD. Returns serial.
func (m *Manager) Restart(ctx context.Context, avd string, coldBoot bool, bootTimeout time.Duration, progressOut io.Writer) (string, error) {
	avds, err := m.ListAVDs(ctx)
	if err != nil {
		return "", err
	}
	for _, a := range avds {
		if a.Name == avd && a.Status == "running" && a.Serial != "" {
			_ = m.Stop(ctx, a.Serial)
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				still, _ := m.ListAVDs(ctx)
				running := false
				for _, x := range still {
					if x.Name == avd && x.Status == "running" {
						running = true
						break
					}
				}
				if !running {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			break
		}
	}
	return m.Start(ctx, avd, coldBoot, bootTimeout, progressOut)
}

// RunningSummary counts configured vs running AVDs and adb emulator serials.
func (m *Manager) RunningSummary(ctx context.Context) (configured, running int, serials []string, err error) {
	avds, err := m.ListAVDs(ctx)
	if err != nil {
		return 0, 0, nil, err
	}
	configured = len(avds)
	seen := map[string]struct{}{}
	for _, a := range avds {
		if a.Status == "running" && a.Serial != "" {
			running++
			seen[a.Serial] = struct{}{}
			serials = append(serials, a.Serial)
		}
	}
	// Include any emulator-* adb devices not mapped to an AVD name.
	if m.ADB != nil {
		devs, _ := device.List(ctx, m.ADB, false)
		for _, d := range devs {
			if !d.IsEmulator {
				continue
			}
			if _, ok := seen[d.Serial]; ok {
				continue
			}
			running++
			serials = append(serials, d.Serial)
		}
	}
	return configured, running, serials, nil
}

// FormatTable renders emulator list.
func FormatTable(avds []AVD) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%-22s %-8s %-12s %-10s %s\n", "AVD NAME", "API", "ARCH", "STATUS", "SERIAL"))
	if len(avds) == 0 {
		b.WriteString("(none — install Android SDK emulator + create an AVD)\n")
		return b.String()
	}
	for _, a := range avds {
		ser := a.Serial
		if ser == "" {
			ser = "—"
		}
		b.WriteString(fmt.Sprintf("%-22s %-8s %-12s %-10s %s\n", a.Name, a.API, a.ABI, a.Status, ser))
	}
	return b.String()
}
