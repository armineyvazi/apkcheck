// Package runtime orchestrates Android dynamic analysis on macOS.
//
// Hierarchy of evidence:
//
//	DEX/Smali → primary static reference
//	Decompiler output → reconstruction
//	Runtime observation → exercised behavior only
//	Inference → derived interpretation
//
// Runtime is NEVER treated as complete application behavior.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/apk"
	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/adb"
	"github.com/armin/apkcheck/internal/runtime/config"
	"github.com/armin/apkcheck/internal/runtime/correlation"
	"github.com/armin/apkcheck/internal/runtime/device"
	"github.com/armin/apkcheck/internal/runtime/emulator"
	"github.com/armin/apkcheck/internal/runtime/env"
	"github.com/armin/apkcheck/internal/runtime/installer"
	"github.com/armin/apkcheck/internal/runtime/instrumentation"
	"github.com/armin/apkcheck/internal/runtime/launcher"
	"github.com/armin/apkcheck/internal/runtime/logcat"
	"github.com/armin/apkcheck/internal/runtime/network"
	"github.com/armin/apkcheck/internal/runtime/permissions"
	"github.com/armin/apkcheck/internal/runtime/process"
	"github.com/armin/apkcheck/internal/runtime/progress"
	"github.com/armin/apkcheck/internal/runtime/scenarios"
	"github.com/armin/apkcheck/internal/runtime/screenshots"
	"github.com/armin/apkcheck/internal/runtime/status"
	"github.com/armin/apkcheck/internal/runtime/timeline"
	"github.com/armin/apkcheck/pkg/model"
)

// Environment prepares, installs, launches, collects, and cleans up.
// Physical device and macOS emulator both implement this interface.
type Environment interface {
	Prepare(ctx context.Context) error
	Install(ctx context.Context, apk string) error
	Launch(ctx context.Context, packageName string) error
	Collect(ctx context.Context) (*Evidence, error)
	Cleanup(ctx context.Context) error
	Serial() string
}

// Options controls a runtime session (CLI overrides config).
type Options struct {
	APKPath          string
	OutputDir        string
	SessionName      string
	DeviceSerial     string // physical device ID (--device-id / --runtime-device)
	EmulatorAVD      string // AVD name (--emulator / --runtime-emulator)
	Package          string
	Activity         string
	Duration         time.Duration
	Screenshots      bool
	KeepEmulator     bool
	ShutdownEmulator bool
	SkipInstall      bool
	Scenario         string
	ConfigPath       string
	DeclaredPerms    []string
	StaticMethods    []model.MethodResult // optional for correlation
	Mode             string               // device|emulator|auto
	// AutoProvision downloads system images / creates AVDs when missing (default true).
	AutoProvision bool
	// NoAutoSetup disables AutoProvision when true.
	NoAutoSetup bool
	// BootTimeout overrides config emulator boot wait (0 = use config).
	BootTimeout time.Duration
}

// Evidence is the full runtime session payload.
type Evidence struct {
	SessionID       string                   `json:"session_id"`
	StartedAt       time.Time                `json:"started_at"`
	EndedAt         time.Time                `json:"ended_at"`
	Warning         string                   `json:"warning"`
	Runtime         RuntimeInfo              `json:"runtime"`
	Device          *device.Info             `json:"device,omitempty"`
	APK             *installer.Meta          `json:"apk,omitempty"`
	Install         *installer.Result        `json:"install,omitempty"`
	Launch          *launcher.Result         `json:"launch,omitempty"`
	Process         *process.Info            `json:"process,omitempty"`
	Permissions     []permissions.Status     `json:"permissions,omitempty"`
	Crashes         []logcat.Crash           `json:"crashes,omitempty"`
	Network         []network.Observation    `json:"network,omitempty"`
	Timeline        []timeline.Event         `json:"timeline"`
	Correlations    []correlation.MethodLink `json:"correlations,omitempty"`
	Screenshots     []string                 `json:"screenshots,omitempty"`
	LogcatPath      string                   `json:"logcat_path"`
	PackageDumpPath string                   `json:"package_dump_path,omitempty"`
	NetworkRawPath  string                   `json:"network_raw_path,omitempty"`
	Notes           []string                 `json:"notes"`
	Limitations     []string                 `json:"limitations"`
	Environment     map[string]string        `json:"environment"`
}

// Session is the orchestrator implementing Environment.
type Session struct {
	opts   Options
	cfg    config.RuntimeConfig
	sdk    env.SDK
	client *adb.Client
	emu    *emulator.Manager
	serial string
	pkg    string
	target launcher.Target
	tl     *timeline.Builder
	dir    string
	ev     *Evidence
	st     *status.Printer
}

// NewSession builds a runtime session from options + yaml config.
func NewSession(opts Options) (*Session, error) {
	// Auto-set ANDROID_HOME / JAVA_HOME / PATH for sdk tools.
	sdk, err := env.Bootstrap()
	if err != nil && opts.Mode == "emulator" {
		return nil, err
	}
	if sdk.Root == "" {
		sdk = env.Discover()
	}

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	if opts.Mode != "" {
		cfg.Mode = opts.Mode
	}
	if opts.EmulatorAVD != "" {
		cfg.Emulator.AVD = opts.EmulatorAVD
		if opts.Mode == "" {
			cfg.Mode = "emulator"
		}
	}
	if opts.DeviceSerial != "" {
		if opts.Mode == "" {
			cfg.Mode = "device"
		}
	}
	if opts.Screenshots {
		cfg.Screenshots.Enabled = true
	}
	if opts.KeepEmulator {
		cfg.Cleanup.KeepEmulator = true
		cfg.Cleanup.Shutdown = false
	}
	if opts.ShutdownEmulator {
		cfg.Cleanup.Shutdown = true
		cfg.Cleanup.KeepEmulator = false
	}
	if opts.SkipInstall {
		cfg.Installation.SkipInstall = true
	}
	if opts.Activity != "" {
		cfg.Execution.Activity = opts.Activity
	}
	if opts.Duration > 0 {
		cfg.Logcat.Duration = config.Duration(opts.Duration)
	}
	if opts.BootTimeout > 0 {
		cfg.Emulator.BootTimeout = config.Duration(opts.BootTimeout)
	}
	if opts.SessionName == "" {
		opts.SessionName = time.Now().UTC().Format("runtime-session-2006-01-02-150405")
	}
	opts.SessionName = SanitizeSessionName(opts.SessionName)
	if opts.OutputDir == "" {
		opts.OutputDir = "./analysis"
	}
	// Default: auto-provision emulator images/AVDs.
	if !opts.NoAutoSetup {
		opts.AutoProvision = true
	}

	client, err := adb.New(sdk)
	if err != nil {
		return nil, err
	}
	s := &Session{opts: opts, cfg: cfg, sdk: sdk, client: client, emu: emulator.NewManager(sdk, client), st: status.New(os.Stderr)}
	if cfg.Instrumentation.Enabled {
		if err := instrumentation.Validate(instrumentation.Request{
			Enabled: true, Provider: cfg.Instrumentation.Provider,
		}); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Prepare selects device/emulator and waits until ready.
func (s *Session) Prepare(ctx context.Context) error {
	if s.st == nil {
		s.st = status.New(os.Stderr)
	}
	s.dir = filepath.Join(s.opts.OutputDir, "runtime", s.opts.SessionName)
	for _, sub := range []string{"", "screenshots", "logcat", "network", "correlation"} {
		if err := os.MkdirAll(filepath.Join(s.dir, sub), 0o750); err != nil {
			return err
		}
	}
	s.tl = timeline.New(time.Now().UTC())
	s.ev = &Evidence{
		SessionID: s.opts.SessionName,
		StartedAt: time.Now().UTC(),
		Warning:   "UNTRUSTED APK: runtime execution runs untrusted software inside Android (device/emulator), not as a privileged host process.",
		Notes: []string{
			"Runtime observations cover only exercised paths.",
			"NOT OBSERVED ≠ does not exist.",
			"DEX/Smali remains primary static reference.",
		},
		Limitations: []string{
			"No TLS MITM / decryption by default.",
			"UI automation is best-effort in this version.",
			"Frida instrumentation is optional and not bundled.",
			"Coverage is incomplete unless scenarios exercise code.",
		},
		Environment: map[string]string{
			"android_sdk": s.sdk.Root,
			"adb":         s.client.Path,
			"emulator":    s.sdk.Emulator,
		},
	}
	s.tl.Add("prepare", "runtime session starting", "RUNTIME_OBSERVATION")

	mode := s.cfg.Mode
	if mode == "" || mode == "auto" {
		if s.cfg.Emulator.AVD != "" || s.opts.EmulatorAVD != "" {
			mode = "emulator"
		} else {
			devs, _ := device.List(ctx, s.client, false)
			if _, err := device.SelectPhysical(devs, s.opts.DeviceSerial); err == nil {
				mode = "device"
			} else if s.opts.DeviceSerial != "" {
				mode = "device"
			} else {
				return fmt.Errorf("runtime auto: cannot choose deterministically\nUse one of:\n  apkcheck runtime app.apk --device-id <USB-ID>\n  apkcheck runtime app.apk --emulator <AVD>\n  apkcheck analyze app.apk --runtime-device <ID>\n  apkcheck analyze app.apk --runtime-emulator <AVD>\n\n%s", device.FormatTable(devs))
			}
		}
	}

	targetHint := s.opts.EmulatorAVD
	if mode == "device" {
		targetHint = firstNonEmpty(s.opts.DeviceSerial, "USB device")
	}
	s.st.Banner(s.opts.APKPath, mode, targetHint)
	if s.cfg.WarnUntrusted {
		s.st.Warn("untrusted APK will execute inside Android (emulator/device), not as a host process")
	}

	switch mode {
	case "emulator":
		if err := s.prepareEmulator(ctx); err != nil {
			s.st.Fail("%v", err)
			return err
		}
	case "device":
		devs, err := device.List(ctx, s.client, true)
		if err != nil {
			return fmt.Errorf("adb devices failed: %w\nIs ADB installed? brew install android-platform-tools", err)
		}
		s.st.Phase("Physical device")
		chosen, err := device.SelectPhysical(devs, s.opts.DeviceSerial)
		if err != nil {
			return err
		}
		s.serial = chosen.Serial
		s.ev.Device = &chosen
		s.ev.Runtime = runtimeInfoFromDevice(&chosen, "device", "")
		s.st.OK("using %s (%s) API %s %s", chosen.Serial, chosen.Model, chosen.APILevel, chosen.ABI)
		s.tl.Add("device", "using "+s.serial+" ("+chosen.Model+")", "RUNTIME_OBSERVATION")
	default:
		return fmt.Errorf("unknown runtime mode %q (want device|emulator|auto)", mode)
	}

	devs, _ := device.List(ctx, s.client, true)
	for i := range devs {
		if devs[i].Serial == s.serial {
			s.ev.Device = &devs[i]
			s.ev.Runtime = runtimeInfoFromDevice(&devs[i], mode, s.cfg.Emulator.AVD)
			break
		}
	}
	if ver, err := s.client.Version(ctx); err == nil {
		s.ev.Environment["adb_version"] = ver
	}
	s.ev.Environment["runtime_type"] = s.ev.Runtime.Type
	s.ev.Environment["host_arch"] = s.sdk.HostArch
	s.st.OK("runtime environment ready")
	return nil
}

func (s *Session) prepareEmulator(ctx context.Context) error {
	s.st.Phase("Environment")
	if s.emu == nil || s.emu.Emulator == "" {
		if sdk, berr := env.Bootstrap(); berr == nil {
			s.sdk = sdk
			s.emu = emulator.NewManager(sdk, s.client)
		}
	}
	if s.emu == nil || s.emu.Emulator == "" {
		return fmt.Errorf("emulator unavailable — brew install --cask android-commandlinetools")
	}
	if s.sdk.Root != "" {
		s.st.OK("ANDROID_HOME = %s", s.sdk.Root)
	}
	if s.sdk.JavaHome != "" {
		s.st.OK("JAVA_HOME = %s", s.sdk.JavaHome)
	} else {
		s.st.Warn("JDK 17+ not found — avdmanager may fail (brew install openjdk@17)")
	}
	s.st.OK("emulator = %s", s.sdk.Emulator)

	avd := s.cfg.Emulator.AVD
	if avd == "" {
		avd = s.opts.EmulatorAVD
	}
	if avd == "" {
		avds, err := s.emu.ListAVDs(ctx)
		if err != nil {
			return err
		}
		if len(avds) == 0 {
			if !s.opts.AutoProvision {
				return fmt.Errorf("no AVDs found — create one or omit --no-auto-setup")
			}
			avd = "Pixel_8_API_34"
			s.st.Info("no AVD found — will auto-create %s", avd)
		} else if len(avds) == 1 {
			avd = avds[0].Name
			s.st.Info("using sole AVD %s", avd)
		} else {
			return fmt.Errorf("multiple AVDs found — specify --emulator <AVD>\n\n%s", emulator.FormatTable(avds))
		}
		s.cfg.Emulator.AVD = avd
		s.opts.EmulatorAVD = avd
	}

	s.st.Phase("System image & AVD")
	opt := emulator.ParseCreateFromName(avd)
	imgDir := emulator.ImageDir(s.sdk.Root, opt.API, opt.Tag, opt.ABI)
	imgOK := emulator.ImageReady(imgDir)
	if imgOK {
		s.st.OK("system image present: android-%s/%s/%s (%.0f MB)", opt.API, opt.Tag, opt.ABI, emulator.ImageSizeMB(imgDir))
	} else {
		s.st.Warn("system image MISSING: %s", imgDir)
		if !s.opts.AutoProvision {
			return fmt.Errorf("system image missing and --no-auto-setup set")
		}
		s.st.Working("fetching system image (resume supported)…")
	}

	avds, _ := s.emu.ListAVDs(ctx)
	found := false
	for _, a := range avds {
		if a.Name == avd {
			found = true
			if ok, msg := s.sdk.CompatibleWithAVD(a.ABI); !ok {
				return fmt.Errorf("%s", msg)
			}
			s.st.OK("AVD %s found (%s, API %s)", a.Name, a.ABI, a.API)
			break
		}
	}
	if !found {
		s.st.Warn("AVD %q does not exist yet", avd)
	}

	needProvision := !found || !imgOK
	if needProvision {
		if !s.opts.AutoProvision {
			return fmt.Errorf("AVD/image missing for %q — run without --no-auto-setup", avd)
		}
		s.st.Phase("Auto-provision")
		opt.Progress = os.Stderr
		opt.Force = false // never wipe existing AVD; EnsureAVD still repairs missing image
		if err := s.emu.EnsureAVD(ctx, opt); err != nil {
			return fmt.Errorf("auto-provision: %w", err)
		}
		s.st.OK("provisioned / verified AVD %s", avd)
		s.ev.Notes = append(s.ev.Notes, "auto-provisioned AVD "+avd)
		s.tl.Add("emulator", "auto-provisioned "+avd, "RUNTIME_OBSERVATION")
	} else {
		s.st.OK("image + AVD ready — no download needed")
	}

	s.st.Phase("Boot emulator")
	s.tl.Add("emulator", "starting "+avd, "RUNTIME_OBSERVATION")
	serial, err := s.emu.Start(ctx, avd, s.cfg.Emulator.ColdBoot, s.cfg.Emulator.BootTimeout.Duration(), os.Stderr)
	if err != nil {
		return err
	}
	s.serial = serial
	s.tl.Add("emulator", "boot completed serial="+serial, "RUNTIME_OBSERVATION")
	s.ev.Runtime = runtimeInfoFromDevice(nil, "emulator", avd)
	if s.sdk.JavaHome != "" {
		s.ev.Environment["java_home"] = s.sdk.JavaHome
	}
	return nil
}

func (s *Session) Serial() string { return s.serial }

// Install installs the APK unless skipped.
func (s *Session) Install(ctx context.Context, apkPath string) error {
	if s.st == nil {
		s.st = status.New(os.Stderr)
	}
	s.st.Phase("Install APK")
	meta, err := installer.InspectAPK(apkPath)
	if err != nil {
		return err
	}
	s.st.Info("sha256 %s…", meta.SHA256[:min(12, len(meta.SHA256))])
	// Enrich package via aapt if missing.
	pkg := s.opts.Package
	activity := s.cfg.Execution.Activity
	if aapt := firstNonEmpty(s.sdk.AAPT2, s.sdk.AAPT); aapt != "" {
		if res, err := runner.Run(ctx, aapt, "dump", "badging", apkPath); err == nil && res != nil {
			p, a := launcher.ParseBadging(res.Stdout + res.Stderr)
			if pkg == "" {
				pkg = p
			}
			if activity == "" {
				activity = a
			}
			if meta.Package == "" {
				meta.Package = p
			}
		}
	}
	s.pkg = pkg
	if s.pkg == "" {
		s.pkg = meta.Package
	}
	s.ev.APK = meta
	if s.pkg != "" {
		s.st.OK("package %s", s.pkg)
	}
	if info, err := apkInspect(apkPath); err == nil && len(info.Permissions) > 0 && len(s.opts.DeclaredPerms) == 0 {
		s.opts.DeclaredPerms = info.Permissions
	}
	s.tl.Add("apk", fmt.Sprintf("sha256=%s package=%s", meta.SHA256, s.pkg), "STATIC_EVIDENCE")

	if note := installer.DetectSplitFormat(apkPath); note != "" && !s.cfg.Installation.SkipInstall {
		s.tl.Add("install", note, "RUNTIME_OBSERVATION")
		return fmt.Errorf("%s", note)
	}
	if s.cfg.Installation.SkipInstall {
		s.tl.Add("install", "skipped", "INFERENCE")
		s.st.Info("install skipped")
		s.target = launcher.Target{Package: s.pkg, Activity: activity}
		return nil
	}
	if s.cfg.Installation.ClearData && s.pkg != "" {
		_ = installer.ClearData(ctx, s.client, s.serial, s.pkg)
	}
	s.st.Working("adb install on %s …", s.serial)
	instBar := progress.NewWaiter(os.Stderr, filepath.Base(apkPath), "install")
	instBar.Start()
	instBar.Info("pushing to %s (not a download)", s.serial)
	res, err := installer.Install(ctx, s.client, s.serial, apkPath, s.cfg.Installation.Reinstall)
	s.ev.Install = res
	if err != nil {
		instBar.Fail(err)
		s.tl.Add("install", "FAILED: "+err.Error(), "RUNTIME_OBSERVATION")
		s.st.Fail("install failed: %v", err)
		return err
	}
	instBar.Success("installed on " + s.serial)
	s.tl.Add("install", "success", "RUNTIME_OBSERVATION")
	s.st.OK("installed")
	if s.pkg == "" && res.Package != "" {
		s.pkg = res.Package
	}
	s.target = launcher.Target{Package: s.pkg, Activity: launcher.NormalizeActivity(s.pkg, activity)}
	return nil
}

// Launch starts the app / scenarios.
func (s *Session) Launch(ctx context.Context, packageName string) error {
	if s.st == nil {
		s.st = status.New(os.Stderr)
	}
	s.st.Phase("Launch app")
	if packageName != "" {
		s.pkg = packageName
		s.target.Package = packageName
	}
	if s.target.Activity == "" {
		t, err := launcher.ResolveLaunchTarget(ctx, s.client, s.serial, s.opts.APKPath, s.pkg, s.cfg.Execution.Activity, firstNonEmpty(s.sdk.AAPT2, s.sdk.AAPT))
		if err != nil {
			s.tl.Add("launch", "activity unresolved; trying monkey: "+err.Error(), "INFERENCE")
			out, merr := s.client.Shell(ctx, s.serial, "monkey", "-p", s.pkg, "-c", "android.intent.category.LAUNCHER", "1")
			if merr != nil {
				s.ev.Launch = &launcher.Result{Success: false, Target: launcher.Target{Package: s.pkg, Source: "monkey"}, Output: out, Error: merr.Error()}
				return fmt.Errorf("launch: %w (monkey: %v)", err, merr)
			}
			s.ev.Launch = &launcher.Result{Success: true, Target: launcher.Target{Package: s.pkg, Source: "monkey"}, Output: out}
			s.target = launcher.Target{Package: s.pkg, Source: "monkey"}
		} else {
			s.target = t
		}
	}
	if s.cfg.Screenshots.Enabled {
		if p, err := screenshots.Capture(ctx, s.client, s.serial, filepath.Join(s.dir, "screenshots"), "000-prelaunch.png"); err == nil {
			s.ev.Screenshots = append(s.ev.Screenshots, p)
		}
	}

	sc := s.cfg.Scenarios
	if s.opts.Scenario != "" {
		var filtered []scenarios.Scenario
		for _, x := range s.cfg.Scenarios {
			if x.Name == s.opts.Scenario {
				filtered = append(filtered, x)
			}
		}
		sc = filtered
		if len(sc) == 0 {
			sc = []scenarios.Scenario{{Name: s.opts.Scenario, Actions: []scenarios.Action{
				{Launch: true},
				{Wait: s.cfg.Logcat.Duration.Duration()},
			}}}
		}
	}
	if !s.cfg.Execution.Launch {
		s.tl.Add("launch", "disabled in config", "INFERENCE")
		return nil
	}
	if err := scenarios.Run(ctx, s.client, s.serial, s.target, sc, s.tl); err != nil {
		return err
	}
	s.ev.Launch = &launcher.Result{Success: true, Target: s.target}
	s.st.OK("launched %s", s.target.Package)
	if s.cfg.Screenshots.Enabled {
		if p, err := screenshots.Capture(ctx, s.client, s.serial, filepath.Join(s.dir, "screenshots"), "001-after-launch.png"); err == nil {
			s.ev.Screenshots = append(s.ev.Screenshots, p)
		}
	}
	return nil
}

// Collect gathers logcat, process, permissions, network, crashes, correlations.
func (s *Session) Collect(ctx context.Context) (*Evidence, error) {
	wait := s.cfg.Logcat.Duration.Duration()
	if wait <= 0 {
		wait = 20 * time.Second
	}
	logPath := filepath.Join(s.dir, "logcat", "logcat.txt")
	if s.cfg.Logcat.Enabled {
		s.tl.Add("logcat", fmt.Sprintf("capturing for %s — exercise the app now", wait), "RUNTIME_OBSERVATION")
		raw, err := logcat.Capture(ctx, s.client, s.serial, logPath, wait)
		if err != nil {
			s.ev.Notes = append(s.ev.Notes, "logcat: "+err.Error())
		}
		s.ev.LogcatPath = logPath
		filtered := logcat.FilterApp(raw, s.pkg)
		_ = os.WriteFile(filepath.Join(s.dir, "logcat", "logcat-filtered.txt"), []byte(filtered), 0o640)
		s.ev.Crashes = logcat.DetectCrashes(raw)
		for _, c := range s.ev.Crashes {
			s.tl.Add("crash", c.Kind+": "+c.Summary, "RUNTIME_OBSERVATION")
		}
	}

	if pi, err := process.Collect(ctx, s.client, s.serial, s.pkg); err == nil {
		s.ev.Process = pi
		if pi.PID != "" {
			s.tl.Add("process", "pid="+pi.PID, "RUNTIME_OBSERVATION")
		}
	}

	dumpPath := filepath.Join(s.dir, "package.json.txt")
	permRows, dump, _ := permissions.Compare(ctx, s.client, s.serial, s.pkg, s.opts.DeclaredPerms, nil)
	s.ev.Permissions = permRows
	if dump != "" {
		_ = os.WriteFile(dumpPath, []byte(dump), 0o640)
		s.ev.PackageDumpPath = dumpPath
	}

	if s.cfg.Network.Enabled && s.cfg.Network.CaptureConnections {
		obs, netRaw, _ := network.Collect(ctx, s.client, s.serial, s.pkg, true)
		s.ev.Network = obs
		if netRaw != "" {
			p := filepath.Join(s.dir, "network", "network-raw.txt")
			_ = os.WriteFile(p, []byte(netRaw), 0o640)
			s.ev.NetworkRawPath = p
		}
		if len(obs) > 0 {
			s.tl.Add("network", fmt.Sprintf("%d connection hints", len(obs)), "RUNTIME_OBSERVATION")
		}
	}

	var frames []logcat.Frame
	for _, c := range s.ev.Crashes {
		frames = append(frames, c.Frames...)
	}
	s.ev.Correlations = correlation.LinkCrashFrames(frames, s.opts.StaticMethods)
	corrPath := filepath.Join(s.dir, "correlation", "runtime-to-static.json")
	_ = writeJSON(corrPath, s.ev.Correlations)

	if s.cfg.Screenshots.Enabled {
		if p, err := screenshots.Capture(ctx, s.client, s.serial, filepath.Join(s.dir, "screenshots"), "002-final.png"); err == nil {
			s.ev.Screenshots = append(s.ev.Screenshots, p)
		}
	}

	s.ev.Timeline = s.tl.Sorted()
	s.ev.EndedAt = time.Now().UTC()
	_ = writeJSON(filepath.Join(s.dir, "session.json"), s.ev)
	_ = writeJSON(filepath.Join(s.dir, "timeline.json"), s.ev.Timeline)
	_ = writeJSON(filepath.Join(s.dir, "crashes.json"), s.ev.Crashes)
	_ = writeJSON(filepath.Join(s.dir, "permissions.json"), s.ev.Permissions)
	_ = writeJSON(filepath.Join(s.dir, "device.json"), s.ev.Device)
	_ = os.WriteFile(filepath.Join(s.dir, "timeline.txt"), []byte(timeline.FormatText(s.ev.Timeline)), 0o640)
	return s.ev, nil
}

// Cleanup optionally stops app / uninstalls / shuts emulator.
func (s *Session) Cleanup(ctx context.Context) error {
	_ = launcher.ForceStop(ctx, s.client, s.serial, s.pkg)
	if s.cfg.Cleanup.ClearData {
		_ = installer.ClearData(ctx, s.client, s.serial, s.pkg)
	}
	if s.cfg.Cleanup.Uninstall {
		_ = installer.Uninstall(ctx, s.client, s.serial, s.pkg)
	}
	if s.cfg.Cleanup.Shutdown && !s.cfg.Cleanup.KeepEmulator && s.emu != nil && s.serial != "" {
		_ = s.emu.Stop(ctx, s.serial)
		if s.tl != nil {
			s.tl.Add("emulator", "shutdown requested", "RUNTIME_OBSERVATION")
		}
	}
	if s.ev != nil && s.tl != nil {
		s.ev.Timeline = s.tl.Sorted()
		s.ev.EndedAt = time.Now().UTC()
		_ = writeJSON(filepath.Join(s.dir, "session.json"), s.ev)
		_ = writeJSON(filepath.Join(s.dir, "timeline.json"), s.ev.Timeline)
		_ = os.WriteFile(filepath.Join(s.dir, "timeline.txt"), []byte(timeline.FormatText(s.ev.Timeline)), 0o640)
	}
	return nil
}

// Run is the high-level pipeline.
func Run(ctx context.Context, opts Options) (*Evidence, error) {
	s, err := NewSession(opts)
	if err != nil {
		return nil, err
	}
	if err := s.Prepare(ctx); err != nil {
		return nil, err
	}
	if err := s.Install(ctx, opts.APKPath); err != nil {
		// still try to persist partial session
		_, _ = s.Collect(ctx)
		return s.ev, err
	}
	if err := s.Launch(ctx, s.pkg); err != nil {
		s.ev.Notes = append(s.ev.Notes, "launch: "+err.Error())
	}
	ev, err := s.Collect(ctx)
	_ = s.Cleanup(ctx)
	return ev, err
}

// ListDevices is a CLI helper.
func ListDevices(ctx context.Context) ([]device.Info, error) {
	sdk, _ := env.Bootstrap()
	if sdk.Root == "" {
		sdk = env.Discover()
	}
	client, err := adb.New(sdk)
	if err != nil {
		return nil, err
	}
	return device.List(ctx, client, true)
}

// ListEmulators is a CLI helper.
func ListEmulators(ctx context.Context) ([]emulator.AVD, error) {
	sdk, _ := env.Bootstrap()
	if sdk.Root == "" {
		sdk = env.Discover()
	}
	client, err := adb.New(sdk)
	if err != nil {
		client = nil
	}
	m := emulator.NewManager(sdk, client)
	return m.ListAVDs(ctx)
}

// CreateEmulator installs a system image (CDN fallback) and creates an AVD.
func CreateEmulator(ctx context.Context, opt EmulatorCreateOptions) error {
	sdk, err := env.Bootstrap()
	if err != nil {
		return err
	}
	client, err := adb.New(sdk)
	if err != nil {
		client = nil
	}
	m := emulator.NewManager(sdk, client)
	return m.EnsureAVD(ctx, opt)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o640)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func apkInspect(path string) (*model.APKInfo, error) {
	return apk.Inspect(path)
}

// FormatDevicesText renders connected devices.
func FormatDevicesText(devices []device.Info) string { return device.FormatTable(devices) }

// FormatEmulatorsText renders available AVDs.
func FormatEmulatorsText(avds []emulator.AVD) string { return emulator.FormatTable(avds) }

// EmulatorCreateOptions configures apkcheck emulator-create.
type EmulatorCreateOptions = emulator.CreateOptions

// SanitizeSessionName cleans session identifiers.
func SanitizeSessionName(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), ".")
	if out == "" || out == "." || out == ".." {
		return time.Now().UTC().Format("runtime-session-2006-01-02-150405")
	}
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}
