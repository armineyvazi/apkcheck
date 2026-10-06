// Package cli implements the apkcheck command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/analyze"
	"github.com/armin/apkcheck/internal/ci"
	"github.com/armin/apkcheck/internal/compareapk"
	"github.com/armin/apkcheck/internal/decompiler"
	"github.com/armin/apkcheck/internal/doctor"
	"github.com/armin/apkcheck/internal/mcp"
	aireport "github.com/armin/apkcheck/internal/report/ai"
	htmlreport "github.com/armin/apkcheck/internal/report/html"
	jsonreport "github.com/armin/apkcheck/internal/report/json"
	mdreport "github.com/armin/apkcheck/internal/report/markdown"
	"github.com/armin/apkcheck/internal/report/text"
	appruntime "github.com/armin/apkcheck/internal/runtime"
	"github.com/armin/apkcheck/internal/runtime/frida"
	"github.com/armin/apkcheck/internal/versioncmp"
	"github.com/armin/apkcheck/pkg/model"
)

// Run is the CLI entrypoint.
func Run(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return 2
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "version", "--version", "-V":
		fmt.Printf("apkcheck %s\n", analyze.Version)
		return 0
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return 0
	case "doctor":
		return cmdDoctor(rest)
	case "analyze":
		return cmdAnalyze(rest)
	case "hunt":
		return cmdHunt(rest)
	case "ci":
		return cmdCI(rest)
	case "diff-releases", "compare-releases":
		return cmdDiffReleases(rest)
	case "methods":
		return cmdMethods(rest)
	case "method":
		return cmdMethod(rest)
	case "diff":
		return cmdDiff(rest)
	case "report":
		return cmdReport(rest)
	case "versions", "compare-versions":
		return cmdCompareVersions(rest)
	case "devices":
		return cmdDevices(rest)
	case "emulators":
		return cmdEmulators(rest)
	case "emulator-create":
		return cmdEmulatorCreate(rest)
	case "mcp":
		return cmdMCP(rest)
	case "runtime":
		return cmdRuntime(rest)
	case "lab":
		return cmdLab(rest)
	default:
		lower := strings.ToLower(cmd)
		if strings.HasSuffix(lower, ".apk") || strings.HasSuffix(lower, ".xapk") ||
			strings.HasSuffix(lower, ".apks") || strings.HasSuffix(lower, ".apkm") ||
			strings.HasSuffix(lower, ".aab") {
			return cmdAnalyze(append([]string{cmd}, rest...))
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage(os.Stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `apkcheck — Smali-backed Android RE + security triage (DEX/Smali = source of truth)

Usage:
  apkcheck <apk|xapk|apks|aab> [options]
  apkcheck analyze <input> [--static] [--runtime] [options]
  apkcheck hunt <input> [options]     # full first-pass → REPORT.md
  apkcheck ci <input> [--config ci.yaml]  # machine-readable gates
  apkcheck diff-releases old.apk new.apk   # security finding delta between app versions
  apkcheck methods|method|diff|report|versions <input> [options]
  apkcheck devices | emulators | emulator-create | runtime | mcp
  apkcheck lab import|rebuild|validate|serve   # APK Laboratory workbench
  apkcheck doctor | version | help

Core differentiator:
  DEX/Smali = ground truth · Decompilers = reconstructions · Runtime = partial observation
  Evidence classes: STATIC_EVIDENCE | RUNTIME_OBSERVATION | INFERENCE | UNCERTAINTY
  NOT OBSERVED ≠ ABSENT

Hunt (one-command workflow):
  apkcheck hunt app.apk --output ./hunt-out
  apkcheck hunt app.xapk --frida --package com.example.app

CI:
  apkcheck ci app.apk --config configs/ci.yaml
  # exit 1 on STATIC_EVIDENCE failures; JSON on stdout

Options:
  --output DIR              Output directory (default: ./analysis)
  --format text|json|html|ai|md   Report formats (md = REPORT.md)
  --workers N               Parallel workers (default: 4)
  --limit N                 Max methods to compare (0 = all after filters)
  --skip-framework          Skip android/androidx/kotlin/java packages (default: true)
  --focus security          Prioritize security-relevant methods
  --decompiler NAME         jadx|cfr|fernflower (repeatable)
  --runtime / --emulator / --device / --frida
  --config PATH             CI or runtime YAML
  --fail-on low|medium|high|critical   (ci)
  See --help on each subcommand for full flags.

`)
}

type commonFlags struct {
	output        string
	formats       multiFlag
	workers       int
	keepTemp      bool
	verbose       bool
	focus         string
	decompilers   multiFlag
	className     string
	methodName    string
	cache         bool
	timeout       time.Duration
	limit         int
	skipFramework bool
	skipSynthetic bool
	includeEmpty  bool
	versionsFile  string
	jadx          string
	apktool       string
	cfr           string
	fernflower    string
	java          string
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

func parseCommon(fs *flag.FlagSet, cf *commonFlags) {
	cf.skipFramework = true
	cf.skipSynthetic = true

	fs.StringVar(&cf.output, "output", "./analysis", "output directory")
	fs.Var(&cf.formats, "format", "output format: text, json, html")
	fs.IntVar(&cf.workers, "workers", 4, "worker count")
	fs.BoolVar(&cf.keepTemp, "keep-temp", false, "keep temp files")
	fs.BoolVar(&cf.verbose, "verbose", false, "verbose logging")
	fs.StringVar(&cf.focus, "focus", "", "focus mode (security)")
	fs.Var(&cf.decompilers, "decompiler", "enable decompiler")
	fs.StringVar(&cf.className, "class", "", "class filter")
	fs.StringVar(&cf.methodName, "method", "", "method filter")
	fs.BoolVar(&cf.cache, "cache", false, "enable content-hash cache")
	fs.DurationVar(&cf.timeout, "timeout", 30*time.Minute, "timeout")
	fs.IntVar(&cf.limit, "limit", 0, "max methods to compare")
	fs.BoolVar(&cf.skipFramework, "skip-framework", true, "skip framework packages")
	fs.BoolVar(&cf.skipSynthetic, "skip-synthetic", true, "skip kotlin/r8 synthetics")
	fs.BoolVar(&cf.includeEmpty, "include-empty", false, "include empty/abstract/native")
	fs.StringVar(&cf.versionsFile, "versions-file", "", "pinned versions YAML")
	fs.StringVar(&cf.jadx, "jadx", "", "jadx path")
	fs.StringVar(&cf.apktool, "apktool", "", "apktool path")
	fs.StringVar(&cf.cfr, "cfr", "", "cfr path")
	fs.StringVar(&cf.fernflower, "fernflower-jar", "", "fernflower jar")
	fs.StringVar(&cf.java, "java", "", "java path")

	// Negating flags for convenience.
	fs.BoolFunc("no-skip-framework", "include framework packages", func(string) error {
		cf.skipFramework = false
		return nil
	})
	fs.BoolFunc("no-skip-synthetic", "include synthetic methods", func(string) error {
		cf.skipSynthetic = false
		return nil
	})
}

// reorderArgs moves positional APK paths after flags so
// `apkcheck analyze app.apk --output ./x` works like
// `apkcheck analyze --output ./x app.apk`.
func reorderArgs(args []string) []string {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			// attach value for --flag value (not --flag=value, not booleans without value)
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				name := strings.TrimLeft(a, "-")
				if !isBoolFlag(name) {
					flags = append(flags, args[i+1])
					i++
				}
			}
			continue
		}
		positionals = append(positionals, a)
	}
	return append(flags, positionals...)
}

func isBoolFlag(name string) bool {
	switch name {
	case "keep-temp", "verbose", "cache", "skip-framework", "skip-synthetic",
		"include-empty", "no-skip-framework", "no-skip-synthetic",
		"skip-install", "runtime", "static", "decompile", "device",
		"screenshots", "keep-emulator", "shutdown-emulator", "force", "no-auto-setup",
		"frida", "h", "help":
		return true
	default:
		return false
	}
}

// runtimeFlags holds shared physical-device / emulator selection flags.
type runtimeFlags struct {
	deviceMode       bool
	deviceID         string
	runtimeDeviceID  string
	emulatorAVD      string
	runtimeEmulator  string
	runtimeMode      string // auto|device|emulator (from --runtime value when string)
	activity         string
	scenario         string
	session          string
	pkg              string
	configPath       string
	instrumentation  string
	screenshots      bool
	keepEmulator     bool
	shutdownEmulator bool
	skipInstall      bool
	duration         time.Duration
	bootTimeout      time.Duration
	noAutoSetup      bool
}

func (rf *runtimeFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&rf.deviceMode, "device", false, "use physical Android device (USB-C)")
	fs.StringVar(&rf.deviceID, "device-id", "", "physical device serial")
	fs.StringVar(&rf.deviceID, "serial", "", "alias of --device-id")
	fs.StringVar(&rf.runtimeDeviceID, "runtime-device", "", "analyze: physical device serial")
	fs.StringVar(&rf.emulatorAVD, "emulator", "", "macOS AVD name (auto-creates/downloads image if missing; use 'auto' for Pixel_8_API_34)")
	fs.StringVar(&rf.runtimeEmulator, "runtime-emulator", "", "analyze: macOS AVD name (auto-provision)")
	fs.StringVar(&rf.runtimeMode, "runtime-mode", "", "auto|device|emulator")
	fs.StringVar(&rf.activity, "activity", "", "launch activity override")
	fs.StringVar(&rf.scenario, "scenario", "", "scenario name")
	fs.StringVar(&rf.session, "session", "", "runtime session name")
	fs.StringVar(&rf.pkg, "package", "", "package filter")
	fs.StringVar(&rf.configPath, "config", "", "apkcheck.yaml path")
	fs.StringVar(&rf.instrumentation, "instrumentation", "", "optional instrumentation")
	fs.BoolVar(&rf.screenshots, "screenshots", false, "capture screenshots")
	fs.BoolVar(&rf.keepEmulator, "keep-emulator", false, "keep emulator running")
	fs.BoolVar(&rf.shutdownEmulator, "shutdown-emulator", false, "shutdown emulator after session")
	fs.BoolVar(&rf.skipInstall, "skip-install", false, "do not adb install")
	fs.BoolVar(&rf.noAutoSetup, "no-auto-setup", false, "do not auto-download system image / create AVD")
	fs.DurationVar(&rf.duration, "duration", 0, "logcat capture duration")
	fs.DurationVar(&rf.bootTimeout, "boot-timeout", 0, "emulator boot wait (e.g. 10m; default from configs/apkcheck.yaml)")
}

func (rf *runtimeFlags) toOptions(apkPath, output string) appruntime.Options {
	opts := appruntime.Options{
		APKPath:          apkPath,
		OutputDir:        output,
		SessionName:      rf.session,
		Package:          rf.pkg,
		Activity:         rf.activity,
		Duration:         rf.duration,
		Screenshots:      rf.screenshots,
		KeepEmulator:     rf.keepEmulator,
		ShutdownEmulator: rf.shutdownEmulator,
		SkipInstall:      rf.skipInstall,
		Scenario:         rf.scenario,
		ConfigPath:       rf.configPath,
		NoAutoSetup:      rf.noAutoSetup,
		BootTimeout:      rf.bootTimeout,
	}
	opts.DeviceSerial = firstNonEmptyStr(rf.runtimeDeviceID, rf.deviceID)
	opts.EmulatorAVD = firstNonEmptyStr(rf.runtimeEmulator, rf.emulatorAVD)
	if opts.EmulatorAVD == "auto" || opts.EmulatorAVD == "default" {
		opts.EmulatorAVD = "Pixel_8_API_34"
	}

	switch {
	case rf.runtimeMode != "":
		opts.Mode = rf.runtimeMode
	case opts.DeviceSerial != "" || rf.deviceMode || rf.runtimeDeviceID != "":
		opts.Mode = "device"
	case opts.EmulatorAVD != "" || rf.runtimeEmulator != "":
		opts.Mode = "emulator"
	}
	return opts
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func parseFlags(name string, args []string, cf *commonFlags, extra func(*flag.FlagSet)) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	parseCommon(fs, cf)
	if extra != nil {
		extra(fs)
	}
	return fs.Parse(reorderArgs(args))
}

func (cf *commonFlags) toConfig(apkPath string) analyze.Config {
	skipFW := cf.skipFramework
	skipSyn := cf.skipSynthetic
	// Targeted method/class inspection should not hide framework matches.
	if cf.className != "" || cf.methodName != "" {
		skipFW = false
		skipSyn = false
	}
	return analyze.Config{
		APKPath:       apkPath,
		OutputDir:     cf.output,
		Workers:       cf.workers,
		KeepTemp:      cf.keepTemp,
		Verbose:       cf.verbose,
		Focus:         cf.focus,
		Decompilers:   cf.decompilers,
		ClassFilter:   cf.className,
		MethodFilter:  cf.methodName,
		UseCache:      cf.cache,
		Timeout:       cf.timeout,
		Limit:         cf.limit,
		SkipFramework: skipFW,
		SkipSynthetic: skipSyn,
		IncludeEmpty:  cf.includeEmpty,
		Paths: decompiler.Paths{
			JADX:       cf.jadx,
			Apktool:    cf.apktool,
			CFR:        cf.cfr,
			FernFlower: cf.fernflower,
			Java:       cf.java,
		},
	}
}

func cmdDoctor(args []string) int {
	var cf commonFlags
	if err := parseFlags("doctor", args, &cf, nil); err != nil {
		return 2
	}
	report := doctor.Check(context.Background(), decompiler.Paths{
		JADX: cf.jadx, Apktool: cf.apktool, CFR: cf.cfr,
		FernFlower: cf.fernflower, Java: cf.java,
	})
	_ = text.WriteDoctor(os.Stdout, report)
	if !report.OK {
		return 1
	}
	return 0
}

func cmdAnalyze(args []string) int {
	var cf commonFlags
	var runRuntime, runStatic, runDecompile bool
	var rf runtimeFlags

	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	parseCommon(fs, &cf)
	fs.BoolVar(&runRuntime, "runtime", false, "run Android runtime after static analysis")
	fs.BoolVar(&runStatic, "static", true, "run static analysis (default true)")
	fs.BoolVar(&runDecompile, "decompile", true, "run decompilers (default true)")
	rf.register(fs)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return 2
	}
	_ = runDecompile
	apkPath, err := requireAPK(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if rf.runtimeDeviceID != "" || rf.runtimeEmulator != "" || rf.deviceMode || rf.emulatorAVD != "" {
		runRuntime = true
	}
	formats := nonEmpty(cf.formats, []string{"text", "json", "html"})
	fmt.Fprintf(os.Stderr, "APKCheck v%s\n\n", analyze.Version)

	var result *model.AnalysisResult
	if runStatic {
		a := analyze.New(cf.toConfig(apkPath))
		result, err = a.Analyze(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "analyze failed: %v\n", err)
			return 1
		}
		if code := writeOutputs(result, cf.output, formats); code != 0 {
			return code
		}
	}

	if runRuntime {
		opts := rf.toOptions(apkPath, cf.output)
		if rf.instrumentation != "" {
			fmt.Fprintf(os.Stderr, "NOTE: instrumentation=%q must be enabled in apkcheck.yaml; CLI flag records intent only.\n", rf.instrumentation)
		}
		if result != nil {
			opts.StaticMethods = result.Methods
			if len(opts.DeclaredPerms) == 0 {
				opts.DeclaredPerms = result.APK.Permissions
			}
		}
		fmt.Fprintln(os.Stderr, "\n[runtime] starting Android runtime session…")
		ev, rerr := appruntime.Run(context.Background(), opts)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "runtime failed: %v\n", rerr)
			if ev != nil {
				if result != nil {
					result.Runtime = runtimeReportFromEvidence(ev, cf.output)
					_ = writeOutputs(result, cf.output, formats)
				}
				printRuntimeSummary(ev, cf.output)
			}
			return 1
		}
		printRuntimeSummary(ev, cf.output)
		if result != nil {
			result.Runtime = runtimeReportFromEvidence(ev, cf.output)
			_ = writeOutputs(result, cf.output, formats)
		} else {
			// Runtime-only analyze: still emit a thin report with runtime section.
			result = &model.AnalysisResult{
				SchemaVersion: model.SchemaVersion,
				ToolVersion:   analyze.Version,
				GeneratedAt:   time.Now().UTC(),
				APK:           model.APKInfo{Path: apkPath},
				Runtime:       runtimeReportFromEvidence(ev, cf.output),
				Notes:         []string{"static analysis skipped; runtime evidence only"},
				Limitations:   []string{"NOT OBSERVED ≠ absent — runtime covers exercised paths only"},
			}
			if ev.APK != nil {
				result.APK.SHA256 = ev.APK.SHA256
				result.APK.Package = ev.APK.Package
			}
			_ = writeOutputs(result, cf.output, formats)
		}
	}
	return 0
}

func cmdDevices(args []string) int {
	fs := flag.NewFlagSet("devices", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	devs, err := appruntime.ListDevices(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "devices: %v\n", err)
		fmt.Fprintln(os.Stderr, "Install ADB: brew install android-platform-tools")
		fmt.Fprintln(os.Stderr, "Connect phone via USB-C, enable USB debugging, authorize this Mac.")
		return 1
	}
	fmt.Print(appruntime.FormatDevicesText(devs))
	return 0
}

func cmdEmulators(args []string) int {
	fs := flag.NewFlagSet("emulators", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	avds, err := appruntime.ListEmulators(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "emulators: %v\n", err)
		fmt.Fprintln(os.Stderr, "Install Android SDK emulator and set ANDROID_HOME / ANDROID_SDK_ROOT.")
		fmt.Fprintln(os.Stderr, "Example: brew install --cask android-commandlinetools")
		fmt.Fprintln(os.Stderr, "Create AVD: apkcheck emulator-create --name Pixel_8_API_34")
		return 1
	}
	fmt.Print(appruntime.FormatEmulatorsText(avds))
	if len(avds) == 0 {
		fmt.Fprintln(os.Stderr, "No AVDs yet. Create one: apkcheck emulator-create --name Pixel_8_API_34")
	}
	return 0
}

func cmdEmulatorCreate(args []string) int {
	fs := flag.NewFlagSet("emulator-create", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := "Pixel_8_API_34"
	api := "34"
	tag := "google_apis"
	abi := "arm64-v8a"
	device := "pixel_8"
	force := false
	fs.StringVar(&name, "name", name, "AVD name")
	fs.StringVar(&api, "api", api, "Android API level")
	fs.StringVar(&tag, "tag", tag, "system image tag (google_apis|default|google_apis_playstore)")
	fs.StringVar(&abi, "abi", abi, "ABI (arm64-v8a on Apple Silicon)")
	fs.StringVar(&device, "device", device, "device skin id")
	fs.BoolVar(&force, "force", false, "recreate AVD if it already exists")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return 2
	}
	opt := appruntime.EmulatorCreateOptions{
		Name: name, API: api, Tag: tag, ABI: abi, Device: device, Force: force, Progress: os.Stderr,
	}
	fmt.Fprintf(os.Stderr, "Creating AVD %s (API %s %s %s)…\n", name, api, tag, abi)
	if err := appruntime.CreateEmulator(context.Background(), opt); err != nil {
		fmt.Fprintf(os.Stderr, "emulator-create failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Done. List with: apkcheck emulators\n")
	fmt.Fprintf(os.Stderr, "Run APK with: apkcheck runtime app.apk --emulator %s\n", name)
	return 0
}

func cmdRuntime(args []string) int {
	var cf commonFlags
	var rf runtimeFlags
	fs := flag.NewFlagSet("runtime", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	parseCommon(fs, &cf)
	rf.register(fs)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return 2
	}
	apkPath, err := requireAPK(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	opts := rf.toOptions(apkPath, cf.output)
	if rf.instrumentation != "" {
		fmt.Fprintf(os.Stderr, "NOTE: enable instrumentation in apkcheck.yaml (provider=%s); default remains non-invasive.\n", rf.instrumentation)
	}
	ev, err := appruntime.Run(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime failed: %v\n", err)
		if ev != nil {
			printRuntimeSummary(ev, cf.output)
		}
		return 1
	}
	printRuntimeSummary(ev, cf.output)
	return 0
}

func printRuntimeSummary(ev *appruntime.Evidence, outputDir string) {
	if ev == nil {
		return
	}
	fmt.Printf("\nRuntime session: %s\n", ev.SessionID)
	fmt.Print(ev.Runtime.FormatText())
	if ev.APK != nil {
		fmt.Printf("APK SHA256: %s\n", ev.APK.SHA256)
		fmt.Printf("Package: %s\n", ev.APK.Package)
	}
	fmt.Printf("Crashes: %d\n", len(ev.Crashes))
	fmt.Printf("Permissions compared: %d\n", len(ev.Permissions))
	fmt.Printf("Network observations: %d\n", len(ev.Network))
	fmt.Printf("Timeline events: %d\n", len(ev.Timeline))
	fmt.Printf("Correlations: %d\n", len(ev.Correlations))
	if ev.LogcatPath != "" {
		fmt.Printf("Logcat: %s\n", ev.LogcatPath)
	}
	if outputDir == "" {
		outputDir = "./analysis"
	}
	fmt.Printf("Session JSON: %s/runtime/%s/session.json\n", outputDir, ev.SessionID)
	for _, n := range ev.Notes {
		fmt.Printf("• %s\n", n)
	}
	for _, l := range ev.Limitations {
		fmt.Printf("Limitation: %s\n", l)
	}
}

func runtimeReportFromEvidence(ev *appruntime.Evidence, outputDir string) *model.RuntimeReport {
	if ev == nil {
		return nil
	}
	if outputDir == "" {
		outputDir = "./analysis"
	}
	return &model.RuntimeReport{
		SessionID:    ev.SessionID,
		Type:         ev.Runtime.Type,
		Connection:   ev.Runtime.Connection,
		Host:         ev.Runtime.Host,
		HostArch:     ev.Runtime.HostArch,
		AVD:          ev.Runtime.AVD,
		Device:       ev.Runtime.Device,
		DeviceID:     ev.Runtime.DeviceID,
		Android:      ev.Runtime.Android,
		API:          ev.Runtime.API,
		Architecture: ev.Runtime.Architecture,
		Screen:       ev.Runtime.Screen,
		Crashes:      len(ev.Crashes),
		Permissions:  len(ev.Permissions),
		Network:      len(ev.Network),
		Timeline:     len(ev.Timeline),
		Correlations: len(ev.Correlations),
		LogcatPath:   ev.LogcatPath,
		SessionJSON:  filepath.Join(outputDir, "runtime", ev.SessionID, "session.json"),
		Notes:        append([]string{}, ev.Notes...),
		Limitations:  append([]string{}, ev.Limitations...),
	}
}

func cmdMethods(args []string) int {
	var cf commonFlags
	var listLimit int
	fs := flag.NewFlagSet("methods", flag.ContinueOnError)
	parseCommon(fs, &cf)
	fs.IntVar(&listLimit, "list-limit", 100, "max rows to print")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return 2
	}
	apkPath, err := requireAPK(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	a := analyze.New(cf.toConfig(apkPath))
	result, err := a.Analyze(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze failed: %v\n", err)
		return 1
	}
	_ = text.WriteDiffTable(os.Stdout, result.Methods, listLimit)
	_ = writeOutputs(result, cf.output, nonEmpty(cf.formats, []string{"json"}))
	return 0
}

func cmdMethod(args []string) int {
	var cf commonFlags
	fs := flag.NewFlagSet("method", flag.ContinueOnError)
	parseCommon(fs, &cf)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return 2
	}
	if cf.className == "" || cf.methodName == "" {
		fmt.Fprintln(os.Stderr, "--class and --method are required")
		return 2
	}
	apkPath, err := requireAPK(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	a := analyze.New(cf.toConfig(apkPath))
	result, err := a.Analyze(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze failed: %v\n", err)
		return 1
	}
	if len(result.Methods) == 0 {
		fmt.Fprintln(os.Stderr, "no matching methods found")
		return 1
	}
	for _, m := range result.Methods {
		_ = text.WriteMethodDetail(os.Stdout, m)
	}
	_ = writeOutputs(result, cf.output, nonEmpty(cf.formats, []string{"json"}))
	return 0
}

func cmdDiff(args []string) int {
	var cf commonFlags
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	parseCommon(fs, &cf)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return 2
	}
	apkPath, err := requireAPK(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	a := analyze.New(cf.toConfig(apkPath))
	result, err := a.Analyze(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze failed: %v\n", err)
		return 1
	}
	var disagreements []model.MethodResult
	for _, m := range result.Methods {
		if m.Status == model.ConfidenceDisagreement || m.Status == model.ConfidencePartiallyConsistent {
			disagreements = append(disagreements, m)
		}
	}
	if len(disagreements) == 0 {
		fmt.Println("No semantic disagreements detected in the analyzed set.")
		fmt.Println("Note: absence of disagreement is not proof that reconstructions are correct.")
		return writeOutputs(result, cf.output, nonEmpty(cf.formats, []string{"json"}))
	}
	for i, m := range disagreements {
		if i >= 25 {
			fmt.Printf("\n… %d more\n", len(disagreements)-25)
			break
		}
		_ = text.WriteMethodDetail(os.Stdout, m)
	}
	return writeOutputs(result, cf.output, nonEmpty(cf.formats, []string{"json"}))
}

func cmdReport(args []string) int {
	var cf commonFlags
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	parseCommon(fs, &cf)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return 2
	}
	apkPath, err := requireAPK(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	formats := nonEmpty(cf.formats, []string{"html", "json", "text"})
	a := analyze.New(cf.toConfig(apkPath))
	result, err := a.Analyze(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze failed: %v\n", err)
		return 1
	}
	return writeOutputs(result, cf.output, formats)
}

func writeOutputs(result *model.AnalysisResult, outDir string, formats []string) int {
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		return 1
	}
	want := map[string]bool{}
	for _, f := range formats {
		want[strings.ToLower(f)] = true
	}
	if want["text"] {
		path := filepath.Join(outDir, "report.txt")
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write text: %v\n", err)
			return 1
		}
		_ = text.WriteReport(f, result)
		_ = f.Close()
		_ = text.WriteReport(os.Stdout, result)
		fmt.Fprintf(os.Stderr, "\nReport: %s\n", path)
	}
	if want["json"] {
		path := filepath.Join(outDir, "report.json")
		if err := jsonreport.WriteFile(path, result); err != nil {
			fmt.Fprintf(os.Stderr, "write json: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "Report: %s\n", path)
	}
	if want["html"] {
		path := filepath.Join(outDir, "report.html")
		if err := htmlreport.WriteFile(path, result); err != nil {
			fmt.Fprintf(os.Stderr, "write html: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "Report: %s\n", path)
	}
	if want["ai"] {
		path := filepath.Join(outDir, "ai-digest.json")
		dig := aireport.FromResult(result, aireport.Options{})
		data, err := json.MarshalIndent(dig, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "write ai: %v\n", err)
			return 1
		}
		if err := os.WriteFile(path, data, 0o640); err != nil {
			fmt.Fprintf(os.Stderr, "write ai: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "Report: %s\n", path)
		// Always print digest to stdout for agent pipelines when ai is requested.
		_, _ = os.Stdout.Write(append(data, '\n'))
	}
	if want["md"] || want["markdown"] {
		path := filepath.Join(outDir, "REPORT.md")
		if err := mdreport.WriteFile(path, result); err != nil {
			fmt.Fprintf(os.Stderr, "write md: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "Report: %s\n", path)
	}
	return 0
}

func cmdHunt(args []string) int {
	var cf commonFlags
	var rf runtimeFlags
	var runRuntime, useFrida bool
	fs := flag.NewFlagSet("hunt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	parseCommon(fs, &cf)
	rf.register(fs)
	fs.BoolVar(&runRuntime, "runtime", false, "also run device/emulator session")
	fs.BoolVar(&useFrida, "frida", false, "optional Frida/Objection runtime pack")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return 2
	}
	apkPath, err := requireAPK(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if cf.output == "" || cf.output == "./analysis" {
		cf.output = "./hunt-out"
	}
	if cf.limit == 0 {
		cf.limit = 800
	}
	if cf.focus == "" {
		cf.focus = "security"
	}
	fmt.Fprintf(os.Stderr, "APKCheck hunt v%s\n", analyze.Version)
	fmt.Fprintln(os.Stderr, "DEX/Smali = ground truth · decompilers = reconstructions · runtime = partial observation")

	a := analyze.New(cf.toConfig(apkPath))
	result, err := a.Analyze(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "hunt failed: %v\n", err)
		return 1
	}

	if runRuntime || rf.deviceMode || rf.emulatorAVD != "" || rf.runtimeDeviceID != "" || rf.runtimeEmulator != "" {
		opts := rf.toOptions(apkPath, cf.output)
		opts.StaticMethods = result.Methods
		opts.DeclaredPerms = result.APK.Permissions
		ev, rerr := appruntime.Run(context.Background(), opts)
		if ev != nil {
			result.Runtime = runtimeReportFromEvidence(ev, cf.output)
			rtType := ""
			if result.Runtime != nil {
				rtType = result.Runtime.Type
			}
			result.RuntimeObs = append(result.RuntimeObs, model.RuntimeObservation{
				Kind: "session", Message: fmt.Sprintf("session=%s type=%s", ev.SessionID, rtType),
				Class: model.EvidenceRuntime, Status: "ran",
				Note: "NOT OBSERVED ≠ ABSENT",
			})
		}
		if rerr != nil {
			result.Notes = append(result.Notes, "runtime: "+rerr.Error())
		}
	}

	if useFrida {
		pack, ferr := frida.Run(context.Background(), frida.Options{
			Package:   firstNonEmptyStr(rf.pkg, result.APK.Package),
			DeviceID:  rf.deviceID,
			OutputDir: filepath.Join(cf.output, "frida"),
			Duration:  15 * time.Second,
		})
		if pack != nil {
			result.RuntimeObs = append(result.RuntimeObs, pack.Obs...)
			result.Notes = append(result.Notes, pack.Notes...)
		}
		if ferr != nil {
			result.Notes = append(result.Notes, "frida pack: "+ferr.Error())
		}
	}

	formats := []string{"md", "json", "html", "ai"}
	if code := writeOutputs(result, cf.output, formats); code != 0 {
		return code
	}
	fmt.Fprintf(os.Stderr, "\nHunt complete: %d findings · %d disagreements · REPORT.md → %s\n",
		len(result.Findings), result.Summary.MethodsDisagreement, filepath.Join(cf.output, "REPORT.md"))
	return 0
}

func cmdDiffReleases(args []string) int {
	var cf commonFlags
	fs := flag.NewFlagSet("diff-releases", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	parseCommon(fs, &cf)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) < 2 {
		fmt.Fprintln(os.Stderr, "usage: apkcheck diff-releases old.apk new.apk [--output DIR] [--limit N]")
		return 2
	}
	if cf.limit == 0 {
		cf.limit = 400
	}
	if cf.output == "" {
		cf.output = "./release-diff"
	}
	fmt.Fprintf(os.Stderr, "APKCheck diff-releases (STATIC_EVIDENCE only for fix/new lists)\n")
	oldR, err := analyze.New(cf.toConfig(rest[0])).Analyze(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze old: %v\n", err)
		return 1
	}
	newR, err := analyze.New(cf.toConfig(rest[1])).Analyze(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyze new: %v\n", err)
		return 1
	}
	diff := compareapk.Compare(oldR, newR)
	if err := os.MkdirAll(cf.output, 0o750); err != nil {
		return 1
	}
	txt := compareapk.FormatText(diff)
	_ = os.WriteFile(filepath.Join(cf.output, "release-diff.txt"), []byte(txt), 0o640)
	raw, _ := json.MarshalIndent(diff, "", "  ")
	_ = os.WriteFile(filepath.Join(cf.output, "release-diff.json"), raw, 0o640)
	fmt.Print(txt)
	fmt.Fprintf(os.Stderr, "\nWrote %s\n", filepath.Join(cf.output, "release-diff.txt"))
	return 0
}

func cmdCI(args []string) int {
	var cf commonFlags
	fs := flag.NewFlagSet("ci", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	parseCommon(fs, &cf)
	cfgPath := fs.String("config", "", "CI YAML (security.fail_on, decompiler.disagreement_threshold, …)")
	failOn := fs.String("fail-on", "", "override security.fail_on")
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return 2
	}
	apkPath, err := requireAPK(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if cf.output == "" {
		cf.output = "./ci-out"
	}
	if cf.limit == 0 {
		cf.limit = 500
	}
	cfg, err := ci.LoadYAML(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ci config: %v\n", err)
		return 2
	}
	if *failOn != "" {
		cfg.Security.FailOn = *failOn
	}

	a := analyze.New(cf.toConfig(apkPath))
	result, err := a.Analyze(context.Background())
	if err != nil {
		out := model.CIResult{OK: false, ExitCode: 2, FailedRules: []string{"analysis_failed"}, Notes: []string{err.Error()}}
		enc, _ := json.MarshalIndent(out, "", "  ")
		_, _ = os.Stdout.Write(append(enc, '\n'))
		return 2
	}
	_ = writeOutputs(result, cf.output, []string{"json", "md"})
	res := ci.Evaluate(result, cfg)
	res.ReportPath = filepath.Join(cf.output, "REPORT.md")
	res.JSONPath = filepath.Join(cf.output, "report.json")
	enc, _ := json.MarshalIndent(res, "", "  ")
	_, _ = os.Stdout.Write(append(enc, '\n'))
	_ = os.WriteFile(filepath.Join(cf.output, "ci-result.json"), enc, 0o640)
	return res.ExitCode
}

func firstNonEmpty(a, b string) string {
	return firstNonEmptyStr(a, b)
}

func cmdMCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fmt.Fprintf(os.Stderr, "apkcheck MCP server v%s (stdio) — tools: doctor, analyze_ai, devices, emulators, runtime, …\n", analyze.Version)
	if err := mcp.New(os.Stdin, os.Stdout, os.Stderr).Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "mcp: %v\n", err)
		return 1
	}
	return 0
}

func requireAPK(args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("apk/bundle path required")
	}
	p := args[0]
	st, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("input: %w", err)
	}
	if st.IsDir() {
		// Split APK directory is supported.
		return p, nil
	}
	lower := strings.ToLower(p)
	switch {
	case strings.HasSuffix(lower, ".apk"),
		strings.HasSuffix(lower, ".xapk"),
		strings.HasSuffix(lower, ".apks"),
		strings.HasSuffix(lower, ".apkm"),
		strings.HasSuffix(lower, ".aab"):
		return p, nil
	default:
		fmt.Fprintf(os.Stderr, "warning: unrecognized package extension (%s)\n", filepath.Base(p))
		return p, nil
	}
}

func nonEmpty(in multiFlag, def []string) []string {
	if len(in) == 0 {
		return def
	}
	return in
}

func cmdCompareVersions(args []string) int {
	var cf commonFlags
	fs := flag.NewFlagSet("compare-versions", flag.ContinueOnError)
	parseCommon(fs, &cf)
	if err := fs.Parse(reorderArgs(args)); err != nil {
		return 2
	}
	apkPath, err := requireAPK(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if cf.limit == 0 {
		cf.limit = 300 // keep version matrix practical by default
	}
	rep, pins, err := analyze.CompareVersions(context.Background(), analyze.VersionCompareConfig{
		Config:       cf.toConfig(apkPath),
		VersionsFile: cf.versionsFile,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare-versions failed: %v\n", err)
		return 1
	}
	_ = pins
	textOut := versioncmp.FormatText(rep, 25)
	fmt.Print(textOut)
	_ = os.MkdirAll(cf.output, 0o750)
	if err := os.WriteFile(filepath.Join(cf.output, "versions.txt"), []byte(textOut), 0o640); err != nil {
		fmt.Fprintf(os.Stderr, "write versions.txt: %v\n", err)
		return 1
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode versions.json: %v\n", err)
		return 1
	}
	if err := os.WriteFile(filepath.Join(cf.output, "versions.json"), data, 0o640); err != nil {
		fmt.Fprintf(os.Stderr, "write versions.json: %v\n", err)
		return 1
	}
	if len(pins) > 0 {
		pinData, _ := json.MarshalIndent(pins, "", "  ")
		_ = os.WriteFile(filepath.Join(cf.output, "tool-pins.json"), pinData, 0o640)
	}
	fmt.Fprintf(os.Stderr, "\nReport: %s\nReport: %s\n",
		filepath.Join(cf.output, "versions.txt"),
		filepath.Join(cf.output, "versions.json"))
	return 0
}
