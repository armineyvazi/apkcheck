package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/authgate"
	"github.com/armin/apkcheck/internal/lab/compare"
	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/logsync"
	"github.com/armin/apkcheck/internal/lab/pipeline"
	"github.com/armin/apkcheck/internal/lab/proxy"
	"github.com/armin/apkcheck/internal/lab/proxysync"
	"github.com/armin/apkcheck/internal/lab/recording"
	"github.com/armin/apkcheck/internal/lab/runtimes"
	"github.com/armin/apkcheck/internal/lab/scenarios"
	"github.com/armin/apkcheck/internal/lab/security"
	"github.com/armin/apkcheck/internal/lab/session"
	"github.com/armin/apkcheck/internal/lab/workspace"
	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/adb"
)

// parseLabArgs allows flags before or after positional args (Go flag stops at first non-flag).
func parseLabArgs(fs *flag.FlagSet, args []string) (positional []string, err error) {
	var flagArgs, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flagArgs = append(flagArgs, a)
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				continue
			}
			if isLabBoolFlag(name) {
				continue
			}
			// value flags consume the next token when it is not another flag
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return pos, nil
}

func cmdLab(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, `apkcheck lab — APK Laboratory

Usage:
  apkcheck lab import <apk> [--workspace DIR] [--label NAME]
  apkcheck lab list [--workspace DIR]
  apkcheck lab decompile <apk-id>
  apkcheck lab build <project-id>
  apkcheck lab sign <unsigned-id>
  apkcheck lab rebuild <apk-id>          # decompile+build+sign
  apkcheck lab validate <signed-id> [--emulator AVD|--device-id ID] [--record] [--profile balanced]
  apkcheck lab compare <left-id> <right-id>
  apkcheck lab security catalog|presets|manifest|run|preset|observations|export|harness
  apkcheck lab runtime list|status|start|stop|restart
  apkcheck lab ui [--open] [--build] [--addr :8787] [--workspace DIR]
  apkcheck lab serve [--addr :8787] [--workspace DIR] [--ui DIR] [--open]
  apkcheck lab reset [--workspace DIR]   # wipe sessions/recordings/logs for a fresh run
  apkcheck lab scenario list|run [--workspace DIR] [--id ID] [--package PKG] [--serial S] [--record]

  lab ui       build (if needed) + serve API and React dashboard
  lab serve    API only (serves web/dist when found)
  lab runtime  manage Android emulator/device instances (start/stop/restart)
  lab reset    delete prior test runs, recordings, logs (keeps APKs/scenarios)
  lab scenario list saved defs · run with package (+ optional record)

Workspace default: ./lab-data
Authorized security testing only. Observations ≠ confirmed vulnerabilities.
Validate --record writes device video + timeline (Lab UI → Runs).
`)
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "import":
		return labImport(rest)
	case "list":
		return labList(rest)
	case "decompile":
		return labDecompile(rest)
	case "build":
		return labBuild(rest)
	case "sign":
		return labSign(rest)
	case "rebuild":
		return labRebuild(rest)
	case "validate":
		return labValidate(rest)
	case "compare":
		return labCompare(rest)
	case "security":
		return labSecurity(rest)
	case "runtime", "runtimes":
		return labRuntime(rest)
	case "ui":
		return labUI(rest)
	case "serve":
		return labServe(rest)
	case "reset", "fresh":
		return labReset(rest)
	case "scenario", "scenarios":
		return labScenario(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown lab subcommand: %s\n", sub)
		return 2
	}
}

func openLab(workspace string) (*lab.Store, *pipeline.Pipeline, *events.Bus, error) {
	if workspace == "" {
		workspace = "./lab-data"
	}
	bus := events.NewBus(2000)
	store, err := lab.OpenStore(workspace, bus)
	if err != nil {
		return nil, nil, nil, err
	}
	pipe := &pipeline.Pipeline{Store: store, Bus: bus}
	return store, pipe, bus, nil
}

func labImport(args []string) int {
	fs := flag.NewFlagSet("lab import", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "lab workspace")
	label := fs.String("label", "", "display label")
	fs.SetOutput(os.Stderr)
	pos, err := parseLabArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "apk path required")
		return 2
	}
	_, pipe, _, err := openLab(*ws)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	a, err := pipe.ImportAPK(pos[0], *label)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	enc, _ := json.MarshalIndent(a, "", "  ")
	fmt.Println(string(enc))
	return 0
}

func labList(args []string) int {
	fs := flag.NewFlagSet("lab list", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "lab workspace")
	fs.SetOutput(os.Stderr)
	if _, err := parseLabArgs(fs, args); err != nil {
		return 2
	}
	store, _, _, err := openLab(*ws)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	enc, _ := json.MarshalIndent(store.List(), "", "  ")
	fmt.Println(string(enc))
	return 0
}

func labDecompile(args []string) int {
	return labPipeID(args, "decompile", func(ctx context.Context, p *pipeline.Pipeline, id string) (any, error) {
		return p.Decompile(ctx, id)
	})
}

func labBuild(args []string) int {
	return labPipeID(args, "build", func(ctx context.Context, p *pipeline.Pipeline, id string) (any, error) {
		return p.Build(ctx, id)
	})
}

func labSign(args []string) int {
	return labPipeID(args, "sign", func(ctx context.Context, p *pipeline.Pipeline, id string) (any, error) {
		return p.Sign(ctx, id)
	})
}

func labRebuild(args []string) int {
	return labPipeID(args, "rebuild", func(ctx context.Context, p *pipeline.Pipeline, id string) (any, error) {
		return p.RebuildFull(ctx, id)
	})
}

func labPipeID(args []string, name string, fn func(context.Context, *pipeline.Pipeline, string) (any, error)) int {
	fs := flag.NewFlagSet("lab "+name, flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "lab workspace")
	fs.SetOutput(os.Stderr)
	pos, err := parseLabArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "artifact id required")
		return 2
	}
	_, pipe, _, err := openLab(*ws)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	out, err := fn(ctx, pipe, pos[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	enc, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(enc))
	return 0
}

func labValidate(args []string) int {
	fs := flag.NewFlagSet("lab validate", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "lab workspace")
	emu := fs.String("emulator", "Pixel_8_API_34", "AVD name")
	device := fs.String("device-id", "", "physical device serial")
	dur := fs.Duration("duration", 15*time.Second, "post-launch observe window")
	record := fs.Bool("record", false, "record device screen + bind Lab session timeline")
	profile := fs.String("profile", "balanced", "recording profile: low|balanced|high")
	fs.SetOutput(os.Stderr)
	labBoolFlags["record"] = true
	pos, err := parseLabArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "signed artifact id required")
		return 2
	}
	store, pipe, bus, err := openLab(*ws)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	opt := pipeline.ValidateOptions{EmulatorAVD: *emu, DeviceSerial: *device, Duration: *dur}
	if *device != "" {
		opt.EmulatorAVD = ""
	}

	var (
		labRun *session.Run
		sess   *session.Manager
		recMgr *recording.Manager
	)
	if *record {
		sess = session.NewManager(store.Root, bus)
		recMgr = recording.NewManager(store.Root, bus, sess)
		serial := security.ResolveDeviceSerial(context.Background(), *device, *emu)
		run, rerr := sess.Start(session.StartOptions{
			Kind: session.KindValidate, ArtifactID: pos[0],
			RuntimeSerial: serial, RuntimeAVD: *emu,
			Record: true, Profile: *profile,
		})
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "session start:", rerr)
		} else {
			labRun = run
			if serial == "" {
				fmt.Fprintln(os.Stderr, "warning: --record set but no device serial — start an emulator first")
			} else if art, err := recMgr.Start(context.Background(), run, serial, recording.ParseProfile(*profile)); err != nil {
				fmt.Fprintln(os.Stderr, "recording start:", err)
				_, _ = sess.AddEvent(run.ID, session.Event{
					Type: "RECORDING_FAILED", Source: "system", Category: "runtime", Level: "warn",
					Message: err.Error(), Bookmark: true, Tags: []string{"recording"},
				})
			} else if art != nil {
				labRun.RecordingID = art.ID
				// SAFETY: only set DeviceSerial on the pipeline when there is no
				// EmulatorAVD; if both are present the pipeline picks mode="device"
				// and SelectPhysical rejects emulator serials.  The recording
				// manager holds the serial itself and does not need it on opt.
				if *emu == "" {
					opt.DeviceSerial = serial
				}
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	res, err := pipe.Validate(ctx, pos[0], opt)
	if res != nil && labRun != nil {
		res.LabRunID = labRun.ID
		if labRun.RecordingID != "" {
			res.RecordingID = labRun.RecordingID
		}
	}
	if labRun != nil && sess != nil && recMgr != nil {
		if stopped, _ := recMgr.Stop(ctx, labRun.ID); stopped != nil && res != nil {
			res.RecordingID = stopped.ID
		}
		ok := err == nil && res != nil && res.OK
		result := "PASSED"
		if !ok {
			result = "FAILED"
		}
		_, _ = sess.Complete(labRun.ID, ok, result, "", 0)
	}
	if res != nil {
		enc, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(enc))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if res != nil && !res.OK {
		return 1
	}
	return 0
}

func labCompare(args []string) int {
	fs := flag.NewFlagSet("lab compare", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "lab workspace")
	fs.SetOutput(os.Stderr)
	pos, err := parseLabArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) < 2 {
		fmt.Fprintln(os.Stderr, "left and right artifact ids required")
		return 2
	}
	store, _, _, err := openLab(*ws)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	left, err := store.Get(pos[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	right, err := store.Get(pos[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	enc, _ := json.MarshalIndent(compare.Artifacts(left, right), "", "  ")
	fmt.Println(string(enc))
	return 0
}

func labSecurity(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, `apkcheck lab security — authorized Android security test library

  catalog
  presets
  manifest --artifact <id>
  run <template-id> --artifact <id> [--device-id SERIAL|--emulator AVD]
  preset <preset-id> --artifact <id> [--device-id SERIAL|--emulator AVD]
  observations
  export <observation-id> [--format markdown|json|html|zip]
  harness [status|seed|build] [--force]
`)
		return 2
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "catalog":
		enc, _ := json.MarshalIndent(security.Catalog(), "", "  ")
		fmt.Println(string(enc))
		return 0
	case "presets":
		enc, _ := json.MarshalIndent(security.Presets(), "", "  ")
		fmt.Println(string(enc))
		return 0
	case "manifest":
		return labSecManifest(rest)
	case "run":
		return labSecRun(rest)
	case "preset":
		return labSecPreset(rest)
	case "observations":
		return labSecObservations(rest)
	case "export":
		return labSecExport(rest)
	case "harness":
		return labSecHarness(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown security subcommand: %s\n", sub)
		return 2
	}
}

func openSec(ws string) (*lab.Store, *security.Engine, error) {
	store, _, bus, err := openLab(ws)
	if err != nil {
		return nil, nil, err
	}
	eng := &security.Engine{Store: store, Sec: &security.Store{Root: store.Root, Bus: bus}, Bus: bus}
	return store, eng, nil
}

func labSecManifest(args []string) int {
	fs := flag.NewFlagSet("lab security manifest", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "")
	art := fs.String("artifact", "", "artifact id")
	fs.SetOutput(os.Stderr)
	pos, err := parseLabArgs(fs, args)
	if err != nil {
		return 2
	}
	id := *art
	if id == "" && len(pos) > 0 {
		id = pos[0]
	}
	if id == "" {
		fmt.Fprintln(os.Stderr, "--artifact required")
		return 2
	}
	store, _, err := openSec(*ws)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	a, err := store.Get(id)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	rev, err := security.ReviewManifest(a)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	enc, _ := json.MarshalIndent(rev, "", "  ")
	fmt.Println(string(enc))
	return 0
}

func labSecRun(args []string) int {
	fs := flag.NewFlagSet("lab security run", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "")
	art := fs.String("artifact", "", "artifact id")
	device := fs.String("device-id", "", "adb serial")
	emu := fs.String("emulator", "", "AVD name (resolved to serial when device-id empty)")
	fs.SetOutput(os.Stderr)
	pos, err := parseLabArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "template id required")
		return 2
	}
	if *art == "" {
		fmt.Fprintln(os.Stderr, "--artifact required")
		return 2
	}
	_, eng, err := openSec(*ws)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	serial := security.ResolveDeviceSerial(context.Background(), *device, *emu)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	rep, err := eng.Run(ctx, security.RunOptions{ArtifactID: *art, TemplateID: pos[0], Serial: serial})
	if rep != nil {
		enc, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(enc))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func labSecPreset(args []string) int {
	fs := flag.NewFlagSet("lab security preset", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "")
	art := fs.String("artifact", "", "artifact id")
	device := fs.String("device-id", "", "adb serial")
	emu := fs.String("emulator", "", "AVD name (resolved to serial when device-id empty)")
	fs.SetOutput(os.Stderr)
	pos, err := parseLabArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) < 1 || *art == "" {
		fmt.Fprintln(os.Stderr, "preset id and --artifact required")
		return 2
	}
	_, eng, err := openSec(*ws)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	serial := security.ResolveDeviceSerial(context.Background(), *device, *emu)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()
	reps, err := eng.RunPreset(ctx, pos[0], security.RunOptions{ArtifactID: *art, Serial: serial})
	enc, _ := json.MarshalIndent(reps, "", "  ")
	fmt.Println(string(enc))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func labSecObservations(args []string) int {
	fs := flag.NewFlagSet("lab security observations", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "")
	fs.SetOutput(os.Stderr)
	if _, err := parseLabArgs(fs, args); err != nil {
		return 2
	}
	_, eng, err := openSec(*ws)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	list, err := eng.Sec.ListObservations()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	enc, _ := json.MarshalIndent(list, "", "  ")
	fmt.Println(string(enc))
	return 0
}

func labSecExport(args []string) int {
	fs := flag.NewFlagSet("lab security export", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "")
	format := fs.String("format", "markdown", "json|markdown|html|zip")
	fs.SetOutput(os.Stderr)
	pos, err := parseLabArgs(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "observation id required")
		return 2
	}
	store, eng, err := openSec(*ws)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	o, err := eng.Sec.GetObservation(pos[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ext := map[string]string{"json": ".json", "markdown": ".md", "html": ".html", "zip": ".zip"}[*format]
	outDir := filepath.Join(store.Root, "exports")
	_ = os.MkdirAll(outDir, 0o750)
	out := filepath.Join(outDir, pos[0]+ext)
	if err := security.ExportObservation(o, security.ExportFormat(*format), out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(out)
	return 0
}

func labSecHarness(args []string) int {
	fs := flag.NewFlagSet("lab security harness", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "")
	force := fs.Bool("force", false, "re-copy harness scaffold even if present")
	fs.SetOutput(os.Stderr)
	labBoolFlags["force"] = true
	pos, err := parseLabArgs(fs, args)
	if err != nil {
		return 2
	}
	action := "status"
	if len(pos) > 0 {
		action = pos[0]
	}
	store, _, err := openSec(*ws)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	src := "testdata/lab/harness"
	switch action {
	case "seed":
		if err := security.SeedHarnessProjectOpts(store.Root, src, *force); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println(`{"seeded":true,"force":` + fmt.Sprintf("%v", *force) + `}`)
	case "build":
		// Refresh scaffold when outdated or --force (fixes broken hand-written manifests).
		if err := security.SeedHarnessProjectOpts(store.Root, src, true); err != nil {
			fmt.Fprintln(os.Stderr, "seed:", err)
			return 1
		}
		note, err := security.EnsureHarness(context.Background(), store.Root, nil, "")
		fmt.Println(note)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	enc, _ := json.MarshalIndent(security.HarnessStatus(store.Root), "", "  ")
	fmt.Println(string(enc))
	return 0
}

func labReset(args []string) int {
	fs := flag.NewFlagSet("lab reset", flag.ContinueOnError)
	ws := fs.String("workspace", "./lab-data", "lab workspace")
	if _, err := parseLabArgs(fs, args); err != nil {
		return 2
	}
	removed, err := workspace.Reset(*ws, workspace.FreshRunReset())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	eng := &scenarios.Engine{Root: *ws}
	eng.EnsureBuiltins()
	out, _ := json.MarshalIndent(map[string]any{
		"ok": true, "workspace": *ws, "removed": removed,
		"note": "sessions/recordings/logs wiped; scenarios re-seeded",
	}, "", "  ")
	fmt.Println(string(out))
	return 0
}

func labScenario(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: apkcheck lab scenario list|run …")
		return 2
	}
	switch args[0] {
	case "list", "ls":
		fs := flag.NewFlagSet("lab scenario list", flag.ContinueOnError)
		ws := fs.String("workspace", "./lab-data", "lab workspace")
		if _, err := parseLabArgs(fs, args[1:]); err != nil {
			return 2
		}
		eng := &scenarios.Engine{Root: *ws}
		eng.EnsureBuiltins()
		list, err := eng.List()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		enc, _ := json.MarshalIndent(list, "", "  ")
		fmt.Println(string(enc))
		return 0
	case "run":
		fs := flag.NewFlagSet("lab scenario run", flag.ContinueOnError)
		ws := fs.String("workspace", "./lab-data", "lab workspace")
		id := fs.String("id", "", "scenario id")
		pkg := fs.String("package", "", "android package (e.g. com.example.app)")
		serial := fs.String("serial", "", "device/emulator serial")
		emu := fs.String("emulator", "", "AVD name (resolves serial)")
		artifact := fs.String("artifact", "", "artifact id (optional)")
		activity := fs.String("activity", "", "launch activity (optional; auto-resolved)")
		record := fs.Bool("record", false, "record device screen")
		profile := fs.String("profile", "high", "recording profile")
		phone := fs.String("phone", "", "prefill phone for interactive login prompts")
		otp := fs.String("otp", "", "prefill SMS OTP for interactive login prompts")
		avd := fs.String("avd", "Pixel_8_API_34", "AVD to fresh-boot after recorded scenario")
		freshEmu := fs.Bool("fresh-emulator", true, "after recording saved: wipe + cold-boot emulator")
		fs.SetOutput(os.Stderr)
		labBoolFlags["record"] = true
		labBoolFlags["fresh-emulator"] = true
		pos, err := parseLabArgs(fs, args[1:])
		if err != nil {
			return 2
		}
		if *id == "" && len(pos) > 0 {
			*id = pos[0]
		}
		if *id == "" || *pkg == "" {
			fmt.Fprintln(os.Stderr, "--id and --package required")
			return 2
		}
		store, _, bus, err := openLab(*ws)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		eng := &scenarios.Engine{Root: store.Root, Bus: bus}
		eng.EnsureBuiltins()
		ser := *serial
		if ser == "" {
			ser = security.ResolveDeviceSerial(context.Background(), "", *emu)
		}
		if ser == "" {
			ser = security.DiscoverDefaultSerial(context.Background())
		}
		if ser == "" {
			fmt.Fprintln(os.Stderr, "serial required — start an emulator or pass --serial")
			return 2
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		var (
			labRun *session.Run
			sess   *session.Manager
			recMgr *recording.Manager
		)
		scenName := *id
		if def, gerr := eng.Get(*id); gerr == nil && def != nil && def.Name != "" {
			scenName = def.Name
		}
		// Always create a Lab session so timeline (scenario/logcat/mitm) is available.
		sess = session.NewManager(store.Root, bus)
		recMgr = recording.NewManager(store.Root, bus, sess)
		run, rerr := sess.Start(session.StartOptions{
			Kind: session.KindScenario, ArtifactID: *artifact, ScenarioID: *id,
			RuntimeSerial: ser, Package: *pkg, Record: *record, Profile: *profile,
			Meta: map[string]string{"scenario_name": scenName, "title": scenName},
		})
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "session start:", rerr)
		} else {
			labRun = run
			adbPath, _ := runner.LookPath("", "adb")
			client := &adb.Client{Path: adbPath}
			_ = logsync.Clear(ctx, client, ser)
			if *record {
				if art, err := recMgr.Start(ctx, run, ser, recording.ParseProfile(*profile)); err != nil {
					fmt.Fprintln(os.Stderr, "recording start:", err)
				} else if art != nil {
					labRun.RecordingID = art.ID
					logsync.WarmRecording(2 * time.Second)
					_, _ = sess.AddEvent(run.ID, session.Event{
						Type: "RECORDING_READY", Source: "system", Category: "runtime",
						Message: "screenrecord warm — scenario actions start now",
						Tags:    []string{"recording"},
					})
				}
			}
			_, _ = sess.AddEvent(run.ID, session.Event{
				Type: "SCENARIO_STARTED", Source: "scenario", Category: "scenario",
				Message: scenName, Tags: []string{"app", "scenario"},
			})
		}

		auth := authgate.New(store.Root, bus)
		runOpt := scenarios.RunOptions{
			Serial: ser, Package: *pkg, Activity: *activity,
			Auth: auth, Phone: *phone, OTP: *otp,
		}
		if labRun != nil {
			runOpt.LabRunID = labRun.ID
			runOpt.Sessions = sess
		}
		res, err := eng.Run(ctx, *id, *artifact, runOpt)
		out := map[string]any{"result": res, "scenario_name": scenName, "serial": ser}
		if labRun != nil && sess != nil && recMgr != nil {
			adbPath, _ := runner.LookPath("", "adb")
			client := &adb.Client{Path: adbPath}
			logN, _ := logsync.Import(ctx, client, ser, sess, labRun, logsync.ImportOptions{Package: *pkg})
			pm := proxy.New(filepath.Join(store.Root, "proxy"), ":8080")
			mitmN := proxysync.Import(pm.WorkDir, sess, labRun)
			out["timeline_logcat"] = logN
			out["timeline_mitm"] = mitmN
			if *record {
				if stopped, _ := recMgr.Stop(ctx, labRun.ID); stopped != nil {
					out["recording_id"] = stopped.ID
					out["recording_status"] = stopped.Status
					out["file_name"] = stopped.FileName
					out["playable"] = recording.HasPlayableMedia(stopped)
				}
			}
			ok := err == nil && res != nil && res.OK
			result := "PASSED"
			if !ok {
				result = "FAILED"
			}
			_, _ = sess.Complete(labRun.ID, ok, result, "", 0)
			out["lab_run_id"] = labRun.ID
			if *record && *freshEmu && strings.HasPrefix(ser, "emulator-") {
				mgr := &runtimes.Manager{Bus: bus}
				fsSerial, ferr := mgr.FreshAfterRecording(ctx, *avd, ser, 12*time.Minute)
				if ferr != nil {
					out["fresh_emulator_error"] = ferr.Error()
					fmt.Fprintln(os.Stderr, "fresh emulator:", ferr)
				} else {
					out["fresh_serial"] = fsSerial
				}
			}
		}
		enc, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(enc))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if res != nil && !res.OK {
			return 1
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown scenario subcommand: %s\n", args[0])
		return 2
	}
}
