package security

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/scenarios"
	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/adb"
	"github.com/armin/apkcheck/internal/runtime/env"
	"github.com/armin/apkcheck/internal/runtime/launcher"
)

// RunOptions configures a security template execution.
type RunOptions struct {
	ArtifactID string
	TemplateID string
	Serial     string
	ADBPath    string
	Package    string
	Duration   time.Duration // background observe window override
}

// Engine runs security templates against lab artifacts.
type Engine struct {
	Store     *lab.Store
	Sec       *Store
	Bus       *events.Bus
	Scenarios *scenarios.Engine // optional — enables StepUserAction with params.scenario
}

func (e *Engine) emit(typ, art, msg, level string) {
	if e.Bus == nil {
		return
	}
	e.Bus.Publish(events.Event{Type: typ, ArtifactID: art, Message: msg, Level: level})
}

// Run executes one template.
func (e *Engine) Run(ctx context.Context, opt RunOptions) (*RunReport, error) {
	tpl, ok := TemplateByID(opt.TemplateID)
	if !ok {
		return nil, fmt.Errorf("unknown template: %s", opt.TemplateID)
	}
	art, err := e.Store.Get(opt.ArtifactID)
	if err != nil {
		return nil, err
	}
	pkg := opt.Package
	if pkg == "" {
		pkg = art.Package
	}
	rep := &RunReport{
		ID: lab.NewID("secrun"), TemplateID: tpl.ID, ArtifactID: art.ID,
		StartedAt: time.Now().UTC(),
	}
	evidDir := filepath.Join(e.Sec.evidRoot(), rep.ID)
	_ = os.MkdirAll(evidDir, 0o750)
	rep.EvidenceDir = evidDir

	e.emit("SECURITY_RUN_STARTED", art.ID, tpl.Name, "info")
	start := time.Now()
	addTL := func(typ, msg string) {
		rep.Timeline = append(rep.Timeline, TimelineEvent{
			OffsetMS: time.Since(start).Milliseconds(),
			At:       time.Now().UTC(),
			Type:     typ,
			Message:  msg,
		})
	}
	addTL("start", tpl.Name)

	var client *adb.Client
	if opt.Serial != "" || tpl.RequiresDevice {
		adbPath := opt.ADBPath
		if adbPath == "" {
			adbPath, _ = runner.LookPath("", "adb")
		}
		if adbPath != "" {
			client = &adb.Client{Path: adbPath}
		}
		if tpl.RequiresDevice && (client == nil || opt.Serial == "") {
			// Still run static steps; mark incomplete for device steps
			addTL("warn", "device required — dynamic steps will be skipped or soft-fail")
		}
	}

	var obsIDs []string
	for _, step := range tpl.Steps {
		select {
		case <-ctx.Done():
			rep.Error = ctx.Err().Error()
			rep.EndedAt = time.Now().UTC()
			_ = e.Sec.SaveRun(rep)
			return rep, ctx.Err()
		default:
		}
		addTL("step", step.Label)
		rep.StepsDone = append(rep.StepsDone, string(step.Kind)+":"+step.Label)
		e.emit("SCENARIO_STEP_STARTED", art.ID, step.Label, "info")

		switch step.Kind {
		case StepAnalyzeManifest, StepListExported:
			rev, err := ReviewManifest(art)
			if err != nil {
				addTL("error", err.Error())
				continue
			}
			_ = writeJSON(filepath.Join(evidDir, "manifest-review.json"), rev)
			o := &Observation{
				Title: "Manifest review — " + tpl.Name, Severity: SeverityNeedsReview,
				Category: tpl.Category, TemplateID: tpl.ID, ArtifactID: art.ID, Package: rev.Package,
				Summary: strings.Join(rev.ReviewNotes, "; "),
				Evidence: []EvidenceItem{{Kind: "manifest", Path: filepath.Join(evidDir, "manifest-review.json"), Label: "manifest review"}},
				Reproduction: []string{"apkcheck lab security manifest --artifact " + art.ID},
				Runtime: opt.Serial,
			}
			if len(rev.ExportedActivities)+len(rev.ExportedServices)+len(rev.ExportedReceivers)+len(rev.ExportedProviders) > 0 {
				o.Severity = SeverityPotential
			}
			_ = e.Sec.SaveObservation(o)
			obsIDs = append(obsIDs, o.ID)
			addTL("manifest", fmt.Sprintf("exported act=%d svc=%d rcv=%d prv=%d",
				len(rev.ExportedActivities), len(rev.ExportedServices), len(rev.ExportedReceivers), len(rev.ExportedProviders)))

		case StepLaunchApp:
			if client == nil || opt.Serial == "" || pkg == "" {
				addTL("skip", "launch_app needs device serial + package")
				continue
			}
			_, err := launcher.Launch(ctx, client, opt.Serial, launcher.Target{Package: pkg})
			if err != nil {
				addTL("error", "launch: "+err.Error())
			} else {
				addTL("launch", pkg)
			}

		case StepBackgroundApp:
			if client == nil || opt.Serial == "" {
				addTL("skip", "background needs device")
				continue
			}
			_, _ = client.Shell(ctx, opt.Serial, "input", "keyevent", "KEYCODE_HOME")
			addTL("background", "HOME keyevent")

		case StepForceStop:
			if client == nil || opt.Serial == "" || pkg == "" {
				addTL("skip", "force_stop needs device + package")
				continue
			}
			_, _ = client.Shell(ctx, opt.Serial, "am", "force-stop", pkg)
			addTL("force_stop", pkg)

		case StepWait:
			d := 5 * time.Second
			if step.Params["duration"] != "" {
				if parsed, err := time.ParseDuration(step.Params["duration"]); err == nil {
					d = parsed
				}
			}
			if opt.Duration > 0 && step.Label == "Observe background window" {
				d = opt.Duration
			}
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return rep, ctx.Err()
			case <-t.C:
			}
			addTL("wait", d.String())

		case StepLaunchComponent:
			if client == nil || opt.Serial == "" {
				addTL("skip", "component launch needs device")
				continue
			}
			rev, err := ReviewManifest(art)
			if err != nil {
				continue
			}
			for i, act := range rev.ExportedActivities {
				if i >= 5 {
					addTL("note", "capped exported activity probes at 5")
					break
				}
				comp := act
				if !strings.Contains(comp, "/") && pkg != "" {
					if strings.HasPrefix(comp, ".") {
						comp = pkg + "/" + pkg + comp
					} else if !strings.Contains(comp, pkg) {
						comp = pkg + "/" + comp
					} else {
						comp = pkg + "/" + act
					}
				}
				out, err := client.Shell(ctx, opt.Serial, "am", "start", "-n", normalizeComponent(pkg, act))
				snippet := out
				if err != nil {
					snippet = err.Error() + "\n" + out
				}
				_ = os.WriteFile(filepath.Join(evidDir, fmt.Sprintf("launch-%d.txt", i)), []byte(snippet), 0o640)
				addTL("launch_component", act)
				time.Sleep(1 * time.Second)
			}

		case StepOpenDeepLink:
			if client == nil || opt.Serial == "" {
				addTL("skip", "deep link needs device")
				continue
			}
			rev, _ := ReviewManifest(art)
			for i, link := range rev.DeepLinks {
				if i >= 5 {
					break
				}
				_, _ = client.Shell(ctx, opt.Serial, "am", "start", "-a", "android.intent.action.VIEW", "-d", link)
				addTL("deep_link", link)
				time.Sleep(1 * time.Second)
			}

		case StepSendIntent:
			if client == nil || opt.Serial == "" {
				addTL("skip", "send_intent needs device")
				continue
			}
			rev, _ := ReviewManifest(art)
			for i, act := range rev.ExportedActivities {
				if i >= 3 {
					break
				}
				_, _ = client.Shell(ctx, opt.Serial, "am", "start", "-n", normalizeComponent(pkg, act),
					"--es", "apkcheck_probe", "authorized_test")
				addTL("intent_probe", act)
			}

		case StepCaptureLogs:
			if client == nil || opt.Serial == "" {
				addTL("skip", "logs need device")
				continue
			}
			out, _ := client.Shell(ctx, opt.Serial, "logcat", "-d", "-t", "200")
			path := filepath.Join(evidDir, "logcat-tail.txt")
			_ = os.WriteFile(path, []byte(out), 0o640)
			addTL("logs", path)

		case StepCaptureNetwork:
			addTL("network", "network capture is observational — enable mitmproxy separately for HTTPS bodies")
			note := "Enable Lab proxy (mitmdump) for authorized MITM. Runtime network hints are partial (NOT OBSERVED ≠ ABSENT)."
			_ = os.WriteFile(filepath.Join(evidDir, "network-note.txt"), []byte(note), 0o640)

		case StepCaptureScreenshot:
			if client == nil || opt.Serial == "" {
				addTL("skip", "screenshot needs device")
				continue
			}
			remote := "/sdcard/Download/apkcheck-lab-shot.png"
			local := filepath.Join(evidDir, "screenshot.png")
			_, _ = client.Shell(ctx, opt.Serial, "screencap", "-p", remote)
			_, _ = client.Run(ctx, "-s", opt.Serial, "pull", remote, local)
			addTL("screenshot", local)

		case StepInspectStorage:
			if client == nil || opt.Serial == "" || pkg == "" {
				addTL("skip", "storage inspect needs device + package")
				continue
			}
			out, _ := client.Shell(ctx, opt.Serial, "run-as", pkg, "ls", "-la", ".")
			if strings.Contains(out, "run-as:") || strings.TrimSpace(out) == "" {
				out2, _ := client.Shell(ctx, opt.Serial, "ls", "-la", "/sdcard/Android/data/"+pkg)
				out = "run-as unavailable (typical for release apps)\n" + out2
			}
			path := filepath.Join(evidDir, "storage-listing.txt")
			_ = os.WriteFile(path, []byte(out), 0o640)
			addTL("storage", path)

		case StepInspectPermissions:
			if client == nil || opt.Serial == "" || pkg == "" {
				addTL("skip", "permissions need device + package")
				continue
			}
			out, _ := client.Shell(ctx, opt.Serial, "dumpsys", "package", pkg)
			// keep a trimmed slice
			if len(out) > 200000 {
				out = out[:200000]
			}
			path := filepath.Join(evidDir, "dumpsys-package.txt")
			_ = os.WriteFile(path, []byte(out), 0o640)
			addTL("permissions", path)

		case StepAssertProcess:
			if client == nil || opt.Serial == "" || pkg == "" {
				continue
			}
			out, _ := client.Shell(ctx, opt.Serial, "pidof", pkg)
			addTL("process", "pidof "+pkg+" = "+strings.TrimSpace(out))
			_ = os.WriteFile(filepath.Join(evidDir, "pidof.txt"), []byte(out), 0o640)

		case StepStartMonitor:
			addTL("monitor", "monitoring window started")

		case StepHarnessInstall:
			note, err := EnsureHarness(ctx, e.Store.Root, client, opt.Serial)
			if err != nil {
				addTL("harness", err.Error())
			} else {
				addTL("harness", note)
			}

		case StepHarnessProbe:
			addTL("harness", "probe via adb intents (harness APK optional)")

		case StepUserAction:
			sid := ""
			if step.Params != nil {
				sid = strings.TrimSpace(step.Params["scenario"])
			}
			if sid == "" {
				addTL("user_action", "manual/scenario user actions — set params.scenario to a saved scenario id")
				break
			}
			if e.Scenarios == nil {
				addTL("user_action", "scenario engine not configured — cannot run "+sid)
				break
			}
			if client == nil || opt.Serial == "" {
				addTL("user_action", "device required to run scenario "+sid)
				break
			}
			addTL("user_action", "running scenario "+sid)
			sres, serr := e.Scenarios.Run(ctx, sid, art.ID, scenarios.RunOptions{
				ADBPath: opt.ADBPath, Serial: opt.Serial, Package: pkg,
			})
			if serr != nil {
				addTL("user_action", "scenario "+sid+" error: "+serr.Error())
			} else if sres != nil {
				addTL("user_action", fmt.Sprintf("scenario %s ok=%v steps=%d", sid, sres.OK, len(sres.Steps)))
			}

		case StepRecordObservation:
			o := &Observation{
				Title: tpl.Name + " — checkpoint", Severity: SeverityInfo,
				Category: tpl.Category, TemplateID: tpl.ID, ArtifactID: art.ID, Package: pkg,
				Summary: "Checkpoint after: " + step.Label + ". Review evidence dir; do not treat as confirmed vulnerability.",
				Evidence: []EvidenceItem{{Kind: "runtime", Path: evidDir, Label: "evidence directory"}},
				Reproduction: []string{tpl.CLIHint},
				Runtime: opt.Serial,
			}
			_ = e.Sec.SaveObservation(o)
			obsIDs = append(obsIDs, o.ID)
		}
	}

	rep.ObservationIDs = obsIDs
	rep.OK = rep.Error == ""
	rep.EndedAt = time.Now().UTC()
	_ = e.Sec.SaveRun(rep)
	e.emit("SECURITY_RUN_COMPLETED", art.ID, fmt.Sprintf("%s ok=%v", tpl.ID, rep.OK), "info")
	addTL("done", fmt.Sprintf("ok=%v observations=%d", rep.OK, len(obsIDs)))
	return rep, nil
}

// RunPreset runs all templates in a preset sequentially (parallelism left to caller for multi-runtime).
func (e *Engine) RunPreset(ctx context.Context, presetID string, opt RunOptions) ([]*RunReport, error) {
	p, ok := PresetByID(presetID)
	if !ok {
		return nil, fmt.Errorf("unknown preset: %s", presetID)
	}
	var out []*RunReport
	for _, tid := range p.TemplateIDs {
		opt.TemplateID = tid
		r, err := e.Run(ctx, opt)
		if r != nil {
			out = append(out, r)
		}
		if err != nil && r == nil {
			return out, err
		}
	}
	return out, nil
}

func normalizeComponent(pkg, act string) string {
	act = strings.TrimSpace(act)
	if strings.Contains(act, "/") {
		return act
	}
	if strings.HasPrefix(act, ".") {
		return pkg + "/" + pkg + act
	}
	if pkg != "" && strings.HasPrefix(act, pkg) {
		return pkg + "/" + act
	}
	if pkg != "" {
		return pkg + "/" + act
	}
	return act
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o640)
}

// DiscoverDefaultSerial returns first device serial if any.
func DiscoverDefaultSerial(ctx context.Context) string {
	sdk := env.Discover()
	c, err := adb.New(sdk)
	if err != nil {
		return ""
	}
	res, err := c.Run(ctx, "devices")
	if err != nil || res == nil {
		return ""
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "device" {
			return f[0]
		}
	}
	return ""
}
