// Package scenarios stores and runs lab scenarios against artifact targets.
package scenarios

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"strings"

	"github.com/armin/apkcheck/internal/lab"
	"github.com/armin/apkcheck/internal/lab/authgate"
	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/session"
	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/adb"
	"github.com/armin/apkcheck/internal/runtime/launcher"
	rtscenarios "github.com/armin/apkcheck/internal/runtime/scenarios"
	"github.com/armin/apkcheck/internal/runtime/timeline"
)

// Definition is a reusable scenario bound to lab IDs at run time.
type Definition struct {
	ID      string               `json:"id"`
	Name    string               `json:"name"`
	Actions []rtscenarios.Action `json:"actions"`
	Created time.Time            `json:"created_at"`
}

// RunResult is one execution against a target artifact/runtime.
type RunResult struct {
	ID         string    `json:"id"`
	ScenarioID string    `json:"scenario_id"`
	ArtifactID string    `json:"artifact_id"`
	OK         bool      `json:"ok"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at"`
	Steps      []string  `json:"steps,omitempty"`
}

// Engine persists scenarios under the lab workspace.
type Engine struct {
	Root string
	Bus  *events.Bus
	mu   sync.Mutex
}

func (e *Engine) dir() string {
	return filepath.Join(e.Root, "scenarios")
}

// Save stores a scenario definition.
func (e *Engine) Save(d *Definition) error {
	if d == nil || d.Name == "" {
		return fmt.Errorf("scenario name required")
	}
	if d.ID == "" {
		d.ID = lab.NewID("scen")
	}
	if d.Created.IsZero() {
		d.Created = time.Now().UTC()
	}
	if err := os.MkdirAll(e.dir(), 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(e.dir(), d.ID+".json"), data, 0o640)
}

// List returns saved scenarios.
func (e *Engine) List() ([]*Definition, error) {
	_ = os.MkdirAll(e.dir(), 0o750)
	entries, err := os.ReadDir(e.dir())
	if err != nil {
		return nil, err
	}
	out := make([]*Definition, 0)
	for _, ent := range entries {
		if ent.IsDir() || filepath.Ext(ent.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(e.dir(), ent.Name()))
		if err != nil {
			continue
		}
		var d Definition
		if json.Unmarshal(data, &d) == nil {
			out = append(out, &d)
		}
	}
	return out, nil
}

// Get loads one scenario.
func (e *Engine) Get(id string) (*Definition, error) {
	data, err := os.ReadFile(filepath.Join(e.dir(), id+".json"))
	if err != nil {
		return nil, err
	}
	var d Definition
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// RunOptions targets a device for ADB UI actions.
type RunOptions struct {
	ADBPath  string
	Serial   string
	Package  string
	Activity string
	// LabRunID + Sessions bind step events onto the §35 recording timeline (live offsets).
	LabRunID string
	Sessions *session.Manager
	// Auth collects interactive phone/OTP/text from Lab UI / API / MCP.
	Auth *authgate.Manager
	// Optional non-interactive fills (CLI/MCP flags).
	Phone string
	OTP   string
}

// Run executes scenario actions against an already-installed package on a device.
func (e *Engine) Run(ctx context.Context, scenarioID, artifactID string, opt RunOptions) (*RunResult, error) {
	d, err := e.Get(scenarioID)
	if err != nil {
		return nil, err
	}
	res := &RunResult{
		ID: lab.NewID("scrun"), ScenarioID: scenarioID, ArtifactID: artifactID,
		StartedAt: time.Now().UTC(),
	}
	if e.Bus != nil {
		e.Bus.Publish(events.Event{
			Type: "SCENARIO_STARTED", ScenarioID: scenarioID, ArtifactID: artifactID,
			RunID: res.ID, Message: d.Name,
		})
	}
	if opt.Serial == "" || opt.Package == "" {
		res.OK = false
		res.Error = "device serial and package required for scenario run"
		res.EndedAt = time.Now().UTC()
		if e.Bus != nil {
			e.Bus.Publish(events.Event{
				Type: "SCENARIO_FAILED", ScenarioID: scenarioID, ArtifactID: artifactID,
				RunID: res.ID, Level: "error", Message: res.Error,
			})
		}
		return res, fmt.Errorf("%s", res.Error)
	}
	adbPath := opt.ADBPath
	if adbPath == "" {
		adbPath, err = runner.LookPath("", "adb")
		if err != nil {
			res.Error = err.Error()
			res.EndedAt = time.Now().UTC()
			return res, err
		}
	}
	client := &adb.Client{Path: adbPath}
	target := launcher.Target{Package: opt.Package, Activity: opt.Activity}
	// Resolve launcher activity when UI/MCP only send package.
	if target.Activity == "" {
		if resolved, rerr := launcher.ResolveLaunchTarget(ctx, client, opt.Serial, "", opt.Package, "", ""); rerr == nil {
			target = resolved
		}
	}
	tl := timeline.New(time.Now().UTC())
	if opt.Auth != nil {
		if opt.Phone != "" {
			opt.Auth.Prefill(opt.LabRunID, authgate.KindPhone, opt.Phone)
		}
		if opt.OTP != "" {
			opt.Auth.Prefill(opt.LabRunID, authgate.KindOTP, opt.OTP)
		}
	}
	emitSession := func(typ, msg string, tags []string, cat string, meta map[string]any) {
		if opt.Sessions == nil || opt.LabRunID == "" {
			return
		}
		if cat == "" {
			cat = "scenario"
		}
		md := map[string]any{"package": opt.Package, "scenario_id": scenarioID}
		for k, v := range meta {
			md[k] = v
		}
		level := "info"
		if cat == "error" || strings.Contains(typ, "FAIL") || strings.Contains(typ, "ASSERT") {
			level = "error"
		}
		_, _ = opt.Sessions.AddEvent(opt.LabRunID, session.Event{
			Type: typ, Source: "scenario", Category: cat, Level: level,
			Message: msg, Tags: tags, Metadata: md,
		})
	}
	pkgTags := scenarioTags(opt.Package)
	// Execute steps one-by-one so Live Log + Runs timeline show real progress.
	for i, a := range d.Actions {
		a = expandActionPkg(a, opt.Package)
		step := describeAction(i+1, a)
		res.Steps = append(res.Steps, step)
		if e.Bus != nil {
			e.Bus.Publish(events.Event{
				Type: "SCENARIO_STEP_STARTED", ScenarioID: scenarioID, ArtifactID: artifactID,
				RunID: res.ID, Message: step,
			})
		}
		tags := pkgTags
		emitSession("SCENARIO_STEP_STARTED", step, tags, "scenario", nil)

		// Interactive field — wait for Lab UI / API / MCP, then type or tap (choice/Allow).
		choiceSoft := false
		if a.Prompt != "" {
			if opt.Auth == nil || opt.LabRunID == "" {
				err = fmt.Errorf("prompt %q requires Lab session + auth gate (run via lab ui/api/mcp)", a.Prompt)
			} else {
				kind := authgate.NormalizeKind(a.Prompt)
				label := a.PromptLabel
				if label == "" {
					label = string(kind) + " for " + opt.Package
				}
				choices := a.PromptChoices
				// Never open AuthGate OTP/phone while a permission dialog covers the app
				// (Divar shows نوتیفیکیشن Allow before the real SMS screen).
				if kind == authgate.KindOTP || kind == authgate.KindPhone {
					emitSession("AUTH_PREPARE", "clear overlays · wait for "+string(kind)+" screen", append(tags, "auth"), "auth", map[string]any{
						"kind": kind,
					})
					if perr := rtscenarios.PrepareAuthUI(ctx, client, opt.Serial, string(kind), 60*time.Second); perr != nil {
						err = perr
					}
				}
				var value string
				if err == nil {
					emitSession("AUTH_PROMPT", label+" ["+string(kind)+"]", append(tags, "auth", string(kind)), "auth", map[string]any{
						"kind": kind, "interactive": true, "choices": choices,
					})
					if kind == authgate.KindOTP {
						// Lab UI submit OR user typing OTP on the device (both unblock the wait).
						value, err = waitOTP(ctx, opt.Auth, client, opt.Serial, opt.LabRunID, label, opt.Package, 5*time.Minute)
					} else {
						value, err = opt.Auth.Wait(ctx, opt.LabRunID, kind, label, opt.Package, 5*time.Minute, choices...)
					}
				}
				if err == nil {
					if authgate.IsChoice(kind) {
						choiceSoft = true
						emitSession("AUTH_CHOICE", "chose "+value, append(tags, "auth", "choice"), "auth", map[string]any{
							"kind": kind, "choice": value,
						})
						low := strings.ToLower(strings.TrimSpace(value))
						switch low {
						case "skip", "not now", "dismiss", "ignore":
							a = rtscenarios.Action{Shell: "input keyevent KEYCODE_BACK; input keyevent KEYCODE_BACK || true"}
						default:
							a = rtscenarios.Action{Tap: value}
						}
					} else {
						// If digits already on device (user typed OTP on emu), don't clear/retype.
						onDevice := false
						if xml0, derr := rtscenarios.DumpUI(ctx, client, opt.Serial); derr == nil &&
							!rtscenarios.UIHasBlockingDialog(xml0) &&
							rtscenarios.UIHasDigits(xml0, value) &&
							(kind != authgate.KindOTP || rtscenarios.UILooksLikeOTP(xml0)) &&
							(kind != authgate.KindPhone || rtscenarios.UILooksLikePhone(xml0)) {
							onDevice = true
							a = rtscenarios.Action{}
							emitSession("AUTH_TYPED", "accepted "+string(kind)+" already on device", append(tags, "auth"), "auth", map[string]any{
								"kind": kind, "redacted": true, "digits": len(value), "source": "device",
							})
						}
						if !onDevice {
							// Focus real EditText (not title/label), clear, type keyevents, verify digits.
							_ = rtscenarios.FocusEditText(ctx, client, opt.Serial)
							rtscenarios.ClearFocusedField(ctx, client, opt.Serial)
							if terr := rtscenarios.TypeText(ctx, client, opt.Serial, value); terr != nil {
								err = terr
							} else if kind == authgate.KindPhone || kind == authgate.KindOTP {
								time.Sleep(400 * time.Millisecond)
								xml, derr := rtscenarios.DumpUI(ctx, client, opt.Serial)
								if derr == nil && rtscenarios.UIHasBlockingDialog(xml) {
									err = fmt.Errorf("%s typed but permission dialog still covering the field — dismiss Allow first", kind)
								} else if derr == nil && !rtscenarios.UIHasDigits(xml, value) {
									emitSession("AUTH_TYPE_RETRY", "UI missing typed digits — focus EditText + retry", append(tags, "auth"), "auth", map[string]any{
										"kind": kind, "redacted": true,
									})
									_ = rtscenarios.FocusEditText(ctx, client, opt.Serial)
									rtscenarios.ClearFocusedField(ctx, client, opt.Serial)
									_ = rtscenarios.TypeText(ctx, client, opt.Serial, value)
									time.Sleep(400 * time.Millisecond)
									xml2, _ := rtscenarios.DumpUI(ctx, client, opt.Serial)
									if !rtscenarios.UIHasDigits(xml2, value) {
										if kind == authgate.KindPhone && strings.HasPrefix(value, "0") && len(value) == 11 {
											alt := value[1:]
											_ = rtscenarios.FocusEditText(ctx, client, opt.Serial)
											rtscenarios.ClearFocusedField(ctx, client, opt.Serial)
											_ = rtscenarios.TypeText(ctx, client, opt.Serial, alt)
											time.Sleep(400 * time.Millisecond)
											xml3, _ := rtscenarios.DumpUI(ctx, client, opt.Serial)
											if rtscenarios.UIHasDigits(xml3, alt) {
												value = alt
												emitSession("AUTH_TYPED_ALT", "typed national form without leading 0", append(tags, "auth"), "auth", map[string]any{
													"kind": kind, "redacted": true, "digits": len(alt),
												})
											} else {
												err = fmt.Errorf("phone digits not visible in UI after typing (wanted %d digits)", len(value))
											}
										} else {
											err = fmt.Errorf("%s digits not visible in UI after typing (wanted %d digits)", kind, len(value))
										}
									}
								}
							}
							if err == nil {
								a = rtscenarios.Action{} // already typed; skip second input in Run()
								emitSession("AUTH_TYPED", "typed "+string(kind)+" into device", append(tags, "auth"), "auth", map[string]any{
									"kind": kind, "redacted": true, "digits": len(value),
								})
							}
						}
					}
				}
			}
			if err != nil {
				res.EndedAt = time.Now().UTC()
				res.OK = false
				res.Error = err.Error()
				emitSession("SCENARIO_FAILED", err.Error(), []string{"scenario", "error", "auth"}, "error", nil)
				return res, err
			}
		}

		// Capture process / dumpsys / provider shells onto timeline for stealth evidence.
		if a.Shell != "" && evidenceShell(a.Shell) && opt.Sessions != nil && opt.LabRunID != "" {
			evCtx, evCancel := context.WithTimeout(ctx, 12*time.Second)
			out, serr := client.Shell(evCtx, opt.Serial, "sh", "-c", a.Shell)
			evCancel()
			msg := strings.TrimSpace(out)
			if len(msg) > 600 {
				msg = msg[:600] + "…"
			}
			if msg == "" {
				if serr != nil {
					msg = "(timeout/error: " + serr.Error() + ")"
				} else {
					msg = "(no output)"
				}
			}
			cat := "process"
			evTags := append(tags, "process", "evidence")
			if strings.Contains(a.Shell, "logcat") {
				cat = "kernel"
				evTags = append(evTags, "kernel")
			}
			if strings.Contains(a.Shell, "content query") {
				cat = "scenario"
				evTags = append(evTags, "attack", "provider")
			}
			emitSession("PROCESS_EVIDENCE", msg, evTags, cat, map[string]any{
				"shell": a.Shell, "error": errString(serr),
			})
			if e.Bus != nil {
				e.Bus.Publish(events.Event{
					Type: "SCENARIO_STEP_COMPLETED", ScenarioID: scenarioID, ArtifactID: artifactID,
					RunID: res.ID, Message: step,
				})
			}
			emitSession("SCENARIO_STEP_COMPLETED", step, tags, "scenario", nil)
			continue
		}

		one := []rtscenarios.Scenario{{Name: d.Name, Actions: []rtscenarios.Action{a}}}
		if err = rtscenarios.Run(ctx, client, opt.Serial, target, one, tl); err != nil {
			if choiceSoft {
				// Dialog may already be gone — dismiss and continue instead of failing the whole run.
				emitSession("AUTH_CHOICE_SOFT", "choice UI miss — continuing: "+err.Error(), append(tags, "auth", "choice"), "auth", nil)
				_, _ = client.Shell(ctx, opt.Serial, "sh", "-c", "input keyevent KEYCODE_BACK || true")
				err = nil
			} else {
				res.EndedAt = time.Now().UTC()
				res.OK = false
				res.Error = err.Error()
				if e.Bus != nil {
					e.Bus.Publish(events.Event{
						Type: "SCENARIO_FAILED", ScenarioID: scenarioID, ArtifactID: artifactID,
						RunID: res.ID, Level: "error", Message: err.Error(),
					})
				}
				emitSession("SCENARIO_FAILED", err.Error(), []string{"scenario", "error"}, "error", nil)
				return res, err
			}
		}
		if e.Bus != nil {
			e.Bus.Publish(events.Event{
				Type: "SCENARIO_STEP_COMPLETED", ScenarioID: scenarioID, ArtifactID: artifactID,
				RunID: res.ID, Message: step,
			})
		}
		emitSession("SCENARIO_STEP_COMPLETED", step, tags, "scenario", nil)
	}
	res.EndedAt = time.Now().UTC()
	res.OK = true
	if e.Bus != nil {
		e.Bus.Publish(events.Event{
			Type: "SCENARIO_COMPLETED", ScenarioID: scenarioID, ArtifactID: artifactID,
			RunID: res.ID, Message: "ok",
		})
	}
	return res, nil
}

func describeAction(n int, a rtscenarios.Action) string {
	switch {
	case a.Prompt != "":
		return fmt.Sprintf("%d:prompt:%s", n, a.Prompt)
	case a.Launch:
		return fmt.Sprintf("%d:launch", n)
	case a.Wait > 0:
		return fmt.Sprintf("%d:wait:%s", n, a.Wait)
	case a.Tap != "":
		return fmt.Sprintf("%d:tap:%s", n, a.Tap)
	case a.Input != "":
		return fmt.Sprintf("%d:input", n)
	case a.Shell != "":
		return fmt.Sprintf("%d:shell", n)
	default:
		return fmt.Sprintf("%d:noop", n)
	}
}

func evidenceShell(cmd string) bool {
	c := strings.ToLower(cmd)
	return strings.Contains(c, "dumpsys") ||
		strings.Contains(c, "ps -") || strings.Contains(c, "ps |") || strings.HasPrefix(strings.TrimSpace(c), "ps ") ||
		strings.Contains(c, "content query") ||
		strings.Contains(c, "logcat")
}

// scenarioTags is package-agnostic (never hardcodes a product name as the only tag).
func scenarioTags(pkg string) []string {
	tags := []string{"scenario", "app"}
	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return tags
	}
	short := pkg
	if i := strings.LastIndex(pkg, "."); i >= 0 && i+1 < len(pkg) {
		short = pkg[i+1:]
	}
	tags = append(tags, short)
	if strings.Contains(strings.ToLower(pkg), "divar") {
		tags = append(tags, "divar")
	}
	return tags
}

// expandPkg substitutes {{package}} / {{pkg}} / $PACKAGE in scenario action strings.
func expandPkg(s, pkg string) string {
	if s == "" || pkg == "" {
		return s
	}
	return strings.NewReplacer(
		"{{package}}", pkg,
		"{{pkg}}", pkg,
		"${PACKAGE}", pkg,
		"$PACKAGE", pkg,
	).Replace(s)
}

func expandActionPkg(a rtscenarios.Action, pkg string) rtscenarios.Action {
	a.Tap = expandPkg(a.Tap, pkg)
	a.Shell = expandPkg(a.Shell, pkg)
	a.Input = expandPkg(a.Input, pkg)
	a.PromptLabel = expandPkg(a.PromptLabel, pkg)
	if len(a.PromptChoices) > 0 {
		out := make([]string, len(a.PromptChoices))
		for i, c := range a.PromptChoices {
			out[i] = expandPkg(c, pkg)
		}
		a.PromptChoices = out
	}
	return a
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// SmokeLaunch is a built-in scenario definition (launch + wait).
func SmokeLaunch() *Definition {
	return &Definition{
		ID:   "builtin-smoke-launch",
		Name: "Smoke Launch",
		Actions: []rtscenarios.Action{
			{Launch: true},
			{Wait: 5 * time.Second},
		},
		Created: time.Now().UTC(),
	}
}

// divarNormalBrowse is a realistic “normal person” path through Divar:
// city → confirm → search product → open ad → scroll description → contact → second look.
// Texts are best-effort uiautomator matches (exact / substring / content-desc).
func divarNormalBrowse() []rtscenarios.Action {
	return []rtscenarios.Action{
		{Launch: true},
		{Wait: 8 * time.Second},
		// City picker (splash or in-app)
		{Tap: "شهر خود را انتخاب کنید"},
		{Wait: 1500 * time.Millisecond},
		{Tap: "تهران"},
		{Wait: 1 * time.Second},
		{Tap: "تأیید"}, // confirm city selection
		{Wait: 4 * time.Second},
		// Home feed — open global search (normal user)
		{Tap: "جستجو در همه"},
		{Wait: 2 * time.Second},
		{Input: "موبایل"},
		{Wait: 1 * time.Second},
		{Shell: "input keyevent KEYCODE_ENTER"},
		{Wait: 7 * time.Second},
		// Browse results like a person scrolling the list
		{Shell: "input swipe 540 1500 540 800 350"},
		{Wait: 2 * time.Second},
		{Shell: "input swipe 540 1500 540 900 350"},
		{Wait: 2 * time.Second},
		// Open an ad (price row is a reliable hit target on listing cards)
		{Tap: "تومان"},
		{Wait: 5 * time.Second},
		// Read description / “comments” area (scroll listing body)
		{Shell: "input swipe 540 1600 540 700 400"},
		{Wait: 2 * time.Second},
		{Shell: "input swipe 540 1600 540 700 400"},
		{Wait: 2 * time.Second},
		// Typical user: open contact / chat entry, glance, go back
		{Tap: "اطلاعات تماس"},
		{Wait: 3 * time.Second},
		{Shell: "input keyevent KEYCODE_BACK"},
		{Wait: 2 * time.Second},
		{Shell: "input keyevent KEYCODE_BACK"},
		{Wait: 2 * time.Second},
		// Second product search (another everyday query)
		{Tap: "جستجو"},
		{Wait: 1500 * time.Millisecond},
		{Input: "لپتاپ"},
		{Wait: 1 * time.Second},
		{Shell: "input keyevent KEYCODE_ENTER"},
		{Wait: 6 * time.Second},
		{Shell: "input swipe 540 1400 540 900 300"},
		{Wait: 2 * time.Second},
		{Tap: "تومان"},
		{Wait: 5 * time.Second},
		{Shell: "input swipe 540 1600 540 800 400"},
		{Wait: 3 * time.Second},
	}
}

// DivarCitySearch drives a normal browse: city → search → open ads → read details.
func DivarCitySearch() *Definition {
	return &Definition{
		ID:      "divar-city-search",
		Name:    "Divar · city select + product search",
		Actions: divarNormalBrowse(),
		Created: time.Now().UTC(),
	}
}

// DivarSC12BgAttack: normal browse → HOME (background) → harness/IPC probes.
func DivarSC12BgAttack() *Definition {
	acts := append([]rtscenarios.Action{}, divarNormalBrowse()...)
	acts = append(acts, []rtscenarios.Action{
		{Shell: "input keyevent KEYCODE_HOME"},
		{Wait: 5 * time.Second},
		{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
		{Wait: 2 * time.Second},
		{Shell: "am start -a com.apkcheck.testharness.PROBE -n com.apkcheck.testharness/.ProbeActivity || true"},
		{Wait: 2 * time.Second},
		{Shell: "am start -a android.intent.action.VIEW -d 'divar://' || true"},
		{Wait: 2 * time.Second},
		{Shell: "am start -a android.intent.action.VIEW -d 'https://divar.ir/' || true"},
		{Wait: 3 * time.Second},
		{Shell: "content query --uri content://ir.divar.provider/ 2>&1 || echo PROVIDER_QUERY_BLOCKED"},
		{Wait: 2 * time.Second},
		{Shell: "dumpsys package ir.divar | head -n 40 || true"},
		{Wait: 5 * time.Second},
		{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
		{Wait: 25 * time.Second},
	}...)
	return &Definition{
		ID:      "divar-sc12-bg-attack",
		Name:    "SC-12 · Divar browse then bg cross-app probe",
		Actions: acts,
		Created: time.Now().UTC(),
	}
}

// DivarSC13ProviderTheft focuses on provider/URI data paths after a short browse.
func DivarSC13ProviderTheft() *Definition {
	return &Definition{
		ID:   "divar-sc13-provider-theft",
		Name: "SC-13 · provider / URI grant probe",
		Actions: []rtscenarios.Action{
			{Launch: true},
			{Wait: 8 * time.Second},
			{Tap: "شهر خود را انتخاب کنید"},
			{Wait: 1500 * time.Millisecond},
			{Tap: "تهران"},
			{Wait: 1 * time.Second},
			{Tap: "تأیید"},
			{Wait: 4 * time.Second},
			{Tap: "جستجو در همه"},
			{Wait: 2 * time.Second},
			{Input: "لپتاپ"},
			{Shell: "input keyevent KEYCODE_ENTER"},
			{Wait: 5 * time.Second},
			{Tap: "تومان"},
			{Wait: 4 * time.Second},
			{Shell: "input keyevent KEYCODE_HOME"},
			{Wait: 3 * time.Second},
			{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
			{Wait: 2 * time.Second},
			{Shell: "content query --uri content://ir.divar.provider/ 2>&1 || echo BLOCKED"},
			{Shell: "content query --uri content://ir.divar/ 2>&1 || echo BLOCKED"},
			{Shell: "find /sdcard/Android/data/ir.divar -type f 2>/dev/null | head -n 20 || echo NO_EXT_DATA"},
			{Wait: 25 * time.Second},
		},
		Created: time.Now().UTC(),
	}
}

// DivarFullSecurityRerun is the end-to-end path: normal Divar use → HOME → harness attack → result.
// Use after workspace reset with record=true (≥3–4 min wall). Video named after this scenario.
func DivarFullSecurityRerun() *Definition {
	acts := append([]rtscenarios.Action{}, divarNormalBrowse()...)
	acts = append(acts, []rtscenarios.Action{
		{Shell: "input keyevent KEYCODE_HOME"},
		{Wait: 6 * time.Second},
		{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
		{Wait: 2 * time.Second},
		{Shell: "am start -a com.apkcheck.testharness.PROBE -n com.apkcheck.testharness/.ProbeActivity || true"},
		{Wait: 2 * time.Second},
		{Shell: "am start -a android.intent.action.VIEW -d 'divar://' || true"},
		{Wait: 2 * time.Second},
		{Shell: "am start -a android.intent.action.VIEW -d 'https://divar.ir/' || true"},
		{Wait: 3 * time.Second},
		{Shell: "content query --uri content://ir.divar.provider/ 2>&1 || echo PROVIDER_QUERY_BLOCKED"},
		{Wait: 2 * time.Second},
		{Shell: "content query --uri content://ir.divar/ 2>&1 || echo PROVIDER_QUERY_BLOCKED"},
		{Wait: 2 * time.Second},
		{Shell: "dumpsys package ir.divar | head -n 60 || true"},
		{Wait: 4 * time.Second},
		{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
		{Wait: 25 * time.Second},
	}...)
	return &Definition{
		ID:      "divar-full-security-rerun",
		Name:    "Divar Full Security Rerun (SC-12)",
		Actions: acts,
		Created: time.Now().UTC(),
	}
}

// AppLoginOTP is a reusable interactive phone + SMS OTP login for any package.
// Pass --package / API package=… Phone via MCP/API prefill; OTP in Lab UI.
// Taps are best-effort multilingual labels (unresolved taps soft-continue).
func AppLoginOTP() *Definition {
	return &Definition{
		ID:   "app-login-otp",
		Name: "App login · phone + SMS OTP (any package)",
		Actions: []rtscenarios.Action{
			{Launch: true},
			{Wait: 4 * time.Second},
			{Tap: "Allow"},
			{Tap: "Allow notifications"},
			{Tap: "While using the app"},
			{Tap: "اجازه دادن"},
			{Wait: 1500 * time.Millisecond},
			{Tap: "ورود"},
			{Wait: 800 * time.Millisecond},
			{Tap: "Login"},
			{Wait: 600 * time.Millisecond},
			{Tap: "Sign in"},
			{Wait: 600 * time.Millisecond},
			{Tap: "Log in"},
			{Wait: 600 * time.Millisecond},
			{Tap: "ورود با شماره موبایل"},
			{Wait: 800 * time.Millisecond},
			{Tap: "شماره موبایل"},
			{Wait: 600 * time.Millisecond},
			{Tap: "Phone"},
			{Wait: 600 * time.Millisecond},
			{Tap: "Mobile"},
			{Wait: 600 * time.Millisecond},
			{Prompt: "phone", PromptLabel: "Phone number for {{package}} (authorized test account)"},
			{Wait: 1500 * time.Millisecond},
			{Tap: "ادامه"},
			{Wait: 500 * time.Millisecond},
			{Tap: "Continue"},
			{Wait: 500 * time.Millisecond},
			{Tap: "Next"},
			{Wait: 500 * time.Millisecond},
			{Tap: "تأیید"},
			{Wait: 3 * time.Second},
			{Prompt: "otp", PromptLabel: "SMS verification code for {{package}}"},
			{Wait: 1500 * time.Millisecond},
			{Tap: "ورود"}, // Divar OTP confirm
			{Wait: 800 * time.Millisecond},
			{Tap: "تأیید"},
			{Wait: 500 * time.Millisecond},
			{Tap: "Confirm"},
			{Wait: 500 * time.Millisecond},
			{Tap: "Verify"},
			{Wait: 500 * time.Millisecond},
			{Tap: "Submit"},
			{Wait: 500 * time.Millisecond},
			{Tap: "Login"},
			{Wait: 2 * time.Second},
			{Tap: "Allow"},
			{Tap: "Accept"},
			{Tap: "اجازه دادن"},
			{Wait: 8 * time.Second},
		},
		Created: time.Now().UTC(),
	}
}

// AppBGProbe: launch target → HOME → harness probe → re-open package / provider (any app).
func AppBGProbe() *Definition {
	return &Definition{
		ID:   "app-bg-probe",
		Name: "App · HOME then bg cross-app probe (any package)",
		Actions: []rtscenarios.Action{
			{Launch: true},
			{Wait: 5 * time.Second},
			{Tap: "Allow"},
			{Tap: "اجازه دادن"},
			{Wait: 1 * time.Second},
			{Shell: "input keyevent KEYCODE_HOME"},
			{Wait: 3 * time.Second},
			{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
			{Wait: 2 * time.Second},
			{Shell: "am start -a com.apkcheck.testharness.PROBE -n com.apkcheck.testharness/.ProbeActivity || true"},
			{Wait: 2 * time.Second},
			{Shell: "am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p {{package}} --activity-no-user-action 2>/dev/null || am start -p {{package}} -c android.intent.category.LAUNCHER || true"},
			{Wait: 3 * time.Second},
			{Shell: "ps -A 2>/dev/null | grep -E '{{package}}|testharness' || ps 2>/dev/null | grep -E 'testharness' || echo NO_PS"},
			{Shell: "dumpsys package {{package}} 2>/dev/null | head -n 40 || true"},
			{Shell: "content query --uri content://{{package}}.provider/ 2>&1 || echo PROVIDER_BLOCKED"},
			{Shell: "content query --uri content://{{package}}/ 2>&1 || echo PROVIDER_BLOCKED"},
			{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
			{Wait: 8 * time.Second},
		},
		Created: time.Now().UTC(),
	}
}

// AppSettingsStealth: Settings app-info for target + harness while package may background.
func AppSettingsStealth() *Definition {
	return &Definition{
		ID:   "app-settings-stealth",
		Name: "App · Settings + stealth reopen (any package)",
		Actions: []rtscenarios.Action{
			{Launch: true},
			{Wait: 4 * time.Second},
			{Tap: "Allow"},
			{Tap: "اجازه دادن"},
			{Wait: 1 * time.Second},
			{Shell: "input keyevent KEYCODE_HOME"},
			{Wait: 2 * time.Second},
			{Shell: "am start -a android.settings.SETTINGS || true"},
			{Wait: 2 * time.Second},
			{Shell: "am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:{{package}} || true"},
			{Wait: 4 * time.Second},
			{Shell: "am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:com.apkcheck.testharness || true"},
			{Wait: 3 * time.Second},
			{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
			{Wait: 2 * time.Second},
			{Shell: "am start -a com.apkcheck.testharness.PROBE -n com.apkcheck.testharness/.ProbeActivity || true"},
			{Wait: 2 * time.Second},
			{Shell: "am start -p {{package}} -c android.intent.category.LAUNCHER || true"},
			{Wait: 3 * time.Second},
			{Shell: "ps -A 2>/dev/null | grep -E '{{package}}|testharness' || echo NO_PS"},
			{Shell: "dumpsys package {{package}} 2>/dev/null | head -n 40 || true"},
			{Shell: "content query --uri content://{{package}}.provider/ 2>&1 || echo PROVIDER_BLOCKED"},
			{Shell: "content query --uri content://{{package}}/ 2>&1 || echo PROVIDER_BLOCKED"},
			{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
			{Wait: 10 * time.Second},
		},
		Created: time.Now().UTC(),
	}
}

// DivarLoginOTP is Divar-flavored interactive SMS login (same auth gate as app-login-otp).
// Fresh installs: city picker → notification allow → دیوار من → ورود به حساب کاربری
// → phone field (شمارهٔ موبایل) → بعدی. Phone typed via keyevents + UI verify; OTP in Lab UI.
func DivarLoginOTP() *Definition {
	return &Definition{
		ID:   "divar-login-otp",
		Name: "Divar · login phone + SMS OTP (interactive)",
		Actions: []rtscenarios.Action{
			{Launch: true},
			{Wait: 5 * time.Second},
			{Tap: "Allow"},
			{Tap: "اجازه دادن"},
			{Tap: "اجازه می‌دهم"},
			{Wait: 1 * time.Second},
			// Fresh-install / cleared-data city gate
			{Tap: "شهر خود را انتخاب کنید"},
			{Wait: 1500 * time.Millisecond},
			{Tap: "تهران"},
			{Wait: 1500 * time.Millisecond},
			{Tap: "تأیید"},
			{Tap: "تایید"},
			{Wait: 2 * time.Second},
			// In-app notification CTA (before home feed)
			{Tap: "اجازه می‌دهم"},
			{Wait: 800 * time.Millisecond},
			{Tap: "Allow"},
			{Wait: 3 * time.Second},
			// Profile tab → login CTA (tap resolves to clickable parent View)
			{Tap: "دیوار من"},
			{Wait: 1500 * time.Millisecond},
			{Tap: "ورود به حساب کاربری"},
			{Wait: 2 * time.Second},
			{Tap: "ورود با شماره موبایل"},
			{Wait: 1 * time.Second},
			{Tap: "شماره موبایل"}, // folded match for شمارهٔ موبایل
			{Tap: "شمارهٔ موبایل"},
			{Wait: 1 * time.Second},
			{Prompt: "phone", PromptLabel: "Phone number for {{package}} (authorized test account)"},
			{Wait: 1500 * time.Millisecond},
			{Tap: "بعدی"},
			{Wait: 800 * time.Millisecond},
			{Tap: "تأیید"},
			{Tap: "تایید"},
			{Tap: "ادامه"},
			// Divar often shows notification Allow again after phone → before OTP.
			{Wait: 1500 * time.Millisecond},
			{Tap: "اجازه می‌دهم"},
			{Wait: 600 * time.Millisecond},
			{Tap: "Allow"},
			{Wait: 800 * time.Millisecond},
			{Tap: "اجازه دادن"},
			{Wait: 2 * time.Second},
			{Prompt: "otp", PromptLabel: "SMS verification code for {{package}}"},
			{Wait: 1500 * time.Millisecond},
			// OTP screen CTA is "ورود" (label often non-clickable; tap remaps to covering View).
			{Tap: "ورود"},
			{Wait: 800 * time.Millisecond},
			{Tap: "تأیید"},
			{Tap: "تایید"},
			{Tap: "بعدی"},
			{Wait: 3 * time.Second},
			{Tap: "Allow"},
			{Tap: "اجازه دادن"},
			{Wait: 8 * time.Second},
		},
		Created: time.Now().UTC(),
	}
}

// DivarBgStealthSettings: open Android Settings on camera, then lightweight harness
// tries to start Divar / query data while process + log evidence hits the timeline.
func DivarBgStealthSettings() *Definition {
	return &Definition{
		ID:   "divar-bg-stealth-settings",
		Name: "SC-12b · Settings + stealth Divar open (attacker)",
		Actions: []rtscenarios.Action{
			{Launch: true},
			{Wait: 4 * time.Second},
			{Tap: "Allow"},
			{Tap: "اجازه دادن"},
			{Wait: 1500 * time.Millisecond},
			{Shell: "input keyevent KEYCODE_HOME"},
			{Wait: 2 * time.Second},
			// Visible Settings path on the recording
			{Shell: "am start -a android.settings.SETTINGS || true"},
			{Wait: 3 * time.Second},
			{Shell: "am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:{{package}} || true"},
			{Wait: 4 * time.Second},
			{Shell: "am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:com.apkcheck.testharness || true"},
			{Wait: 4 * time.Second},
			{Shell: "ps -A | grep -E '{{package}}|testharness' || echo NO_PS"},
			{Shell: "dumpsys activity activities | head -n 40"},
			{Wait: 2 * time.Second},
			{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
			{Wait: 2 * time.Second},
			{Shell: "am start -a com.apkcheck.testharness.PROBE -n com.apkcheck.testharness/.ProbeActivity || true"},
			{Wait: 2 * time.Second},
			{Shell: "am start -p {{package}} -c android.intent.category.LAUNCHER || true"},
			{Wait: 3 * time.Second},
			{Shell: "am start -a android.intent.action.VIEW -d 'divar://' || true"},
			{Wait: 2 * time.Second},
			{Shell: "am start -a android.intent.action.VIEW -d 'https://divar.ir/' || true"},
			{Wait: 2 * time.Second},
			{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
			{Wait: 2 * time.Second},
			{Shell: "ps -A | grep -E '{{package}}|testharness' || echo NO_PS"},
			{Shell: "dumpsys package {{package}} | head -n 40"},
			{Shell: "dumpsys activity activities | head -n 60"},
			{Shell: "logcat -d -t 40"},
			{Shell: "content query --uri content://{{package}}.provider/ || echo PROVIDER_BLOCKED"},
			{Shell: "content query --uri content://{{package}}/ || echo PROVIDER_BLOCKED"},
			{Shell: "am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:{{package}} || true"},
			{Wait: 5 * time.Second},
			{Shell: "am start -n com.apkcheck.testharness/.MainActivity || true"},
			{Wait: 25 * time.Second},
		},
		Created: time.Now().UTC(),
	}
}

// waitOTP blocks on AuthGate submit while also polling the device for a typed OTP.
// Dismisses permission overlays; only accepts codes when the OTP screen is visible.
func waitOTP(ctx context.Context, auth *authgate.Manager, client *adb.Client, serial, runID, label, pkg string, timeout time.Duration) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("auth gate not configured")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		v   string
		err error
	}
	ch := make(chan outcome, 2)
	go func() {
		v, err := auth.Wait(ctx, runID, authgate.KindOTP, label, pkg, timeout)
		ch <- outcome{v, err}
	}()
	go func() {
		if client == nil || serial == "" {
			return
		}
		tick := time.NewTicker(700 * time.Millisecond)
		defer tick.Stop()
		last, same := "", 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				xml, err := rtscenarios.DumpUI(ctx, client, serial)
				if err != nil {
					continue
				}
				if rtscenarios.UIHasBlockingDialog(xml) {
					_ = rtscenarios.DismissBlockingDialogs(ctx, client, serial)
					last, same = "", 0
					continue
				}
				if !rtscenarios.UILooksLikeOTP(xml) {
					last, same = "", 0
					continue
				}
				code := rtscenarios.ExtractOTPFromUI(xml)
				if len(code) < 4 {
					last, same = "", 0
					continue
				}
				if code == last {
					same++
				} else {
					last, same = code, 1
				}
				// Stable for ~1.4s → treat as complete entry; Submit unblocks Auth.Wait.
				if same >= 2 {
					if _, serr := auth.Submit(runID, authgate.KindOTP, code); serr != nil {
						ch <- outcome{code, nil}
					}
					return
				}
			}
		}
	}()
	res := <-ch
	cancel()
	return res.v, res.err
}

// EnsureBuiltins writes/updates built-in scenario JSON files in the workspace.
func (e *Engine) EnsureBuiltins() {
	for _, d := range []*Definition{
		SmokeLaunch(),
		AppLoginOTP(),
		AppBGProbe(),
		AppSettingsStealth(),
		DivarLoginOTP(),
		DivarCitySearch(),
		DivarSC12BgAttack(),
		DivarBgStealthSettings(),
		DivarSC13ProviderTheft(),
		DivarFullSecurityRerun(),
	} {
		_ = e.Save(d)
	}
}
