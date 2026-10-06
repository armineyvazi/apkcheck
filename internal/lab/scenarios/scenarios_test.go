package scenarios_test

import (
	"testing"
	"time"

	"github.com/armin/apkcheck/internal/lab/events"
	"github.com/armin/apkcheck/internal/lab/scenarios"
	rtscenarios "github.com/armin/apkcheck/internal/runtime/scenarios"
)

func TestSaveListGet(t *testing.T) {
	root := t.TempDir()
	eng := &scenarios.Engine{Root: root, Bus: events.NewBus(10)}
	d := &scenarios.Definition{
		Name: "login",
		Actions: []rtscenarios.Action{
			{Launch: true},
			{Wait: 2 * time.Second},
			{Tap: "Login"},
		},
	}
	if err := eng.Save(d); err != nil {
		t.Fatal(err)
	}
	if d.ID == "" {
		t.Fatal("id not set")
	}
	got, err := eng.Get(d.ID)
	if err != nil || got.Name != "login" {
		t.Fatalf("%+v %v", got, err)
	}
	list, err := eng.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
}

func TestEnsureBuiltinsDivarScenarios(t *testing.T) {
	root := t.TempDir()
	eng := &scenarios.Engine{Root: root}
	eng.EnsureBuiltins()
	for _, id := range []string{
		"divar-city-search",
		"divar-sc12-bg-attack",
		"divar-bg-stealth-settings",
		"divar-full-security-rerun",
		"app-login-otp",
		"divar-login-otp",
		"builtin-smoke-launch",
	} {
		d, err := eng.Get(id)
		if err != nil || d == nil || len(d.Actions) == 0 {
			t.Fatalf("%s: %+v %v", id, d, err)
		}
	}
	login, _ := eng.Get("app-login-otp")
	hasPrompt := false
	for _, a := range login.Actions {
		if a.Prompt == "phone" || a.Prompt == "otp" {
			hasPrompt = true
			break
		}
	}
	if !hasPrompt {
		t.Fatal("app-login-otp must include interactive prompts")
	}
	divar, _ := eng.Get("divar-login-otp")
	otpIdx, loginTap := -1, false
	for i, a := range divar.Actions {
		if a.Prompt == "otp" {
			otpIdx = i
		}
		if otpIdx >= 0 && i > otpIdx && a.Tap == "ورود" {
			loginTap = true
			break
		}
	}
	if otpIdx < 0 || !loginTap {
		t.Fatal("divar-login-otp must tap ورود after OTP prompt")
	}
}

func TestRunRequiresSerialPackage(t *testing.T) {
	root := t.TempDir()
	eng := &scenarios.Engine{Root: root, Bus: events.NewBus(8)}
	eng.EnsureBuiltins()
	res, err := eng.Run(t.Context(), "builtin-smoke-launch", "", scenarios.RunOptions{})
	if err == nil || res == nil || res.OK {
		t.Fatalf("expected serial/package error, got %+v %v", res, err)
	}
}
