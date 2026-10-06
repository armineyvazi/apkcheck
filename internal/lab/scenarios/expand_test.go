package scenarios

import (
	"strings"
	"testing"

	rtscenarios "github.com/armin/apkcheck/internal/runtime/scenarios"
)

func TestExpandPkgAndScenarioTags(t *testing.T) {
	got := expandPkg("dumpsys package {{package}} | grep $PACKAGE", "com.example.app")
	if !strings.Contains(got, "com.example.app") || strings.Contains(got, "{{") {
		t.Fatalf("expand: %q", got)
	}
	a := expandActionPkg(rtscenarios.Action{
		Shell: "content query --uri content://{{package}}/",
		PromptLabel: "OTP for {{package}}",
	}, "ir.divar")
	if a.Shell != "content query --uri content://ir.divar/" {
		t.Fatalf("shell %q", a.Shell)
	}
	if a.PromptLabel != "OTP for ir.divar" {
		t.Fatalf("label %q", a.PromptLabel)
	}
	tags := scenarioTags("com.foo.bar")
	if !containsAll(tags, "scenario", "app", "bar") {
		t.Fatalf("tags %#v", tags)
	}
	tags = scenarioTags("ir.divar")
	if !containsAll(tags, "app", "divar") {
		t.Fatalf("divar tags %#v", tags)
	}
}

func containsAll(ss []string, want ...string) bool {
	set := map[string]bool{}
	for _, s := range ss {
		set[s] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
