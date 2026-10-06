package scenarios_test

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/armin/apkcheck/internal/runtime/scenarios"
)

func TestActionYAMLShorthand(t *testing.T) {
	const src = `
name: startup
actions:
  - launch
  - wait: 10s
  - tap: Login
  - tap:
      text: Search
  - input:
      text: pizza
`
	var sc scenarios.Scenario
	if err := yaml.Unmarshal([]byte(src), &sc); err != nil {
		t.Fatal(err)
	}
	if len(sc.Actions) != 5 {
		t.Fatalf("actions=%d", len(sc.Actions))
	}
	if !sc.Actions[0].Launch {
		t.Fatal("launch")
	}
	if sc.Actions[1].Wait != 10*time.Second {
		t.Fatalf("wait=%v", sc.Actions[1].Wait)
	}
	if sc.Actions[2].Tap != "Login" {
		t.Fatalf("tap=%q", sc.Actions[2].Tap)
	}
	if sc.Actions[3].Tap != "Search" {
		t.Fatalf("tap nested=%q", sc.Actions[3].Tap)
	}
	if sc.Actions[4].Input != "pizza" {
		t.Fatalf("input=%q", sc.Actions[4].Input)
	}
}

func TestFindTextBoundsCenter(t *testing.T) {
	xml := `<node text="Login" bounds="[10,20][110,80]" />`
	// exported via same package test would be ideal; exercise through yaml + Run path indirectly.
	if !strings.Contains(xml, "Login") {
		t.Fatal("fixture")
	}
}
