package scenarios_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/armin/apkcheck/internal/lab/scenarios"
)

func TestBuiltinScenariosHaveActions(t *testing.T) {
	dir := t.TempDir()
	eng := &scenarios.Engine{Root: dir}
	eng.EnsureBuiltins()
	ids := []string{
		"builtin-smoke-launch",
		"app-login-otp",
		"app-bg-probe",
		"app-settings-stealth",
		"divar-login-otp",
		"divar-bg-stealth-settings",
		"divar-full-security-rerun",
	}
	for _, id := range ids {
		def, err := eng.Get(id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if def == nil || len(def.Actions) == 0 {
			t.Fatalf("%s: expected actions", id)
		}
		// On-disk JSON must round-trip (Lab workspace persistence).
		raw, err := os.ReadFile(filepath.Join(dir, "scenarios", id+".json"))
		if err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		var again scenarios.Definition
		if err := json.Unmarshal(raw, &again); err != nil {
			t.Fatalf("json %s: %v", id, err)
		}
		if again.ID != id {
			t.Fatalf("%s id mismatch %q", id, again.ID)
		}
	}
}
