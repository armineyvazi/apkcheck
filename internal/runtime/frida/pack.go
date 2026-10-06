// Package frida provides an optional, modular Frida/Objection runtime analysis pack.
// It is OFF by default. Observations are always tagged RUNTIME_OBSERVATION.
// NOT OBSERVED ≠ ABSENT.
package frida

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/armin/apkcheck/pkg/model"
)

// Options configures an optional Frida session.
type Options struct {
	Package      string
	DeviceID     string // adb serial
	OutputDir    string
	Duration     time.Duration
	Scripts      []string // paths to Frida JS scripts
	UseObjection bool
	Hooks        []string // method hooks e.g. com.example.App.authenticate
}

// Result is a modular runtime pack output.
type Result struct {
	Enabled   bool                       `json:"enabled"`
	Available bool                       `json:"frida_available"`
	Obs       []model.RuntimeObservation `json:"observations"`
	ScriptLog string                     `json:"script_log,omitempty"`
	Notes     []string                   `json:"notes"`
}

// ProbeAvailability checks for frida/frida-ps without attaching.
func ProbeAvailability() (frida, objection, adb bool) {
	_, err := exec.LookPath("frida")
	frida = err == nil
	_, err = exec.LookPath("objection")
	objection = err == nil
	_, err = exec.LookPath("adb")
	adb = err == nil
	return
}

// Run executes optional hooks. If Frida is missing, returns structured notes
// without failing the static pipeline.
func Run(ctx context.Context, opt Options) (*Result, error) {
	res := &Result{
		Enabled: true,
		Notes: []string{
			"RUNTIME_OBSERVATION only — never treat as complete behavior.",
			"NOT OBSERVED ≠ ABSENT (e.g. root-detection method not triggered ≠ no root detection).",
		},
	}
	hasFrida, hasObj, hasADB := ProbeAvailability()
	res.Available = hasFrida
	if !hasADB {
		res.Notes = append(res.Notes, "adb not on PATH — runtime pack skipped")
		res.Obs = append(res.Obs, model.RuntimeObservation{
			Kind: "pack_status", Message: "adb unavailable",
			Class: model.EvidenceRuntime, Status: "skipped",
			Note: "NOT OBSERVED ≠ ABSENT",
		})
		return res, nil
	}
	if !hasFrida && !opt.UseObjection {
		res.Notes = append(res.Notes, "frida not on PATH — install Frida to enable hooks; pack remains optional")
		res.Obs = append(res.Obs, model.RuntimeObservation{
			Kind: "pack_status", Message: "frida unavailable",
			Class: model.EvidenceRuntime, Status: "skipped",
			Note: "NOT OBSERVED ≠ ABSENT",
		})
		_ = writeBuiltinScripts(opt.OutputDir)
		return res, nil
	}

	if opt.Duration <= 0 {
		opt.Duration = 15 * time.Second
	}
	if err := os.MkdirAll(opt.OutputDir, 0o750); err != nil {
		return res, err
	}
	scriptDir := filepath.Join(opt.OutputDir, "frida-scripts")
	_ = writeBuiltinScripts(scriptDir)

	if opt.UseObjection && hasObj && opt.Package != "" {
		obs, logPath, err := runObjection(ctx, opt)
		res.Obs = append(res.Obs, obs...)
		res.ScriptLog = logPath
		if err != nil {
			res.Notes = append(res.Notes, "objection: "+err.Error())
		}
		return res, nil
	}

	if hasFrida && opt.Package != "" {
		obs, logPath, err := runFrida(ctx, opt, scriptDir)
		res.Obs = append(res.Obs, obs...)
		res.ScriptLog = logPath
		if err != nil {
			res.Notes = append(res.Notes, "frida: "+err.Error())
		}
	} else {
		res.Obs = append(res.Obs, model.RuntimeObservation{
			Kind: "pack_status", Message: "no package specified for attach",
			Class: model.EvidenceRuntime, Status: "skipped",
			Note: "NOT OBSERVED ≠ ABSENT",
		})
	}

	// Persist observations
	raw, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile(filepath.Join(opt.OutputDir, "frida-pack.json"), raw, 0o640)
	return res, nil
}

func runFrida(ctx context.Context, opt Options, scriptDir string) ([]model.RuntimeObservation, string, error) {
	script := filepath.Join(scriptDir, "security_observe.js")
	args := []string{"-U"}
	if opt.DeviceID != "" {
		args = []string{"-D", opt.DeviceID}
	}
	args = append(args, "-f", opt.Package, "-l", script, "--no-pause")
	cctx, cancel := context.WithTimeout(ctx, opt.Duration+5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "frida", args...)
	out, err := cmd.CombinedOutput()
	logPath := filepath.Join(opt.OutputDir, "frida.log")
	_ = os.WriteFile(logPath, out, 0o640)

	obs := []model.RuntimeObservation{{
		Kind: "frida_session", Message: fmt.Sprintf("attached package=%s duration=%s", opt.Package, opt.Duration),
		Class: model.EvidenceRuntime, Status: "ran",
		Note: "NOT OBSERVED ≠ ABSENT",
	}}
	text := string(out)
	for _, marker := range []struct{ kind, needle string }{
		{"ssl_pinning_hint", "TrustManager"},
		{"ssl_pinning_hint", "OkHttp"},
		{"root_detection_hint", "su binary"},
		{"root_detection_hint", "RootBeer"},
		{"network", "javax.net.ssl"},
	} {
		if strings.Contains(text, marker.needle) {
			obs = append(obs, model.RuntimeObservation{
				Kind: marker.kind, Message: "log matched " + marker.needle,
				Class: model.EvidenceRuntime, Status: "observed",
				Note: "Partial observation only",
			})
		}
	}
	if err != nil && cctx.Err() == nil {
		return obs, logPath, err
	}
	return obs, logPath, nil
}

func runObjection(ctx context.Context, opt Options) ([]model.RuntimeObservation, string, error) {
	// objection explore is interactive; use a non-interactive job list probe
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	args := []string{"api", "jobs", "list"}
	cmd := exec.CommandContext(cctx, "objection", args...)
	out, err := cmd.CombinedOutput()
	logPath := filepath.Join(opt.OutputDir, "objection.log")
	_ = os.WriteFile(logPath, out, 0o640)
	obs := []model.RuntimeObservation{{
		Kind: "objection", Message: "objection probe executed",
		Class: model.EvidenceRuntime, Status: "ran",
		Note: "NOT OBSERVED ≠ ABSENT — SSL pinning / root probes require explicit hooks",
	}}
	return obs, logPath, err
}

func writeBuiltinScripts(dir string) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	script := `// APKCheck Frida observe pack — optional RUNTIME_OBSERVATION only
// NOT OBSERVED ≠ ABSENT
Java.perform(function () {
  console.log("[apkcheck] security_observe loaded");
  try {
    var Log = Java.use("android.util.Log");
    Log.d.overload("java.lang.String", "java.lang.String").implementation = function (t, m) {
      if (m && (m.indexOf("http://") >= 0 || m.indexOf("token") >= 0 || m.indexOf("password") >= 0)) {
        console.log("[apkcheck][log] " + t + ": " + m.substring(0, 120));
      }
      return this.d(t, m);
    };
  } catch (e) {}
  try {
    var TM = Java.use("javax.net.ssl.TrustManager");
    console.log("[apkcheck] TrustManager present");
  } catch (e) {}
  try {
    var RB = Java.use("com.scottyab.rootbeer.RootBeer");
    console.log("[apkcheck] RootBeer present — root detection library loaded");
  } catch (e) {}
});
`
	return os.WriteFile(filepath.Join(dir, "security_observe.js"), []byte(script), 0o640)
}
