// Package launcher resolves and starts launchable activities.
package launcher

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/armin/apkcheck/internal/runner"
	"github.com/armin/apkcheck/internal/runtime/adb"
)

var (
	packageRe = regexp.MustCompile(`package: name='([^']+)'`)
	launchRe  = regexp.MustCompile(`launchable-activity: name='([^']+)'`)
)

// Target is a launchable component.
type Target struct {
	Package  string `json:"package"`
	Activity string `json:"activity"`
	Source   string `json:"source"` // aapt | cmd package | override
}

// Result is launch evidence.
type Result struct {
	Success bool   `json:"success"`
	Output  string `json:"output"`
	Error   string `json:"error,omitempty"`
	Target  Target `json:"target"`
}

// ResolveLaunchTarget finds package + activity.
func ResolveLaunchTarget(ctx context.Context, client *adb.Client, serial, apkPath, pkg, activityOverride, aaptPath string) (Target, error) {
	t := Target{Package: pkg, Activity: activityOverride}
	if activityOverride != "" && pkg != "" {
		t.Activity = NormalizeActivity(pkg, activityOverride)
		t.Source = "override"
		return t, nil
	}

	if aaptPath != "" && apkPath != "" && (pkg == "" || activityOverride == "") {
		if res, err := runner.Run(ctx, aaptPath, "dump", "badging", apkPath); err == nil && res != nil {
			p, a := ParseBadging(res.Stdout + res.Stderr)
			if pkg == "" {
				pkg = p
				t.Package = p
			}
			if activityOverride == "" && a != "" {
				t.Activity = NormalizeActivity(pkg, a)
				t.Source = "aapt"
				if t.Package != "" && t.Activity != "" {
					return t, nil
				}
			}
		}
	}

	if pkg == "" {
		return t, fmt.Errorf("package name unknown — pass --package or ensure aapt can read the APK")
	}
	if activityOverride != "" {
		t.Activity = NormalizeActivity(pkg, activityOverride)
		t.Source = "override"
		return t, nil
	}

	// cmd package resolve-activity
	out, err := client.Shell(ctx, serial, "cmd", "package", "resolve-activity", "--brief", pkg)
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "/") {
				parts := strings.SplitN(line, "/", 2)
				if len(parts) == 2 {
					t.Package = parts[0]
					t.Activity = NormalizeActivity(parts[0], parts[1])
					t.Source = "cmd package"
					return t, nil
				}
			}
		}
	}

	// dumpsys package grep MAIN
	dump, err := client.Shell(ctx, serial, "dumpsys", "package", pkg)
	if err == nil {
		if act := findMainActivity(dump, pkg); act != "" {
			t.Activity = NormalizeActivity(pkg, act)
			t.Source = "dumpsys"
			return t, nil
		}
	}
	return t, fmt.Errorf("could not resolve launchable activity for %s — pass --activity", pkg)
}

func findMainActivity(dump, pkg string) string {
	lines := strings.Split(dump, "\n")
	for i, line := range lines {
		if strings.Contains(line, "android.intent.action.MAIN") {
			// look nearby for component
			for j := i; j >= 0 && j > i-15; j-- {
				if strings.Contains(lines[j], pkg+"/") {
					fields := strings.Fields(lines[j])
					for _, f := range fields {
						if strings.HasPrefix(f, pkg+"/") {
							return strings.TrimPrefix(f, pkg+"/")
						}
					}
				}
			}
		}
	}
	return ""
}

// ParseBadging extracts package + launchable activity from aapt badging text.
func ParseBadging(text string) (pkg, activity string) {
	if m := packageRe.FindStringSubmatch(text); len(m) == 2 {
		pkg = m[1]
	}
	if m := launchRe.FindStringSubmatch(text); len(m) == 2 {
		activity = m[1]
	}
	return pkg, activity
}

// Component returns package/activity suitable for `am start -n`.
func (t Target) Component() string {
	act := NormalizeActivity(t.Package, t.Activity)
	if t.Package == "" || act == "" {
		return ""
	}
	return t.Package + "/" + act
}

// NormalizeActivity turns ".MainActivity" into a form am start accepts.
func NormalizeActivity(pkg, activity string) string {
	activity = strings.TrimSpace(activity)
	if activity == "" {
		return ""
	}
	if strings.HasPrefix(activity, ".") && pkg != "" {
		return pkg + activity
	}
	return activity
}

// Launch starts the activity via am start.
// When Activity is empty but Package is set, resolves the launcher activity
// (cmd package / dumpsys) and falls back to monkey if needed.
func Launch(ctx context.Context, client *adb.Client, serial string, t Target) (*Result, error) {
	res := &Result{Target: t}
	if strings.TrimSpace(t.Package) == "" {
		res.Error = "missing package"
		return res, fmt.Errorf("%s", res.Error)
	}
	t.Package = strings.TrimSpace(t.Package)
	t.Activity = NormalizeActivity(t.Package, t.Activity)

	if t.Activity == "" {
		resolved, err := ResolveLaunchTarget(ctx, client, serial, "", t.Package, "", "")
		if err == nil && resolved.Activity != "" {
			t = resolved
		} else {
			// Package-only launch via monkey (same fallback as runtime Session.Launch).
			out, merr := client.Shell(ctx, serial, "monkey", "-p", t.Package, "-c", "android.intent.category.LAUNCHER", "1")
			res.Target = Target{Package: t.Package, Source: "monkey"}
			res.Output = strings.TrimSpace(out)
			if merr != nil {
				msg := "missing package/activity"
				if err != nil {
					msg = err.Error()
				}
				res.Error = fmt.Sprintf("%s (monkey: %v)", msg, merr)
				return res, fmt.Errorf("%s", res.Error)
			}
			res.Success = true
			return res, nil
		}
	}

	res.Target = t
	comp := t.Component()
	if comp == "" {
		res.Error = "missing package/activity"
		return res, fmt.Errorf("%s", res.Error)
	}
	out, err := client.SerialRun(ctx, serial, "shell", "am", "start",
		"-n", comp,
		"-a", "android.intent.action.MAIN",
		"-c", "android.intent.category.LAUNCHER",
	)
	if out != nil {
		res.Output = strings.TrimSpace(out.Stdout + "\n" + out.Stderr)
	}
	if err != nil {
		res.Error = err.Error()
		return res, err
	}
	low := strings.ToLower(res.Output)
	if strings.Contains(low, "error") || strings.Contains(low, "exception") {
		res.Error = res.Output
		return res, fmt.Errorf("am start error: %s", res.Output)
	}
	res.Success = true
	return res, nil
}

// ForceStop stops the app.
func ForceStop(ctx context.Context, client *adb.Client, serial, pkg string) error {
	if pkg == "" {
		return nil
	}
	_, err := client.Shell(ctx, serial, "am", "force-stop", pkg)
	return err
}
