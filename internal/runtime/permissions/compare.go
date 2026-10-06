// Package permissions compares manifest-declared vs runtime-granted permissions.
package permissions

import (
	"context"
	"strings"

	"github.com/armin/apkcheck/internal/runtime/adb"
)

// Status is one permission comparison row.
type Status struct {
	Name           string `json:"name"`
	DeclaredStatic bool   `json:"declared_static"`
	GrantedRuntime bool   `json:"granted_runtime"`
	ObservedUsage  bool   `json:"observed_usage"`
	Classification string `json:"classification"`
	Conclusion     string `json:"conclusion"`
}

// Compare merges static declared list with dumpsys runtime grants.
// observedUsage should come from logcat/API heuristics (may be empty).
func Compare(ctx context.Context, client *adb.Client, serial, pkg string, declared []string, observed map[string]bool) ([]Status, string, error) {
	dump := ""
	if pkg != "" {
		out, err := client.Shell(ctx, serial, "dumpsys", "package", pkg)
		if err == nil {
			dump = out
		}
	}
	granted := parseGranted(dump)
	var rows []Status
	seen := map[string]bool{}
	for _, d := range declared {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		seen[d] = true
		g := granted[d]
		obs := observed[d]
		row := Status{
			Name: d, DeclaredStatic: true, GrantedRuntime: g, ObservedUsage: obs,
		}
		row.Classification, row.Conclusion = classify(row)
		rows = append(rows, row)
	}
	for g := range granted {
		if seen[g] {
			continue
		}
		row := Status{Name: g, DeclaredStatic: false, GrantedRuntime: true, ObservedUsage: observed[g]}
		row.Classification, row.Conclusion = classify(row)
		rows = append(rows, row)
	}
	return rows, dump, nil
}

func parseGranted(dump string) map[string]bool {
	out := map[string]bool{}
	inGranted := false
	for _, line := range strings.Split(dump, "\n") {
		trim := strings.TrimSpace(line)
		if strings.Contains(trim, "granted=true") || strings.HasPrefix(trim, "android.permission.") {
			// install permissions section lines like: android.permission.INTERNET: granted=true
			if strings.HasPrefix(trim, "android.permission.") || strings.Contains(trim, "permission.") {
				name := trim
				if i := strings.IndexByte(name, ':'); i >= 0 {
					name = strings.TrimSpace(name[:i])
				}
				if strings.Contains(trim, "granted=true") {
					out[name] = true
				}
			}
		}
		if strings.Contains(trim, "runtime permissions:") {
			inGranted = true
			continue
		}
		if inGranted {
			if trim == "" || strings.HasPrefix(trim, "User ") {
				inGranted = false
				continue
			}
			if strings.Contains(trim, "granted=true") {
				name := trim
				if i := strings.IndexByte(name, ':'); i >= 0 {
					name = strings.TrimSpace(name[:i])
				}
				out[name] = true
			}
		}
	}
	return out
}

func classify(s Status) (string, string) {
	switch {
	case s.DeclaredStatic && s.GrantedRuntime && s.ObservedUsage:
		return "STATIC_AND_RUNTIME_CORRELATED", "Declared, granted, and usage observed in this session."
	case s.DeclaredStatic && s.GrantedRuntime && !s.ObservedUsage:
		return "RUNTIME_OBSERVED", "Declared and granted; protected API usage was NOT OBSERVED in this session."
	case s.DeclaredStatic && !s.GrantedRuntime:
		return "STATIC_CONFIRMED", "Declared in manifest; not granted at runtime during this session."
	case !s.DeclaredStatic && s.GrantedRuntime:
		return "RUNTIME_OBSERVED", "Granted at runtime but not in provided static declaration list."
	default:
		return "NOT_OBSERVED", "No static declaration and not granted."
	}
}
