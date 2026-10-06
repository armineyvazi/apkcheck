// Package network collects optional, non-MITM connection observations.
package network

import (
	"context"
	"regexp"
	"strings"

	"github.com/armin/apkcheck/internal/runtime/adb"
)

// Observation is a best-effort connection hint (no TLS decryption).
type Observation struct {
	Kind     string `json:"kind"` // dns | connect | cleartext_hint | failure
	Detail   string `json:"detail"`
	Evidence string `json:"evidence_class"`
}

var ipPortRe = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b`)

// Collect dumpsys connectivity / netstats snippets filtered by package when possible.
// MITM is intentionally unsupported here (must stay false).
func Collect(ctx context.Context, client *adb.Client, serial, pkg string, enabled bool) ([]Observation, string, error) {
	if !enabled {
		return nil, "", nil
	}
	var raw strings.Builder
	var obs []Observation
	for _, args := range [][]string{
		{"dumpsys", "connectivity"},
		{"dumpsys", "netstats"},
	} {
		out, err := client.Shell(ctx, serial, args...)
		if err != nil {
			continue
		}
		raw.WriteString("=== " + strings.Join(args, " ") + " ===\n")
		// Keep a bounded slice to avoid huge dumps.
		if len(out) > 200_000 {
			out = out[:200_000] + "\n…truncated…\n"
		}
		raw.WriteString(out)
		raw.WriteByte('\n')
		for _, line := range strings.Split(out, "\n") {
			if pkg != "" && !strings.Contains(line, pkg) && !strings.Contains(line, "NetworkAgent") {
				continue
			}
			low := strings.ToLower(line)
			switch {
			case strings.Contains(low, "cleartext") || strings.Contains(low, "http://"):
				obs = append(obs, Observation{Kind: "cleartext_hint", Detail: trim(line), Evidence: "RUNTIME_OBSERVATION"})
			case strings.Contains(low, "failed") || strings.Contains(low, "timeout"):
				obs = append(obs, Observation{Kind: "failure", Detail: trim(line), Evidence: "RUNTIME_OBSERVATION"})
			case ipPortRe.MatchString(line):
				obs = append(obs, Observation{Kind: "connect", Detail: trim(line), Evidence: "RUNTIME_OBSERVATION"})
			}
			if len(obs) >= 100 {
				break
			}
		}
	}
	return obs, raw.String(), nil
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return s[:299] + "…"
	}
	return s
}
